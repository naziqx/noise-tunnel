use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::Connector;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::protocol::noise::{Handshake, Keypair};
use crate::protocol::frame::{Frame, FrameType};
use bytes::Bytes;

const KEEPALIVE_INTERVAL: u64 = 30;

pub async fn run(
    server_url:        &str,
    my_keys:           Keypair,
    server_public_key: Vec<u8>,
) -> anyhow::Result<()> {
    println!("[клиент] подключаюсь к {}...", server_url);

    let connector = Connector::NativeTls(native_tls::TlsConnector::new()?);
    let (ws, _) = tokio_tungstenite::connect_async_tls_with_config(
        server_url,
        None,
        false,
        Some(connector),
    ).await?;
    let (mut ws_tx, mut ws_rx) = ws.split();

    println!("[клиент] WebSocket установлен, начинаю handshake...");

    // ── Noise XX handshake ───────────────────────────────
    let mut hs = Handshake::initiate(&my_keys.private, &server_public_key)?;

    let msg1 = hs.write_message(&[])?;
    ws_tx.send(Message::Binary(msg1.into())).await?;
    println!("[клиент] → msg1 отправлен");

    let msg2 = ws_rx.next().await
        .ok_or(anyhow::anyhow!("соединение закрыто"))??;
    hs.read_message(&msg2.into_data())?;
    println!("[клиент] ← msg2 получен");

    let msg3 = hs.write_message(&[])?;
    ws_tx.send(Message::Binary(msg3.into())).await?;
    println!("[клиент] → msg3 отправлен");

    println!("[клиент] ✓ Handshake завершён!");

    let session = std::sync::Arc::new(tokio::sync::Mutex::new(hs.into_transport()?));

    // ── Получаем назначенный IP от сервера ───────────────
    let ip_msg = ws_rx.next().await
        .ok_or(anyhow::anyhow!("сервер не прислал IP"))??;

    let assigned_ip = {
        let mut sess = session.lock().await;
        let decrypted = sess.decrypt(&ip_msg.into_data())?;
        String::from_utf8(decrypted)?
    };

    println!("[клиент] ✓ Получен IP от сервера: {}", assigned_ip);
    std::fs::write("/tmp/vpn.client_ip", &assigned_ip)?;

    // ── Создаём TUN с назначенным IP ────────────────────
    let tun_dev = crate::client::tun::create_tun(&assigned_ip)?;
    let (mut tun_rx, mut tun_tx) = tokio::io::split(tun_dev);

    let ws_tx = std::sync::Arc::new(tokio::sync::Mutex::new(ws_tx));

    // Клонируем ВСЕ Arc до того как они переместятся в замыкания
    let sess_tun_to_ws = session.clone();
    let sess_ws_to_tun = session.clone(); // клон до move в ws_to_tun
    let sess_ka        = session.clone();
    let ws_tx_tun      = ws_tx.clone();
    let ws_tx_ka       = ws_tx.clone();

    // ── TUN → WebSocket ──────────────────────────────────
    let tun_to_ws = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let n = match tun_rx.read(&mut buf).await {
                Ok(n) if n == 0 => break,
                Ok(n) => n,
                Err(e) => { eprintln!("[клиент] TUN read ошибка: {}", e); break; }
            };

            let frame   = Frame::new_data(Bytes::copy_from_slice(&buf[..n]));
            let encoded = frame.encode();

            let encrypted = {
                let mut sess = sess_tun_to_ws.lock().await;
                match sess.encrypt(&encoded) {
                    Ok(e) => e,
                    Err(e) => { eprintln!("[клиент] encrypt ошибка: {}", e); break; }
                }
            };

            let mut tx = ws_tx_tun.lock().await;
            if tx.send(Message::Binary(encrypted.into())).await.is_err() {
                break;
            }
        }
    });

    // ── WebSocket → TUN ──────────────────────────────────
    let ws_to_tun = tokio::spawn(async move {
        while let Some(msg) = ws_rx.next().await {
            let msg = match msg {
                Ok(m) => m,
                Err(e) => { eprintln!("[клиент] WS read ошибка: {}", e); break; }
            };

            if !msg.is_binary() { continue; }

            let decrypted = {
                let mut sess = sess_ws_to_tun.lock().await;
                match sess.decrypt(&msg.into_data()) {
                    Ok(d) => d,
                    Err(e) => { eprintln!("[клиент] decrypt ошибка: {}", e); break; }
                }
            };

            let frame = match Frame::decode(&decrypted) {
                Ok(f) => f,
                Err(e) => { eprintln!("[клиент] frame decode ошибка: {}", e); continue; }
            };

            if frame.frame_type == FrameType::Data {
                if tun_tx.write_all(&frame.payload).await.is_err() {
                    break;
                }
            }
        }
    });

    // ── Keepalive ────────────────────────────────────────
    let keepalive = tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(KEEPALIVE_INTERVAL)).await;

            let frame   = Frame::new_keepalive();
            let encoded = frame.encode();

            let encrypted = {
                let mut sess = sess_ka.lock().await;
                match sess.encrypt(&encoded) {
                    Ok(e) => e,
                    Err(e) => { eprintln!("[клиент] keepalive encrypt: {}", e); break; }
                }
            };

            let mut tx = ws_tx_ka.lock().await;
            if tx.send(Message::Binary(encrypted.into())).await.is_err() {
                break;
            }

            println!("[клиент] ♥ keepalive отправлен");
        }
    });

    println!("[клиент] Туннель запущен! Keepalive каждые {}с", KEEPALIVE_INTERVAL);

    tokio::select! {
        _ = tun_to_ws => println!("[клиент] TUN→WS завершена"),
        _ = ws_to_tun => println!("[клиент] WS→TUN завершена"),
        _ = keepalive => println!("[клиент] keepalive завершён"),
    }

    std::fs::remove_file("/tmp/vpn.client_ip").ok();

    Ok(())
}
