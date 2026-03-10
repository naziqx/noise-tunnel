use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::protocol::noise::{Handshake, Keypair, NoiseSession};
use crate::protocol::frame::{Frame, FrameType};

use native_tls::{Identity, TlsAcceptor};
use std::fs;

pub async fn run(addr: &str, server_keys: Keypair) -> anyhow::Result<()> {
    // Загружаем TLS сертификат
    let cert = fs::read("/etc/letsencrypt/live/noise-tunnel.ddns.net/fullchain.pem")?;
    let key  = fs::read("/etc/letsencrypt/live/noise-tunnel.ddns.net/privkey.pem")?;

    let cert_str = String::from_utf8(cert)?;
    let key_str  = String::from_utf8(key)?;

    let identity = Identity::from_pkcs8(cert_str.as_bytes(), key_str.as_bytes())?;
    let acceptor = TlsAcceptor::new(identity)?;
    let acceptor = tokio_native_tls::TlsAcceptor::from(acceptor);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("[сервер] слушаю на {} (TLS)", addr);

    loop {
        let (stream, peer) = listener.accept().await?;
        println!("[сервер] подключился: {}", peer);

        let acceptor     = acceptor.clone();
        let private_key  = server_keys.private.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => { eprintln!("[сервер] TLS ошибка: {}", e); return; }
            };

            let ws = match tokio_tungstenite::accept_async(tls_stream).await {
                Ok(s) => s,
                Err(e) => { eprintln!("[сервер] WS ошибка: {}", e); return; }
            };

            if let Err(e) = handle_client(ws, private_key).await {
                let msg = e.to_string();
                if !msg.contains("Connection reset") {
                    println!("[сервер] ошибка: {}", msg);
                }
            }       
        });
    }
}

async fn handle_client(
    ws: tokio_tungstenite::WebSocketStream<tokio_native_tls::TlsStream<tokio::net::TcpStream>>,
    private_key: Vec<u8>,
) -> anyhow::Result<()> {
    let (mut ws_tx, mut ws_rx) = ws.split();

    println!("[сервер] WebSocket установлен, начинаю handshake...");

    // ── Noise XX handshake ──────────────────────────────────────
    let mut hs = Handshake::respond(&private_key)?;

    let msg1 = ws_rx.next().await
        .ok_or(anyhow::anyhow!("соединение закрыто"))??;
    hs.read_message(&msg1.into_data())?;
    println!("[сервер] ← msg1 получен");

    let msg2 = hs.write_message(&[])?;
    ws_tx.send(Message::Binary(msg2.into())).await?;
    println!("[сервер] → msg2 отправлен");

    let msg3 = ws_rx.next().await
        .ok_or(anyhow::anyhow!("соединение закрыто"))??;
    hs.read_message(&msg3.into_data())?;
    println!("[сервер] ← msg3 получен");

    println!("[сервер] ✓ Handshake завершён!");

    let session = Arc::new(Mutex::new(hs.into_transport()?));

    // ── Создаём TUN на сервере ──────────────────────────────────
    let mut tun_config = tun::Configuration::default();
    tun_config
        .address("172.16.0.1")
        .destination("172.16.0.2") // IP клиента в туннеле
        .netmask("255.255.255.0")
        .mtu(1420)
        .up();

    #[cfg(target_os = "linux")]
    tun_config.platform(|p| { p.packet_information(false); });

    let tun_dev = tun::create_as_async(&tun_config)?;
    println!("[сервер] ✓ TUN интерфейс создан (172.16.0.1)");
    tokio::process::Command::new("ip")
    .args(["route", "add", "172.16.0.2", "dev", "tun0"])
    .output()
    .await
    .ok();
    let (mut tun_rx, mut tun_tx) = tokio::io::split(tun_dev);
    let ws_tx = Arc::new(Mutex::new(ws_tx));
    let session_clone = session.clone();
    let ws_tx_clone   = ws_tx.clone();

    // ── TUN → WebSocket ─────────────────────────────────────────
    let tun_to_ws = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let n = match tun_rx.read(&mut buf).await {
                Ok(n) if n == 0 => break,
                Ok(n) => n,
                Err(e) => { eprintln!("[сервер] TUN read ошибка: {}", e); break; }
            };

            let frame   = Frame::new_data(bytes::Bytes::copy_from_slice(&buf[..n]));
            let encoded = frame.encode();

            let encrypted = {
                let mut sess = session_clone.lock().await;
                match sess.encrypt(&encoded) {
                    Ok(e) => e,
                    Err(e) => { eprintln!("[сервер] encrypt ошибка: {}", e); break; }
                }
            };

            let mut tx = ws_tx_clone.lock().await;
            if tx.send(Message::Binary(encrypted.into())).await.is_err() {
                break;
            }
        }
    });

    // ── WebSocket → TUN ─────────────────────────────────────────
    let ws_to_tun = tokio::spawn(async move {
        while let Some(msg) = ws_rx.next().await {
            let msg = match msg {
                Ok(m) => m,
                Err(_) => break,
            };

            if !msg.is_binary() { continue; }

            let decrypted = {
                let mut sess = session.lock().await;
                match sess.decrypt(&msg.into_data()) {
                    Ok(d) => d,
                    Err(e) => { eprintln!("[сервер] decrypt ошибка: {}", e); break; }
                }
            };

            let frame = match Frame::decode(&decrypted) {
                Ok(f) => f,
                Err(e) => { eprintln!("[сервер] frame decode: {}", e); continue; }
            };

            if frame.frame_type == FrameType::Data {
                if tun_tx.write_all(&frame.payload).await.is_err() {
                    break;
                }
            }
        }
    });

    println!("[сервер] Туннель активен!");

    tokio::select! {
        _ = tun_to_ws => println!("[сервер] TUN→WS завершена"),
        _ = ws_to_tun => println!("[сервер] WS→TUN завершена"),
    }

    Ok(())
}