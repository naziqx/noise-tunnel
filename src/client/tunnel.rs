use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::connect_async_tls_with_config;
use tokio_tungstenite::Connector;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};


use crate::protocol::noise::{Handshake, Keypair};
use crate::protocol::frame::{Frame, FrameType};
use bytes::Bytes;

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

    // ── Noise XX handshake ──────────────────────────────────────
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

    let session = hs.into_transport()?;

    // Оборачиваем сессию в Arc<Mutex> — будем использовать из двух задач
    let session = std::sync::Arc::new(tokio::sync::Mutex::new(session));

    // ── Создаём TUN интерфейс ───────────────────────────────────
    let tun_dev = crate::client::tun::create_tun()?;

    // Разделяем TUN на чтение и запись
    let (mut tun_rx, mut tun_tx) = tokio::io::split(tun_dev);

    // Разделяем WebSocket
    // ws_tx уже есть, ws_rx уже есть
    let ws_tx = std::sync::Arc::new(tokio::sync::Mutex::new(ws_tx));

    let session_clone = session.clone();
    let ws_tx_clone   = ws_tx.clone();

    // ── Задача 1: TUN → WebSocket ───────────────────────────────
    // Читаем IP пакеты с TUN и шлём на сервер
    let tun_to_ws = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let n = match tun_rx.read(&mut buf).await {
                Ok(n) if n == 0 => break,
                Ok(n) => n,
                Err(e) => { eprintln!("[клиент] TUN read ошибка: {}", e); break; }
            };

            let packet = Bytes::copy_from_slice(&buf[..n]);
            let frame  = Frame::new_data(packet);
            let encoded = frame.encode();

            let encrypted = {
                let mut sess = session_clone.lock().await;
                match sess.encrypt(&encoded) {
                    Ok(e) => e,
                    Err(e) => { eprintln!("[клиент] encrypt ошибка: {}", e); break; }
                }
            };

            let mut tx = ws_tx_clone.lock().await;
            if tx.send(Message::Binary(encrypted.into())).await.is_err() {
                break;
            }
        }
    });

    // ── Задача 2: WebSocket → TUN ───────────────────────────────
    // Получаем пакеты от сервера и пишем в TUN
    let ws_to_tun = tokio::spawn(async move {
        while let Some(msg) = ws_rx.next().await {
            let msg = match msg {
                Ok(m) => m,
                Err(e) => { eprintln!("[клиент] WS read ошибка: {}", e); break; }
            };

            if !msg.is_binary() { continue; }

            let decrypted = {
                let mut sess = session.lock().await;
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

    println!("[клиент]  Туннель запущен! Трафик идёт через TUN");

    // Ждём завершения любой из задач
    tokio::select! {
        _ = tun_to_ws => println!("[клиент] TUN→WS задача завершена"),
        _ = ws_to_tun => println!("[клиент] WS→TUN задача завершена"),
    }

    Ok(())
}