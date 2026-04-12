use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::Connector;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::{Arc, Mutex};

use crate::protocol::noise::{Handshake, Keypair};
use crate::protocol::frame::{Frame, FrameType};
use crate::client::tui::{AppState, ConnectionState};
use bytes::Bytes;

const KEEPALIVE_INTERVAL: u64 = 30;

// Логируем в TUI state
fn log(state: &Arc<Mutex<AppState>>, msg: &str) {
    if let Ok(mut s) = state.lock() {
        s.add_log(msg);
    }
}

pub async fn run(
    server_url:        &str,
    my_keys:           Keypair,
    server_public_key: Vec<u8>,
    state:             Arc<Mutex<AppState>>,
    mut stop_rx:       tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    log(&state, &format!("Подключаюсь к {}...", server_url));

    {
        let mut s = state.lock().unwrap();
        s.connection = ConnectionState::Connecting;
    }

    let connector = Connector::NativeTls(native_tls::TlsConnector::new()?);
    let (ws, _) = match tokio_tungstenite::connect_async_tls_with_config(
        server_url, None, false, Some(connector),
    ).await {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("✗ Ошибка подключения: {}", e);
            log(&state, &msg);
            let mut s = state.lock().unwrap();
            s.connection = ConnectionState::Error(e.to_string());
            return Err(e.into());
        }
    };

    let (mut ws_tx, mut ws_rx) = ws.split();
    log(&state, "WebSocket установлен, начинаю handshake...");

    // ── Noise XX handshake ───────────────────────────────
    let mut hs = Handshake::initiate(&my_keys.private, &server_public_key)?;

    let msg1 = hs.write_message(&[])?;
    ws_tx.send(Message::Binary(msg1.into())).await?;
    log(&state, "→ msg1 отправлен");

    let msg2 = ws_rx.next().await
        .ok_or(anyhow::anyhow!("соединение закрыто"))??;
    hs.read_message(&msg2.into_data())?;
    log(&state, "← msg2 получен");

    let msg3 = hs.write_message(&[])?;
    ws_tx.send(Message::Binary(msg3.into())).await?;
    log(&state, "→ msg3 отправлен");

    log(&state, "✓ Handshake завершён!");

    let session = Arc::new(tokio::sync::Mutex::new(hs.into_transport()?));

    // ── Получаем назначенный IP от сервера ───────────────
    let ip_msg = ws_rx.next().await
        .ok_or(anyhow::anyhow!("сервер не прислал IP"))??;

    let assigned_ip = {
        let mut sess = session.lock().await;
        let decrypted = sess.decrypt(&ip_msg.into_data())?;
        String::from_utf8(decrypted)?
    };

    log(&state, &format!("✓ Получен IP: {}", assigned_ip));

    // Сохраняем IP и обновляем статус
    std::fs::write("/tmp/vpn.client_ip", &assigned_ip)?;
    {
        let mut s = state.lock().unwrap();
        s.connection = ConnectionState::Connected {
            assigned_ip: assigned_ip.clone(),
            started_at:  std::time::Instant::now(),
        };
    }

    // ── Создаём TUN ──────────────────────────────────────
    let tun_dev = crate::client::tun::create_tun(&assigned_ip)?;
    log(&state, &format!("✓ TUN создан ({})", assigned_ip));

    let (mut tun_rx, mut tun_tx) = tokio::io::split(tun_dev);
    let ws_tx = Arc::new(tokio::sync::Mutex::new(ws_tx));

    let sess_tun_to_ws = session.clone();
    let sess_ws_to_tun = session.clone();
    let sess_ka        = session.clone();
    let ws_tx_tun      = ws_tx.clone();
    let ws_tx_ka       = ws_tx.clone();
    let state_ka       = state.clone();

    // ── TUN → WebSocket ──────────────────────────────────
    let tun_to_ws = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let n = match tun_rx.read(&mut buf).await {
                Ok(n) if n == 0 => break,
                Ok(n) => n,
                Err(_) => break,
            };

            let frame   = Frame::new_data(Bytes::copy_from_slice(&buf[..n]));
            let encoded = frame.encode();

            let encrypted = {
                let mut sess = sess_tun_to_ws.lock().await;
                match sess.encrypt(&encoded) {
                    Ok(e) => e,
                    Err(_) => break,
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
                Err(_) => break,
            };

            if !msg.is_binary() { continue; }

            let decrypted = {
                let mut sess = sess_ws_to_tun.lock().await;
                match sess.decrypt(&msg.into_data()) {
                    Ok(d) => d,
                    Err(_) => break,
                }
            };

            let frame = match Frame::decode(&decrypted) {
                Ok(f) => f,
                Err(_) => continue,
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
                    Err(_) => break,
                }
            };

            let mut tx = ws_tx_ka.lock().await;
            if tx.send(Message::Binary(encrypted.into())).await.is_err() {
                break;
            }

            log(&state_ka, "♥ keepalive отправлен");
        }
    });

    log(&state, "✓ Туннель активен!");

    // Ждём сигнала остановки или завершения задач
    tokio::select! {
        _ = tun_to_ws  => log(&state, "TUN→WS завершена"),
        _ = ws_to_tun  => log(&state, "WS→TUN завершена"),
        _ = keepalive  => log(&state, "keepalive завершён"),
        _ = &mut stop_rx => log(&state, "Получен сигнал остановки"),
    }

    // Чистка
    std::fs::remove_file("/tmp/vpn.client_ip").ok();
    {
        let mut s = state.lock().unwrap();
        s.connection = ConnectionState::Disconnected;
    }
    log(&state, "✓ Отключено");

    Ok(())
}
