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
const ROUTES_SCRIPT: &str = "/usr/local/bin/vpn-routes.sh";

fn log(state: &Arc<Mutex<AppState>>, msg: &str) {
    if let Ok(mut s) = state.lock() {
        s.add_log(msg);
    }
}

async fn setup_routes(
    vps_ip:    &str,
    client_ip: &str,
    state:     &Arc<Mutex<AppState>>,
) -> anyhow::Result<()> {
    let out = tokio::process::Command::new("sudo")
        .args([ROUTES_SCRIPT, "up", vps_ip, client_ip])
        .output().await?;

    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();

    if !out.status.success() {
        let msg = if stderr.is_empty() { stdout } else { stderr };
        return Err(anyhow::anyhow!("{}", msg));
    }

    log(state, &format!("✓ Маршруты настроены ({})", stdout));
    Ok(())
}

async fn restore_routes(state: &Arc<Mutex<AppState>>) {
    let out = tokio::process::Command::new("sudo")
        .args([ROUTES_SCRIPT, "down"])
        .output().await;

    match out {
        Ok(o) if o.status.success() => {
            let msg = String::from_utf8_lossy(&o.stdout).trim().to_string();
            log(state, &format!("✓ Маршруты восстановлены ({})", msg));
        }
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
            log(state, &format!("✗ Ошибка восстановления маршрутов: {}", err));
        }
        Err(e) => {
            log(state, &format!("✗ Не удалось запустить скрипт: {}", e));
        }
    }
}

pub async fn run(
    server_url:        &str,
    my_keys:           Keypair,
    server_public_key: Vec<u8>,
    state:             Arc<Mutex<AppState>>,
    mut stop_rx:       tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let vps_host = server_url
        .trim_start_matches("wss://")
        .trim_start_matches("ws://")
        .split(':').next()
        .unwrap_or("").to_string();

    log(&state, &format!("Подключаюсь к {}...", server_url));
    { state.lock().unwrap().connection = ConnectionState::Connecting; }

    let connector = Connector::NativeTls(native_tls::TlsConnector::new()?);
    let (ws, _) = match tokio_tungstenite::connect_async_tls_with_config(
        server_url, None, false, Some(connector),
    ).await {
        Ok(r) => r,
        Err(e) => {
            log(&state, &format!("✗ Ошибка подключения: {}", e));
            state.lock().unwrap().connection = ConnectionState::Error(e.to_string());
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

    let msg2 = ws_rx.next().await.ok_or(anyhow::anyhow!("соединение закрыто"))??;
    hs.read_message(&msg2.into_data())?;
    log(&state, "← msg2 получен");

    let msg3 = hs.write_message(&[])?;
    ws_tx.send(Message::Binary(msg3.into())).await?;
    log(&state, "→ msg3 отправлен");
    log(&state, "✓ Handshake завершён!");

    // ── Получаем IP (используем временную сессию) ────────
    let session = hs.into_transport()?;

    let ip_msg = ws_rx.next().await.ok_or(anyhow::anyhow!("сервер не прислал IP"))??;
    let assigned_ip = {
        let decrypted = session.decrypt(&ip_msg.into_data()).await?;
        String::from_utf8(decrypted)?
    };
    log(&state, &format!("✓ Получен IP: {}", assigned_ip));
    std::fs::write("/tmp/vpn.client_ip", &assigned_ip)?;

    // ── Разбиваем сессию на два независимых направления ──
    let (encryptor, decryptor) = session.into_split();

    // ── Создаём TUN ──────────────────────────────────────
    let tun_dev = crate::client::tun::create_tun(&assigned_ip)?;
    log(&state, &format!("✓ TUN создан ({})", assigned_ip));

    if let Err(e) = setup_routes(&vps_host, &assigned_ip, &state).await {
        log(&state, &format!("✗ Ошибка маршрутов: {}", e));
    }

    {
        let mut s = state.lock().unwrap();
        s.connection = ConnectionState::Connected {
            assigned_ip: assigned_ip.clone(),
            started_at:  std::time::Instant::now(),
        };
    }

    let (mut tun_rx, mut tun_tx) = tokio::io::split(tun_dev);
    let ws_tx = Arc::new(tokio::sync::Mutex::new(ws_tx));

    let ws_tx_tun  = ws_tx.clone();
    let ws_tx_ka   = ws_tx.clone();
    let enc_ka     = encryptor.clone();
    let state_ka   = state.clone();

    // ── TUN → WebSocket (encrypt) ────────────────────────
    let tun_to_ws = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let n = match tun_rx.read(&mut buf).await {
                Ok(n) if n == 0 => break,
                Ok(n) => n,
                Err(_) => break,
            };

            let frame   = Frame::new_data(Bytes::copy_from_slice(&buf[..n]));
            let encoded = frame.encode();

            let encrypted = match encryptor.encrypt(&encoded).await {
                Ok(e) => e,
                Err(_) => break,
            };

            let mut tx = ws_tx_tun.lock().await;
            if tx.send(Message::Binary(encrypted.into())).await.is_err() { break; }
        }
    });

    // ── WebSocket → TUN (decrypt) ────────────────────────
    let ws_to_tun = tokio::spawn(async move {
        while let Some(msg) = ws_rx.next().await {
            let msg = match msg { Ok(m) => m, Err(_) => break };
            if !msg.is_binary() { continue; }

            let decrypted = match decryptor.decrypt(&msg.into_data()).await {
                Ok(d) => d,
                Err(_) => break,
            };

            let frame = match Frame::decode(&decrypted) {
                Ok(f) => f,
                Err(_) => continue,
            };

            if frame.frame_type == FrameType::Data {
                if tun_tx.write_all(&frame.payload).await.is_err() { break; }
            }
        }
    });

    // ── Keepalive (encrypt, независимо от TUN→WS) ────────
    let keepalive = tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(KEEPALIVE_INTERVAL)).await;

            let frame   = Frame::new_keepalive();
            let encoded = frame.encode();

            let encrypted = match enc_ka.encrypt(&encoded).await {
                Ok(e) => e,
                Err(_) => break,
            };

            let mut tx = ws_tx_ka.lock().await;
            if tx.send(Message::Binary(encrypted.into())).await.is_err() { break; }

            log(&state_ka, "♥ keepalive отправлен");
        }
    });

    log(&state, "✓ Туннель активен!");

    let abort_tun_to_ws = tun_to_ws.abort_handle();
    let abort_ws_to_tun = ws_to_tun.abort_handle();
    let abort_keepalive = keepalive.abort_handle();

    tokio::select! {
        _ = tun_to_ws    => log(&state, "TUN→WS завершена"),
        _ = ws_to_tun    => log(&state, "WS→TUN завершена"),
        _ = keepalive    => log(&state, "keepalive завершён"),
        _ = &mut stop_rx => log(&state, "Получен сигнал остановки"),
    }
    abort_tun_to_ws.abort();
    abort_ws_to_tun.abort();
    abort_keepalive.abort();

    restore_routes(&state).await;
    std::fs::remove_file("/tmp/vpn.client_ip").ok();
    { state.lock().unwrap().connection = ConnectionState::Disconnected; }
    log(&state, "✓ Отключено");

    Ok(())
}
