use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::Connector;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

use crate::protocol::noise::{Handshake, Keypair};
use crate::protocol::frame::{Frame, FrameType};
use crate::client::tui::{AppState, ConnectionState};
use bytes::Bytes;

const KEEPALIVE_INTERVAL: u64 = 30;
// Авто-реконнект: начинаем с 1с, удваиваем, максимум 60с
const RECONNECT_BASE_SECS: u64 = 1;
const RECONNECT_MAX_SECS:  u64 = 60;

fn log(state: &Arc<Mutex<AppState>>, msg: &str) {
    if let Ok(mut s) = state.lock() {
        s.add_log(msg);
    }
}

// Настраиваем маршруты
async fn setup_routes(
    vps_ip:    &str,
    client_ip: &str,
    state:     &Arc<Mutex<AppState>>,
) -> anyhow::Result<()> {
    let output = tokio::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output().await?;

    let route_str = String::from_utf8_lossy(&output.stdout);
    let parts: Vec<&str> = route_str.split_whitespace().collect();

    let gateway = parts.iter().position(|&s| s == "via")
        .and_then(|i| parts.get(i + 1))
        .copied()
        .ok_or_else(|| anyhow::anyhow!("не удалось определить gateway"))?;

    let iface = parts.iter().position(|&s| s == "dev")
        .and_then(|i| parts.get(i + 1))
        .copied()
        .ok_or_else(|| anyhow::anyhow!("не удалось определить интерфейс"))?;

    log(state, &format!("Маршруты: gateway={} iface={}", gateway, iface));

    std::fs::write("/tmp/vpn.gw",     gateway)?;
    std::fs::write("/tmp/vpn.iface",  iface)?;
    std::fs::write("/tmp/vpn.vps_ip", vps_ip)?;

    tokio::process::Command::new("sudo")
        .args(["ip", "route", "add", vps_ip, "via", gateway, "dev", iface])
        .output().await.ok();

    tokio::process::Command::new("sudo")
        .args(["ip", "route", "del", "default"])
        .output().await.ok();

    tokio::process::Command::new("sudo")
        .args(["ip", "route", "add", "default", "dev", "tun0"])
        .output().await.ok();

    tokio::process::Command::new("sudo")
        .args(["sh", "-c", "echo nameserver 8.8.8.8 > /etc/resolv.conf"])
        .output().await.ok();

    log(state, "✓ Маршруты настроены, трафик идёт через VPN");
    Ok(())
}

// Восстанавливаем маршруты при отключении
async fn restore_routes(state: &Arc<Mutex<AppState>>) {
    let gateway = std::fs::read_to_string("/tmp/vpn.gw").unwrap_or_default();
    let iface   = std::fs::read_to_string("/tmp/vpn.iface").unwrap_or_default();
    let vps_ip  = std::fs::read_to_string("/tmp/vpn.vps_ip").unwrap_or_default();

    let gateway = gateway.trim();
    let iface   = iface.trim();
    let vps_ip  = vps_ip.trim();

    tokio::process::Command::new("sudo")
        .args(["ip", "route", "del", "default"])
        .output().await.ok();

    tokio::process::Command::new("sudo")
        .args(["ip", "route", "del", vps_ip])
        .output().await.ok();

    if !gateway.is_empty() {
        tokio::process::Command::new("sudo")
            .args(["ip", "route", "add", "default", "via", gateway, "dev", iface])
            .output().await.ok();

        log(state, &format!("✓ Маршрут восстановлен через {} ({})", gateway, iface));
    }

    tokio::process::Command::new("sudo")
        .args(["sh", "-c", "echo nameserver 1.1.1.1 > /etc/resolv.conf"])
        .output().await.ok();
}

// Одна попытка подключения и работы туннеля.
// Возвращает Ok(true) если нужен реконнект, Ok(false) если намеренное отключение.
async fn connect_once(
    server_url:        &str,
    my_keys:           &Keypair,
    server_public_key: &[u8],
    state:             &Arc<Mutex<AppState>>,
    cancel:            &CancellationToken,
) -> anyhow::Result<bool> {
    let vps_host = server_url
        .trim_start_matches("wss://")
        .trim_start_matches("ws://")
        .split(':').next()
        .unwrap_or("").to_string();

    log(state, &format!("Подключаюсь к {}...", server_url));
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
            log(state, &format!("✗ Ошибка подключения: {}", e));
            {
                let mut s = state.lock().unwrap();
                s.connection = ConnectionState::Error(e.to_string());
            }
            return Ok(true); // нужен реконнект
        }
    };

    let (mut ws_tx, mut ws_rx) = ws.split();
    log(state, "WebSocket установлен, начинаю handshake...");

    // ── Noise XX handshake ───────────────────────────────
    let mut hs = Handshake::initiate(&my_keys.private, server_public_key)?;

    let msg1 = hs.write_message(&[])?;
    ws_tx.send(Message::Binary(msg1.into())).await?;
    log(state, "→ msg1 отправлен");

    let msg2 = ws_rx.next().await
        .ok_or(anyhow::anyhow!("соединение закрыто"))??;
    hs.read_message(&msg2.into_data())?;
    log(state, "← msg2 получен");

    let msg3 = hs.write_message(&[])?;
    ws_tx.send(Message::Binary(msg3.into())).await?;
    log(state, "→ msg3 отправлен");

    log(state, "✓ Handshake завершён!");

    let session = Arc::new(tokio::sync::Mutex::new(hs.into_transport()?));

    // ── Получаем назначенный IP от сервера ───────────────
    let ip_msg = ws_rx.next().await
        .ok_or(anyhow::anyhow!("сервер не прислал IP"))??;

    let assigned_ip = {
        let mut sess = session.lock().await;
        let decrypted = sess.decrypt(&ip_msg.into_data())?;
        String::from_utf8(decrypted)?
    };

    log(state, &format!("✓ Получен IP: {}", assigned_ip));
    std::fs::write("/tmp/vpn.client_ip", &assigned_ip)?;

    // ── Создаём TUN ──────────────────────────────────────
    let tun_dev = crate::client::tun::create_tun(&assigned_ip)?;
    log(state, &format!("✓ TUN создан ({})", assigned_ip));

    if let Err(e) = setup_routes(&vps_host, &assigned_ip, state).await {
        log(state, &format!("✗ Ошибка маршрутов: {}", e));
    }

    {
        let mut s = state.lock().unwrap();
        s.connection = ConnectionState::Connected {
            assigned_ip: assigned_ip.clone(),
            started_at:  std::time::Instant::now(),
        };
        s.reset_stats();
    }

    let (mut tun_rx, mut tun_tx) = tokio::io::split(tun_dev);
    let ws_tx = Arc::new(tokio::sync::Mutex::new(ws_tx));

    let sess_tun_to_ws = session.clone();
    let sess_ws_to_tun = session.clone();
    let sess_ka        = session.clone();
    let ws_tx_tun      = ws_tx.clone();
    let ws_tx_ka       = ws_tx.clone();
    let state_tun      = state.clone();
    let state_ka       = state.clone();
    let cancel_tun     = cancel.clone();
    let cancel_ws      = cancel.clone();
    let cancel_ka      = cancel.clone();

    // ── TUN → WebSocket (считаем TX) ─────────────────────
    let tun_to_ws = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let n = tokio::select! {
                res = tun_rx.read(&mut buf) => match res {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                },
                _ = cancel_tun.cancelled() => break,
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

            let tx_len = encrypted.len() as u64;
            let mut tx = ws_tx_tun.lock().await;
            if tx.send(Message::Binary(encrypted.into())).await.is_err() {
                break;
            }
            // Считаем отправленные байты
            if let Ok(mut s) = state_tun.lock() {
                s.add_tx(tx_len);
            }
        }
    });

    // ── WebSocket → TUN (считаем RX) ─────────────────────
    let state_rx = state.clone();
    let ws_to_tun = tokio::spawn(async move {
        loop {
            let msg = tokio::select! {
                res = ws_rx.next() => match res {
                    Some(Ok(m)) => m,
                    _ => break,
                },
                _ = cancel_ws.cancelled() => break,
            };

            if !msg.is_binary() { continue; }

            let raw_len = msg.len() as u64;

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
                // Считаем полученные байты
                if let Ok(mut s) = state_rx.lock() {
                    s.add_rx(raw_len);
                }
            }
        }
    });

    // ── Keepalive ─────────────────────────────────────────
    let keepalive = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(KEEPALIVE_INTERVAL)) => {}
                _ = cancel_ka.cancelled() => break,
            }

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

    log(state, "✓ Туннель активен!");

    // Ждём: либо один из потоков упал, либо пришёл сигнал отмены
    let reconnect_needed = tokio::select! {
        _ = tun_to_ws => { log(state, "TUN→WS завершена"); true  }
        _ = ws_to_tun => { log(state, "WS→TUN завершена"); true  }
        _ = keepalive => { log(state, "keepalive завершён"); true }
        _ = cancel.cancelled() => { log(state, "Получен сигнал остановки"); false }
    };

    // Абортим все оставшиеся задачи
    cancel.cancel();

    restore_routes(state).await;
    std::fs::remove_file("/tmp/vpn.client_ip").ok();

    {
        let mut s = state.lock().unwrap();
        s.connection = ConnectionState::Disconnected;
    }
    log(state, "✓ Отключено");

    Ok(reconnect_needed)
}

// ── Главная точка входа — с авто-реконнектом ─────────────
pub async fn run(
    server_url:        &str,
    my_keys:           Keypair,
    server_public_key: Vec<u8>,
    state:             Arc<Mutex<AppState>>,
    stop_rx:           tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    // Конвертируем oneshot в CancellationToken — один раз, до цикла.
    // Это решает проблему с borrowing stop_rx внутри loop + spawn.
    let stop_token = CancellationToken::new();
    let stop_token_task = stop_token.clone();
    tokio::spawn(async move {
        let _ = stop_rx.await;
        stop_token_task.cancel();
    });

    let mut attempt: u32 = 0;
    let mut backoff = RECONNECT_BASE_SECS;

    loop {
        // Свежий дочерний токен для каждой попытки.
        // Когда сработает stop_token — сработает и child (иерархия).
        let cancel = stop_token.child_token();

        match connect_once(server_url, &my_keys, &server_public_key, &state, &cancel).await {
            Ok(false) => {
                // Намеренное отключение — выходим
                break;
            }
            Ok(true) => {
                // Если stop уже пришёл — не реконнектимся
                if stop_token.is_cancelled() {
                    let mut s = state.lock().unwrap();
                    s.connection = ConnectionState::Disconnected;
                    break;
                }

                let should_reconnect = state.lock().unwrap().auto_reconnect;
                if !should_reconnect {
                    break;
                }

                attempt += 1;
                log(&state, &format!(
                    "↻ Переподключение через {}с (попытка {})...", backoff, attempt
                ));

                {
                    let mut s = state.lock().unwrap();
                    s.connection = ConnectionState::Reconnecting { attempt };
                }

                // Ждём backoff или сигнал остановки
                tokio::select! {
                    _ = tokio::time::sleep(tokio::time::Duration::from_secs(backoff)) => {}
                    _ = stop_token.cancelled() => {
                        log(&state, "Остановка во время ожидания реконнекта");
                        let mut s = state.lock().unwrap();
                        s.connection = ConnectionState::Disconnected;
                        break;
                    }
                }

                // Exponential backoff
                backoff = (backoff * 2).min(RECONNECT_MAX_SECS);
            }
            Err(e) => {
                log(&state, &format!("✗ Критическая ошибка: {}", e));
                let mut s = state.lock().unwrap();
                s.connection = ConnectionState::Error(e.to_string());
                break;
            }
        }
    }

    Ok(())
}
