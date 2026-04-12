use tokio_tungstenite::tungstenite::Message;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::protocol::noise::{Handshake, Keypair};
use crate::protocol::frame::{Frame, FrameType};

use native_tls::{Identity, TlsAcceptor};
use std::fs;

const MAX_CLIENTS: u8 = 50;
const KEEPALIVE_INTERVAL: u64 = 30;

type SlotPool = Arc<Mutex<Vec<u8>>>;

pub async fn run(addr: &str, server_keys: Keypair) -> anyhow::Result<()> {
    let cert = fs::read("/etc/letsencrypt/live/noise-tunnel.ddns.net/fullchain.pem")?;
    let key  = fs::read("/etc/letsencrypt/live/noise-tunnel.ddns.net/privkey.pem")?;

    let cert_str = String::from_utf8(cert)?;
    let key_str  = String::from_utf8(key)?;

    let identity = Identity::from_pkcs8(cert_str.as_bytes(), key_str.as_bytes())?;
    let acceptor = TlsAcceptor::new(identity)?;
    let acceptor = tokio_native_tls::TlsAcceptor::from(acceptor);

    // ── Чистим старые TUN интерфейсы при старте ──────────
    println!("[сервер] чищу старые TUN интерфейсы...");
    for i in 0..MAX_CLIENTS {
        let tun_name = format!("tun{}", i);
        tokio::process::Command::new("ip")
            .args(["link", "delete", &tun_name])
            .output().await.ok();
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("[сервер] слушаю на {} (TLS)", addr);
    println!("[сервер] максимум клиентов: {}", MAX_CLIENTS);

    let pool: SlotPool = Arc::new(Mutex::new((0..MAX_CLIENTS).collect()));

    loop {
        let (stream, peer) = listener.accept().await?;
        println!("[сервер] подключился: {}", peer);

        let acceptor    = acceptor.clone();
        let private_key = server_keys.private.clone();
        let pool        = pool.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => { eprintln!("[сервер] TLS ошибка: {}", e); return; }
            };

            let ws = match tokio_tungstenite::accept_async(tls_stream).await {
                Ok(s) => s,
                Err(e) => { eprintln!("[сервер] WS ошибка: {}", e); return; }
            };

            if let Err(e) = handle_client(ws, private_key, pool).await {
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
    pool: SlotPool,
) -> anyhow::Result<()> {
    let (mut ws_tx, mut ws_rx) = ws.split();

    // ── Берём слот из пула ───────────────────────────────
    let slot = {
        let mut p = pool.lock().await;
        match p.pop() {
            Some(s) => s,
            None => {
                eprintln!("[сервер] нет свободных слотов, отклоняю подключение");
                return Ok(());
            }
        }
    };

    let tun_name  = format!("tun{}", slot);
    let client_ip = format!("172.16.0.{}", slot + 2);
    let server_ip = format!("172.16.1.{}", slot + 2);

    println!("[сервер] слот #{} → {} (клиент: {}, сервер: {})",
        slot, tun_name, client_ip, server_ip);

    // ── Noise XX handshake ───────────────────────────────
    let mut hs = Handshake::respond(&private_key)?;

    let msg1 = ws_rx.next().await
        .ok_or(anyhow::anyhow!("соединение закрыто"))??;
    hs.read_message(&msg1.into_data())?;
    println!("[сервер] ← msg1 получен (слот #{})", slot);

    let msg2 = hs.write_message(&[])?;
    ws_tx.send(Message::Binary(msg2.into())).await?;
    println!("[сервер] → msg2 отправлен (слот #{})", slot);

    let msg3 = ws_rx.next().await
        .ok_or(anyhow::anyhow!("соединение закрыто"))??;
    hs.read_message(&msg3.into_data())?;
    println!("[сервер] ← msg3 получен (слот #{})", slot);

    println!("[сервер] ✓ Handshake завершён (слот #{})", slot);

    let session = Arc::new(Mutex::new(hs.into_transport()?));

    // ── Отправляем клиенту его IP ────────────────────────
    {
        let mut sess = session.lock().await;
        let ip_msg = sess.encrypt(client_ip.as_bytes())?;
        ws_tx.send(Message::Binary(ip_msg.into())).await?;
        println!("[сервер] → IP {} отправлен клиенту (слот #{})", client_ip, slot);
    }

    // ── Создаём TUN для этого клиента ───────────────────
    let mut tun_config = tun::Configuration::default();
    tun_config
        .name(&tun_name)
        .address(server_ip.as_str())
        .destination(client_ip.as_str())
        .netmask("255.255.255.255")
        .mtu(1420)
        .up();

    #[cfg(target_os = "linux")]
    tun_config.platform(|p| { p.packet_information(false); });

    let tun_dev = match tun::create_as_async(&tun_config) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[сервер] ошибка создания {}: {}", tun_name, e);
            let mut p = pool.lock().await;
            p.push(slot);
            p.sort_unstable();
            return Err(e.into());
        }
    };

    println!("[сервер] ✓ {} создан ({} ↔ {})", tun_name, server_ip, client_ip);

    tokio::process::Command::new("ip")
        .args(["route", "add", &client_ip, "dev", &tun_name])
        .output().await.ok();

    tokio::process::Command::new("iptables")
        .args(["-t", "nat", "-A", "POSTROUTING",
               "-s", &client_ip, "-j", "MASQUERADE"])
        .output().await.ok();

    let (mut tun_rx, mut tun_tx) = tokio::io::split(tun_dev);
    let ws_tx = Arc::new(Mutex::new(ws_tx));

    // Клонируем ВСЕ Arc до того как они переместятся в замыкания
    let sess_tun_to_ws = session.clone();
    let sess_ws_to_tun = session.clone();
    let sess_ka        = session.clone();
    let ws_tx_tun      = ws_tx.clone();
    let ws_tx_ka       = ws_tx.clone();
    let tun_name_c     = tun_name.clone();
    let tun_name_ka    = tun_name.clone();

    // ── TUN → WebSocket ──────────────────────────────────
    let tun_to_ws = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let n = match tun_rx.read(&mut buf).await {
                Ok(n) if n == 0 => break,
                Ok(n) => n,
                Err(e) => { eprintln!("[{}] TUN read: {}", tun_name_c, e); break; }
            };

            let frame   = Frame::new_data(bytes::Bytes::copy_from_slice(&buf[..n]));
            let encoded = frame.encode();

            let encrypted = {
                let mut sess = sess_tun_to_ws.lock().await;
                match sess.encrypt(&encoded) {
                    Ok(e) => e,
                    Err(e) => { eprintln!("[{}] encrypt: {}", tun_name_c, e); break; }
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
                    Err(e) => { eprintln!("[сервер] decrypt: {}", e); break; }
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
                    Err(e) => { eprintln!("[{}] keepalive encrypt: {}", tun_name_ka, e); break; }
                }
            };

            let mut tx = ws_tx_ka.lock().await;
            if tx.send(Message::Binary(encrypted.into())).await.is_err() {
                break;
            }

            println!("[{}] ♥ keepalive отправлен", tun_name_ka);
        }
    });

    println!("[сервер] туннель {} активен! Keepalive каждые {}с",
        tun_name, KEEPALIVE_INTERVAL);

    tokio::select! {
        _ = tun_to_ws => println!("[{}] TUN→WS завершена", tun_name),
        _ = ws_to_tun => println!("[{}] WS→TUN завершена", tun_name),
        _ = keepalive => println!("[{}] keepalive завершён", tun_name),
    }

    // ── Чистка при отключении ────────────────────────────
    println!("[сервер] слот #{} освобождается...", slot);

    tokio::process::Command::new("ip")
        .args(["route", "del", &client_ip])
        .output().await.ok();

    tokio::process::Command::new("iptables")
        .args(["-t", "nat", "-D", "POSTROUTING",
               "-s", &client_ip, "-j", "MASQUERADE"])
        .output().await.ok();

    // Удаляем TUN интерфейс
    tokio::process::Command::new("ip")
        .args(["link", "delete", &tun_name])
        .output().await.ok();

    {
        let mut p = pool.lock().await;
        p.push(slot);
        p.sort_unstable();
        println!("[сервер] слот #{} возвращён в пул. Свободно: {}/{}",
            slot, p.len(), MAX_CLIENTS);
    }

    Ok(())
}
