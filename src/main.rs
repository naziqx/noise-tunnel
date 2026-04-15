mod protocol;
mod server;
mod client;

use protocol::noise::Keypair;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "noise-tunnel")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Запустить сервер
    Server,

    /// Запустить клиент (без TUI, для скриптов)
    Client {
        #[arg(long)]
        server_key: String,
    },

    /// Запустить клиент с TUI интерфейсом
    Tui {
        /// URL сервера (можно задать в TUI)
        #[arg(long, default_value = "wss://noise-tunnel.ddns.net:2443")]
        url: String,

        /// Публичный ключ сервера (можно задать в TUI)
        #[arg(long, default_value = "")]
        server_key: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        // ── Сервер ───────────────────────────────────────
        Commands::Server => {
            println!("╔══════════════════════════════════════════╗");
            println!("║         NOISE TUNNEL — СЕРВЕР            ║");
            println!("╚══════════════════════════════════════════╝");

            let key_path = std::path::Path::new("/etc/noise-tunnel/keys");

            let keys = if key_path.exists() {
                let data    = std::fs::read(key_path)?;
                let private = data[..32].to_vec();
                let public  = data[32..].to_vec();
                println!("\n🔑 Загружены сохранённые ключи");
                println!("   Публичный: {}\n", hex::encode(&public));
                Keypair { public, private }
            } else {
                let keys = Keypair::generate()?;
                std::fs::create_dir_all("/etc/noise-tunnel")?;
                let mut data = keys.private.clone();
                data.extend_from_slice(&keys.public);
                std::fs::write(key_path, &data)?;
                println!("\n✓ Новые ключи сгенерированы и сохранены");
                println!("   Публичный ключ сервера (дай клиенту):");
                println!("   {}\n", hex::encode(&keys.public));
                keys
            };

            server::listener::run("0.0.0.0:2443", keys).await?;
        }

        // ── Клиент без TUI ───────────────────────────────
        Commands::Client { server_key } => {
            println!("╔══════════════════════════════════════════╗");
            println!("║         NOISE TUNNEL — КЛИЕНТ            ║");
            println!("╚══════════════════════════════════════════╝\n");

            let server_public = hex::decode(&server_key)
                .expect("неверный формат ключа — нужен hex");

            let my_keys = Keypair::generate()?;
            println!(" Мой публичный ключ: {}\n", hex::encode(&my_keys.public));

            let state = std::sync::Arc::new(std::sync::Mutex::new(
                client::tui::AppState::new(
                    "wss://noise-tunnel.ddns.net:2443".to_string(),
                    server_key,
                )
            ));

            let (_stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();

            client::tunnel::run(
                "wss://noise-tunnel.ddns.net:2443",
                my_keys,
                server_public,
                state,
                stop_rx,
            ).await?;
        }

        // ── TUI клиент ───────────────────────────────────
        Commands::Tui { url, server_key } => {
            use std::sync::{Arc, Mutex};
            use client::tui::{AppState, TunnelCommand};

            let state = Arc::new(Mutex::new(AppState::new(url, server_key)));

            let (cmd_tx, mut cmd_rx) =
                tokio::sync::mpsc::unbounded_channel::<TunnelCommand>();

            let state_for_tunnel = state.clone();

            let stop_tx_cell: Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>> =
                Arc::new(Mutex::new(None));
            let stop_cell = stop_tx_cell.clone();

            tokio::spawn(async move {
                while let Some(cmd) = cmd_rx.recv().await {
                    match cmd {
                        TunnelCommand::Connect { url, key } => {
                            let server_public = match hex::decode(&key) {
                                Ok(k) => k,
                                Err(e) => {
                                    let mut s = state_for_tunnel.lock().unwrap();
                                    s.add_log(&format!("✗ Неверный ключ: {}", e));
                                    s.connection = client::tui::ConnectionState::Error(
                                        e.to_string()
                                    );
                                    continue;
                                }
                            };

                            let my_keys = match Keypair::generate() {
                                Ok(k) => k,
                                Err(e) => {
                                    state_for_tunnel.lock().unwrap()
                                        .add_log(&format!("✗ Ошибка генерации ключей: {}", e));
                                    continue;
                                }
                            };

                            let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
                            *stop_cell.lock().unwrap() = Some(stop_tx);

                            let state_c = state_for_tunnel.clone();
                            tokio::spawn(async move {
                                if let Err(e) = client::tunnel::run(
                                    &url,
                                    my_keys,
                                    server_public,
                                    state_c.clone(),
                                    stop_rx,
                                ).await {
                                    let mut s = state_c.lock().unwrap();
                                    s.add_log(&format!("✗ Ошибка туннеля: {}", e));
                                    s.connection = client::tui::ConnectionState::Error(
                                        e.to_string()
                                    );
                                }
                            });
                        }

                        TunnelCommand::Disconnect => {
                            if let Some(tx) = stop_cell.lock().unwrap().take() {
                                let _ = tx.send(());
                            }
                        }
                    }
                }
            });

            client::tui::run_tui(state, cmd_tx)?;
        }
    }

    Ok(())
}
