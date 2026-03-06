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
    /// Запустить клиент
    Client {
        /// Публичный ключ сервера (hex)
        #[arg(long)]
        server_key: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Server => {
            println!("╔══════════════════════════════════════════╗");
            println!("║         NOISE TUNNEL — СЕРВЕР            ║");
            println!("╚══════════════════════════════════════════╝");

            // Путь к файлу с ключами
            let key_path = std::path::Path::new("/etc/noise-tunnel/keys");

            let keys = if key_path.exists() {
                // Загружаем существующие ключи
                let data = std::fs::read(key_path)?;
                let private = data[..32].to_vec();
                let public  = data[32..].to_vec();
                println!("\n🔑 Загружены сохранённые ключи");
                println!("   Публичный: {}\n", hex::encode(&public));
                Keypair { public, private }
            } else {
                // Генерируем новые и сохраняем
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

        Commands::Client { server_key } => {
            println!("╔══════════════════════════════════════════╗");
            println!("║         NOISE TUNNEL — КЛИЕНТ            ║");
            println!("╚══════════════════════════════════════════╝\n");

            let server_public = hex::decode(&server_key)
                .expect("неверный формат ключа — нужен hex");

            let my_keys = Keypair::generate()?;
            println!(" Мой публичный ключ: {}\n", hex::encode(&my_keys.public));

            client::tunnel::run(
                "wss://noise-tunnel.ddns.net:2443",
                my_keys,
                server_public,
            ).await?;
        }
    }

    Ok(())
}