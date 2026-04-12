use tun::Configuration;

// Создаёт TUN интерфейс с IP назначенным сервером
pub fn create_tun(client_ip: &str) -> anyhow::Result<tun::AsyncDevice> {
    let mut config = Configuration::default();

    config
        .address(client_ip)          // IP назначен сервером динамически
        .destination("0.0.0.0")      // не важно — роутинг через ip route
        .netmask("255.255.255.0")
        .mtu(1420)
        .up();

    #[cfg(target_os = "linux")]
    config.platform(|p| {
        p.packet_information(false);
    });

    let dev = tun::create_as_async(&config)?;
    println!("[клиент] ✓ TUN создан с IP {}", client_ip);
    Ok(dev)
}
