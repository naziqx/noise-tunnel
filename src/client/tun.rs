use tun::Configuration;

// Создаёт виртуальный сетевой интерфейс tun0
// Это виртуальная сетевая карта — ОС будет слать сюда пакеты
use tun::Configuration;

pub fn create_tun() -> anyhow::Result<tun::AsyncDevice> {
    let mut config = Configuration::default();

    config
        .address("172.16.0.2")
        .destination("172.16.0.1")
        .netmask("255.255.255.0")
        .mtu(1420)
        .up();

    // На Android не используем platform-специфичные настройки
    #[cfg(target_os = "linux")]
    #[cfg(not(target_env = "android"))]
    config.platform(|p| {
        p.packet_information(false);
    });

    let dev = tun::create_as_async(&config)?;
    Ok(dev)
}
