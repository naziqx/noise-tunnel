use tun::Configuration;

// Создаёт виртуальный сетевой интерфейс tun0
// Это виртуальная сетевая карта — ОС будет слать сюда пакеты
pub fn create_tun() -> anyhow::Result<tun::AsyncDevice> {
    let mut config = Configuration::default();

    config
        .address("172.16.0.2")
        .destination("172.16.0.1")   // IP адрес сервера в туннеле
        .netmask("255.255.255.0")   // маска подсети
        .mtu(1420)                  // размер пакета (чуть меньше стандартного)
        .up();                      // сразу поднять интерфейс

    #[cfg(target_os = "linux")]
    config.platform(|p| {
        p.packet_information(false); // не добавлять лишний заголовок
    });

    let dev = tun::create_as_async(&config)?;
    Ok(dev)
}