use bytes::{Bytes, BytesMut, BufMut};
use rand::Rng;

// Магический маркер нашего протокола "NTUN"
pub const MAGIC: u32 = 0x4E54554E;
pub const VERSION: u8 = 1;

// Типы пакетов
#[derive(Debug, Clone, PartialEq)]
pub enum FrameType {
    Data      = 0x01,  // реальные данные
    KeepAlive = 0x02,  // пинг чтобы соединение не рвалось
    Padding   = 0x03,  // пустышка для запутывания DPI
}

impl FrameType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(FrameType::Data),
            0x02 => Some(FrameType::KeepAlive),
            0x03 => Some(FrameType::Padding),
            _ => None,
        }
    }
}

// Структура одного пакета
#[derive(Debug, Clone)]
pub struct Frame {
    pub frame_type: FrameType,
    pub timestamp:  u64,    // защита от replay-атак
    pub payload:    Bytes,  // полезная нагрузка
}

impl Frame {
    // Создать пакет с данными
    pub fn new_data(payload: Bytes) -> Self {
        Self {
            frame_type: FrameType::Data,
            timestamp: now(),
            payload,
        }
    }

    // Создать keepalive пинг
    pub fn new_keepalive() -> Self {
        Self {
            frame_type: FrameType::KeepAlive,
            timestamp: now(),
            payload: Bytes::new(),
        }
    }

    // Сериализация: Frame → байты для отправки
    //
    // Формат пакета:
    // ┌────────┬─────────┬───────────┬──────┬─────────────┬─────────┐
    // │ MAGIC  │ VERSION │ TIMESTAMP │ TYPE │ PAYLOAD_LEN │ PAYLOAD │ PADDING
    // │ 4 байт │ 1 байт  │ 8 байт   │1 байт│   2 байта   │ N байт  │ X байт
    // └────────┴─────────┴───────────┴──────┴─────────────┴─────────┘
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();

        buf.put_u32(MAGIC);
        buf.put_u8(VERSION);
        buf.put_u64(self.timestamp);
        buf.put_u8(self.frame_type.clone() as u8);
        buf.put_u16(self.payload.len() as u16);
        buf.put_slice(&self.payload);

        // Добиваем случайным мусором до ближайшего блока
        // Это скрывает реальный размер пакета от DPI
        let padding_needed = padding_to_add(buf.len());
        let padding: Vec<u8> = (0..padding_needed)
            .map(|_| rand::thread_rng().gen::<u8>())
            .collect();
        buf.put_slice(&padding);

        buf.freeze()
    }

    // Десериализация: байты → Frame
    pub fn decode(data: &[u8]) -> Result<Self, FrameError> {
        // Минимальный размер: 4+1+8+1+2 = 16 байт
        if data.len() < 16 {
            return Err(FrameError::TooShort);
        }

        // Проверяем магический маркер
        let magic = u32::from_be_bytes(data[0..4].try_into().unwrap());
        if magic != MAGIC {
            return Err(FrameError::InvalidMagic);
        }

        // Проверяем версию
        let version = data[4];
        if version != VERSION {
            return Err(FrameError::UnknownVersion(version));
        }

        let timestamp = u64::from_be_bytes(data[5..13].try_into().unwrap());

        let frame_type = FrameType::from_byte(data[13])
            .ok_or(FrameError::UnknownType(data[13]))?;

        let payload_len = u16::from_be_bytes(data[14..16].try_into().unwrap()) as usize;

        if data.len() < 16 + payload_len {
            return Err(FrameError::TooShort);
        }

        let payload = Bytes::copy_from_slice(&data[16..16 + payload_len]);

        Ok(Self { frame_type, timestamp, payload })
    }
}

// Наши ошибки — в Rust принято делать свой enum ошибок
#[derive(Debug)]
pub enum FrameError {
    TooShort,
    InvalidMagic,
    UnknownVersion(u8),
    UnknownType(u8),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FrameError::TooShort          => write!(f, "пакет слишком короткий"),
            FrameError::InvalidMagic      => write!(f, "неверный magic bytes — не наш протокол"),
            FrameError::UnknownVersion(v) => write!(f, "неизвестная версия: {}", v),
            FrameError::UnknownType(t)    => write!(f, "неизвестный тип пакета: 0x{:02x}", t),
        }
    }
}

impl std::error::Error for FrameError {}

// Округляем размер до ближайшего блока: 512, 1024, 2048 байт
fn padding_to_add(current_len: usize) -> usize {
    let target = [512, 1024, 2048]
        .iter()
        .find(|&&block| current_len <= block)
        .copied()
        .unwrap_or(((current_len / 2048) + 1) * 2048);
    target - current_len
}

// Текущее время в секундах
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}