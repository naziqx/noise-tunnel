use snow::{Builder, Error as SnowError, HandshakeState, TransportState};

// Параметры нашего протокола:
// XX      = оба конца проверяют друг друга (взаимная аутентификация)
// 25519   = алгоритм обмена ключами (Diffie-Hellman)
// ChaChaPoly = шифрование (быстрее AES на мобильных/ARM)
// BLAKE2s = хэш-функция
const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

// Пара ключей: публичный + приватный
pub struct Keypair {
    pub public:  Vec<u8>,
    pub private: Vec<u8>,
}

impl Keypair {
    // Генерируем новую пару ключей
    pub fn generate() -> Result<Self, SnowError> {
        let builder = Builder::new(NOISE_PARAMS.parse()?);
        let keypair = builder.generate_keypair()?;
        Ok(Self {
            public: keypair.public,
            private: keypair.private,
        })
    }
}

// Состояние handshake — пока ключи ещё обмениваются
pub struct Handshake {
    state: HandshakeState,
}

impl Handshake {
    // Клиент начинает handshake
    // Знает публичный ключ сервера заранее (как в WireGuard)
    pub fn initiate(my_private_key: &[u8], server_public_key: &[u8]) -> Result<Self, SnowError> {
        // ? только на финальном build_* — Builder возвращает себя, а не Result
        let state = Builder::new(NOISE_PARAMS.parse()?)
            .local_private_key(my_private_key)
            .remote_public_key(server_public_key)
            .build_initiator()?;

        Ok(Self { state })
    }

    pub fn respond(my_private_key: &[u8]) -> Result<Self, SnowError> {
        let state = Builder::new(NOISE_PARAMS.parse()?)
            .local_private_key(my_private_key)
            .build_responder()?;

        Ok(Self { state })
    }

    // Записать следующее сообщение handshake
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, SnowError> {
        let mut buf = vec![0u8; 65535];
        let len = self.state.write_message(payload, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    // Прочитать входящее сообщение handshake
    pub fn read_message(&mut self, data: &[u8]) -> Result<Vec<u8>, SnowError> {
        let mut buf = vec![0u8; 65535];
        let len = self.state.read_message(data, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    // Handshake завершён — переходим в режим шифрования
    pub fn into_transport(self) -> Result<NoiseSession, SnowError> {
        Ok(NoiseSession {
            transport: self.state.into_transport_mode()?,
        })
    }

    pub fn is_handshake_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }
}

// Сессия после handshake — уже можно шифровать данные
pub struct NoiseSession {
    transport: TransportState,
}

impl NoiseSession {
    // Зашифровать данные для отправки
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SnowError> {
        let mut buf = vec![0u8; plaintext.len() + 16]; // +16 для AEAD тега
        let len = self.transport.write_message(plaintext, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    // Расшифровать входящие данные
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, SnowError> {
        let mut buf = vec![0u8; ciphertext.len()];
        let len = self.transport.read_message(ciphertext, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }
}
