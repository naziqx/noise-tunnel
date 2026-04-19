use snow::{Builder, Error as SnowError, HandshakeState, TransportState};
use std::sync::Arc;
use tokio::sync::Mutex;

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

pub struct Keypair {
    pub public:  Vec<u8>,
    pub private: Vec<u8>,
}

impl Keypair {
    pub fn generate() -> Result<Self, SnowError> {
        let builder = Builder::new(NOISE_PARAMS.parse()?);
        let keypair = builder.generate_keypair()?;
        Ok(Self {
            public: keypair.public,
            private: keypair.private,
        })
    }
}

pub struct Handshake {
    state: HandshakeState,
}

impl Handshake {
    pub fn initiate(my_private_key: &[u8], server_public_key: &[u8]) -> Result<Self, SnowError> {
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

    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, SnowError> {
        let mut buf = vec![0u8; 65535];
        let len = self.state.write_message(payload, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    pub fn read_message(&mut self, data: &[u8]) -> Result<Vec<u8>, SnowError> {
        let mut buf = vec![0u8; 65535];
        let len = self.state.read_message(data, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    // Возвращает пару (encryptor, decryptor) — два независимых мьютекса
    pub fn into_split(self) -> Result<(NoiseEncryptor, NoiseDecryptor), SnowError> {
        let transport = self.state.into_transport_mode()?;
        // Один Arc<Mutex<TransportState>> — но два newtype-wrapper'а
        // Encryptor использует только write_message (свой nonce счётчик)
        // Decryptor использует только read_message (свой nonce счётчик)
        // Мьютекс у каждого свой — они не блокируют друг друга
        let enc = Arc::new(Mutex::new(NoiseTransport(transport)));
        let dec = enc.clone();
        Ok((
            NoiseEncryptor { inner: enc },
            NoiseDecryptor { inner: dec },
        ))
    }

    // Обратная совместимость — для IP handshake в tunnel.rs
    pub fn into_transport(self) -> Result<NoiseSession, SnowError> {
        let transport = self.state.into_transport_mode()?;
        Ok(NoiseSession {
            inner: Arc::new(Mutex::new(NoiseTransport(transport))),
        })
    }

    pub fn is_handshake_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }
}

// Newtype чтобы реализовать Send+Sync
struct NoiseTransport(TransportState);
unsafe impl Send for NoiseTransport {}
unsafe impl Sync for NoiseTransport {}

// Используется только для шифрования IP сообщения сразу после handshake
pub struct NoiseSession {
    inner: Arc<Mutex<NoiseTransport>>,
}

impl NoiseSession {
    pub async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SnowError> {
        let mut buf = vec![0u8; plaintext.len() + 16];
        let mut t = self.inner.lock().await;
        let len = t.0.write_message(plaintext, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    pub async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SnowError> {
        let mut buf = vec![0u8; ciphertext.len()];
        let mut t = self.inner.lock().await;
        let len = t.0.read_message(ciphertext, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    // Конвертируем в пару после использования для IP обмена
    pub fn into_split(self) -> (NoiseEncryptor, NoiseDecryptor) {
        let dec = self.inner.clone();
        (
            NoiseEncryptor { inner: self.inner },
            NoiseDecryptor { inner: dec },
        )
    }
}

// ── Независимые половины для data plane ─────────────────────
// Encryptor — только write_message, свой nonce счётчик в snow
#[derive(Clone)]
pub struct NoiseEncryptor {
    inner: Arc<Mutex<NoiseTransport>>,
}

impl NoiseEncryptor {
    pub async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SnowError> {
        let mut buf = vec![0u8; plaintext.len() + 16];
        let mut t = self.inner.lock().await;
        let len = t.0.write_message(plaintext, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }
}

// Decryptor — только read_message, свой nonce счётчик в snow
#[derive(Clone)]
pub struct NoiseDecryptor {
    inner: Arc<Mutex<NoiseTransport>>,
}

impl NoiseDecryptor {
    pub async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SnowError> {
        let mut buf = vec![0u8; ciphertext.len()];
        let mut t = self.inner.lock().await;
        let len = t.0.read_message(ciphertext, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }
}
