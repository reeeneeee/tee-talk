//! Noise protocol wrapper for encrypted communication.
//!
//! Uses the Noise_XX pattern which provides mutual authentication:
//! - Both parties prove knowledge of their static keys
//! - Forward secrecy via ephemeral keys
//! - Identity hiding (static keys encrypted)

use snow::{Builder, TransportState, HandshakeState};
use anyhow::Result;

/// Noise protocol pattern: XX provides mutual authentication
const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Maximum message size for Noise transport
pub const MAX_MSG_SIZE: usize = 65535;

/// Create a new Noise handshake initiator (client)
pub fn new_initiator(static_key: &[u8]) -> Result<HandshakeState> {
    let builder = Builder::new(NOISE_PATTERN.parse()?);
    let state = builder
        .local_private_key(static_key)
        .build_initiator()?;
    Ok(state)
}

/// Create a new Noise handshake responder (server/TEE)
#[cfg(feature = "server")]
pub fn new_responder(static_key: &[u8]) -> Result<HandshakeState> {
    let builder = Builder::new(NOISE_PATTERN.parse()?);
    let state = builder
        .local_private_key(static_key)
        .build_responder()?;
    Ok(state)
}



/// Wrapper around TransportState for easier message handling
pub struct NoiseTransport {
    state: TransportState,
}

impl NoiseTransport {
    pub fn new(state: TransportState) -> Self {
        Self { state }
    }

    /// Encrypt a message
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; plaintext.len() + 16]; // 16 bytes for auth tag
        let len = self.state.write_message(plaintext, &mut buffer)?;
        buffer.truncate(len);
        Ok(buffer)
    }

    /// Decrypt a message
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; ciphertext.len()];
        let len = self.state.read_message(ciphertext, &mut buffer)?;
        buffer.truncate(len);
        Ok(buffer)
    }
}
