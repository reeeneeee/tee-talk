//! Client for connecting to the TEE with end-to-end encryption.

use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use anyhow::Result;

use crate::noise::{self, NoiseTransport, MAX_MSG_SIZE};
use crate::attestation::AttestationReport;
use crate::certs;
use crate::messages::{ChatRequest, ChatResponse, Message};

/// Encrypted client that connects to a TEE
pub struct Client {
    transport: NoiseTransport,
    stream: TcpStream,
    /// Conversation history (in-memory only)
    history: Vec<Message>,
    /// Last known context usage
    pub context_tokens: usize,
    pub context_limit: usize,
}

impl Client {
    /// Connect to a TEE server and perform handshake with attestation verification
    pub async fn connect(addr: &str, trust_server: bool) -> Result<Self> {
        println!("[Client] Connecting to TEE at {}...", addr);
        let mut stream = TcpStream::connect(addr).await?;

        // Generate client's static keypair
        let builder = snow::Builder::new("Noise_XX_25519_ChaChaPoly_BLAKE2s".parse()?);
        let keypair = builder.generate_keypair()?;
        println!("[Client] Generated keypair");

        // Create initiator handshake
        let mut handshake = noise::new_initiator(&keypair.private)?;
        let mut buf = vec![0u8; MAX_MSG_SIZE];

        // Noise XX handshake:
        // 1. -> e (send our ephemeral)
        // 2. <- e, ee, s, es (receive TEE's ephemeral + static + attestation)
        // 3. -> s, se (send our static)

        // Step 1: Send first message
        let len = handshake.write_message(&[], &mut buf)?;
        write_frame(&mut stream, &buf[..len]).await?;
        println!("[Client] Sent handshake message 1");

        // Step 2: Receive TEE's response with attestation
        let len = read_frame(&mut stream).await?;
        let mut response = vec![0u8; len];
        stream.read_exact(&mut response).await?;

        let mut payload = vec![0u8; MAX_MSG_SIZE];
        let payload_len = handshake.read_message(&response, &mut payload)?;
        println!("[Client] Received handshake message 2");

        // Parse attestation report
        let report = AttestationReport::from_bytes(&payload[..payload_len])?;
        println!("[Client] Received attestation report");
        println!("[Client]   Version: {}", report.version);
        println!("[Client]   Measurement: {}", &report.measurement);
        println!("[Client]   Is real: {}", report.is_real);

        // Get the remote static public key from handshake
        let remote_static = handshake.get_remote_static()
            .ok_or_else(|| anyhow::anyhow!("No remote static key"))?;

        // Verify attestation
        certs::verify_attestation(&report, remote_static, trust_server).await?;

        // Step 3: Send our final message
        let len = handshake.write_message(&[], &mut buf)?;
        write_frame(&mut stream, &buf[..len]).await?;
        println!("[Client] Sent handshake message 3");

        // Handshake complete
        let transport = handshake.into_transport_mode()?;
        let mut noise = NoiseTransport::new(transport);
        println!("[Client] Secure channel established!");

        // Receive welcome message from server
        let len = read_frame(&mut stream).await?;
        let mut welcome_data = vec![0u8; len];
        stream.read_exact(&mut welcome_data).await?;
        let welcome_plaintext = noise.decrypt(&welcome_data)?;
        let welcome: ChatResponse = serde_json::from_slice(&welcome_plaintext)
            .unwrap_or_else(|_| ChatResponse::new(
                String::from_utf8_lossy(&welcome_plaintext).to_string(), 0, 0,
            ));

        let context_tokens = welcome.context_tokens;
        let context_limit = welcome.context_limit;

        let mut client = Self {
            transport: noise,
            stream,
            history: Vec::new(),
            context_tokens,
            context_limit,
        };

        // Store welcome in history
        client.history.push(Message::assistant(welcome.content.clone()));
        println!("\n{}\n", welcome.content);

        Ok(client)
    }

    /// Send an encrypted prompt and receive encrypted response
    pub async fn send_prompt(&mut self, prompt: &str) -> Result<ChatResponse> {
        // Create request
        let request = ChatRequest::new(prompt.to_string());
        let request_bytes = serde_json::to_vec(&request)?;

        // Encrypt and send
        let ciphertext = self.transport.encrypt(&request_bytes)?;
        write_frame(&mut self.stream, &ciphertext).await?;

        // Read encrypted response
        let len = read_frame(&mut self.stream).await?;
        let mut response_data = vec![0u8; len];
        self.stream.read_exact(&mut response_data).await?;

        // Decrypt response
        let plaintext = self.transport.decrypt(&response_data)?;

        // Parse response (with backwards compatibility for plain text)
        let response: ChatResponse = match serde_json::from_slice(&plaintext) {
            Ok(r) => r,
            Err(_) => {
                // Backwards compatibility: treat as plain text response
                ChatResponse::new(
                    String::from_utf8_lossy(&plaintext).to_string(),
                    0,
                    0,
                )
            }
        };

        // Update context tracking
        self.context_tokens = response.context_tokens;
        self.context_limit = response.context_limit;

        // Update history
        self.history.push(Message::user(prompt.to_string()));
        self.history.push(Message::assistant(response.content.clone()));

        // Handle context overflow
        if response.context_overflow {
            if let Some(ref summary) = response.compacted_summary {
                // Replace history with summary
                self.history.clear();
                self.history.push(Message::system(format!("Previous conversation summary: {}", summary)));
            }
        }

        Ok(response)
    }

    /// Reset the conversation (clear context)
    pub async fn reset(&mut self) -> Result<()> {
        let request = ChatRequest::reset();
        let request_bytes = serde_json::to_vec(&request)?;

        let ciphertext = self.transport.encrypt(&request_bytes)?;
        write_frame(&mut self.stream, &ciphertext).await?;

        // Read response
        let len = read_frame(&mut self.stream).await?;
        let mut response_data = vec![0u8; len];
        self.stream.read_exact(&mut response_data).await?;

        // Decrypt (we don't need to parse it)
        let _ = self.transport.decrypt(&response_data)?;

        // Clear local history
        self.history.clear();
        self.context_tokens = 0;

        Ok(())
    }

    /// Get the welcome message (first assistant message in history)
    pub fn welcome_message(&self) -> Option<&str> {
        self.history.first().map(|m| m.content.as_str())
    }

    /// Get current context usage as percentage
    pub fn context_usage(&self) -> Option<f32> {
        if self.context_limit == 0 {
            return None;
        }
        Some((self.context_tokens as f32 / self.context_limit as f32) * 100.0)
    }

}

// Simple framing: 4-byte length prefix
async fn read_frame(stream: &mut TcpStream) -> Result<usize> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    Ok(u32::from_le_bytes(len_buf) as usize)
}

async fn write_frame(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    let len = (data.len() as u32).to_le_bytes();
    stream.write_all(&len).await?;
    stream.write_all(data).await?;
    Ok(())
}
