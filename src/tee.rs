//! Trusted Execution Environment (TEE) server.
//!
//! In mock mode: Runs locally with simulated attestation.
//! In real mode: Runs on AMD SEV-SNP Confidential VM with hardware attestation.

use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::noise::{self, NoiseTransport, MAX_MSG_SIZE};
use crate::attestation::AttestationReport;
use crate::messages::{ChatRequest, ChatResponse};

/// Ollama API endpoints
const OLLAMA_CHAT_URL: &str = "http://localhost:11434/api/chat";
const OLLAMA_EMBED_URL: &str = "http://localhost:11434/api/embed";

/// Default model to use (overridable via TEE_MODEL env var)
const DEFAULT_MODEL: &str = "llama3.2:latest";

fn model_name() -> String {
    std::env::var("TEE_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.to_string())
}
const EMBED_MODEL: &str = "nomic-embed-text";

/// Source text for semantic search (compile-time embed)
const SOURCE_TEXT: &str = include_str!("../readings.txt");

/// Context window size we request from Ollama
pub const CONTEXT_SIZE: usize = 8192;

/// Context overflow threshold (80% of limit)
const CONTEXT_OVERFLOW_THRESHOLD: f32 = 0.8;

#[derive(Serialize, Clone)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Serialize)]
struct OllamaChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    stream: bool,
    options: OllamaOptions,
}

#[derive(Serialize)]
struct OllamaOptions {
    num_ctx: usize,
}

#[derive(Deserialize)]
struct OllamaChatResponse {
    message: OllamaChatResponseMessage,
}

#[derive(Deserialize)]
struct OllamaChatResponseMessage {
    content: String,
}

#[derive(Serialize)]
struct OllamaEmbedRequest {
    model: String,
    input: Vec<String>,
}

#[derive(Deserialize)]
struct OllamaEmbedResponse {
    embeddings: Vec<Vec<f32>>,
}

#[allow(dead_code)]
struct Passage {
    number: usize,
    title: String,
    poem: String,
}

struct TextIndex {
    passages: Vec<Passage>,
    embeddings: Vec<Vec<f32>>,
}

/// Base system prompt (compile-time embed)
const BASE_PROMPT: &str = include_str!("../system-prompt.txt");

#[derive(Clone, Copy)]
pub enum Channel {
    Encrypted,
    Sms,
}

/// Build system prompt with channel-appropriate privacy line
pub fn system_prompt(channel: Channel) -> String {
    let privacy = match channel {
        Channel::Encrypted => "This is TEE Talk — an end-to-end encrypted conversation running inside secure hardware. You can read more at https://tee-talk.vercel.app/",
        Channel::Sms => "This is TEE Talk. Note: SMS is not end-to-end encrypted — your carrier and our provider can see messages. For full encryption, visit https://tee-talk.vercel.app/",
    };
    BASE_PROMPT.replace("{{PRIVACY}}", privacy)
}

/// Conversation context state
struct ConversationContext {
    /// Chat message history
    messages: Vec<ChatMessage>,
    /// Estimated token count
    estimated_tokens: usize,
    /// Model's maximum context size
    limit: usize,
}

/// TEE server configuration
pub struct TeeConfig {
    pub use_real_attestation: bool,
}

impl Default for TeeConfig {
    fn default() -> Self {
        Self {
            use_real_attestation: false,
        }
    }
}

/// TEE server that handles encrypted LLM requests
pub struct TeeServer {
    static_key: Vec<u8>,
    public_key: Vec<u8>,
    config: TeeConfig,
}

impl TeeServer {
    pub fn new(config: TeeConfig) -> Result<Self> {
        // Generate TEE's static keypair
        let builder = snow::Builder::new("Noise_XX_25519_ChaChaPoly_BLAKE2s".parse()?);
        let keypair = builder.generate_keypair()?;

        Ok(Self {
            static_key: keypair.private.to_vec(),
            public_key: keypair.public.to_vec(),
            config,
        })
    }

    /// Start the TEE server
    pub async fn run(&self, addr: &str) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        println!("[TEE] Listening on {}", addr);
        println!("[TEE] Public key: {}", hex::encode(&self.public_key));
        println!("[TEE] Attestation mode: {}",
            if self.config.use_real_attestation { "REAL (SEV-SNP)" } else { "MOCK" });

        // Build semantic search index
        let passages = parse_passages(SOURCE_TEXT);
        println!("[TEE] Parsed {} passages", passages.len());

        let poems: Vec<&str> = passages.iter().map(|c| c.poem.as_str()).collect();
        let embeddings = embed_texts(&poems).await?;
        println!("[TEE] Embedded {} passages", embeddings.len());

        let text_index = Arc::new(TextIndex { passages, embeddings });

        loop {
            let (stream, peer) = listener.accept().await?;
            println!("[TEE] Connection from {}", peer);

            let static_key = self.static_key.clone();
            let public_key = self.public_key.clone();
            let use_real = self.config.use_real_attestation;
            let idx = Arc::clone(&text_index);

            tokio::spawn(async move {
                if let Err(e) = handle_client(stream, &static_key, &public_key, use_real, idx).await {
                    eprintln!("[TEE] Error handling client: {}", e);
                }
            });
        }
    }
}

async fn handle_client(
    mut stream: TcpStream,
    static_key: &[u8],
    public_key: &[u8],
    use_real_attestation: bool,
    text_index: Arc<TextIndex>,
) -> Result<()> {
    // Create responder handshake state
    let mut handshake = noise::new_responder(static_key)?;
    let mut buf = vec![0u8; MAX_MSG_SIZE];

    // Noise XX handshake (3 messages):
    // 1. <- e (receive initiator's ephemeral)
    // 2. -> e, ee, s, es (send our ephemeral + static, with attestation)
    // 3. <- s, se (receive initiator's static)

    // Step 1: Receive initiator's first message
    let len = read_frame(&mut stream).await?;
    stream.read_exact(&mut buf[..len]).await?;
    let mut response = vec![0u8; MAX_MSG_SIZE];
    handshake.read_message(&buf[..len], &mut response)?;
    println!("[TEE] Received handshake message 1");

    // Step 2: Generate attestation and send response
    let report = generate_attestation(public_key, use_real_attestation)?;
    let report_bytes = report.to_bytes();

    let len = handshake.write_message(&report_bytes, &mut response)?;
    write_frame(&mut stream, &response[..len]).await?;
    println!("[TEE] Sent handshake message 2 with {} attestation",
        if report.is_real { "REAL" } else { "MOCK" });

    // Step 3: Receive initiator's final message
    let len = read_frame(&mut stream).await?;
    stream.read_exact(&mut buf[..len]).await?;
    handshake.read_message(&buf[..len], &mut response)?;
    println!("[TEE] Received handshake message 3");

    // Handshake complete - transition to transport mode
    let transport = handshake.into_transport_mode()?;
    let mut noise = NoiseTransport::new(transport);
    println!("[TEE] Secure channel established!");

    // Initialize conversation context with system prompt
    let prompt = system_prompt(Channel::Encrypted);
    let mut context = ConversationContext {
        messages: vec![ChatMessage {
            role: "system".to_string(),
            content: prompt.clone(),
        }],
        estimated_tokens: estimate_tokens(&prompt),
        limit: CONTEXT_SIZE,
    };
    println!("[TEE] Model context limit: {} tokens", CONTEXT_SIZE);

    // Use a static welcome to avoid blocking on slow LLM model load
    let welcome_text = "Welcome. I'm listening.".to_string();

    let welcome_response = ChatResponse::new(welcome_text, context.estimated_tokens, context.limit);
    let welcome_bytes = serde_json::to_vec(&welcome_response)?;
    let encrypted = noise.encrypt(&welcome_bytes)?;
    write_frame(&mut stream, &encrypted).await?;
    println!("[TEE] Sent welcome message");

    // Message loop
    loop {
        // Read encrypted message
        let len = match read_frame(&mut stream).await {
            Ok(l) => l,
            Err(_) => {
                println!("[TEE] Client disconnected");
                break;
            }
        };

        let mut ciphertext = vec![0u8; len];
        stream.read_exact(&mut ciphertext).await?;

        // Decrypt and parse request
        let plaintext = noise.decrypt(&ciphertext)?;
        let request: ChatRequest = match serde_json::from_slice(&plaintext) {
            Ok(r) => r,
            Err(_) => {
                // Backwards compatibility: treat as plain text prompt
                ChatRequest::new(String::from_utf8_lossy(&plaintext).to_string())
            }
        };

        // Handle reset command
        if request.reset {
            context.messages.truncate(1); // keep system message
            context.estimated_tokens = estimate_tokens(&context.messages[0].content);
            println!("[TEE] Context cleared");
            let response = ChatResponse::new(
                "Conversation cleared.".to_string(),
                0,
                context.limit,
            );
            let response_bytes = serde_json::to_vec(&response)?;
            let encrypted = noise.encrypt(&response_bytes)?;
            write_frame(&mut stream, &encrypted).await?;
            continue;
        }

        println!("[TEE] Received prompt ({} chars)", request.prompt.len());

        // Find relevant passage via semantic search
        let word_count = request.prompt.split_whitespace().count();
        let passage_block = match find_relevant_passage(&text_index, &request.prompt).await {
            Ok(idx) => {
                let ch = &text_index.passages[idx];
                println!("[TEE] Matched passage {}: {}", ch.number, ch.title);
                format!("\n{}\n", ch.poem)
            }
            Err(e) => {
                eprintln!("[TEE] Search failed: {}", e);
                String::new()
            }
        };

        let length_hint = match word_count {
            0..=3 => "Respond in 1 sentence at most.",
            4..=10 => "Respond in 1-2 sentences at most.",
            _ => "Keep it short — a few sentences at most.",
        };

        // Add user message to history (just the raw message, no passage)
        context.messages.push(ChatMessage {
            role: "user".to_string(),
            content: request.prompt.clone(),
        });
        context.estimated_tokens += estimate_tokens(&request.prompt);

        // Build messages for this request
        // Passage and length hint are ephemeral — injected as a system message
        // before the user message, not stored in history
        let mut request_messages = context.messages.clone();
        if !passage_block.is_empty() {
            // Insert passage as a system message before the final user message
            let passage_msg = ChatMessage {
                role: "system".to_string(),
                content: format!("[Let this passage inspire your response — its feeling, its spare style — but never quote or reference it. {}]\n{}", length_hint, passage_block.trim()),
            };
            let insert_pos = request_messages.len() - 1;
            request_messages.insert(insert_pos, passage_msg);
        } else {
            // Just add length hint to the user message
            let last = request_messages.last_mut().unwrap();
            last.content = format!("[{}]\n{}", length_hint, last.content);
        }

        // Generate response using Ollama
        println!("[TEE] Calling Ollama ({} messages, ~{} tokens)...",
            context.messages.len(), context.estimated_tokens);
        let llm_response = match generate_chat_response(&request_messages).await {
            Ok(r) => r,
            Err(e) => {
                // Remove the user message we just added
                context.messages.pop();
                let error_response = ChatResponse::new(
                    format!("Error calling LLM: {}", e),
                    context.estimated_tokens,
                    context.limit,
                );
                let response_bytes = serde_json::to_vec(&error_response)?;
                let encrypted = noise.encrypt(&response_bytes)?;
                write_frame(&mut stream, &encrypted).await?;
                continue;
            }
        };

        // Strip <think>...</think> blocks (reasoning models like DeepSeek-R1)
        let llm_response = strip_think_tags(&llm_response);

        // Add assistant response to history
        context.estimated_tokens += estimate_tokens(&llm_response);
        context.messages.push(ChatMessage {
            role: "assistant".to_string(),
            content: llm_response.clone(),
        });
        println!("[TEE] Generated response ({} chars, ~{} tokens)",
            llm_response.len(), context.estimated_tokens);

        // Check for context overflow
        let response = if context.estimated_tokens as f32 > context.limit as f32 * CONTEXT_OVERFLOW_THRESHOLD {
            println!("[TEE] Context at {}% - generating summary...",
                (context.estimated_tokens as f32 / context.limit as f32 * 100.0) as u32);

            // Generate summary from current messages
            let mut summary_messages = context.messages.clone();
            summary_messages.push(ChatMessage {
                role: "user".to_string(),
                content: "Please provide a brief 2-3 sentence summary of our conversation so far.".to_string(),
            });
            let summary = generate_chat_response(&summary_messages).await
                .unwrap_or_else(|_| "Previous conversation context.".to_string());

            // Reset to system prompt + summary
            context.messages.truncate(1);
            context.messages.push(ChatMessage {
                role: "user".to_string(),
                content: format!("Previous conversation summary: {}", summary),
            });
            context.estimated_tokens = estimate_tokens(&context.messages[0].content)
                + estimate_tokens(&context.messages[1].content);

            ChatResponse::with_overflow(
                llm_response,
                summary,
                context.estimated_tokens,
                context.limit,
            )
        } else {
            ChatResponse::new(llm_response, context.estimated_tokens, context.limit)
        };

        // Encrypt and send response
        let response_bytes = serde_json::to_vec(&response)?;
        let encrypted = noise.encrypt(&response_bytes)?;
        write_frame(&mut stream, &encrypted).await?;
        println!("[TEE] Sent encrypted response");
    }

    Ok(())
}

/// Parse source text into passages, stripping [NOTE]...[/NOTE] commentary
fn parse_passages(raw: &str) -> Vec<Passage> {
    raw.strip_prefix("---\n").unwrap_or(raw)
        .split("\n---\n")
        .filter_map(|chunk| {
            let chunk = chunk.trim();
            if chunk.is_empty() {
                return None;
            }

            // Parse "CHAPTER N: Title"
            let first_line = chunk.lines().next()?;
            let rest = first_line.strip_prefix("CHAPTER ")?;
            let (num_str, title) = rest.split_once(": ")?;
            let number: usize = num_str.parse().ok()?;
            let title = title.to_string();

            // Get everything after the header line
            let body = &chunk[chunk.find('\n').map(|i| i + 1).unwrap_or(chunk.len())..];

            // Strip [NOTE]...[/NOTE] to get just the poem
            let poem = if let Some(note_start) = body.find("[NOTE]") {
                body[..note_start].trim().to_string()
            } else {
                body.trim().to_string()
            };

            Some(Passage { number, title, poem })
        })
        .collect()
}

/// Embed multiple texts using Ollama's embedding API
async fn embed_texts(texts: &[&str]) -> Result<Vec<Vec<f32>>> {
    let client = reqwest::Client::new();

    let request = OllamaEmbedRequest {
        model: EMBED_MODEL.to_string(),
        input: texts.iter().map(|t| t.to_string()).collect(),
    };

    let response = client
        .post(OLLAMA_EMBED_URL)
        .json(&request)
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("Ollama embed error: {}", response.status());
    }

    let embed_response: OllamaEmbedResponse = response.json().await?;
    Ok(embed_response.embeddings)
}

/// Cosine similarity between two vectors
fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let mag_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let mag_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if mag_a == 0.0 || mag_b == 0.0 {
        return 0.0;
    }
    dot / (mag_a * mag_b)
}

/// Find the most relevant chapter for a query
async fn find_relevant_passage(index: &TextIndex, query: &str) -> Result<usize> {
    let client = reqwest::Client::new();

    let request = OllamaEmbedRequest {
        model: EMBED_MODEL.to_string(),
        input: vec![query.to_string()],
    };

    let response = client
        .post(OLLAMA_EMBED_URL)
        .json(&request)
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("Ollama embed error: {}", response.status());
    }

    let embed_response: OllamaEmbedResponse = response.json().await?;
    let query_embedding = embed_response.embeddings.into_iter().next()
        .ok_or_else(|| anyhow::anyhow!("No embedding returned"))?;

    let best = index.embeddings.iter()
        .enumerate()
        .map(|(i, emb)| (i, cosine_similarity(&query_embedding, emb)))
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(i, _)| i)
        .ok_or_else(|| anyhow::anyhow!("No passages in index"))?;

    Ok(best)
}

/// Strip <think>...</think> blocks from reasoning model output
fn strip_think_tags(text: &str) -> String {
    let mut result = text.to_string();
    while let Some(start) = result.find("<think>") {
        if let Some(end) = result.find("</think>") {
            result = format!("{}{}", &result[..start], &result[end + 8..]);
        } else {
            // Unclosed <think> — strip from tag to end
            result = result[..start].to_string();
            break;
        }
    }
    result.trim().to_string()
}

/// Generate attestation report (mock or real based on feature flag)
fn generate_attestation(public_key: &[u8], use_real: bool) -> Result<AttestationReport> {
    if use_real {
        #[cfg(feature = "real-tee")]
        {
            return AttestationReport::generate_real(public_key);
        }
        #[cfg(not(feature = "real-tee"))]
        {
            anyhow::bail!("Real attestation requested but 'real-tee' feature not enabled");
        }
    }

    Ok(AttestationReport::generate_mock(public_key))
}

/// Rough token estimate (~4 chars per token)
fn estimate_tokens(text: &str) -> usize {
    text.len() / 4 + 1
}

/// Generate response using Ollama chat API
pub async fn generate_chat_response(messages: &[ChatMessage]) -> Result<String> {
    let client = reqwest::Client::new();

    let request = OllamaChatRequest {
        model: model_name(),
        messages: messages.to_vec(),
        stream: false,
        options: OllamaOptions { num_ctx: CONTEXT_SIZE },
    };

    let response = client
        .post(OLLAMA_CHAT_URL)
        .json(&request)
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("Ollama error: {}", response.status());
    }

    let ollama_response: OllamaChatResponse = response.json().await?;
    Ok(ollama_response.message.content)
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
