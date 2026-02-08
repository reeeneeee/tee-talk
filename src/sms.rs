//! Twilio SMS webhook handler for tee-talk.
//!
//! Provides an insecure (SMS) interface to the TEE-hosted LLM.
//! Messages are NOT end-to-end encrypted - Twilio and carriers can read them.
//! The TEE still protects processing from the cloud provider.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::post,
    Form, Router,
};
use serde::Deserialize;

use crate::tee;

/// Per-phone-number conversation context
struct Session {
    messages: Vec<tee::ChatMessage>,
}

impl Session {
    fn new() -> Self {
        Session {
            messages: vec![tee::ChatMessage {
                role: "system".to_string(),
                content: tee::system_prompt(tee::Channel::Sms),
            }],
        }
    }

    fn reset(&mut self) {
        self.messages.truncate(1);
    }

    fn estimated_tokens(&self) -> usize {
        self.messages.iter().map(|m| m.content.len() / 4 + 1).sum()
    }
}

struct SmsState {
    sessions: HashMap<String, Session>,
}

type SharedSmsState = Arc<Mutex<SmsState>>;

#[derive(Deserialize)]
#[allow(dead_code)]
struct TwilioWebhook {
    #[serde(rename = "From")]
    from: String,
    #[serde(rename = "Body")]
    body: String,
    #[serde(rename = "To", default)]
    to: String,
}

const SMS_DISCLAIMER: &str = "Note: SMS is not end-to-end encrypted. \
    For full privacy, use the native client at github.com/reeeneeee/tee-talk\n\n";

/// Start the SMS webhook server
pub async fn start_server(port: u16) -> anyhow::Result<()> {
    let state = Arc::new(Mutex::new(SmsState {
        sessions: HashMap::new(),
    }));

    let app = Router::new()
        .route("/sms", post(handle_sms))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    println!("[SMS] Twilio webhook listening on http://{}/sms", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn handle_sms(
    State(state): State<SharedSmsState>,
    Form(webhook): Form<TwilioWebhook>,
) -> impl IntoResponse {
    let phone = webhook.from.clone();
    let body = webhook.body.trim().to_string();

    println!("[SMS] Message from {} ({} chars)", phone, body.len());

    let mut state = state.lock().await;

    // Get or create session for this phone number
    let session = state.sessions.entry(phone.clone()).or_insert_with(Session::new);

    // Handle opt-out
    if body.eq_ignore_ascii_case("stop") {
        state.sessions.remove(&phone);
        return twiml("You've been unsubscribed. Text START to re-subscribe.");
    }

    // Handle help
    if body.eq_ignore_ascii_case("help") {
        return twiml("tee-talk: an AI that listens without judgment. Text START to begin, STOP to unsubscribe, RESET to clear conversation. Not therapy. Crisis: call/text 988.");
    }

    // Handle opt-in
    if body.eq_ignore_ascii_case("start") || body.eq_ignore_ascii_case("hello") {
        session.reset();
        return twiml("Welcome. Whatever you say here stays here — no memory between sessions, no judgment.\n\nSMS is not end-to-end encrypted. For full privacy, use the native client.\n\nReply STOP to unsubscribe at any time.");
    }

    // Handle reset command
    if body.eq_ignore_ascii_case("reset") {
        session.reset();
        return twiml("Conversation cleared. Text again to start fresh.");
    }

    let is_first = session.messages.len() == 1; // only system prompt

    // Add user message
    session.messages.push(tee::ChatMessage {
        role: "user".to_string(),
        content: body,
    });

    // Call Ollama
    let response = match tee::generate_chat_response(&session.messages).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[SMS] Ollama error: {}", e);
            session.messages.pop(); // remove failed user message
            return twiml("Something went wrong. Please try again.");
        }
    };

    // Add assistant response to history
    session.messages.push(tee::ChatMessage {
        role: "assistant".to_string(),
        content: response.clone(),
    });

    // Check context overflow — simple reset on overflow
    let estimated = session.estimated_tokens();
    if estimated as f32 > tee::CONTEXT_SIZE as f32 * 0.8 {
        session.reset();
        println!("[SMS] Context overflow for {}, cleared", phone);
    }

    println!("[SMS] Response to {} ({} chars, ~{} tokens)",
        phone, response.len(), estimated);

    // Prepend disclaimer on first message, truncate for SMS limits
    let response_text = if is_first {
        format!("{}{}", SMS_DISCLAIMER, response)
    } else {
        response
    };
    let truncated = if response_text.len() > 1500 {
        format!("{}...", &response_text[..1497])
    } else {
        response_text
    };
    twiml(&truncated)
}

/// Wrap a message in TwiML response format
fn twiml(message: &str) -> impl IntoResponse {
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Response>\n  <Message>{}</Message>\n</Response>",
        escape_xml(message)
    );

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/xml")],
        xml,
    )
}

/// Basic XML escaping
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
