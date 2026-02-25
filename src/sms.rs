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
    twilio: Option<TwilioClient>,
}

type SharedSmsState = Arc<Mutex<SmsState>>;

/// Twilio REST API client for sending messages asynchronously
#[derive(Clone)]
struct TwilioClient {
    account_sid: String,
    auth_token: String,
    from_number: String,
    http: reqwest::Client,
}

impl TwilioClient {
    fn from_env() -> Option<Self> {
        let account_sid = std::env::var("TWILIO_ACCOUNT_SID").ok()?;
        let auth_token = std::env::var("TWILIO_AUTH_TOKEN").ok()?;
        let from_number = std::env::var("TWILIO_FROM_NUMBER").ok()?;
        Some(TwilioClient {
            account_sid,
            auth_token,
            from_number,
            http: reqwest::Client::new(),
        })
    }

    async fn send_message(&self, to: &str, body: &str) -> Result<(), String> {
        let url = format!(
            "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
            self.account_sid
        );
        let resp = self.http.post(&url)
            .basic_auth(&self.account_sid, Some(&self.auth_token))
            .form(&[
                ("To", to),
                ("From", &self.from_number),
                ("Body", body),
            ])
            .send()
            .await
            .map_err(|e| format!("HTTP error: {}", e))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            Err(format!("Twilio API error {}: {}", status, body))
        }
    }
}

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

const SMS_DISCLAIMER: &str = "TEE Talk: Note: SMS is not end-to-end encrypted \
    — your carrier and Twilio can see messages, but the LLM runs inside secure \
    hardware that no one can access, not even the server operator. Responses may \
    occasionally be slow or dropped — just resend if you don't hear back. \
    Reply STOP to unsubscribe.";

/// Start the SMS webhook server
pub async fn start_server(port: u16) -> anyhow::Result<()> {
    let twilio = TwilioClient::from_env();
    if twilio.is_some() {
        println!("[SMS] Twilio API credentials found — first message will be answered asynchronously");
    } else {
        println!("[SMS] No Twilio API credentials — all responses will be synchronous (may timeout on slow LLM responses)");
        println!("[SMS] Set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_FROM_NUMBER to enable async replies");
    }

    let state = Arc::new(Mutex::new(SmsState {
        sessions: HashMap::new(),
        twilio,
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

    let mut guard = state.lock().await;
    let twilio_client = guard.twilio.clone();

    // Get or create session for this phone number
    let session = guard.sessions.entry(phone.clone()).or_insert_with(Session::new);

    // Handle opt-out
    if body.eq_ignore_ascii_case("stop") {
        guard.sessions.remove(&phone);
        return twiml("You have successfully been unsubscribed. You will not receive any more messages from this number. Reply START to resubscribe.");
    }

    // Handle help
    if body.eq_ignore_ascii_case("help") {
        return twiml("TEE Talk: An AI that listens without judgment. Text START to begin, STOP to unsubscribe, RESET to clear conversation. Msg & data rates may apply. Not therapy. Crisis: call/text 988.");
    }

    // Handle opt-in
    if body.eq_ignore_ascii_case("start") || body.eq_ignore_ascii_case("hello") {
        session.reset();
        return twiml("TEE Talk: Welcome. Whatever you say here stays here — no memory between sessions, no judgment. SMS is not e2e encrypted. Msg frequency varies. Msg & data rates may apply. Reply HELP for help, STOP to unsubscribe.");
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

    // On first real message with Twilio API available: return disclaimer immediately,
    // generate LLM response in background, and send it via Twilio REST API.
    // This avoids Twilio's ~15s webhook timeout on cold LLM responses.
    if is_first {
        if let Some(twilio) = twilio_client.clone() {
            let messages = session.messages.clone();
            let phone_clone = phone.clone();
            let state_clone = Arc::clone(&state);

            // Drop the lock before spawning so the background task can acquire it
            drop(guard);

            tokio::spawn(async move {
                let response = match tee::generate_chat_response(&messages).await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("[SMS] Ollama error for {}: {}", phone_clone, e);
                        return;
                    }
                };

                // Update session history
                {
                    let mut st = state_clone.lock().await;
                    if let Some(session) = st.sessions.get_mut(&phone_clone) {
                        session.messages.push(tee::ChatMessage {
                            role: "assistant".to_string(),
                            content: response.clone(),
                        });
                        let estimated = session.estimated_tokens();
                        if estimated as f32 > tee::CONTEXT_SIZE as f32 * 0.8 {
                            session.reset();
                            println!("[SMS] Context overflow for {}, cleared", phone_clone);
                        }
                        println!("[SMS] Async response to {} ({} chars, ~{} tokens)",
                            phone_clone, response.len(), estimated);
                    }
                }

                let truncated = truncate_sms(&response);
                if let Err(e) = twilio.send_message(&phone_clone, &truncated).await {
                    eprintln!("[SMS] Failed to send async reply to {}: {}", phone_clone, e);
                }
            });

            return twiml(SMS_DISCLAIMER);
        }
    }

    // Synchronous path: call Ollama and reply inline
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

    // Check context overflow
    let estimated = session.estimated_tokens();
    if estimated as f32 > tee::CONTEXT_SIZE as f32 * 0.8 {
        session.reset();
        println!("[SMS] Context overflow for {}, cleared", phone);
    }

    println!("[SMS] Response to {} ({} chars, ~{} tokens)",
        phone, response.len(), estimated);

    // Prepend disclaimer on first message (sync path, no Twilio API)
    let response_text = if is_first {
        format!("{}\n\n{}", SMS_DISCLAIMER, response)
    } else {
        response
    };
    twiml(&truncate_sms(&response_text))
}

/// Truncate a message to fit SMS limits
fn truncate_sms(message: &str) -> String {
    if message.len() > 1500 {
        format!("{}...", &message[..1497])
    } else {
        message.to_string()
    }
}

/// Wrap a message in TwiML response format (empty string = no message)
fn twiml(message: &str) -> impl IntoResponse {
    let xml = if message.is_empty() {
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Response/>".to_string()
    } else {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Response>\n  <Message>{}</Message>\n</Response>",
            escape_xml(message)
        )
    };

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
