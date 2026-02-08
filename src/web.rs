//! Local web UI for tee-talk.
//!
//! Runs on localhost only - the browser is just a UI,
//! all crypto and attestation happens in the Rust client.

use std::sync::Arc;
use tokio::sync::Mutex;
use axum::{
    extract::State,
    http::StatusCode,
    response::Html,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::client::Client;

type SharedClient = Arc<Mutex<Client>>;

#[derive(Deserialize)]
struct ChatInput {
    prompt: String,
}

#[derive(Serialize)]
struct StatusResponse {
    context_tokens: usize,
    context_limit: usize,
}

#[derive(Serialize)]
struct ResetResponse {
    ok: bool,
}

#[derive(Serialize)]
struct WelcomeResponse {
    content: String,
}

/// Start the local web server
pub async fn start_server(client: Client, port: u16) -> anyhow::Result<()> {
    let shared = Arc::new(Mutex::new(client));

    let app = Router::new()
        .route("/", get(index))
        .route("/api/chat", post(chat))
        .route("/api/reset", post(reset))
        .route("/api/status", get(status))
        .route("/api/welcome", get(welcome))
        .with_state(shared);

    let addr = format!("127.0.0.1:{}", port);
    println!("[Web] Listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn chat(
    State(client): State<SharedClient>,
    Json(input): Json<ChatInput>,
) -> Result<Json<crate::messages::ChatResponse>, StatusCode> {
    let mut c = client.lock().await;
    match c.send_prompt(&input.prompt).await {
        Ok(response) => Ok(Json(response)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn reset(
    State(client): State<SharedClient>,
) -> Result<Json<ResetResponse>, StatusCode> {
    let mut c = client.lock().await;
    match c.reset().await {
        Ok(_) => Ok(Json(ResetResponse { ok: true })),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn welcome(
    State(client): State<SharedClient>,
) -> Json<WelcomeResponse> {
    let c = client.lock().await;
    let content = c.welcome_message().unwrap_or("").to_string();
    Json(WelcomeResponse { content })
}

async fn status(
    State(client): State<SharedClient>,
) -> Json<StatusResponse> {
    let c = client.lock().await;
    Json(StatusResponse {
        context_tokens: c.context_tokens,
        context_limit: c.context_limit,
    })
}

const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>tee talk</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  ::selection { background: #ff5ec4; color: #a6ff47; }
  ::-moz-selection { background: #ff5ec4; color: #a6ff47; }

  body {
    background: #000;
    color: #a6ff47;
    font-family: Georgia, 'Times New Roman', serif;
    font-size: 1.1rem;
    height: 100vh;
    display: flex;
    flex-direction: column;
  }

  #welcome {
    position: fixed;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 50;
    background: #000;
    transition: opacity 1.2s ease-out;
  }

  #welcome.hidden {
    opacity: 0;
    pointer-events: none;
  }

  #welcome-msg {
    position: absolute;
    bottom: 8rem;
    left: 2rem;
    color: #a6ff47;
    font-size: 1.1rem;
    line-height: 1.7;
    opacity: 0;
    transition: opacity 1s ease-in;
  }

  #welcome-msg.visible {
    opacity: 1;
  }

  #welcome-inner {
    text-align: center;
    max-width: 500px;
    padding: 2rem;
  }

  #welcome-inner p {
    font-size: 1.2rem;
    line-height: 1.8;
    color: #ffcfc4;
    animation: glow 4s ease-out infinite;
  }

  @keyframes glow {
    0%   { opacity: 0.3; }
    50%  { opacity: 0.8; }
    100% { opacity: 0.3; }
  }

  #messages {
    flex: 1;
    overflow-y: auto;
    padding: 2rem 2rem 1rem;
    display: flex;
    flex-direction: column;
    justify-content: flex-end;
    gap: 1.4rem;
  }

  .msg {
    max-width: 80%;
    line-height: 1.7;
    font-size: 1.1rem;
  }

  .msg.assistant {
    align-self: flex-start;
    color: #a6ff47;
  }

  .msg.user {
    align-self: flex-end;
    color: #ff5ec4;
    text-align: right;
  }

  .msg.system {
    align-self: center;
    color: rgba(166, 255, 71, 0.35);
    font-size: 0.95rem;
    text-align: center;
  }

  #context-bar {
    position: relative;
    z-index: 60;
    padding: 0.4rem 2rem;
    font-size: 0.85rem;
    color: rgba(166, 255, 71, 0.3);
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  #context-mushrooms {
    letter-spacing: 2px;
  }

  #input-area {
    position: relative;
    z-index: 60;
    display: flex;
    padding: 1rem 2rem 1.5rem;
    gap: 0.8rem;
    border-top: 1px solid rgba(166, 255, 71, 0.1);
  }

  #prompt {
    flex: 1;
    background: transparent;
    border: none;
    border-bottom: 1px solid rgba(166, 255, 71, 0.15);
    color: #a6ff47;
    padding: 0.5rem 0;
    font-family: Georgia, 'Times New Roman', serif;
    font-size: 1.1rem;
    outline: none;
    resize: none;
  }

  #prompt:focus {
    border-bottom-color: #ff5ec4;
  }

  #prompt::placeholder {
    color: rgba(166, 255, 71, 0.25);
  }

  button {
    background: none;
    border: none;
    color: rgba(166, 255, 71, 0.3);
    padding: 0.5rem;
    cursor: pointer;
    font-family: Georgia, 'Times New Roman', serif;
    font-size: 1rem;
  }

  button:hover {
    color: #ff5ec4;
  }

  button:disabled {
    opacity: 0.3;
    cursor: not-allowed;
  }

  #reset-btn {
    font-size: 0.8rem;
  }

  .thinking {
    align-self: flex-start;
    color: #ff5ec4;
    font-size: 1rem;
    letter-spacing: 3px;
  }
</style>
</head>
<body>

<div id="welcome">
  <div id="welcome-inner">
    <p>This is a secure, encrypted space &mdash; your words are protected and will not be remembered after you leave.</p>
    <p style="margin-top:1.2rem;font-size:0.95rem;color:rgba(166,255,71,0.4)">The first message may take a moment.</p>
  </div>
  <div id="welcome-msg"></div>
</div>

<div id="messages"></div>

<div id="context-bar">
  <span id="context-mushrooms"></span>
  <span id="context-pct"></span>
  <span style="flex:1"></span>
  <button id="reset-btn" onclick="doReset()">clear</button>
</div>

<div id="input-area">
  <textarea id="prompt" rows="1" placeholder="Speak freely..." autofocus spellcheck="false" autocomplete="off" autocorrect="off" autocapitalize="off"></textarea>
  <button id="send-btn" onclick="send()">&#x10D022;</button>
</div>

<script>
const messagesEl = document.getElementById('messages');
const promptEl = document.getElementById('prompt');
const sendBtn = document.getElementById('send-btn');
const mushroomsEl = document.getElementById('context-mushrooms');
const pctEl = document.getElementById('context-pct');
const welcomeEl = document.getElementById('welcome');
let firstSend = true;

// Fetch and display the server's welcome message
let welcomeText = '';
fetch('/api/welcome').then(r => r.json()).then(data => {
  if (data.content) {
    welcomeText = data.content;
    const wmsg = document.getElementById('welcome-msg');
    wmsg.textContent = data.content;
    setTimeout(() => wmsg.classList.add('visible'), 100);
  }
}).catch(() => {});

promptEl.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    send();
  }
});

promptEl.addEventListener('input', () => {
  promptEl.style.height = 'auto';
  promptEl.style.height = Math.min(promptEl.scrollHeight, 120) + 'px';
});

function addMessage(role, content) {
  const div = document.createElement('div');
  div.className = 'msg ' + role;
  div.textContent = content;
  messagesEl.appendChild(div);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function showThinking() {
  const div = document.createElement('div');
  div.className = 'thinking';
  div.id = 'thinking';
  const syms = ['\u2727', '\u2726', '\u2736', '\u273F', '\u2740'];
  let i = 0;
  div.textContent = syms[0];
  div._interval = setInterval(() => {
    i = (i + 1) % syms.length;
    div.textContent = syms.slice(0, i + 1).join(' ');
  }, 300);
  messagesEl.appendChild(div);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function hideThinking() {
  const el = document.getElementById('thinking');
  if (el) {
    clearInterval(el._interval);
    el.remove();
  }
}

function updateContext(tokens, limit) {
  if (!limit) return;
  const usage = tokens / limit;
  const slots = 20;
  const filled = Math.min(Math.max(tokens > 0 ? 1 : 0, Math.round(usage * slots)), slots);
  const syms = ['\u2727', '\u2726', '\u2736', '\u273F', '\u2740'];
  let bar = '';
  for (let i = 0; i < filled; i++) {
    bar += syms[i % syms.length];
  }
  for (let i = filled; i < slots; i++) {
    bar += '\u00B7';
  }
  mushroomsEl.textContent = bar;
  pctEl.textContent = (usage * 100).toFixed(1) + '%';
}

async function send() {
  const text = promptEl.value.trim();
  if (!text) return;

  if (firstSend) {
    firstSend = false;
    if (welcomeText) addMessage('assistant', welcomeText);
    welcomeEl.classList.add('hidden');
    setTimeout(() => welcomeEl.remove(), 800);
  }

  promptEl.value = '';
  promptEl.style.height = 'auto';
  sendBtn.disabled = true;

  addMessage('user', text);
  showThinking();

  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt: text }),
    });

    hideThinking();

    if (!res.ok) {
      addMessage('system', 'Something went wrong. Please try again.');
      return;
    }

    const data = await res.json();

    if (data.context_overflow) {
      addMessage('system', 'Context compacted \u2014 conversation summarized');
    }

    addMessage('assistant', data.content);
    updateContext(data.context_tokens, data.context_limit);
  } catch (e) {
    hideThinking();
    addMessage('system', 'Connection lost.');
  } finally {
    sendBtn.disabled = false;
    promptEl.focus();
  }
}

function doReset() {
  messagesEl.innerHTML = '';
  mushroomsEl.textContent = '';
  pctEl.textContent = '';
  addMessage('system', 'Conversation cleared.');
  fetch('/api/reset', { method: 'POST' }).catch(() => {
    addMessage('system', 'Reset failed on server.');
  });
}
</script>
</body>
</html>
"#;
