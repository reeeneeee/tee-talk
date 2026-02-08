//! Private LLM Chat - End-to-end encrypted AI chat with TEE attestation
//!
//! Implements Moxie Marlinspike's Confer architecture:
//! - End-to-end encryption using Noise protocol
//! - Hardware attestation via AMD SEV-SNP (when deployed on Confidential VM)
//! - Forward secrecy via ephemeral keys

mod attestation;
mod certs;
mod client;
mod messages;
mod noise;
#[cfg(feature = "server")]
mod sms;
#[cfg(feature = "server")]
mod tee;
mod web;

use std::io::{self, Write};
use anyhow::Result;
use clap::{Parser, Subcommand};

// ANSI color codes
const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[2m";
const GRAY: &str = "\x1b[90m";
const GREEN: &str = "\x1b[32m";
const BLUE: &str = "\x1b[34m";
const YELLOW: &str = "\x1b[33m";

/// Render context usage as a mushroom garden
fn context_bar(tokens: usize, limit: usize) -> String {
    if limit == 0 {
        return String::new();
    }
    let usage = tokens as f32 / limit as f32;
    let total_slots = 20;
    let filled = (usage * total_slots as f32).round() as usize;
    let filled = if tokens > 0 { filled.max(1) } else { 0 };
    let filled = filled.min(total_slots);

    let mushrooms = ["𖡼", "𖤣", "𖥧", "𓋼", "𓍊"];
    let bar: String = (0..filled)
        .map(|i| mushrooms[i % mushrooms.len()])
        .collect::<Vec<_>>()
        .join("");
    let empty: String = "·".repeat(total_slots - filled);

    format!("{DIM}{bar}{empty} {:.1}%{RESET}", usage * 100.0)
}

#[derive(Parser)]
#[command(name = "tee-talk")]
#[command(about = "End-to-end encrypted LLM chat with TEE attestation")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    #[cfg(feature = "server")]
    /// Run as TEE server (on Confidential VM)
    Server {
        /// Address to bind to
        #[arg(short, long, default_value = "127.0.0.1:9999")]
        bind: String,

        /// Use real SEV-SNP attestation (requires --features real-tee)
        #[arg(long)]
        real_attestation: bool,

        /// Enable Twilio SMS webhook on this port
        #[arg(long)]
        sms_port: Option<u16>,
    },
    /// Connect to a TEE server
    Connect {
        /// Server address to connect to
        #[arg(short, long)]
        address: String,

        /// Launch local web UI instead of terminal
        #[arg(long)]
        web: bool,

        /// Skip attestation verification (connection is still encrypted)
        #[arg(long)]
        trust_server: bool,
    },
    #[cfg(feature = "server")]
    /// Run local demo (server + client together)
    Demo,
}

#[cfg(feature = "server")]
const DEFAULT_ADDR: &str = "127.0.0.1:9999";

/// Public TEE server for zero-config client usage
#[cfg(not(feature = "server"))]
const PUBLIC_SERVER: &str = "34.60.196.117:9999";

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        #[cfg(feature = "server")]
        Some(Commands::Server { bind, real_attestation, sms_port }) => {
            run_server(&bind, real_attestation, sms_port).await
        }
        Some(Commands::Connect { address, web, trust_server }) => {
            if web {
                run_web_client(&address, trust_server).await
            } else {
                run_client(&address, trust_server).await
            }
        }
        #[cfg(feature = "server")]
        Some(Commands::Demo) => {
            run_demo().await
        }
        None => {
            #[cfg(feature = "server")]
            {
                return run_demo().await;
            }
            #[cfg(not(feature = "server"))]
            {
                return run_web_client(PUBLIC_SERVER, true).await;
            }
        }
    }
}

#[cfg(feature = "server")]
async fn run_server(bind: &str, real_attestation: bool, sms_port: Option<u16>) -> Result<()> {
    println!("=== TEE Talk Server ===\n");

    // Start SMS webhook server if enabled
    if let Some(port) = sms_port {
        tokio::spawn(async move {
            if let Err(e) = sms::start_server(port).await {
                eprintln!("[SMS] Server error: {}", e);
            }
        });
    }

    let config = tee::TeeConfig {
        use_real_attestation: real_attestation,
    };

    let server = tee::TeeServer::new(config)?;
    server.run(bind).await
}

async fn run_web_client(address: &str, trust_server: bool) -> Result<()> {
    println!("=== TEE Talk - Web UI ===\n");

    let client = client::Client::connect(address, trust_server).await?;

    let url = "http://localhost:8080";
    println!("\n--- Opening {url} in your browser ---\n");

    // Auto-open browser
    let _ = open::that(url);

    web::start_server(client, 8080).await
}

async fn run_client(address: &str, trust_server: bool) -> Result<()> {
    println!("{GRAY}=== TEE Talk ==={RESET}\n");

    let mut client = client::Client::connect(address, trust_server).await?;

    println!("\n{GRAY}Type your message, or 'quit' to exit{RESET}");
    println!("{GRAY}Commands: /reset, /status{RESET}\n");

    loop {
        print!("{GREEN}> {RESET}");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let prompt = input.trim();

        if prompt.is_empty() {
            continue;
        }

        // Handle commands
        if prompt == "quit" || prompt == "exit" {
            println!("{GRAY}Goodbye!{RESET}");
            break;
        }

        if prompt == "/reset" {
            match client.reset().await {
                Ok(_) => println!("{GRAY}[Conversation cleared]{RESET}\n"),
                Err(e) => eprintln!("{YELLOW}Error resetting: {}{RESET}\n", e),
            }
            continue;
        }

        if prompt == "/status" {
            if let Some(_) = client.context_usage() {
                println!("{}\n", context_bar(client.context_tokens, client.context_limit));
            } else {
                println!("{GRAY}[Context usage not available]{RESET}\n");
            }
            continue;
        }

        // Show spinner while waiting for response
        let spinner_handle = tokio::spawn(async {
            let frames = ["𖡼 .", "𖤣 ..", "𖥧 ...", "𓋼 ....", "𓍊 ...."];
            let mut i = 0;
            loop {
                print!("\r{DIM}{}{RESET}", frames[i % frames.len()]);
                io::stdout().flush().ok();
                i += 1;
                tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
            }
        });

        let result = client.send_prompt(prompt).await;
        spinner_handle.abort();
        print!("\r\x1b[2K"); // Clear spinner line
        io::stdout().flush().ok();

        match result {
            Ok(response) => {
                // Show context overflow warning
                if response.context_overflow {
                    println!("{YELLOW}[Context compacted]{RESET}");
                }

                println!("{BLUE}{}{RESET}", response.content);

                // Show context usage
                if response.context_limit > 0 {
                    println!("{}\n", context_bar(response.context_tokens, response.context_limit));
                } else {
                    println!();
                }
            }
            Err(e) => {
                eprintln!("{YELLOW}Error: {}{RESET}", e);
                break;
            }
        }
    }

    Ok(())
}

#[cfg(feature = "server")]
async fn run_demo() -> Result<()> {
    println!("{GRAY}=== TEE Talk (local) ==={RESET}\n");

    // Start TEE server in background (mock attestation)
    let config = tee::TeeConfig::default();
    let tee_server = tee::TeeServer::new(config)?;

    tokio::spawn(async move {
        if let Err(e) = tee_server.run(DEFAULT_ADDR).await {
            eprintln!("[TEE] Server error: {}", e);
        }
    });

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Connect client and serve web UI
    let client = client::Client::connect(DEFAULT_ADDR, false).await?;

    println!("\n--- Open {BLUE}http://localhost:8080{RESET} in your browser ---\n");

    web::start_server(client, 8080).await
}
