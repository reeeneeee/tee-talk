//! Protocol messages for client-server communication.
//!
//! Defines structured message types for multi-turn conversation support.

use serde::{Deserialize, Serialize};

/// Request from client to server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    /// The user's prompt
    pub prompt: String,
    /// If true, clear conversation context and start fresh
    #[serde(default)]
    pub reset: bool,
}

impl ChatRequest {
    pub fn new(prompt: String) -> Self {
        Self {
            prompt,
            reset: false,
        }
    }

    pub fn reset() -> Self {
        Self {
            prompt: String::new(),
            reset: true,
        }
    }
}

/// Response from server to client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    /// The LLM's response
    pub content: String,
    /// Current context size in tokens
    pub context_tokens: usize,
    /// Maximum context size for the model
    pub context_limit: usize,
    /// True if context was compacted due to overflow
    pub context_overflow: bool,
    /// Summary of conversation if overflow occurred
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compacted_summary: Option<String>,
}

impl ChatResponse {
    pub fn new(content: String, context_tokens: usize, context_limit: usize) -> Self {
        Self {
            content,
            context_tokens,
            context_limit,
            context_overflow: false,
            compacted_summary: None,
        }
    }

    #[cfg(feature = "server")]
    pub fn with_overflow(
        content: String,
        summary: String,
        context_tokens: usize,
        context_limit: usize,
    ) -> Self {
        Self {
            content,
            context_tokens,
            context_limit,
            context_overflow: true,
            compacted_summary: Some(summary),
        }
    }

}

/// A single message in conversation history (client-side)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Assistant,
    System,
}

impl Message {
    pub fn user(content: String) -> Self {
        Self {
            role: Role::User,
            content,
        }
    }

    pub fn assistant(content: String) -> Self {
        Self {
            role: Role::Assistant,
            content,
        }
    }

    pub fn system(content: String) -> Self {
        Self {
            role: Role::System,
            content,
        }
    }
}
