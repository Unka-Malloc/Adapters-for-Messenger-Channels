//! The bounded error type for the signed-webhook boundary.
//!
//! Error construction is a sanitization point: neither field may carry
//! the signing secret, a request body, a signature value or runtime
//! evidence beyond the bounded summary.

use std::fmt;

/// One bounded webhook verification or lowering failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookError {
    pub code: String,
    pub message: String,
}

impl WebhookError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for WebhookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for WebhookError {}
