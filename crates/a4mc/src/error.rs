//! The bounded error type that crosses every contract boundary.

use serde::{Deserialize, Serialize};
use std::fmt;

/// One bounded, sanitized failure.
///
/// `code` is a stable `snake_case` identifier a host can branch on.
/// `message` is a short human summary. Error construction is a
/// sanitization point: neither field may carry secret material, response
/// bodies, credentials or runtime evidence beyond the bounded summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelError {
    pub code: String,
    pub message: String,
}

impl ChannelError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for ChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ChannelError {}
