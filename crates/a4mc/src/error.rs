//! The bounded error type that crosses every contract boundary.

use serde::{Deserialize, Serialize};
use std::fmt;

/// One bounded, sanitized failure.
///
/// `code` is a stable `snake_case` identifier a host can branch on.
/// `message` is a short human summary. `retry_after_ms` carries the
/// delay a platform or pipeline stage requested before the caller
/// retries, when the failure reported one. Error construction is a
/// sanitization point: no field may carry secret material, response
/// bodies, credentials or runtime evidence beyond the bounded summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelError {
    pub code: String,
    pub message: String,
    /// Requested wait before retrying, in milliseconds. Present on
    /// rate-limit and deferral failures that carry a machine-readable
    /// hint; absent on every other failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

impl ChannelError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retry_after_ms: None,
        }
    }

    /// Attach the requested retry delay to this failure.
    pub fn with_retry_after_ms(mut self, retry_after_ms: u64) -> Self {
        self.retry_after_ms = Some(retry_after_ms);
        self
    }
}

impl fmt::Display for ChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ChannelError {}
