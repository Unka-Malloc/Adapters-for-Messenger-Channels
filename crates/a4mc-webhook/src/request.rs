//! One inbound HTTP request, reduced to the parts signature verification
//! needs.
//!
//! The composing host owns the HTTP server and adapts its request into
//! this type; the dialect never opens a socket. Header names are
//! normalized to lowercase so casing never changes a verification
//! outcome. `Debug` prints header names and the body length, never
//! header values or the body itself.

use std::collections::BTreeMap;
use std::fmt;

/// An inbound webhook request.
#[derive(Clone, PartialEq, Eq)]
pub struct WebhookRequest {
    method: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl WebhookRequest {
    pub fn new(method: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            method: method.into().trim().to_ascii_uppercase(),
            headers: BTreeMap::new(),
            body: body.into(),
        }
    }

    /// Add one header. The name is lowercased and surrounding whitespace
    /// is trimmed from both name and value, matching HTTP's
    /// case-insensitive field names.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into().trim().to_ascii_lowercase();
        let value = value.into().trim().to_owned();
        if !name.is_empty() {
            self.headers.insert(name, value);
        }
        self
    }

    pub fn method(&self) -> &str {
        &self.method
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.trim().to_ascii_lowercase())
            .map(String::as_str)
    }

    pub fn headers(&self) -> impl Iterator<Item = (&str, &str)> {
        self.headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

impl fmt::Debug for WebhookRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookRequest")
            .field("method", &self.method)
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .field("body_len", &self.body.len())
            .finish()
    }
}
