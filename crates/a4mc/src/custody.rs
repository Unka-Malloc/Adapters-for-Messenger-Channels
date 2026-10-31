//! Channel credential custody port.
//!
//! Custody — keyring reads, token files, environment fallbacks, owner
//! authorization — belongs to the host. An adapter asks for its bot
//! token through this port and never reads custody itself. This module
//! is the port only: it stores nothing, and secret material never
//! appears in serialized, debug or error output.

use crate::error::ChannelError;
use crate::identity::ChannelId;
use std::fmt;
use std::sync::{Arc, RwLock};
use zeroize::Zeroizing;

/// Maximum secret bytes one channel token may carry.
pub const MAX_SECRET_BYTES: usize = 8 * 1024;

/// Validation failure for [`SecretToken`] construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretError {
    Empty,
    Oversize,
    NotUtf8,
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "a4mc_secret_empty",
            Self::Oversize => "a4mc_secret_oversize",
            Self::NotUtf8 => "a4mc_secret_not_utf8",
        })
    }
}

impl std::error::Error for SecretError {}

/// A channel secret (e.g. a bot token) retrieved from host custody.
///
/// Redacted in `Debug`, never `Serialize`/`Deserialize`, zeroized on
/// drop. The only way out is [`SecretToken::expose_bytes`] /
/// [`SecretToken::expose_utf8`], called at the single point a transport
/// consumes the token.
pub struct SecretToken {
    bytes: Zeroizing<Vec<u8>>,
}

impl SecretToken {
    pub fn try_from_bytes(bytes: Vec<u8>) -> Result<Self, SecretError> {
        let bytes = Zeroizing::new(bytes);
        if bytes.is_empty() {
            return Err(SecretError::Empty);
        }
        if bytes.len() > MAX_SECRET_BYTES {
            return Err(SecretError::Oversize);
        }
        Ok(Self { bytes })
    }

    pub fn try_from_string(value: String) -> Result<Self, SecretError> {
        Self::try_from_bytes(value.into_bytes())
    }

    pub fn expose_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn expose_utf8(&self) -> Result<&str, SecretError> {
        std::str::from_utf8(&self.bytes).map_err(|_| SecretError::NotUtf8)
    }

    /// An explicit second copy for a consumer that keeps the secret
    /// beyond the caller's lifetime (e.g. a long-lived transport).
    pub fn copy_for_persistent_read(&self) -> Self {
        Self {
            bytes: Zeroizing::new(self.bytes.to_vec()),
        }
    }
}

impl fmt::Debug for SecretToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretToken([redacted])")
    }
}

/// The custody owner's token answer for channels.
///
/// The port decides where the token lives (system keyring, token file,
/// environment, remote vault) and whether the caller may have it; the
/// adapter only asks. Returning `Ok(None)` means custody holds no token
/// for the channel — configuration, not an error.
pub trait CustodyPort: Send + Sync {
    /// Resolve the bot token for `channel` (e.g. `"telegram"`).
    fn channel_token(&self, channel: &ChannelId) -> Result<Option<SecretToken>, ChannelError>;
}

static CUSTODY: RwLock<Option<Arc<dyn CustodyPort>>> = RwLock::new(None);

/// Install this host's custody port. One composition owns the port per
/// process; reinstalling the same port is accepted so repeated startup
/// is harmless; a different port is refused.
pub fn install(port: Arc<dyn CustodyPort>) -> Result<(), &'static str> {
    let mut guard = CUSTODY
        .write()
        .map_err(|_| "a4mc_custody_port_lock_failed")?;
    match guard.as_ref() {
        Some(installed) if Arc::ptr_eq(installed, &port) => return Ok(()),
        Some(_) => return Err("a4mc_custody_port_already_installed"),
        None => {}
    }
    *guard = Some(port);
    Ok(())
}

pub fn installed() -> bool {
    CUSTODY.read().map(|guard| guard.is_some()).unwrap_or(false)
}

/// Drop the installed port. Used by tests that need to prove the
/// fail-closed path; production composition installs once per process.
pub fn clear() {
    if let Ok(mut guard) = CUSTODY.write() {
        *guard = None;
    }
}

/// Consume the installed port; fails closed when nothing is installed.
pub fn require() -> Result<Arc<dyn CustodyPort>, ChannelError> {
    CUSTODY
        .read()
        .ok()
        .and_then(|guard| guard.as_ref().cloned())
        .ok_or_else(|| {
            ChannelError::new(
                "a4mc_custody_port_unavailable",
                "custody port not installed",
            )
        })
}
