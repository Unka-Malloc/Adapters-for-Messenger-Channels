//! Platform-native receive-mechanism classification.

use serde::{Deserialize, Serialize};

/// The platform-native ways a channel can receive updates. A dialect
/// declares its level of support for every mechanism the platform
/// offers — not only the one it implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneMechanism {
    /// Repeated bounded pull (e.g. Telegram `getUpdates` long polling).
    Poll,
    /// Platform pushes to a listener the host side exposes.
    Webhook,
    /// A persistent bidirectional socket (e.g. websocket-mode SDKs).
    Socket,
}
