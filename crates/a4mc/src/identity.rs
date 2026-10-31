//! External channel identity.
//!
//! These types name what a messenger *platform* asserts about its own
//! users, chats and messages. They never assert a host principal: a
//! [`ChannelUser`] is "who Telegram says sent this", nothing more.
//! Mapping channel identity to host principals — pairing approval,
//! agent admission — is host policy exercised through the ports.

use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! external_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(
            Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default,
        )]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_owned())
            }
        }

        impl From<i64> for $name {
            fn from(value: i64) -> Self {
                Self(value.to_string())
            }
        }
    };
}

external_id!(
    ChannelId,
    "Identifier of one channel dialect (e.g. `\"telegram\"`)."
);
external_id!(
    ExternalUserId,
    "A user id in the platform's own namespace — never a host principal."
);
external_id!(
    ExternalChatId,
    "A chat/conversation id in the platform's own namespace."
);
external_id!(
    ExternalMessageId,
    "A message id in the platform's own namespace."
);

/// The platform-reported kind of one chat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ChatKind {
    /// One-to-one direct conversation.
    Direct,
    /// A group chat.
    Group,
    /// A broadcast channel.
    Channel,
    /// The platform's shape is not mapped.
    #[default]
    Unknown,
}

/// A user as the channel platform describes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ChannelUser {
    pub id: ExternalUserId,
    pub username: Option<String>,
    pub display_name: Option<String>,
}

/// A chat as the channel platform describes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ChannelChat {
    pub id: ExternalChatId,
    pub kind: ChatKind,
    pub title: Option<String>,
}
