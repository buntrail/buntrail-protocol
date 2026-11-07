//! Explicit terminal boundary values; output is raw bytes, never a screen snapshot.
use crate::services::invalid;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use buntrail_core::contracts as c;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndIntent {
    ExplicitClose,
    FinalWorkspaceClose,
    RetentionExpiry,
}
impl EndIntent {
    pub fn core(&self) -> c::TerminalEndIntent {
        match self {
            Self::ExplicitClose => c::TerminalEndIntent::ExplicitClose,
            Self::FinalWorkspaceClose => c::TerminalEndIntent::FinalWorkspaceClose,
            Self::RetentionExpiry => c::TerminalEndIntent::RetentionExpiry,
        }
    }
    pub fn from_core(v: c::TerminalEndIntent) -> Self {
        match v {
            c::TerminalEndIntent::ExplicitClose => Self::ExplicitClose,
            c::TerminalEndIntent::FinalWorkspaceClose => Self::FinalWorkspaceClose,
            c::TerminalEndIntent::RetentionExpiry => Self::RetentionExpiry,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    Output {
        sequence: u64,
        bytes_base64: String,
    },
    Gap {
        first: u64,
        last: u64,
    },
    ProcessExit {
        #[serde(deserialize_with = "crate::types::required_option")]
        code: Option<i32>,
    },
    Ended {
        intent: EndIntent,
    },
    Disconnected {
        expires_at_unix_seconds: u64,
    },
    Reattached,
    Expired,
    RuntimeLost,
}
impl Event {
    pub fn from_core(e: c::TerminalEvent) -> Self {
        match e {
            c::TerminalEvent::Output { sequence, bytes } => Self::Output {
                sequence,
                bytes_base64: B64.encode(bytes),
            },
            c::TerminalEvent::Gap { first, last } => Self::Gap { first, last },
            c::TerminalEvent::ProcessExit { code } => Self::ProcessExit { code },
            c::TerminalEvent::Ended { intent } => Self::Ended {
                intent: EndIntent::from_core(intent),
            },
            c::TerminalEvent::Disconnected {
                expires_at_unix_seconds,
            } => Self::Disconnected {
                expires_at_unix_seconds,
            },
            c::TerminalEvent::Reattached => Self::Reattached,
            c::TerminalEvent::Expired => Self::Expired,
            c::TerminalEvent::RuntimeLost => Self::RuntimeLost,
        }
    }
    pub fn core(self) -> Result<c::TerminalEvent, c::CoreError> {
        Ok(match self {
            Self::Output {
                sequence,
                bytes_base64,
            } => c::TerminalEvent::Output {
                sequence,
                bytes: B64.decode(bytes_base64).map_err(|_| invalid())?,
            },
            Self::Gap { first, last } => c::TerminalEvent::Gap { first, last },
            Self::ProcessExit { code } => c::TerminalEvent::ProcessExit { code },
            Self::Ended { intent } => c::TerminalEvent::Ended {
                intent: intent.core(),
            },
            Self::Disconnected {
                expires_at_unix_seconds,
            } => c::TerminalEvent::Disconnected {
                expires_at_unix_seconds,
            },
            Self::Reattached => c::TerminalEvent::Reattached,
            Self::Expired => c::TerminalEvent::Expired,
            Self::RuntimeLost => c::TerminalEvent::RuntimeLost,
        })
    }
}
pub fn size(columns: u16, rows: u16) -> Result<c::TerminalSize, c::CoreError> {
    Ok(c::TerminalSize {
        columns: columns.try_into().map_err(|_| invalid())?,
        rows: rows.try_into().map_err(|_| invalid())?,
    })
}
