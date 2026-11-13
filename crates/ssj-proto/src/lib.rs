//! Wire format, replay buffer, and resume logic of `ssj`, without any IO.
//!
//! Everything here works on byte slices and plain values, so the parsers can be fuzzed and the
//! state logic tested without sockets.

pub mod bootstrap;
pub mod compress;
pub mod control;
pub mod destination;
pub mod env;
pub mod env_filter;
pub mod frame;
pub mod replay;
pub mod resume;
pub mod types;

pub use env::{Env, EnvError};
pub use env_filter::{EnvFilter, PatternError};
pub use frame::{
    ClientFrame, DecodeError, EncodeError, ErrorCode, ExitStatus, Hello, Peek, ServerFrame,
    Welcome, decode_client, decode_server, peek_server,
};
pub use replay::{ReplayBuffer, ReplayError};
pub use types::{SessionId, SessionName, WindowSize, is_selector};

/// Version of the wire protocol. Two peers talk only if their versions are equal.
///
/// Increase it with every change of the wire format, and store a new golden file for it.
pub const PROTOCOL: u16 = 3;

/// ALPN identifier of the protocol, the only one a peer offers or accepts.
pub fn alpn() -> Vec<u8> {
    format!("ssj/{PROTOCOL}").into_bytes()
}
