//! Server side of `ssj`: owns the shell of a session and talks to the client.

pub mod backend;
pub mod cli;
pub mod config;
pub mod control_cli;
pub mod control_server;
pub mod control_socket;
pub mod daemon;
pub mod frontend;
pub mod launch;
pub mod listen;
pub mod relay;
pub mod session;
pub mod stream;
pub mod transport;
