//! Raw mode and window size of the local terminal.

use std::io::{self, Write};

use rustix::stdio::stdin;
use rustix::termios::{OptionalActions, Termios, isatty, tcgetattr, tcgetwinsize, tcsetattr};
use ssj_proto::WindowSize;

/// Puts the terminal into raw mode and restores it when dropped.
pub struct RawMode {
    original: Termios,
}

impl RawMode {
    /// Returns `None` if stdin is not a terminal, such as in a pipe.
    pub fn enable() -> io::Result<Option<Self>> {
        let fd = stdin();
        if !isatty(fd) {
            return Ok(None);
        }
        let original = tcgetattr(fd)?;
        let mut raw = original.clone();
        raw.make_raw();
        tcsetattr(fd, OptionalActions::Now, &raw)?;
        Ok(Some(Self { original }))
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = tcsetattr(stdin(), OptionalActions::Now, &self.original);
    }
}

/// Size of the terminal, or 24 by 80 if it cannot be read.
pub fn window_size() -> WindowSize {
    tcgetwinsize(stdin())
        .ok()
        .and_then(|size| {
            WindowSize::new(size.ws_row, size.ws_col)
                .map(|window| window.with_pixels(size.ws_xpixel, size.ws_ypixel))
        })
        .unwrap_or_else(|| WindowSize::new(24, 80).expect("valid size"))
}

/// Ends the process as Ctrl-C does, with the cursor shown that a prompt hid.
fn interrupted() -> ! {
    let _ = io::stderr().write_all(b"\x1b[?25h");
    std::process::exit(130)
}

/// Makes a Ctrl-C end `ssj`. A prompt of `dialoguer` reads the key and then raises `SIGINT`, which
/// would kill the process with the cursor still hidden. Needs a running runtime.
pub fn exit_on_interrupt() {
    if let Ok(mut interrupt) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
    {
        tokio::spawn(async move {
            interrupt.recv().await;
            interrupted()
        });
    }
}

/// Reads the answer of a `dialoguer` prompt: `None` for a cancel (Esc or `q`) and for no terminal.
pub fn ask<T>(answer: dialoguer::Result<Option<T>>) -> Option<T> {
    match answer {
        Ok(answer) => answer,
        Err(dialoguer::Error::IO(err)) if err.kind() == io::ErrorKind::Interrupted => interrupted(),
        Err(_) => None,
    }
}
