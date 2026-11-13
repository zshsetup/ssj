//! Backend that runs the program on a pseudo terminal of its own.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use pty_process::Size;
use tokio::io::AsyncWrite;
use tokio::process::Child;

use super::{Backend, Parts, SessionId, Shell, ShellWriter, SpawnSpec, WindowSize};

/// Backend that runs the shell as a child of the server, which ends with the server.
#[derive(Clone, Copy, Debug, Default)]
pub struct Direct;

/// Shell on a PTY owned by the server process.
pub struct DirectShell {
    pty: pty_process::Pty,
    child: Child,
}

/// Input side of a [`DirectShell`].
pub struct DirectWriter(pty_process::OwnedWritePty);

fn to_size(size: WindowSize) -> Size {
    Size::new_with_pixel(size.rows(), size.cols(), size.xpixel(), size.ypixel())
}

fn to_io(err: pty_process::Error) -> io::Error {
    io::Error::other(err)
}

impl Backend for Direct {
    type Shell = DirectShell;

    const SURVIVES_SERVER_RESTART: bool = false;

    async fn spawn(&self, _id: &SessionId, spec: SpawnSpec) -> io::Result<DirectShell> {
        let (pty, pts) = pty_process::open().map_err(to_io)?;
        pty.resize(to_size(spec.size)).map_err(to_io)?;
        let mut command = pty_process::Command::new(&spec.program)
            .args(&spec.args)
            .env_clear()
            .envs(spec.env.iter().map(|(k, v)| (k, v)))
            .kill_on_drop(true);
        if let Some(cwd) = &spec.cwd {
            command = command.current_dir(cwd);
        }
        let child = command.spawn(pts).map_err(to_io)?;
        Ok(DirectShell { pty, child })
    }

    async fn attach(&self, _id: &SessionId) -> io::Result<Option<DirectShell>> {
        Ok(None)
    }
}

impl Shell for DirectShell {
    type Reader = pty_process::OwnedReadPty;
    type Writer = DirectWriter;

    fn split(self) -> Parts<Self::Reader, Self::Writer> {
        let (reader, writer) = self.pty.into_split();
        let mut child = self.child;
        Parts {
            reader,
            writer: DirectWriter(writer),
            exit: Box::pin(async move { child.wait().await }),
        }
    }
}

impl ShellWriter for DirectWriter {
    fn resize(&self, size: WindowSize) -> io::Result<()> {
        self.0.resize(to_size(size)).map_err(to_io)
    }
}

impl AsyncWrite for DirectWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use rustix::termios::Winsize;

    use super::*;

    #[test]
    fn the_pixel_size_reaches_the_terminal_of_the_shell() {
        let size = WindowSize::new(57, 94).unwrap().with_pixels(752, 913);
        let winsize = Winsize::from(to_size(size));
        assert_eq!(
            (
                winsize.ws_row,
                winsize.ws_col,
                winsize.ws_xpixel,
                winsize.ws_ypixel
            ),
            (57, 94, 752, 913)
        );
    }
}
