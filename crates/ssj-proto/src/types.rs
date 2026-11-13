//! Small validated types of the protocol: window size, session id, and session name.

use serde::{Deserialize, Serialize};

/// Terminal dimensions in character cells, always between 1 and [`WindowSize::MAX`], and the size
/// of the terminal in pixels (0 if the terminal does not tell).
///
/// The pixel size lets programs on the host find the size of a cell, as they do over `ssh`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "(u16, u16, u16, u16)", into = "(u16, u16, u16, u16)")]
pub struct WindowSize {
    rows: u16,
    cols: u16,
    xpixel: u16,
    ypixel: u16,
}

impl WindowSize {
    /// Largest number of rows or columns.
    pub const MAX: u16 = 4096;

    /// Returns `None` if a dimension is zero or larger than [`WindowSize::MAX`]. The pixel size is
    /// unknown (0).
    pub fn new(rows: u16, cols: u16) -> Option<Self> {
        let valid = 1..=Self::MAX;
        (valid.contains(&rows) && valid.contains(&cols)).then_some(Self {
            rows,
            cols,
            xpixel: 0,
            ypixel: 0,
        })
    }

    /// Returns the size with the given size of the terminal in pixels.
    pub fn with_pixels(self, xpixel: u16, ypixel: u16) -> Self {
        Self {
            xpixel,
            ypixel,
            ..self
        }
    }

    pub fn rows(self) -> u16 {
        self.rows
    }

    pub fn cols(self) -> u16 {
        self.cols
    }

    /// Width of the terminal in pixels, or 0 if unknown.
    pub fn xpixel(self) -> u16 {
        self.xpixel
    }

    /// Height of the terminal in pixels, or 0 if unknown.
    pub fn ypixel(self) -> u16 {
        self.ypixel
    }
}

impl TryFrom<(u16, u16, u16, u16)> for WindowSize {
    type Error = &'static str;

    fn try_from((rows, cols, xpixel, ypixel): (u16, u16, u16, u16)) -> Result<Self, &'static str> {
        Self::new(rows, cols)
            .map(|size| size.with_pixels(xpixel, ypixel))
            .ok_or("a window size out of range")
    }
}

impl From<WindowSize> for (u16, u16, u16, u16) {
    fn from(size: WindowSize) -> Self {
        (size.rows, size.cols, size.xpixel, size.ypixel)
    }
}

/// Name that a user gives to a session, to find it again.
///
/// It appears in file names, commands, and lists, so only a few characters are allowed.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SessionName(String);

impl SessionName {
    /// Longest session name, in characters.
    pub const MAX_LEN: usize = 32;

    /// Accepts 1 to 32 characters of `A-Z a-z 0-9 . _ -`, not starting with `.` or `-`.
    pub fn parse(name: &str) -> Option<Self> {
        let valid = (1..=Self::MAX_LEN).contains(&name.len())
            && !name.starts_with(['.', '-'])
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        valid.then(|| Self(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether `text` can name a session, as an id or as a name.
pub fn is_selector(text: &str) -> bool {
    SessionId::parse(text).is_some() || SessionName::parse(text).is_some()
}

/// Identifier of a session, restricted to characters that are safe in file names and commands.
///
/// It names control sockets and multiplexer sessions, so it must never contain path separators,
/// dots, whitespace, or option prefixes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(String);

impl SessionId {
    const MIN_LEN: usize = 8;
    const MAX_LEN: usize = 64;

    /// Accepts lowercase ASCII letters and digits, between 8 and 64 characters.
    pub fn parse(id: &str) -> Option<Self> {
        let valid = (Self::MIN_LEN..=Self::MAX_LEN).contains(&id.len())
            && id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        valid.then(|| Self(id.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
