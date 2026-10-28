//! Putting the server on a host: finding the right file, uploading it, and deciding when to.

use std::io::IsTerminal;

use sha2::{Digest, Sha256};
use ssj_proto::bootstrap::sanitize;

use crate::bootstrap::{run_remote_command, sh_command};
use crate::cli::Args;
use crate::config::AutoInstall;
use crate::terminal::ask;
use crate::vlog;

/// Largest server file the client uploads.
pub const MAX_BINARY: u64 = 64 * 1024 * 1024;

/// The oldest glibc that the `gnu` builds run on (they are linked against it by `zig`).
pub const MIN_GLIBC: (u32, u32) = (2, 17);

/// Systems that have a server build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    LinuxX86_64,
    LinuxAarch64,
    /// A Linux host with a glibc that the `gnu` build runs on.
    LinuxX86_64Gnu,
    LinuxAarch64Gnu,
    MacArm64,
}

impl Target {
    /// Name of the build. The `gnu` build is for hosts with a glibc of [`MIN_GLIBC`] or newer, and
    /// the static `musl` build runs on any other distribution.
    pub fn triple(self) -> &'static str {
        match self {
            Self::LinuxX86_64 => "x86_64-unknown-linux-musl",
            Self::LinuxAarch64 => "aarch64-unknown-linux-musl",
            Self::LinuxX86_64Gnu => "x86_64-unknown-linux-gnu",
            Self::LinuxAarch64Gnu => "aarch64-unknown-linux-gnu",
            Self::MacArm64 => "aarch64-apple-darwin",
        }
    }
}

/// The version in an answer of `getconf GNU_LIBC_VERSION`, such as `glibc 2.35`.
fn glibc_version(line: &[u8]) -> Option<(u32, u32)> {
    let text = std::str::from_utf8(line).ok()?;
    let version = text.trim().strip_prefix("glibc ")?;
    let (major, rest) = version.split_once('.')?;
    let minor: String = rest.chars().take_while(char::is_ascii_digit).collect();
    Some((major.parse().ok()?, minor.parse().ok()?))
}

/// Reads the answer of the probe: `SSJ TARGET <os> <arch>` from `uname -sm`, which has to be in a
/// line of its own, and optionally `SSJ LIBC glibc <version>` from `getconf GNU_LIBC_VERSION`.
///
/// A Linux host with a glibc of [`MIN_GLIBC`] or newer gets the `gnu` build, and any other (musl,
/// no `getconf`, an older glibc) the static `musl` build.
pub fn parse_target(stdout: &[u8]) -> Result<Target, String> {
    let lines: Vec<&[u8]> = stdout
        .split(|b| *b == b'\n')
        .filter_map(|line| line.strip_prefix(b"SSJ TARGET "))
        .collect();
    let [system] = lines[..] else {
        return Err("the host did not report its system".to_owned());
    };
    let glibc = stdout
        .split(|b| *b == b'\n')
        .filter_map(|line| line.strip_prefix(b"SSJ LIBC "))
        .find_map(glibc_version)
        .is_some_and(|version| version >= MIN_GLIBC);
    match system {
        b"Linux x86_64" if glibc => Ok(Target::LinuxX86_64Gnu),
        b"Linux aarch64" if glibc => Ok(Target::LinuxAarch64Gnu),
        b"Linux x86_64" => Ok(Target::LinuxX86_64),
        b"Linux aarch64" => Ok(Target::LinuxAarch64),
        b"Darwin arm64" => Ok(Target::MacArm64),
        other => Err(format!(
            "there is no server for the system {:?}",
            sanitize(other, 60)
        )),
    }
}

/// Asks the host for its system and CPU, and returns the matching release target.
pub async fn detect_target(args: &Args) -> Result<Target, String> {
    let command = sh_command(
        r#"printf 'SSJ TARGET %s\n' "$(uname -sm)"; printf 'SSJ LIBC %s\n' "$(getconf GNU_LIBC_VERSION 2>/dev/null)""#,
        &[],
    );
    let remote = run_remote_command(args, &command, Vec::new()).await?;
    if !remote.status.success() {
        return Err(format!(
            "could not ask the host for its system: {}",
            remote.error_text()
        ));
    }
    parse_target(&remote.stdout)
}

/// Returns the SHA-256 digest of `bytes` as lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Runs on the host. The first line of stdin is the expected SHA-256, the rest is the file.
///
/// The file is checked, tested, and moved into place only then, so that a broken upload never
/// replaces a working server.
const INSTALL_SCRIPT: &str = r#"set -e
umask 077
dir="${XDG_DATA_HOME:-$HOME/.local/share}/ssj/bin"
mkdir -p "$dir"
tmp="$dir/.ssj-server-p__PROTOCOL__.$$"
trap 'rm -f "$tmp"' EXIT
IFS= read -r want
cat > "$tmp"
if command -v sha256sum >/dev/null 2>&1; then
  got=$(sha256sum "$tmp" | cut -d' ' -f1)
elif command -v shasum >/dev/null 2>&1; then
  got=$(shasum -a 256 "$tmp" | cut -d' ' -f1)
else
  echo 'neither sha256sum nor shasum is available, so the upload cannot be verified' >&2
  exit 3
fi
if [ "$got" != "$want" ]; then
  echo 'the uploaded file does not match its digest' >&2
  exit 4
fi
chmod 700 "$tmp"
if ! "$tmp" --version >/dev/null 2>&1; then
  echo "the uploaded server cannot run in $dir (is it on a noexec mount?)" >&2
  exit 5
fi
was=$("$dir/ssj-server-p__PROTOCOL__" --version 2>/dev/null || true)
mv -f "$tmp" "$dir/ssj-server-p__PROTOCOL__"
trap - EXIT
if [ -n "$was" ]; then
  echo "SSJ REPLACED $was"
fi
echo "SSJ INSTALLED $dir/ssj-server-p__PROTOCOL__""#;

/// Runs on the host: says `SSJ HAVE <path>` if the installed file has the digest in `$1`.
const CHECK_SCRIPT: &str = r#"f="${XDG_DATA_HOME:-$HOME/.local/share}/ssj/bin/ssj-server-p__PROTOCOL__"
[ -f "$f" ] || exit 0
if command -v sha256sum >/dev/null 2>&1; then
  got=$(sha256sum "$f" | cut -d' ' -f1)
elif command -v shasum >/dev/null 2>&1; then
  got=$(shasum -a 256 "$f" | cut -d' ' -f1)
else
  exit 0
fi
[ "$got" = "$1" ] && echo "SSJ HAVE $f"
exit 0"#;

/// The path of the installed server file if the host has the file with `digest` already.
async fn installed_digest(args: &Args, digest: &str) -> Result<Option<String>, String> {
    let script = CHECK_SCRIPT.replace("__PROTOCOL__", &ssj_proto::PROTOCOL.to_string());
    let remote =
        run_remote_command(args, &sh_command(&script, &[digest.to_owned()]), Vec::new()).await?;
    Ok(remote
        .stdout
        .split(|b| *b == b'\n')
        .find_map(|line| line.strip_prefix(b"SSJ HAVE "))
        .map(|path| sanitize(path, 300)))
}

/// Uploads the server file for the host and returns the path it was installed at.
pub async fn install(args: &Args) -> Result<String, String> {
    // a wrong address is found before the host is asked for anything.
    if args.server_binary.is_none() {
        crate::download::base_url(args)?;
    }
    let target = detect_target(args).await?;
    vlog!(1, "the host runs {}", target.triple());
    // the file named by the user, or else the release of the same version. The digest is known
    // before anything is transferred, so a host that has the file already gets nothing.
    let (digest, local) = if let Some(file) = &args.server_binary {
        let size = std::fs::metadata(file)
            .map_err(|e| format!("cannot read {}: {e}", file.display()))?
            .len();
        if size == 0 || size > MAX_BINARY {
            return Err(format!(
                "{} has an implausible size of {size} bytes",
                file.display()
            ));
        }
        let bytes =
            std::fs::read(file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
        (sha256_hex(&bytes), Some(bytes))
    } else {
        (crate::download::release_digest(args, target).await?, None)
    };
    let script = INSTALL_SCRIPT.replace("__PROTOCOL__", &ssj_proto::PROTOCOL.to_string());
    if let Some(path) = installed_digest(args, &digest).await? {
        vlog!(1, "the host has the file already (SHA-256 {digest})");
        return Ok(format!("{path} (already up to date)"));
    }
    let binary = match local {
        Some(bytes) => bytes,
        None => {
            vlog!(1, "downloading the server file from the release");
            crate::download::server_file(args, target, &digest).await?
        }
    };
    vlog!(
        1,
        "uploading {} bytes of the server (SHA-256 {digest})",
        binary.len()
    );

    let mut stdin = format!("{digest}\n").into_bytes();
    stdin.extend_from_slice(&binary);
    let remote = run_remote_command(args, &sh_command(&script, &[]), stdin).await?;
    if !remote.status.success() {
        return Err(format!(
            "the installation failed ({}): {}",
            remote.status,
            remote.error_text()
        ));
    }
    let installed: Vec<&[u8]> = remote
        .stdout
        .split(|b| *b == b'\n')
        .filter_map(|line| line.strip_prefix(b"SSJ INSTALLED "))
        .collect();
    // an older file of the same protocol is replaced; the sessions that run keep their process.
    let replaced = remote
        .stdout
        .split(|b| *b == b'\n')
        .find_map(|line| line.strip_prefix(b"SSJ REPLACED "))
        .map(|was| sanitize(was, 100));
    match installed[..] {
        [path] => Ok(match replaced {
            Some(was) => format!("{} (replaced {was})", sanitize(path, 300)),
            None => sanitize(path, 300),
        }),
        _ => Err("the host did not confirm the installation".to_owned()),
    }
}

/// What to do about a missing server.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Install,
    /// Do not install, and say why and what to do instead.
    Skip(String),
}

/// Applies the policy. `ask` is only called when a person can be asked.
pub fn decide(
    policy: AutoInstall,
    destination: &str,
    interactive: bool,
    ask: impl FnOnce(&str) -> bool,
) -> Decision {
    let hint = format!("run `ssj install {destination}` to install it");
    match policy {
        AutoInstall::Always => Decision::Install,
        AutoInstall::Never => Decision::Skip(format!(
            "ssj-server is not installed on {destination}; {hint}"
        )),
        AutoInstall::Ask if !interactive => Decision::Skip(format!(
            "ssj-server is not installed on {destination}, and there is no terminal to ask; \
             {hint}, or use --install"
        )),
        AutoInstall::Ask => {
            let question = format!("ssj-server is not installed on {destination}. Install it now?");
            if ask(&question) {
                Decision::Install
            } else {
                Decision::Skip(format!("not installed; {hint}"))
            }
        }
    }
}

/// Whether a person can answer: both input and output are terminals.
pub fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

/// Asks on the terminal, with one key. Enter and `y` agree, as the capital in `[Y/n]` says. `n` and
/// Esc decline, and other keys are ignored. A missing terminal is no answer, which is no.
pub fn confirm(question: &str) -> bool {
    ask(dialoguer::Confirm::new()
        .with_prompt(question)
        .default(true)
        .interact_opt())
    .unwrap_or(false)
}
