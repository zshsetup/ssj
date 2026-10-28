//! Fetching the server file from the release, over HTTPS.

use std::time::Duration;

use crate::cli::Args;
use crate::install::{MAX_BINARY, Target, sha256_hex};
use crate::vlog;

/// Time for a whole download.
const TIMEOUT: Duration = Duration::from_secs(180);
/// Largest list of checksums.
const MAX_SUMS: u64 = 1024 * 1024;
/// Name of the file with the checksums in a release.
const SUMS_FILE: &str = "SHA256SUMS";

/// The directory of the release files: the one given, else the one of this version in the
/// repository of the package.
pub fn base_url(args: &Args) -> Result<String, String> {
    let base = match &args.download_url {
        Some(url) => url.clone(),
        None => {
            let repository = env!("CARGO_PKG_REPOSITORY");
            if repository.is_empty() {
                return Err(
                    "this build does not know where the releases are; give --download-url"
                        .to_owned(),
                );
            }
            format!(
                "{}/releases/download/v{}",
                repository.trim_end_matches('/'),
                env!("CARGO_PKG_VERSION")
            )
        }
    };
    if !base.starts_with("https://") {
        return Err("the download address must start with https://".to_owned());
    }
    Ok(base.trim_end_matches('/').to_owned())
}

/// The digest listed for `name` in the text of a `SHA256SUMS` file (`<hex>  <name>` per line).
pub fn digest_for(sums: &str, name: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let (digest, file) = line.split_once(char::is_whitespace)?;
        let file = file.trim_start().trim_start_matches('*');
        let valid = digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit());
        (valid && file == name).then(|| digest.to_ascii_lowercase())
    })
}

/// Downloads `url` into memory, refusing anything larger than `limit` bytes. Blocking.
fn fetch(url: &str, limit: u64) -> Result<Vec<u8>, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .timeout_global(Some(TIMEOUT))
        .build()
        .into();
    let mut response = agent
        .get(url)
        .call()
        .map_err(|e| format!("cannot download {url}: {e}"))?;
    response
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .map_err(|e| format!("cannot download {url}: {e}"))
}

/// The name of the server file for `target` in a release.
pub fn file_name(target: Target) -> String {
    format!("ssj-server-{}", target.triple())
}

/// The digest that the checksums of the release list for the server file of `target`. Only the
/// small list is downloaded.
pub async fn release_digest(args: &Args, target: Target) -> Result<String, String> {
    let sums_url = format!("{}/{SUMS_FILE}", base_url(args)?);
    vlog!(1, "checksums from {sums_url}");
    let sums = tokio::task::spawn_blocking(move || fetch(&sums_url, MAX_SUMS))
        .await
        .map_err(|e| format!("the download failed: {e}"))??;
    let name = file_name(target);
    digest_for(&String::from_utf8_lossy(&sums), &name)
        .ok_or_else(|| format!("{SUMS_FILE} of the release has no entry for {name}"))
}

/// Downloads the server file for `target` and checks it against `wanted`, its digest from the
/// checksums of the release.
pub async fn server_file(args: &Args, target: Target, wanted: &str) -> Result<Vec<u8>, String> {
    let name = file_name(target);
    let file_url = format!("{}/{name}", base_url(args)?);
    eprintln!("ssj: downloading {file_url}");
    let binary = tokio::task::spawn_blocking(move || fetch(&file_url, MAX_BINARY))
        .await
        .map_err(|e| format!("the download failed: {e}"))??;
    if binary.is_empty() || sha256_hex(&binary) != wanted {
        return Err(format!(
            "the downloaded {name} does not match {SUMS_FILE} of the release"
        ));
    }
    Ok(binary)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn the_digest_of_a_file_is_found_in_the_list() {
        let sums = format!("{HASH}  ssj-server-x\n{}  other\n", HASH.replace('0', "1"));
        assert_eq!(digest_for(&sums, "ssj-server-x").as_deref(), Some(HASH));
        assert_eq!(
            digest_for(&format!("{HASH} *ssj-server-x"), "ssj-server-x").as_deref(),
            Some(HASH)
        );
        assert_eq!(digest_for(&sums, "ssj-server"), None);
        assert_eq!(digest_for("short  ssj-server-x", "ssj-server-x"), None);
        assert_eq!(digest_for("", "ssj-server-x"), None);
    }

    fn args(url: Option<&str>) -> Args {
        let mut args = crate::cli::parse(["connect", "host"].map(String::from)).unwrap();
        args.download_url = url.map(str::to_owned);
        args
    }

    #[test]
    fn only_https_addresses_are_taken_and_a_slash_at_the_end_is_dropped() {
        assert_eq!(
            base_url(&args(Some("https://example.org/r/v1/"))).unwrap(),
            "https://example.org/r/v1"
        );
        assert!(base_url(&args(Some("http://example.org/r"))).is_err());
        assert!(base_url(&args(Some("ftp://example.org/r"))).is_err());
        assert!(base_url(&args(Some("file:///tmp"))).is_err());
        // no repository is known to this build, so there is no default.
        if env!("CARGO_PKG_REPOSITORY").is_empty() {
            assert!(
                base_url(&args(None))
                    .unwrap_err()
                    .contains("--download-url")
            );
        }
    }
}
