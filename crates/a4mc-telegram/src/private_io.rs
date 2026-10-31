//! Minimal bounded private file IO for channel state.
//!
//! Local equivalents of the helpers the binding store needs — nothing
//! more. Unix marks state directories `0700` and state/lock files
//! `0600`; other platforms get plain create/write, where OS-level access
//! control remains the composing host's responsibility.

use anyhow::{Result, anyhow};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

/// Create the directory (and parents) owner-only on Unix.
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|_| anyhow!("a4mc_telegram_state_dir_failed"))?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| anyhow!("a4mc_telegram_state_dir_mode_failed"))?;
    Ok(())
}

/// Replace `path` atomically with `text`: write a sibling temp file
/// owner-only, then rename so readers never see a partial document.
pub fn atomic_write_private_text(path: &Path, text: &str) -> Result<()> {
    let tmp = temp_sibling(path);
    {
        let mut file = private_options()
            .open(&tmp)
            .map_err(|_| anyhow!("a4mc_telegram_state_write_failed"))?;
        file.write_all(text.as_bytes())
            .map_err(|_| anyhow!("a4mc_telegram_state_write_failed"))?;
        file.sync_all()
            .map_err(|_| anyhow!("a4mc_telegram_state_write_failed"))?;
    }
    fs::rename(&tmp, path).map_err(|_| anyhow!("a4mc_telegram_state_write_failed"))?;
    Ok(())
}

/// Read a small state file. `Ok(None)` means absent; oversize or invalid
/// UTF-8 is an error, never a silent truncate.
pub fn read_private_text_bounded(path: &Path, max_bytes: usize) -> Result<Option<String>> {
    match fs::metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(anyhow!("a4mc_telegram_state_read_failed")),
        Ok(metadata) if metadata.len() > max_bytes as u64 => {
            return Err(anyhow!("a4mc_telegram_state_oversize"));
        }
        Ok(_) => {}
    }
    let bytes = fs::read(path).map_err(|_| anyhow!("a4mc_telegram_state_read_failed"))?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| anyhow!("a4mc_telegram_state_invalid"))
}

/// Open (creating if needed) the advisory-lock file for a state file.
pub fn open_private_lock_file(path: &Path) -> Result<File> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    private_options()
        .read(true)
        .open(path)
        .map_err(|_| anyhow!("a4mc_telegram_state_lock_open_failed"))
}

fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    options
}

fn temp_sibling(path: &Path) -> PathBuf {
    // pid alone collides for concurrent writes inside one process; the
    // counter keeps each in-flight temp file distinct.
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut name = path
        .file_name()
        .map(|value| value.to_os_string())
        .unwrap_or_else(|| "state.tmp".into());
    name.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn temp_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "a4mc-tg-io-{}-{}-{tag}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn atomic_write_and_bounded_read_roundtrip() {
        let root = temp_root("rw");
        let path = root.join("state.json");
        atomic_write_private_text(&path, "{\"ok\":true}").unwrap();
        assert_eq!(
            read_private_text_bounded(&path, 128).unwrap().as_deref(),
            Some("{\"ok\":true}")
        );
        assert!(read_private_text_bounded(&path, 4).is_err());
        assert!(
            read_private_text_bounded(&root.join("absent"), 128)
                .unwrap()
                .is_none()
        );
        let _ = fs::remove_dir_all(root);
    }
}
