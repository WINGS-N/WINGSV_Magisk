//! Minimal size-rotating file logger for wingsvd.
//!
//! No external crates on purpose: the daemon ships in the app's native library dir
//! and stays dependency-light. Lines still go to stderr too (the caller does that),
//! so service.sh's `2>&1 | log -t wingsvd` pipe keeps feeding logcat; this only adds
//! a persistent file in the daemon's own directory that rotates by size, so it can
//! never grow without bound on a device.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// The daemon's own directory. Always writable (on /data), created on init.
const LOG_DIR: &str = "/data/adb/wingsvd";
const LOG_PATH: &str = "/data/adb/wingsvd/wingsvd.log";
/// Rotate once the active file reaches this size (~256 KiB).
const MAX_BYTES: u64 = 256 * 1024;
/// How many rotated generations to keep: wingsvd.log.1 .. wingsvd.log.KEEP.
const KEEP: u32 = 3;

static FILE: Mutex<Option<File>> = Mutex::new(None);

/// Opens (or creates) the log file. Call once, from the daemon path only - the
/// short-lived `wingsvd status|stop` CLI polls often and must not churn the file.
pub fn init() {
    let _ = fs::create_dir_all(LOG_DIR);
    if let Ok(file) = OpenOptions::new().create(true).append(true).open(LOG_PATH) {
        if let Ok(mut guard) = FILE.lock() {
            *guard = Some(file);
        }
    }
}

/// Appends one epoch-prefixed line, rotating first when the file is full. A no-op
/// until init() has opened the file, and it never panics - logging must not be able
/// to take the daemon down.
pub fn write(msg: &str) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!("[{secs}] {msg}\n");

    let mut guard = match FILE.lock() {
        Ok(guard) => guard,
        Err(_) => return,
    };
    if guard.is_none() {
        return;
    }
    let too_big = guard
        .as_ref()
        .and_then(|f| f.metadata().ok())
        .map(|m| m.len())
        .unwrap_or(0)
        >= MAX_BYTES;
    if too_big {
        rotate();
        *guard = OpenOptions::new()
            .create(true)
            .append(true)
            .open(LOG_PATH)
            .ok();
    }
    if let Some(file) = guard.as_mut() {
        let _ = file.write_all(line.as_bytes());
    }
}

/// wingsvd.log -> .1, .1 -> .2, ... dropping the oldest generation.
fn rotate() {
    let _ = fs::remove_file(format!("{LOG_PATH}.{KEEP}"));
    for i in (1..KEEP).rev() {
        let from = format!("{LOG_PATH}.{i}");
        if Path::new(&from).exists() {
            let _ = fs::rename(&from, format!("{LOG_PATH}.{}", i + 1));
        }
    }
    let _ = fs::rename(LOG_PATH, format!("{LOG_PATH}.1"));
}
