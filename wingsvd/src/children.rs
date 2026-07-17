//! Runs xray / vk-turn-proxy as children of the daemon rather than of the app.
//!
//! The point is ownership: children re-parented here keep running when the app dies
//! (which is the whole reason the session survives an LMK kill), and they are reaped
//! deterministically on teardown instead of being hunted down by scanning /proc for a
//! cmdline, which is what the app has to do today.

use crate::rootd::{ChildHandle, ChildKind, SpawnChildCommand};
use std::collections::HashMap;
use std::path::Path;
use std::process::{Child, Command, Stdio};

#[derive(Default)]
pub struct Children {
    next_id: u64,
    running: HashMap<u64, Entry>,
}

struct Entry {
    kind: i32,
    child: Child,
}

/// Entry point the app_process children are started on. Pinned here rather than taken
/// from the request: the class name is what decides which code runs as root, so letting
/// a client choose it would turn the daemon into a general-purpose root exec for anyone
/// who got past the uid check.
const ENTRY_CLASS: &str = "wings.v.root.RootCommandMain";

/// The uid check on the socket is the trust boundary, but it should not be the only
/// thing standing between a client and root exec: a binary is only startable if it
/// lives in the app's extracted native library directory, which nothing but the
/// package manager can write.
fn is_allowed_binary(path: &str) -> bool {
    let path = Path::new(path);
    if !path.is_absolute() || !path.is_file() {
        return false;
    }
    // Reject symlinks and .. games by resolving first.
    let resolved = match path.canonicalize() {
        Ok(resolved) => resolved,
        Err(_) => return false,
    };
    let text = resolved.to_string_lossy();
    text.starts_with("/data/app/") && text.contains("/lib/")
}

/// Same rule for the apk and the library dir handed to app_process: only what the
/// package manager installed, never a path the client invented.
fn is_app_owned(path: &str) -> bool {
    let path = Path::new(path);
    if !path.is_absolute() || !path.exists() {
        return false;
    }
    match path.canonicalize() {
        Ok(resolved) => resolved.to_string_lossy().starts_with("/data/app/"),
        Err(_) => false,
    }
}

/// app_process for this device's bitness. The 64-bit one exists only on 64-bit
/// devices, so fall back rather than assume.
fn app_process() -> &'static str {
    if Path::new("/system/bin/app_process64").is_file() {
        "/system/bin/app_process64"
    } else {
        "/system/bin/app_process"
    }
}

impl Children {
    pub fn spawn(&mut self, request: &SpawnChildCommand) -> Result<ChildHandle, String> {
        let kind = request.kind;
        let mut command = if kind == ChildKind::Byedpi as i32 || kind == ChildKind::Xray as i32 {
            self.app_process_command(request)?
        } else if kind == ChildKind::Vkturn as i32 {
            if !is_allowed_binary(&request.binary_path) {
                return Err(format!(
                    "refusing to exec {}: not an app native library",
                    request.binary_path
                ));
            }
            let mut command = Command::new(&request.binary_path);
            command.args(&request.args);
            command
        } else {
            return Err("child kind not set".to_string());
        };
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if !request.working_dir.is_empty() {
            command.current_dir(&request.working_dir);
        }
        let child = command
            .spawn()
            .map_err(|error| format!("spawn kind {kind}: {error}"))?;
        let pid = child.id() as i32;
        self.next_id += 1;
        let child_id = self.next_id;
        self.running.insert(child_id, Entry { kind, child });
        Ok(ChildHandle {
            kind,
            child_id,
            pid,
            running: true,
        })
    }

    /// Builds the app_process invocation for the kinds that are Java entry points
    /// rather than executables. The client supplies only paths the package manager
    /// owns and the arguments for the proxy itself; the entry class and subcommand are
    /// ours.
    fn app_process_command(&self, request: &SpawnChildCommand) -> Result<Command, String> {
        if !is_app_owned(&request.classpath) {
            return Err(format!(
                "refusing classpath {}: not an installed apk",
                request.classpath
            ));
        }
        if !is_app_owned(&request.lib_dir) {
            return Err(format!(
                "refusing lib dir {}: not an app library dir",
                request.lib_dir
            ));
        }
        let subcommand = if request.kind == ChildKind::Byedpi as i32 {
            "byedpi"
        } else {
            "xray-tproxy"
        };
        let mut command = Command::new(app_process());
        command
            .env("CLASSPATH", &request.classpath)
            .arg("/system/bin")
            .arg(ENTRY_CLASS)
            .arg(subcommand)
            .arg("--lib-dir")
            .arg(&request.lib_dir);
        if request.kind == ChildKind::Byedpi as i32 {
            // Everything after "--" is the proxy's own command line.
            command.arg("--");
        }
        command.args(&request.args);
        Ok(command)
    }

    pub fn kill(&mut self, child_id: u64) -> Result<(), String> {
        match self.running.remove(&child_id) {
            // Already gone is the outcome the caller wanted, not an error.
            None => Ok(()),
            Some(mut entry) => {
                let _ = entry.child.kill();
                let _ = entry.child.wait();
                Ok(())
            }
        }
    }

    pub fn kill_all(&mut self) {
        let ids: Vec<u64> = self.running.keys().copied().collect();
        for id in ids {
            let _ = self.kill(id);
        }
    }

    /// Handles for the session state, reaping any child that exited on its own so the
    /// app is not told something is running when it is not.
    pub fn snapshot(&mut self) -> Vec<ChildHandle> {
        let mut handles = Vec::new();
        let mut dead = Vec::new();
        for (id, entry) in self.running.iter_mut() {
            let running = matches!(entry.child.try_wait(), Ok(None));
            if !running {
                dead.push(*id);
            }
            handles.push(ChildHandle {
                kind: entry.kind,
                child_id: *id,
                pid: entry.child.id() as i32,
                running,
            });
        }
        for id in dead {
            self.running.remove(&id);
        }
        handles
    }
}
