//! wingsvd - the optional WINGS V root helper.
//!
//! It exists because kernel routing state must not be owned by a process Android is
//! free to kill. The app's teardown runs under a foreground-service contract and the
//! low-memory killer; when it loses that race the ip rules survive their tunnel and
//! take the device's connectivity with them. Here the same work is owned by a daemon
//! init supervises, so no Android lifecycle rule applies to it.
//!
//! Security model, in one place:
//!   * the socket lives in the abstract namespace, so any process may *reach* it;
//!   * therefore every connection is authenticated by SO_PEERCRED against the app's
//!     uid, which the kernel fills in and a caller cannot forge;
//!   * the uid is resolved per connection from the package database, because it
//!     changes whenever the app is reinstalled;
//!   * root is accepted too - that is the module's own web ui and CLI talking to us,
//!     and a uid that can already rewrite our binary gains nothing from the socket;
//!   * the daemon never runs a string it was handed: routing is rebuilt from a typed
//!     spec, and only binaries inside the app's native library dir may be exec'd.

/// Writes one line to stderr (kept for service.sh's `| log -t wingsvd` pipe) and to
/// the rotating file log. In scope for the whole daemon module below.
macro_rules! logln {
    ($($arg:tt)*) => {{
        let __line = format!($($arg)*);
        eprintln!("{__line}");
        crate::log::write(&__line);
    }};
}

mod children;
mod cli;
mod log;
mod packages;
mod routing;
mod wire;

pub mod rootd {
    include!(concat!(env!("OUT_DIR"), "/wingsv.rootd.rs"));
}

use children::Children;
use prost::Message;
use rootd::client_envelope::Command as ClientCommand;
use rootd::daemon_envelope::Frame;
use rootd::reply_frame::Payload;
use rootd::{
    Ack, ClientEnvelope, Counters, DaemonEnvelope, ErrorFrame, HelloReply, NetDev, ReplyFrame,
    RoutingSpec, SessionState,
};
use std::io;
use std::sync::{Arc, Mutex};
use std::thread;
// std gates the abstract-socket extension on target_os, so the same trait lives under
// two names even though the kernel behaviour is identical. The daemon only ever ships
// for Android; the linux arm exists so it still builds - and so clippy still runs - on
// a development host.
#[cfg(target_os = "android")]
use std::os::android::net::SocketAddrExt;
#[cfg(target_os = "linux")]
use std::os::linux::net::SocketAddrExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};

pub const SOCKET_NAME: &str = "wings.v.rootd";
const APP_PACKAGE: &str = "wings.v";
// 2 adds the read_net_dev command (the "netdev" cap). Additive, so MIN_SUPPORTED
// stays at 1: an older app that never sends read_net_dev still works unchanged.
const PROTOCOL_VERSION: u32 = 2;
/// Oldest client we still speak to. Moves only when semantics change, never when a
/// field is added.
const MIN_SUPPORTED: u32 = 1;
const MODULE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// What the daemon believes it installed. Survives the client that asked for it: an
/// app that disappears is almost always the low-memory killer rather than a user who
/// wanted the tunnel down, so the session is kept and marked orphaned instead of being
/// torn down under them.
#[derive(Default)]
struct Session {
    spec: Option<RoutingSpec>,
    orphaned: bool,
    children: Children,
    /// How many app-uid clients are connected. The web ui shows "app connected"
    /// separately from "routing active", because the two really do come apart.
    app_clients: u32,
}

fn main() {
    // `wingsvd status` / `wingsvd stop` are the module's web ui talking to a daemon
    // that is already running; only a bare `wingsvd` is the daemon itself.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(command) = args.first() {
        std::process::exit(cli::run(command));
    }

    // Daemon path only (never the short-lived status/stop CLI, which polls): open
    // the rotating file log before anything else can fail.
    log::init();

    let addr = match SocketAddr::from_abstract_name(SOCKET_NAME) {
        Ok(addr) => addr,
        Err(error) => {
            logln!("wingsvd: abstract name {SOCKET_NAME}: {error}");
            std::process::exit(1);
        }
    };
    let listener = match UnixListener::bind_addr(&addr) {
        Ok(listener) => listener,
        Err(error) => {
            // Another instance already holds the name; the module's service.sh restarts
            // us, so exiting is the right move rather than fighting over it.
            logln!("wingsvd: bind @{SOCKET_NAME}: {error}");
            std::process::exit(1);
        }
    };
    logln!("wingsvd {MODULE_VERSION} listening on @{SOCKET_NAME}");

    // A thread per client, not a serial loop: the app holds its connection open for the
    // life of the tunnel, so anything serial would leave the web ui waiting forever for
    // a turn that never comes. The lock is taken per request, never across a read.
    let session = Arc::new(Mutex::new(Session::default()));
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let session = Arc::clone(&session);
                thread::spawn(move || serve(stream, &session));
            }
            Err(error) => logln!("wingsvd: accept: {error}"),
        }
    }
}

/// Serves one client to completion.
fn serve(stream: UnixStream, session: &Mutex<Session>) {
    let uid = match peer_uid(&stream) {
        Ok(uid) => uid,
        Err(error) => {
            logln!("wingsvd: SO_PEERCRED failed, dropping connection: {error}");
            return;
        }
    };
    let app_uid = packages::app_uid(APP_PACKAGE);
    let is_app = Some(uid) == app_uid;
    // Root is the module's own web ui / CLI. It could edit our files anyway, so the
    // socket is not what keeps it out; everyone else is refused.
    if !is_app && uid != 0 {
        logln!("wingsvd: rejected uid={uid} (app is {app_uid:?})");
        return;
    }

    if is_app {
        let mut session = session.lock().unwrap();
        session.app_clients += 1;
        if session.spec.is_some() {
            // The app is back for a session that outlived it.
            session.orphaned = false;
        }
    }

    loop {
        let request = match wire::read_frame(&stream) {
            Ok(Some(bytes)) => bytes,
            // EOF. The routing deliberately stays up; only an explicit clear, or a
            // returning app that decides otherwise, takes it down.
            Ok(None) => break,
            Err(error) => {
                logln!("wingsvd: read: {error}");
                break;
            }
        };
        let envelope = match ClientEnvelope::decode(request.as_slice()) {
            Ok(envelope) => envelope,
            Err(error) => {
                logln!("wingsvd: malformed envelope: {error}");
                break;
            }
        };
        let call_id = envelope.call_id;
        let frame = match dispatch(envelope, session) {
            Ok(payload) => Frame::Reply(ReplyFrame {
                payload: Some(payload),
            }),
            Err(message) => Frame::Error(ErrorFrame { message }),
        };
        let response = DaemonEnvelope {
            call_id,
            frame: Some(frame),
        };
        if let Err(error) = wire::write_frame(&stream, &response.encode_to_vec()) {
            logln!("wingsvd: write: {error}");
            break;
        }
    }

    if !is_app {
        return;
    }
    let mut session = session.lock().unwrap();
    session.app_clients = session.app_clients.saturating_sub(1);
    if session.app_clients == 0 && session.spec.is_some() {
        session.orphaned = true;
        logln!("wingsvd: app gone, keeping the session (orphaned)");
    }
}

fn dispatch(envelope: ClientEnvelope, session: &Mutex<Session>) -> Result<Payload, String> {
    // Locked per request rather than for the life of the connection: the app keeps its
    // connection open indefinitely, and holding the lock that long would block the web
    // ui from ever reading the status.
    let session = &mut *session.lock().unwrap();
    let command = envelope
        .command
        .ok_or_else(|| "empty command".to_string())?;
    match command {
        ClientCommand::Hello(hello) => {
            // Answer even when the versions disagree: the client needs our numbers to
            // tell the user which side is behind.
            logln!(
                "wingsvd: hello from app {} (protocol {})",
                hello.app_version,
                hello.protocol_version
            );
            Ok(Payload::Hello(HelloReply {
                protocol_version: PROTOCOL_VERSION,
                min_supported: MIN_SUPPORTED,
                module_version: MODULE_VERSION.to_string(),
                caps: vec![
                    "routing".to_string(),
                    "children".to_string(),
                    "counters".to_string(),
                    "netdev".to_string(),
                ],
            }))
        }
        ClientCommand::ApplyRouting(command) => {
            let spec = command
                .spec
                .ok_or_else(|| "apply_routing without a spec".to_string())?;
            routing::apply(&spec)?;
            logln!("apply_routing ok");
            session.spec = Some(spec);
            session.orphaned = false;
            Ok(Payload::Ack(Ack {}))
        }
        ClientCommand::ClearRouting(_) => {
            if let Some(spec) = session.spec.take() {
                routing::clear(&spec);
            }
            session.children.kill_all();
            session.orphaned = false;
            logln!("clear_routing ok");
            Ok(Payload::Ack(Ack {}))
        }
        ClientCommand::SessionState(_) => {
            let tproxy_mark_bytes = session
                .spec
                .as_ref()
                .and_then(|spec| spec.tproxy.as_ref())
                .map(|tproxy| routing::read_tproxy_mark_bytes(&tproxy.mark_chains))
                .unwrap_or(0);
            Ok(Payload::SessionState(SessionState {
                routing_active: session.spec.is_some(),
                orphaned: session.orphaned,
                tunnel_name: session
                    .spec
                    .as_ref()
                    .map(|spec| spec.tunnel_name.clone())
                    .unwrap_or_default(),
                children: session.children.snapshot(),
                app_connected: session.app_clients > 0,
                tproxy_mark_bytes,
            }))
        }
        ClientCommand::SpawnChild(command) => {
            let handle = session.children.spawn(&command)?;
            Ok(Payload::Child(handle))
        }
        ClientCommand::KillChild(command) => {
            session.children.kill(command.child_id)?;
            Ok(Payload::Ack(Ack {}))
        }
        ClientCommand::ReadCounters(_) => {
            let spec = session
                .spec
                .as_ref()
                .ok_or_else(|| "no active session".to_string())?;
            let tproxy_mark_bytes = match &spec.tproxy {
                Some(tproxy) => routing::read_tproxy_mark_bytes(&tproxy.mark_chains),
                None => 0,
            };
            Ok(Payload::Counters(Counters { tproxy_mark_bytes }))
        }
        ClientCommand::ReadNetDev(_) => {
            // The app is denied this read from its own untrusted_app context on
            // Android 16; we are in a permitted one, so read it and hand back the raw
            // text for the app to parse.
            let content = std::fs::read_to_string("/proc/net/dev")
                .map_err(|error| format!("read /proc/net/dev: {error}"))?;
            Ok(Payload::NetDev(NetDev { content }))
        }
    }
}

/// The kernel fills these in on the socket, so a client cannot lie about who it is.
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid)
}
