//! `wingsvd status` / `wingsvd stop` - the shell face of the daemon.
//!
//! KernelSU's web ui can only run shell commands, so it cannot speak protobuf over the
//! socket itself. These subcommands connect to the daemon exactly like the app does and
//! print JSON, which the page renders. They are a client, not a second server: the
//! running daemon stays the only thing that owns any state.

use crate::rootd::client_envelope::Command as ClientCommand;
use crate::rootd::daemon_envelope::Frame;
use crate::rootd::reply_frame::Payload;
use crate::rootd::{
    ClearRoutingCommand, ClientEnvelope, DaemonEnvelope, SessionState, SessionStateCommand,
};
use crate::wire;
use crate::SOCKET_NAME;
use prost::Message;
#[cfg(target_os = "android")]
use std::os::android::net::SocketAddrExt;
#[cfg(target_os = "linux")]
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixStream};

pub fn run(command: &str) -> i32 {
    match command {
        "status" => match session_state() {
            Ok(state) => {
                println!("{}", state_json(&state));
                0
            }
            Err(error) => {
                // Still JSON: the web ui has one parser, and "the daemon is down" is a
                // status worth rendering rather than an error to swallow.
                println!("{{\"running\":false,\"error\":{}}}", quote(&error));
                1
            }
        },
        "stop" => match clear_routing() {
            Ok(()) => {
                println!("{{\"ok\":true}}");
                0
            }
            Err(error) => {
                println!("{{\"ok\":false,\"error\":{}}}", quote(&error));
                1
            }
        },
        other => {
            eprintln!("usage: wingsvd [status|stop]   (no arguments runs the daemon)");
            let _ = other;
            2
        }
    }
}

fn connect() -> Result<UnixStream, String> {
    let addr = SocketAddr::from_abstract_name(SOCKET_NAME)
        .map_err(|error| format!("abstract name: {error}"))?;
    UnixStream::connect_addr(&addr).map_err(|error| format!("daemon not running: {error}"))
}

fn call(command: ClientCommand) -> Result<Payload, String> {
    let stream = connect()?;
    let request = ClientEnvelope {
        call_id: 1,
        command: Some(command),
    };
    wire::write_frame(&stream, &request.encode_to_vec()).map_err(|e| format!("write: {e}"))?;
    let body = wire::read_frame(&stream)
        .map_err(|e| format!("read: {e}"))?
        .ok_or_else(|| "daemon closed the connection".to_string())?;
    let response = DaemonEnvelope::decode(body.as_slice()).map_err(|e| format!("decode: {e}"))?;
    match response.frame {
        Some(Frame::Reply(reply)) => reply.payload.ok_or_else(|| "empty reply".to_string()),
        Some(Frame::Error(error)) => Err(error.message),
        None => Err("empty frame".to_string()),
    }
}

fn session_state() -> Result<SessionState, String> {
    match call(ClientCommand::SessionState(SessionStateCommand {}))? {
        Payload::SessionState(state) => Ok(state),
        _ => Err("unexpected reply".to_string()),
    }
}

fn clear_routing() -> Result<(), String> {
    match call(ClientCommand::ClearRouting(ClearRoutingCommand {}))? {
        Payload::Ack(_) => Ok(()),
        _ => Err("unexpected reply".to_string()),
    }
}

fn state_json(state: &SessionState) -> String {
    let children: Vec<String> = state
        .children
        .iter()
        .map(|child| {
            format!(
                "{{\"kind\":{},\"pid\":{},\"running\":{}}}",
                child.kind, child.pid, child.running
            )
        })
        .collect();
    format!(
        "{{\"running\":true,\"version\":{},\"tunnel\":{},\"orphaned\":{},\"app_connected\":{},\"tunnel_name\":{},\"tproxy_bytes\":{},\"children\":[{}]}}",
        quote(env!("CARGO_PKG_VERSION")),
        state.routing_active,
        state.orphaned,
        state.app_connected,
        quote(&state.tunnel_name),
        state.tproxy_mark_bytes,
        children.join(",")
    )
}

/// Minimal JSON string escaping - enough for versions, tunnel names and error text,
/// and worth doing by hand rather than linking a json crate into a root daemon.
fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
