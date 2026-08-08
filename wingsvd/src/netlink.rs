//! Watches the kernel for network changes and reads its routing table directly over a
//! NETLINK_ROUTE socket, so the daemon can keep an orphaned session's upstream mirror
//! pointed at the live physical default with no app alive to notice a handover.
//!
//! Routes and links are what netlink is for, so they are read and watched here instead
//! of by scraping the ip binary: structured attributes rather than parsed text, and a
//! table field on every route change so the daemon can ignore the churn it causes
//! itself. Applying state stays in routing.rs over ip/iptables - reimplementing
//! netfilter against the kernel is a different order of effort and buys nothing here.

use std::ffi::CStr;
use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr;

// NETLINK_ROUTE message types, flags and attributes. Defined here rather than pulled
// from libc so the daemon does not depend on which of these a given libc version exports.
const NETLINK_ROUTE: i32 = 0;
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x001;
const NLM_F_DUMP: u16 = 0x300;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_TABLE: u16 = 15;
const RT_TABLE_MAIN: u32 = 254;
// Multicast groups to listen on: link up/down, address add/remove, and route changes for
// both families. A handover shows up as some combination of these.
const RTMGRP_LINK: u32 = 0x1;
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
const RTMGRP_IPV4_ROUTE: u32 = 0x40;
const RTMGRP_IPV6_IFADDR: u32 = 0x100;
const RTMGRP_IPV6_ROUTE: u32 = 0x400;

const NLMSG_HDR_LEN: usize = mem::size_of::<NlMsgHdr>();
const RTATTR_HDR_LEN: usize = mem::size_of::<RtAttr>();

// The three kernel structs, read straight out of the byte stream. Several fields are
// never accessed - they exist so the ones that are sit at the right offset for the fixed
// C layout, which is the whole point of reading them as a struct.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct NlMsgHdr {
    len: u32,
    kind: u16,
    flags: u16,
    seq: u32,
    pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct RtMsg {
    family: u8,
    dst_len: u8,
    src_len: u8,
    tos: u8,
    table: u8,
    protocol: u8,
    scope: u8,
    kind: u8,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RtAttr {
    len: u16,
    kind: u16,
}

/// A netlink socket subscribed to the network-change multicast groups.
pub struct Monitor {
    fd: OwnedFd,
}

impl Monitor {
    pub fn open() -> io::Result<Self> {
        let groups = RTMGRP_LINK
            | RTMGRP_IPV4_IFADDR
            | RTMGRP_IPV4_ROUTE
            | RTMGRP_IPV6_IFADDR
            | RTMGRP_IPV6_ROUTE;
        Ok(Self {
            fd: open_route_socket(groups)?,
        })
    }

    /// Blocks until the kernel reports a change worth acting on. Route changes in
    /// ignore_tables are skipped: those are the tables the daemon writes itself, and
    /// reacting to its own reassert would loop forever.
    pub fn wait_for_change(&self, ignore_tables: &[u32]) -> io::Result<()> {
        let mut buf = [0u8; 8192];
        loop {
            let received = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                )
            };
            if received < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if received == 0 {
                continue;
            }
            if any_message_relevant(&buf[..received as usize], ignore_tables) {
                return Ok(());
            }
        }
    }
}

/// The default routes of the main table, each reduced to the form ip route add accepts
/// (default via GW dev IFACE metric N), read structurally so there is no dependence on
/// the ip binary's text output. Empty on any failure - a best-effort read for a
/// best-effort reassert.
pub fn default_routes(v6: bool) -> Vec<String> {
    let family = if v6 { libc::AF_INET6 } else { libc::AF_INET } as u8;
    dump_default_routes(family).unwrap_or_default()
}

fn open_route_socket(groups: u32) -> io::Result<OwnedFd> {
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_groups = groups;
    let bound = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if bound < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

fn any_message_relevant(mut data: &[u8], ignore_tables: &[u32]) -> bool {
    while data.len() >= NLMSG_HDR_LEN {
        let header: NlMsgHdr = unsafe { ptr::read_unaligned(data.as_ptr() as *const NlMsgHdr) };
        let len = header.len as usize;
        if len < NLMSG_HDR_LEN || len > data.len() {
            break;
        }
        let payload = &data[NLMSG_HDR_LEN..len];
        match header.kind {
            RTM_NEWLINK | RTM_DELLINK | RTM_NEWADDR | RTM_DELADDR => return true,
            RTM_NEWROUTE | RTM_DELROUTE
                if default_route_change_is_watched(payload, ignore_tables) =>
            {
                return true;
            }
            _ => {}
        }
        let step = len.next_multiple_of(4);
        if step == 0 || step > data.len() {
            break;
        }
        data = &data[step..];
    }
    false
}

/// True when a route message is a default-route change in a table we do not own. Only a
/// default going away or appearing changes which uplink is live; everything else is noise.
fn default_route_change_is_watched(payload: &[u8], ignore_tables: &[u32]) -> bool {
    let rtmsg_size = mem::size_of::<RtMsg>();
    if payload.len() < rtmsg_size {
        return false;
    }
    let rtmsg: RtMsg = unsafe { ptr::read_unaligned(payload.as_ptr() as *const RtMsg) };
    if rtmsg.dst_len != 0 {
        return false;
    }
    let mut table = rtmsg.table as u32;
    // A table above 255 travels in RTA_TABLE; rtm_table then holds a compat/truncated value.
    for attr in attributes(&payload[rtmsg_size..]) {
        if attr.kind == RTA_TABLE {
            if let Some(value) = read_u32(attr.value) {
                table = value;
            }
        }
    }
    !ignore_tables.contains(&table)
}

fn dump_default_routes(family: u8) -> io::Result<Vec<String>> {
    let fd = open_route_socket(0)?;
    send_route_dump_request(&fd, family)?;
    let mut routes = Vec::new();
    let mut buf = [0u8; 8192];
    'recv: loop {
        let received = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if received < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if received == 0 {
            break;
        }
        let mut data = &buf[..received as usize];
        while data.len() >= NLMSG_HDR_LEN {
            let header: NlMsgHdr = unsafe { ptr::read_unaligned(data.as_ptr() as *const NlMsgHdr) };
            let len = header.len as usize;
            if len < NLMSG_HDR_LEN || len > data.len() {
                break;
            }
            match header.kind {
                NLMSG_DONE => break 'recv,
                NLMSG_ERROR => {
                    return Err(io::Error::other("netlink route dump returned an error"));
                }
                RTM_NEWROUTE => {
                    if let Some(route) = parse_default_route(&data[NLMSG_HDR_LEN..len]) {
                        if !routes.contains(&route) {
                            routes.push(route);
                        }
                    }
                }
                _ => {}
            }
            let step = len.next_multiple_of(4);
            if step == 0 || step > data.len() {
                break;
            }
            data = &data[step..];
        }
    }
    Ok(routes)
}

fn send_route_dump_request(fd: &OwnedFd, family: u8) -> io::Result<()> {
    let total = NLMSG_HDR_LEN + mem::size_of::<RtMsg>();
    let mut request = vec![0u8; total.next_multiple_of(4)];
    let header = NlMsgHdr {
        len: total as u32,
        kind: RTM_GETROUTE,
        flags: NLM_F_REQUEST | NLM_F_DUMP,
        seq: 1,
        pid: 0,
    };
    let rtmsg = RtMsg {
        family,
        dst_len: 0,
        src_len: 0,
        tos: 0,
        table: 0,
        protocol: 0,
        scope: 0,
        kind: 0,
        flags: 0,
    };
    unsafe {
        ptr::write_unaligned(request.as_mut_ptr() as *mut NlMsgHdr, header);
        ptr::write_unaligned(request.as_mut_ptr().add(NLMSG_HDR_LEN) as *mut RtMsg, rtmsg);
    }
    let sent = unsafe {
        libc::send(
            fd.as_raw_fd(),
            request.as_ptr() as *const libc::c_void,
            request.len(),
            0,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn parse_default_route(payload: &[u8]) -> Option<String> {
    let rtmsg_size = mem::size_of::<RtMsg>();
    if payload.len() < rtmsg_size {
        return None;
    }
    let rtmsg: RtMsg = unsafe { ptr::read_unaligned(payload.as_ptr() as *const RtMsg) };
    if rtmsg.dst_len != 0 {
        return None;
    }
    let mut table = rtmsg.table as u32;
    let mut gateway: Option<String> = None;
    let mut dev: Option<String> = None;
    let mut metric: Option<u32> = None;
    for attr in attributes(&payload[rtmsg_size..]) {
        match attr.kind {
            RTA_TABLE => {
                if let Some(value) = read_u32(attr.value) {
                    table = value;
                }
            }
            RTA_GATEWAY => gateway = format_addr(rtmsg.family, attr.value),
            RTA_OIF => dev = read_u32(attr.value).and_then(index_to_name),
            RTA_PRIORITY => metric = read_u32(attr.value),
            _ => {}
        }
    }
    if table != RT_TABLE_MAIN {
        return None;
    }
    if gateway.is_none() && dev.is_none() {
        return None;
    }
    let mut route = String::from("default");
    if let Some(gateway) = gateway {
        route.push_str(" via ");
        route.push_str(&gateway);
    }
    if let Some(dev) = dev {
        route.push_str(" dev ");
        route.push_str(&dev);
    }
    // Keep the kernel's metric so several defaults preserve their relative preference.
    if let Some(metric) = metric {
        if metric != 0 {
            route.push_str(" metric ");
            route.push_str(&metric.to_string());
        }
    }
    Some(route)
}

struct AttrRef<'a> {
    kind: u16,
    value: &'a [u8],
}

fn attributes(data: &[u8]) -> Attributes<'_> {
    Attributes { data }
}

struct Attributes<'a> {
    data: &'a [u8],
}

impl<'a> Iterator for Attributes<'a> {
    type Item = AttrRef<'a>;

    fn next(&mut self) -> Option<AttrRef<'a>> {
        if self.data.len() < RTATTR_HDR_LEN {
            return None;
        }
        let attr: RtAttr = unsafe { ptr::read_unaligned(self.data.as_ptr() as *const RtAttr) };
        let len = attr.len as usize;
        if len < RTATTR_HDR_LEN || len > self.data.len() {
            return None;
        }
        let value = &self.data[RTATTR_HDR_LEN..len];
        let step = len.next_multiple_of(4);
        self.data = if step > self.data.len() {
            &[]
        } else {
            &self.data[step..]
        };
        Some(AttrRef {
            kind: attr.kind,
            value,
        })
    }
}

fn read_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 4 {
        return None;
    }
    Some(u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn format_addr(family: u8, bytes: &[u8]) -> Option<String> {
    match family as i32 {
        libc::AF_INET if bytes.len() >= 4 => {
            let octets: [u8; 4] = bytes[..4].try_into().ok()?;
            Some(Ipv4Addr::from(octets).to_string())
        }
        libc::AF_INET6 if bytes.len() >= 16 => {
            let octets: [u8; 16] = bytes[..16].try_into().ok()?;
            Some(Ipv6Addr::from(octets).to_string())
        }
        _ => None,
    }
}

fn index_to_name(index: u32) -> Option<String> {
    let mut buf = [0u8; libc::IF_NAMESIZE];
    let result = unsafe { libc::if_indextoname(index, buf.as_mut_ptr() as *mut libc::c_char) };
    if result.is_null() {
        return None;
    }
    let name = unsafe { CStr::from_ptr(buf.as_ptr() as *const libc::c_char) };
    name.to_str().ok().map(str::to_string)
}
