//! # OMNISEC eBPF Common Types
//!
//! Shared fixed-size structs used between BPF kernel programs and userspace.
//! BPF requires `#[repr(C)]` and fixed-size arrays — no `String`, no `Vec`.

#![no_std]

// =========================================================================
// Event type constants
// =========================================================================

pub const EVENT_PROCESS_EXEC: u32 = 1;
pub const EVENT_PROCESS_EXIT: u32 = 2;
pub const EVENT_PROCESS_FORK: u32 = 3;
pub const EVENT_NETWORK_CONNECT: u32 = 10;
pub const EVENT_NETWORK_LISTEN: u32 = 11;
pub const EVENT_NETWORK_ACCEPT: u32 = 12;
pub const EVENT_FILE_ACCESS: u32 = 20;
pub const EVENT_FILE_DELETE: u32 = 21;
pub const EVENT_FILE_MODIFY: u32 = 22;
pub const EVENT_DNS_QUERY: u32 = 30;

// =========================================================================
// Protocol constants
// =========================================================================

pub const PROTOCOL_TCP: u8 = 1;
pub const PROTOCOL_TCP6: u8 = 2;
pub const PROTOCOL_UDP: u8 = 3;

// =========================================================================
// Operation constants (file events)
// =========================================================================

pub const OPERATION_OPEN: u32 = 1;
pub const OPERATION_OPENAT: u32 = 2;
pub const OPERATION_UNLINK: u32 = 3;
pub const OPERATION_RENAME: u32 = 4;
pub const OPERATION_CHMOD: u32 = 5;

// =========================================================================
// Fixed-size event structs (mirrors between BPF ↔ userspace)
// =========================================================================

/// Unified process event (exec, exit, fork)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessEvent {
    pub event_type: u8,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; 16],           // process command name (like /proc/pid/comm)
    pub filename: [u8; 64],       // executable path
    pub exit_code: i32,           // for exit events
    pub parent_pid: u32,          // for fork events
    pub child_pid: u32,           // for fork events (filled from sys_exit)
    pub flags: u64,
    pub timestamp_ns: u64,
}

impl ProcessEvent {
    pub fn comm_str(&self) -> &str {
        let end = self.comm.iter().position(|&b| b == 0).unwrap_or(self.comm.len());
        core::str::from_utf8(&self.comm[..end]).unwrap_or("")
    }

    pub fn filename_str(&self) -> &str {
        let end = self.filename.iter().position(|&b| b == 0).unwrap_or(self.filename.len());
        core::str::from_utf8(&self.filename[..end]).unwrap_or("")
    }
}

/// Unified network event (connect, bind, accept)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NetworkEvent {
    pub event_type: u8,
    pub pid: u32,
    pub uid: u32,
    pub dest_ip: [u8; 4],
    pub dest_port: u16,
    pub src_ip: [u8; 4],
    pub src_port: u16,
    pub protocol: u8,
    pub backlog: u32,             // for bind/listen
    pub client_port: u16,         // for accept
    pub server_port: u16,         // for accept
    pub flags: u64,
    pub timestamp_ns: u64,
}



/// Unified file access event (openat, unlinkat, renameat)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FileEvent {
    pub event_type: u8,
    pub pid: u32,
    pub uid: u32,
    pub path: [u8; 64],
    pub operation: u32,
    pub flags: u32,
    pub mode: u32,
    pub timestamp_ns: u64,
}

impl FileEvent {
    pub fn path_str(&self) -> &str {
        let end = self.path.iter().position(|&b| b == 0).unwrap_or(self.path.len());
        core::str::from_utf8(&self.path[..end]).unwrap_or("")
    }

    pub fn operation_str(&self) -> &str {
        match self.operation {
            OPERATION_OPEN => "open",
            OPERATION_OPENAT => "openat",
            OPERATION_UNLINK => "unlink",
            OPERATION_RENAME => "rename",
            OPERATION_CHMOD => "chmod",
            _ => "unknown",
        }
    }
}

/// DNS query event
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DnsEvent {
    pub pid: u32,
    pub domain_hash: u64,         // hash of queried domain (full domain decoded in userspace)
    pub dns_type: u16,            // 1=A, 28=AAAA, etc.
    pub resolver_ip: [u8; 4],
    pub response_ip_count: u8,
    pub flags: u64,
    pub timestamp_ns: u64,
}


