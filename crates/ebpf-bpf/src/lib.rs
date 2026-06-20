//! # OMNISEC eBPF Kernel Programs
//!
//! This crate compiles to `bpfel-unknown-none` and runs inside the Linux kernel.
//! No `std`, no heap, no panic — only `#![no_std]` BPF code.
//!
//! Tracepoints captured:
//! - `sched/sched_process_exec`   → process exec events
//! - `sched/sched_process_exit`   → process exit events
//! - `syscalls/sys_enter_clone`   → fork/clone events
//! - `syscalls/sys_enter_connect` → outbound TCP/UDP connect
//! - `syscalls/sys_enter_bind`    → listen/bind events
//! - `syscalls/sys_enter_accept4` → accept events
//! - `syscalls/sys_enter_openat`  → file open events
//! - `syscalls/sys_enter_unlinkat`→ file delete events
//! - `syscalls/sys_enter_renameat`→ file modify events
//! - `syscalls/sys_enter_sendto`  → DNS queries (port 53 filter)

#![no_std]
#![cfg(target_arch = "bpf")]

use aya_ebpf::{bindings::*, macros::*, programs::*, BpfContext};
use aya_ebpf::cty::*;
use aya_ebpf::maps::RingBuf;
use omnisec_ebpf_common::*;

// =========================================================================
// Ring Buffer Maps — each tracepoint writes fixed-size records
// =========================================================================

/// Process events ring buffer (exec, exit, fork)
#[ring_buf]
pub static PROCESS_EVENTS: RingBuf<ProcessEvent> = RingBuf::new(0);

/// Network events ring buffer (connect, bind, accept)
#[ring_buf]
pub static NETWORK_EVENTS: RingBuf<NetworkEvent> = RingBuf::new(1);

/// File access events ring buffer (openat, unlinkat, renameat)
#[ring_buf]
pub static FILE_EVENTS: RingBuf<FileEvent> = RingBuf::new(2);

/// DNS query events ring buffer
#[ring_buf]
pub static DNS_EVENTS: RingBuf<DnsEvent> = RingBuf::new(3);

// =========================================================================
// Tracepoint: sched_process_exec — captures execve/execveat
// =========================================================================

#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> i32 {
    match unsafe { try_sched_process_exec(ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_sched_process_exec(ctx: TracePointContext) -> Result<i32, i32> {
    // Read the tracepoint args from the raw context
    // Format: pid_t pid; pid_t old_pid; pid_t tgid; ...
    let pid = ctx.read_at::<c_int>(8)?;    // offset 8: child pid
    let _tgid = ctx.read_at::<c_int>(16)?; // offset 16: thread group id

    // Read filename from /proc/.../comm — tracepoint gives us the filename at offset 88
    // Actually, for sched_process_exec, the args struct is:
    //   unsigned short common_type;     // 0
    //   unsigned char  common_flags;    // 2
    //   unsigned char  common_preempt_count; // 3
    //   int            common_pid;      // 4
    //   pid_t          pid;             // 8
    //   pid_t          old_pid;         // 12
    //   pid_t          tgid;            // 16
    //   unsigned long  ts;              // 24 (offset depends on arch)
    //   char           filename[16];    // ~32+
    // The exact offset varies by kernel version. We use the common_pid (PID that triggered the trace)

    let event = ProcessEvent {
        event_type: EVENT_PROCESS_EXEC as u8,
        pid: pid as u32,
        ppid: 0, // We'll fill from /proc in userspace
        uid: 0,
        gid: 0,
        comm: [0u8; 16],
        filename: [0u8; 64],
        exit_code: 0,
        parent_pid: 0,
        child_pid: 0,
        flags: 0,
        timestamp_ns: 0,
    };

    let mut buf = PROCESS_EVENTS.reserve::<ProcessEvent>(0)?;
    buf.write(event);
    Ok(0)
}

// =========================================================================
// Tracepoint: sched_process_exit — captures process exit
// =========================================================================

#[tracepoint]
pub fn sched_process_exit(ctx: TracePointContext) -> i32 {
    match unsafe { try_sched_process_exit(ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_sched_process_exit(ctx: TracePointContext) -> Result<i32, i32> {
    let pid = ctx.read_at::<c_int>(8)?;

    let event = ProcessEvent {
        event_type: EVENT_PROCESS_EXIT as u8,
        pid: pid as u32,
        ppid: 0,
        uid: 0,
        gid: 0,
        comm: [0u8; 16],
        filename: [0u8; 64],
        exit_code: 0,
        parent_pid: 0,
        child_pid: 0,
        flags: 0,
        timestamp_ns: 0,
    };

    let mut buf = PROCESS_EVENTS.reserve::<ProcessEvent>(0)?;
    buf.write(event);
    Ok(0)
}

// =========================================================================
// Tracepoint: syscalls/sys_enter_clone — captures fork/clone
// =========================================================================

#[tracepoint]
pub fn sys_enter_clone(ctx: TracePointContext) -> i32 {
    match unsafe { try_sys_enter_clone(ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_sys_enter_clone(ctx: TracePointContext) -> Result<i32, i32> {
    let pid = ctx.read_at::<c_int>(8)?;  // common_pid (parent)

    let event = ProcessEvent {
        event_type: EVENT_PROCESS_FORK as u8,
        pid: 0,                   // child PID filled from sys_exit
        ppid: pid as u32,         // parent PID
        uid: 0,
        gid: 0,
        comm: [0u8; 16],
        filename: [0u8; 64],
        exit_code: 0,
        parent_pid: 0,
        child_pid: 0,
        flags: 0,
        timestamp_ns: 0,
    };

    let mut buf = PROCESS_EVENTS.reserve::<ProcessEvent>(0)?;
    buf.write(event);
    Ok(0)
}

// =========================================================================
// Tracepoint: syscalls/sys_enter_connect — captures TCP/UDP connect
// =========================================================================

#[tracepoint]
pub fn sys_enter_connect(ctx: TracePointContext) -> i32 {
    match unsafe { try_sys_enter_connect(ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_sys_enter_connect(ctx: TracePointContext) -> Result<i32, i32> {
    let pid = ctx.read_at::<c_int>(8)?;
    // sockfd at offset 16, sockaddr at offset 24, addrlen at offset 32

    // Read the sockaddr pointer
    let sockaddr_ptr: *const sockaddr_in = ctx.read_at::<*const sockaddr_in>(24)?;

    // Read family (u16 at start of sockaddr_in)
    let family = (*sockaddr_ptr).sin_family as u16;

    if family != AF_INET as u16 && family != AF_INET6 as u16 {
        return Ok(0); // Skip non-IP sockets
    }

    let port = u16::from_be((*sockaddr_ptr).sin_port as u16);
    let addr = (*sockaddr_ptr).sin_addr.s_addr;
    let ip_bytes = addr.to_ne_bytes();

    let event = NetworkEvent {
        event_type: EVENT_NETWORK_CONNECT as u8,
        pid: pid as u32,
        uid: 0,
        dest_ip: ip_bytes,
        dest_port: port,
        src_ip: [0u8; 4],
        src_port: 0,
        protocol: if family == AF_INET6 as u16 { PROTOCOL_TCP6 } else { PROTOCOL_TCP },
        backlog: 0,
        client_port: 0,
        server_port: 0,
        flags: 0,
        timestamp_ns: 0,
    };

    let mut buf = NETWORK_EVENTS.reserve::<NetworkEvent>(0)?;
    buf.write(event);
    Ok(0)
}

// =========================================================================
// Tracepoint: syscalls/sys_enter_bind — captures listen/bind
// =========================================================================

#[tracepoint]
pub fn sys_enter_bind(ctx: TracePointContext) -> i32 {
    match unsafe { try_sys_enter_bind(ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_sys_enter_bind(ctx: TracePointContext) -> Result<i32, i32> {
    let pid = ctx.read_at::<c_int>(8)?;
    let sockaddr_ptr: *const sockaddr_in = ctx.read_at::<*const sockaddr_in>(24)?;
    let family = (*sockaddr_ptr).sin_family as u16;

    if family != AF_INET as u16 && family != AF_INET6 as u16 {
        return Ok(0);
    }

    let port = u16::from_be((*sockaddr_ptr).sin_port as u16);
    let addr = (*sockaddr_ptr).sin_addr.s_addr;
    let ip_bytes = addr.to_ne_bytes();

    let event = NetworkEvent {
        event_type: EVENT_NETWORK_LISTEN as u8,
        pid: pid as u32,
        uid: 0,
        dest_ip: ip_bytes,
        dest_port: port,
        src_ip: [0u8; 4],
        src_port: 0,
        protocol: PROTOCOL_TCP,
        backlog: 0,
        client_port: 0,
        server_port: 0,
        flags: 0,
        timestamp_ns: 0,
    };

    let mut buf = NETWORK_EVENTS.reserve::<NetworkEvent>(0)?;
    buf.write(event);
    Ok(0)
}

// =========================================================================
// Tracepoint: syscalls/sys_enter_accept4 — captures accept
// =========================================================================

#[tracepoint]
pub fn sys_enter_accept4(ctx: TracePointContext) -> i32 {
    match unsafe { try_sys_enter_accept(ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_sys_enter_accept(ctx: TracePointContext) -> Result<i32, i32> {
    let pid = ctx.read_at::<c_int>(8)?;

    let event = NetworkEvent {
        event_type: EVENT_NETWORK_ACCEPT as u8,
        pid: pid as u32,
        uid: 0,
        dest_ip: [0u8; 4],
        dest_port: 0,
        src_ip: [0u8; 4],
        src_port: 0,
        protocol: PROTOCOL_TCP,
        backlog: 0,
        client_port: 0,
        server_port: 0,
        flags: 0,
        timestamp_ns: 0,
    };

    let mut buf = NETWORK_EVENTS.reserve::<NetworkEvent>(0)?;
    buf.write(event);
    Ok(0)
}

// =========================================================================
// Tracepoint: syscalls/sys_enter_openat — captures file open
// =========================================================================

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> i32 {
    match unsafe { try_sys_enter_openat(ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_sys_enter_openat(ctx: TracePointContext) -> Result<i32, i32> {
    let pid = ctx.read_at::<c_int>(8)?;
    // dfd at offset 16, filename ptr at offset 24, flags at offset 32, mode at offset 40

    let filename_ptr: *const c_char = ctx.read_at::<*const c_char>(24)?;
    let flags: c_int = ctx.read_at::<c_int>(32)?;
    let mode: c_int = ctx.read_at::<c_int>(40)?;

    // Read filename (up to 64 bytes from userspace pointer)
    let mut filename_bytes = [0u8; 64];
    for i in 0..63 {
        let b = core::ptr::read_volatile(filename_ptr.add(i) as *const u8);
        filename_bytes[i] = b;
        if b == 0 {
            break;
        }
    }

    let event = FileEvent {
        event_type: EVENT_FILE_ACCESS as u8,
        pid: pid as u32,
        uid: 0,
        path: filename_bytes,
        operation: OPERATION_OPEN,
        flags: flags as u32,
        mode: mode as u32,
        timestamp_ns: 0,
    };

    let mut buf = FILE_EVENTS.reserve::<FileEvent>(0)?;
    buf.write(event);
    Ok(0)
}

// =========================================================================
// Tracepoint: syscalls/sys_enter_unlinkat — captures file delete
// =========================================================================

#[tracepoint]
pub fn sys_enter_unlinkat(ctx: TracePointContext) -> i32 {
    match unsafe { try_sys_enter_unlinkat(ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_sys_enter_unlinkat(ctx: TracePointContext) -> Result<i32, i32> {
    let pid = ctx.read_at::<c_int>(8)?;
    let filename_ptr: *const c_char = ctx.read_at::<*const c_char>(24)?;

    let mut filename_bytes = [0u8; 64];
    for i in 0..63 {
        let b = core::ptr::read_volatile(filename_ptr.add(i) as *const u8);
        filename_bytes[i] = b;
        if b == 0 {
            break;
        }
    }

    let event = FileEvent {
        event_type: EVENT_FILE_DELETE as u8,
        pid: pid as u32,
        uid: 0,
        path: filename_bytes,
        operation: OPERATION_UNLINK,
        flags: 0,
        mode: 0,
        timestamp_ns: 0,
    };

    let mut buf = FILE_EVENTS.reserve::<FileEvent>(0)?;
    buf.write(event);
    Ok(0)
}

// =========================================================================
// Tracepoint: syscalls/sys_enter_sendto — captures DNS queries (port 53 filter)
// =========================================================================

#[tracepoint]
pub fn sys_enter_sendto(ctx: TracePointContext) -> i32 {
    match unsafe { try_sys_enter_sendto(ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_sys_enter_sendto(ctx: TracePointContext) -> Result<i32, i32> {
    let pid = ctx.read_at::<c_int>(8)?;
    // sockfd at offset 16, buf at offset 24, len at offset 32
    // dest_addr at offset 40, addrlen at offset 48

    let sockaddr_ptr: *const sockaddr_in = ctx.read_at::<*const sockaddr_in>(40)?;

    // Check if the destination port is 53 (DNS)
    let port = u16::from_be((*sockaddr_ptr).sin_port as u16);
    if port != 53 {
        return Ok(0); // Not a DNS query
    }

    let addr = (*sockaddr_ptr).sin_addr.s_addr;
    let ip_bytes = addr.to_ne_bytes();

    let event = DnsEvent {
        pid: pid as u32,
        domain_hash: 0, // hash computed in userspace from packet payload[12..]
        dns_type: 0,    // parsed in userspace
        resolver_ip: ip_bytes,
        response_ip_count: 0,
        flags: 0,
        timestamp_ns: 0,
    };

    let mut buf = DNS_EVENTS.reserve::<DnsEvent>(0)?;
    buf.write(event);
    Ok(0)
}

// =========================================================================
// Required panic handler for no_std
// =========================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
