//! macOS process monitoring via sysctl
//!
//! Uses two sysctl calls:
//!
//! 1. sysctl(CTL_KERN, KERN_PROC, KERN_PROC_ALL) → kinfo_proc array
//!    Returns PID, PPID, and the short comm name (≤16 chars) for every
//!    process visible to the calling user.
//!
//! 2. sysctl(CTL_KERN, KERN_PROCARGS2, pid) → argc + execpath + argv
//!    Returns the full command line for a specific PID.
//!
//! libc 0.2 does not expose kinfo_proc for macOS, so we declare the layout
//! manually. Offsets verified with clang on macOS 14 (arm64 / amd64):
//!   sizeof kinfo_proc = 648; kp_proc at 0 (296 bytes); kp_eproc at 296 (352 bytes)
//!   p_pid  at extern_proc+40  (i32)
//!   p_comm at extern_proc+243 (char[17])
//!   e_ppid at eproc+264       (i32)

use super::super::ProcessEntry;
use libc::{c_int, c_void, size_t};

// ---------------------------------------------------------------------------
// Manual struct layout (verified with clang on macOS 14)
// ---------------------------------------------------------------------------

#[repr(C)]
struct ExternProc {
    _pad0: [u8; 40],   // fields before p_pid
    p_pid: i32,        // offset 40
    _pad1: [u8; 199],  // fields between p_pid and p_comm: 243 - 40 - 4 = 199
    p_comm: [u8; 17],  // offset 243 — MAXCOMLEN+1
    _pad2: [u8; 36],   // remainder: 296 - 243 - 17 = 36
}
// Total: 40 + 4 + 199 + 17 + 36 = 296

#[repr(C)]
struct EProc {
    _pad0: [u8; 264],  // fields before e_ppid
    e_ppid: i32,       // offset 264
    _pad1: [u8; 84],   // remainder: 352 - 264 - 4 = 84
}
// Total: 264 + 4 + 84 = 352

#[repr(C)]
struct KInfoProc {
    kp_proc: ExternProc, // offset 0,   size 296
    kp_eproc: EProc,     // offset 296, size 352
}
// Total: 296 + 352 = 648

const _: () = {
    assert!(std::mem::size_of::<ExternProc>() == 296);
    assert!(std::mem::size_of::<EProc>() == 352);
    assert!(std::mem::size_of::<KInfoProc>() == 648);
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Enumerate all running processes using sysctl KERN_PROC_ALL.
pub fn list_processes() -> Vec<ProcessEntry> {
    let mut mib: [c_int; 4] = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_ALL,
        0,
    ];

    // First call: query required buffer size.
    let mut size: size_t = 0;
    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            4,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 || size == 0 {
        return Vec::new();
    }

    let entry_size = std::mem::size_of::<KInfoProc>();
    // Over-allocate slightly to handle races.
    let capacity = size / entry_size + 8;
    let mut procs: Vec<KInfoProc> = Vec::with_capacity(capacity);

    // Second call: fill the buffer.
    let ret = unsafe {
        procs.set_len(capacity);
        let r = libc::sysctl(
            mib.as_mut_ptr(),
            4,
            procs.as_mut_ptr() as *mut c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        );
        // Truncate to actually written entries.
        procs.set_len(size / entry_size);
        r
    };

    if ret != 0 {
        return Vec::new();
    }

    procs
        .into_iter()
        .filter(|p| p.kp_proc.p_pid > 0)
        .map(|p| {
            let pid = p.kp_proc.p_pid as u32;
            let ppid = p.kp_eproc.e_ppid as u32;

            // p_comm is a fixed-length C string (MAXCOMLEN = 16).
            let comm = unsafe {
                std::ffi::CStr::from_ptr(p.kp_proc.p_comm.as_ptr() as *const i8)
                    .to_string_lossy()
                    .to_string()
            };
            let cmdline = read_cmdline(pid).unwrap_or_else(|| comm.clone());

            ProcessEntry { pid, ppid, comm, cmdline }
        })
        .collect()
}

/// Read the full command line for a PID via sysctl KERN_PROCARGS2.
///
/// Buffer layout:
///   [0..4]   argc (i32, native-endian)
///   [4..]    execpath\0\0...padding...arg1\0arg2\0...env1\0...
pub fn read_cmdline(pid: u32) -> Option<String> {
    let mut mib: [c_int; 3] = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as c_int];

    // KERN_PROCARGS2 buffers can be large; ARG_MAX is typically 256 KB.
    const ARG_MAX: usize = 256 * 1024;
    let mut size: size_t = ARG_MAX;
    let mut buf: Vec<u8> = vec![0u8; ARG_MAX];

    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr() as *mut c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };

    if ret != 0 || size < 4 {
        return None;
    }
    buf.truncate(size);

    // First 4 bytes: argc as native-endian i32.
    let argc = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]).max(0) as usize;

    // The rest starts with the execpath, then NUL bytes for alignment,
    // then argv[0] … argv[argc-1], then env vars.
    let rest = &buf[4..];

    // Split on NUL bytes; the first non-empty segment is execpath (= argv[0]),
    // followed by argc-1 additional arguments.
    let segments: Vec<&[u8]> = rest
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .collect();

    // We want execpath + the first argc args (total: 1 + argc, but execpath
    // is argv[0] so just take argc + 1 items if argc > 0, else just execpath).
    let take = (argc + 1).max(1);
    let parts: Vec<String> = segments
        .into_iter()
        .take(take)
        .map(|s| String::from_utf8_lossy(s).to_string())
        .collect();

    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}
