//! Platform abstraction layer for the OmniSec daemon.
//!
//! Provides platform-specific implementations for:
//! - Process enumeration and command-line reading
//! - Network connection monitoring and blocking
//! - File system event monitoring
//! - Service manager integration (systemd / launchd)
//!
//! Linux implementation: /proc, inotify, nftables, Netlink, systemd sd_notify
//! macOS implementation: sysctl, kqueue, pf packet filter, launchd

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

/// Lightweight process info used for restart / verification.
#[derive(Debug, Clone)]
pub struct ProcessEntry {
    pub pid: u32,
    pub ppid: u32,
    /// Short name (comm / basename of executable)
    pub comm: String,
    /// Full command line with arguments
    pub cmdline: String,
}

/// Result of a network-blocking operation.
#[derive(Debug, Clone)]
pub struct BlockResult {
    pub success: bool,
    /// Which mechanism was used ("nftables", "pf", "simulated")
    pub method: String,
    pub details: String,
}

/// A file-system event from the kernel.
#[derive(Debug, Clone)]
pub struct FileSysEvent {
    pub path: String,
    /// "WRITE", "DELETE", "ATTRIB", "RENAME", "ACCESS", …
    pub action: String,
    /// true = real kernel event; false = pattern-matched heuristic
    pub real_event: bool,
}

// ---------------------------------------------------------------------------
// POSIX helpers (available on Linux and macOS)
// ---------------------------------------------------------------------------

/// Check whether a PID is alive by sending signal 0 (POSIX kill probe).
/// Returns true if the process exists and we have permission to signal it.
pub fn pid_alive(pid: u32) -> bool {
    // Safety: signal 0 is a no-op probe — it never delivers a signal.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

// ---------------------------------------------------------------------------
// Platform-dispatched helpers
// ---------------------------------------------------------------------------

/// Read the full command line for a process.
///
/// Linux: reads /proc/{pid}/cmdline (NUL-separated argv).
/// macOS: uses sysctl KERN_PROCARGS2 (argc + execpath + argv).
pub fn read_cmdline(pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        linux::process::read_cmdline(pid)
    }

    #[cfg(target_os = "macos")]
    {
        macos::process::read_cmdline(pid)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

/// Notify the service manager that the daemon is ready.
///
/// Linux: sends READY=1 to NOTIFY_SOCKET (systemd sd_notify).
/// macOS: logs a ready message (launchd manages keepalive via plist).
pub fn notify_ready() {
    #[cfg(target_os = "linux")]
    linux::service::notify_ready();

    #[cfg(target_os = "macos")]
    macos::service::notify_ready();
}

/// Ping the service manager watchdog.
///
/// Linux: sends WATCHDOG=1 to NOTIFY_SOCKET.
/// macOS: no-op (launchd restarts on crash automatically).
pub fn notify_watchdog() {
    #[cfg(target_os = "linux")]
    linux::service::notify_watchdog();

    #[cfg(target_os = "macos")]
    macos::service::notify_watchdog();
}

/// Human-readable platform identifier, e.g. "linux/amd64" or "macos/arm64".
pub fn platform_id() -> String {
    let os = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "unknown"
    };

    let arch = if cfg!(target_arch = "x86_64") {
        "amd64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "unknown"
    };

    format!("{}/{}", os, arch)
}
