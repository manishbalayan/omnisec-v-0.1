//! macOS service management via launchd
//!
//! Communicates lifecycle state through launchctl check-in and a keepalive
//! plist at /Library/LaunchDaemons/com.omnisec.daemon.plist.
//!
//! Note: launchd has no READY/WATCHDOG protocol equivalent to systemd's
//! sd_notify. We simulate readiness by logging and optionally writing a
//! PID file that the plist can use as a health check.

const PID_FILE: &str = "/var/run/omnisec-daemon.pid";

/// Record that the daemon has finished initializing.
/// Writes a PID file so launchd KeepAlive/PIDFile can track liveness.
pub fn notify_ready() {
    let pid = std::process::id();
    match std::fs::write(PID_FILE, format!("{}\n", pid)) {
        Ok(_) => tracing::info!("launchd: PID file written ({}) → {}", pid, PID_FILE),
        Err(e) => tracing::warn!("launchd: failed to write PID file: {}", e),
    }
    tracing::info!("launchd: daemon ready (pid {})", pid);
}

/// Heartbeat — no-op on macOS (launchd uses process liveness, not watchdog pings).
pub fn notify_watchdog() {
    // launchd monitors the process directly; no periodic ping needed.
}

// Note: the launchd plist is installed and managed by the host-native installer
// (deploy/launchd/com.omnisec.daemon.plist via deploy/install.sh), not by the
// daemon itself. The daemon only reports readiness via the PID file above.
