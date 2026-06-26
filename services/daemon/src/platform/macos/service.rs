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

/// Install (or update) the launchd plist so the daemon starts on boot.
pub fn install_plist(binary_path: &str) {
    const PLIST_PATH: &str = "/Library/LaunchDaemons/com.omnisec.daemon.plist";

    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.omnisec.daemon</string>
  <key>ProgramArguments</key>
  <array>
    <string>{}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/var/log/omnisec-daemon.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/omnisec-daemon.err</string>
  <key>PIDFile</key>
  <string>{}</string>
</dict>
</plist>
"#,
        binary_path, PID_FILE
    );

    match std::fs::write(PLIST_PATH, plist) {
        Ok(_) => {
            tracing::info!("launchd: plist written to {}", PLIST_PATH);
            // Reload so launchd picks up the new file.
            let _ = std::process::Command::new("launchctl")
                .args(["load", "-w", PLIST_PATH])
                .output();
        }
        Err(e) => tracing::warn!("launchd: failed to write plist: {}", e),
    }
}
