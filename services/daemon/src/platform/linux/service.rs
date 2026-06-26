//! Linux service manager integration via systemd sd_notify
//!
//! Communicates with the systemd watchdog through the NOTIFY_SOCKET
//! Unix datagram socket set by systemd Type=notify units.

/// Notify systemd that the daemon has finished initializing.
pub fn notify_ready() {
    sd_notify("READY=1\n");
    tracing::info!("systemd: READY=1 sent");
}

/// Ping the systemd watchdog to prevent the unit from being restarted.
/// Call this at least once per WatchdogSec interval.
pub fn notify_watchdog() {
    sd_notify("WATCHDOG=1\n");
}

fn sd_notify(state: &str) {
    let socket_path = match std::env::var("NOTIFY_SOCKET") {
        Ok(p) => p,
        Err(_) => return, // Not running under systemd — silently skip
    };

    use std::os::unix::net::UnixDatagram;
    if let Ok(sock) = UnixDatagram::unbound() {
        let _ = sock.send_to(state.as_bytes(), &socket_path);
    }
}
