// OMNISEC Linux Runtime Control — Real File Access Monitoring (Phase 1)
//
// Linux: real inotify watches via libc. Background thread posts FileAccessEvents
// to a channel that the daemon drains each cycle.
//
// Other platforms: pattern-match only (no kernel hooks).

use crate::RuntimeMode;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccessEvent {
    pub id: Uuid,
    pub pid: u32,
    pub agent_name: String,
    pub file_path: String,
    pub action: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub real_event: bool,
}

/// Sensitive paths to monitor — default set.
pub const SENSITIVE_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/root/.ssh",
    "/etc/kubernetes",
    "/var/log/auth.log",
    "/var/log/secure",
];

// ---------------------------------------------------------------------------
// File monitor engine
// ---------------------------------------------------------------------------

pub struct FileMonitorEngine {
    monitored_paths: Vec<String>,
    mode: RuntimeMode,
    /// Receiver for events produced by the background inotify thread (Linux only).
    rx: Option<std::sync::mpsc::Receiver<FileAccessEvent>>,
    /// Accumulated events since last drain (includes both real + pattern-matched).
    events: Vec<FileAccessEvent>,
}

impl FileMonitorEngine {
    pub fn new() -> Self {
        Self {
            monitored_paths: SENSITIVE_PATHS.iter().map(|s| s.to_string()).collect(),
            mode: crate::detect_runtime_mode(),
            rx: None,
            events: Vec::new(),
        }
    }

    /// Start inotify monitoring (Linux) or log a simulated-mode notice.
    pub fn start_monitoring(&mut self) {
        match self.mode {
            RuntimeMode::Native => {
                #[cfg(target_os = "linux")]
                {
                    self.start_inotify_thread();
                }
                tracing::info!(
                    "File monitor started — tracking {} sensitive paths",
                    self.monitored_paths.len()
                );
            }
            RuntimeMode::Simulated => {
                tracing::info!(
                    "[SIMULATED] File monitor would watch {} paths (inotify not available)",
                    self.monitored_paths.len()
                );
            }
        }
    }

    /// Drain all pending events from the background thread (and pattern-matched events).
    /// Call this each monitoring cycle.
    pub fn drain_events(&mut self) -> Vec<FileAccessEvent> {
        // Pull events from inotify background thread
        if let Some(ref rx) = self.rx {
            while let Ok(evt) = rx.try_recv() {
                self.events.push(evt);
            }
        }
        std::mem::take(&mut self.events)
    }

    /// Check if a file access should be flagged based on path pattern.
    /// Used for non-inotify event sources (e.g., audit log parsing, eBPF).
    pub fn check_file_access(
        &mut self,
        pid: u32,
        agent_name: &str,
        file_path: &str,
    ) -> Option<FileAccessEvent> {
        let path_lower = file_path.to_lowercase();
        let is_sensitive = self
            .monitored_paths
            .iter()
            .any(|sp| path_lower.contains(&sp.to_lowercase()));

        if is_sensitive {
            let event = FileAccessEvent {
                id: Uuid::new_v4(),
                pid,
                agent_name: agent_name.to_string(),
                file_path: file_path.to_string(),
                action: "FLAG".to_string(),
                timestamp: chrono::Utc::now(),
                real_event: false,
            };
            tracing::warn!(
                "FILE ACCESS: {} accessed {} (PID: {})",
                agent_name, file_path, pid
            );
            self.events.push(event.clone());
            Some(event)
        } else {
            None
        }
    }

    pub fn add_monitored_path(&mut self, path: String) {
        self.monitored_paths.push(path);
    }

    pub fn is_monitored(&self, file_path: &str) -> bool {
        self.monitored_paths
            .iter()
            .any(|sp| file_path.contains(sp.as_str()))
    }

    pub fn monitor_count(&self) -> usize {
        self.monitored_paths.len()
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

// ---------------------------------------------------------------------------
// Linux inotify background thread
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
impl FileMonitorEngine {
    fn start_inotify_thread(&mut self) {
        let (tx, rx) = std::sync::mpsc::channel::<FileAccessEvent>();
        self.rx = Some(rx);

        let paths = self.monitored_paths.clone();

        std::thread::Builder::new()
            .name("omnisec-inotify".to_string())
            .spawn(move || inotify_reader(paths, tx))
            .unwrap_or_else(|e| {
                tracing::error!("Failed to spawn inotify thread: {}", e);
                // Return a dummy handle — Rust requires a JoinHandle from spawn
                std::thread::spawn(|| {})
            });
    }
}

#[cfg(target_os = "linux")]
fn inotify_reader(
    paths: Vec<String>,
    tx: std::sync::mpsc::Sender<FileAccessEvent>,
) {
    use libc::{
        inotify_add_watch, inotify_init1, read,
        IN_ACCESS, IN_ATTRIB, IN_CLOSE_WRITE, IN_CLOEXEC,
        IN_MODIFY, IN_OPEN,
    };
    use std::ffi::CString;

    // -- Initialise inotify --
    let fd = unsafe { inotify_init1(IN_CLOEXEC) };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        tracing::error!("inotify_init1 failed: {}", err);
        return;
    }

    // -- Build watch-descriptor → path map --
    let mut wd_to_path: std::collections::HashMap<i32, String> =
        std::collections::HashMap::new();

    let mask = IN_ACCESS | IN_MODIFY | IN_OPEN | IN_CLOSE_WRITE | IN_ATTRIB;

    for path in &paths {
        let c_path = match CString::new(path.as_str()) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let wd = unsafe { inotify_add_watch(fd, c_path.as_ptr(), mask) };
        if wd < 0 {
            tracing::debug!("inotify_add_watch: {} not found ({})", path, std::io::Error::last_os_error());
        } else {
            wd_to_path.insert(wd, path.clone());
            tracing::info!("inotify watching: {}", path);
        }
    }

    if wd_to_path.is_empty() {
        tracing::warn!("inotify: no paths could be watched (root required for /etc/shadow, etc.)");
    }

    // -- Read loop --
    // inotify_event is variable-length: fixed header + name[len] bytes
    // We use a large buffer to handle multiple events per read.
    const BUF_SIZE: usize = 4096;
    let mut buf = [0u8; BUF_SIZE];

    loop {
        let n = unsafe {
            read(fd, buf.as_mut_ptr() as *mut libc::c_void, BUF_SIZE)
        };

        if n <= 0 {
            if n < 0 {
                tracing::error!("inotify read error: {}", std::io::Error::last_os_error());
            }
            break;
        }

        let mut offset = 0usize;
        let n = n as usize;

        while offset + std::mem::size_of::<libc::inotify_event>() <= n {
            // SAFETY: aligned read of inotify_event from our buffer
            let evt = unsafe {
                &*(buf.as_ptr().add(offset) as *const libc::inotify_event)
            };

            let action = inotify_mask_to_action(evt.mask);
            let path = wd_to_path
                .get(&evt.wd)
                .cloned()
                .unwrap_or_else(|| format!("wd:{}", evt.wd));

            let event = FileAccessEvent {
                id: Uuid::new_v4(),
                pid: 0, // inotify doesn't give us PID — would need eBPF for that
                agent_name: "kernel".to_string(),
                file_path: path.clone(),
                action: action.to_string(),
                timestamp: chrono::Utc::now(),
                real_event: true,
            };

            tracing::warn!(
                "INOTIFY: {} on {} (mask=0x{:08x})",
                action, path, evt.mask
            );

            if tx.send(event).is_err() {
                // Receiver dropped — daemon is shutting down
                return;
            }

            // Advance past this event (fixed header + name)
            let event_size = std::mem::size_of::<libc::inotify_event>() + evt.len as usize;
            offset += event_size;
        }
    }

    unsafe { libc::close(fd) };
}

#[cfg(target_os = "linux")]
fn inotify_mask_to_action(mask: u32) -> &'static str {
    // Check flags in priority order
    if mask & libc::IN_MODIFY != 0 { return "MODIFY"; }
    if mask & libc::IN_CLOSE_WRITE != 0 { return "CLOSE_WRITE"; }
    if mask & libc::IN_ACCESS != 0 { return "ACCESS"; }
    if mask & libc::IN_OPEN != 0 { return "OPEN"; }
    if mask & libc::IN_ATTRIB != 0 { return "ATTRIB"; }
    "UNKNOWN"
}

impl Default for FileMonitorEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_pattern_check_flags_sensitive_path() {
        let mut monitor = FileMonitorEngine::new();
        let evt = monitor.check_file_access(1234, "test-agent", "/etc/passwd");
        assert!(evt.is_some());
        let evt = evt.unwrap();
        assert_eq!(evt.file_path, "/etc/passwd");
        assert!(!evt.real_event);
    }

    #[test]
    fn test_pattern_check_ignores_non_sensitive() {
        let mut monitor = FileMonitorEngine::new();
        let evt = monitor.check_file_access(1234, "test-agent", "/tmp/workfile.txt");
        assert!(evt.is_none());
    }

    #[test]
    fn test_drain_returns_accumulated_events() {
        let mut monitor = FileMonitorEngine::new();
        monitor.check_file_access(1, "a", "/etc/shadow");
        monitor.check_file_access(2, "b", "/etc/sudoers");
        let drained = monitor.drain_events();
        assert_eq!(drained.len(), 2);
        // Second drain should be empty
        let drained2 = monitor.drain_events();
        assert!(drained2.is_empty());
    }

    #[test]
    fn test_add_custom_monitored_path() {
        let mut monitor = FileMonitorEngine::new();
        monitor.add_monitored_path("/tmp/secrets.env".to_string());
        let evt = monitor.check_file_access(1, "agent", "/tmp/secrets.env");
        assert!(evt.is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_inotify_real_file_event() {
        // Only runs on Linux with access to temp files
        // Creates a temp file, adds it to monitoring, writes to it,
        // and expects an inotify event within 500ms.
        use std::time::Duration;

        let mut monitor = FileMonitorEngine::new();
        // Clear default paths and watch a temp file we can actually write
        monitor.monitored_paths.clear();

        let tmp = NamedTempFile::new().expect("temp file");
        let tmp_path = tmp.path().to_string_lossy().to_string();
        monitor.add_monitored_path(tmp_path.clone());
        monitor.start_monitoring();

        // Give inotify thread a moment to set up watches
        std::thread::sleep(Duration::from_millis(100));

        // Trigger an event
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&tmp_path)
            .expect("open tmp");
        file.write_all(b"test").expect("write");
        drop(file);

        // Poll for event
        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        loop {
            let events = monitor.drain_events();
            if events.iter().any(|e| e.real_event) {
                return; // success
            }
            if std::time::Instant::now() > deadline {
                panic!("No real inotify event received within 500ms");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
