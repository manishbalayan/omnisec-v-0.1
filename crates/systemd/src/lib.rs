use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Systemd service representation
// ---------------------------------------------------------------------------

/// A discovered systemd service that may correspond to an AI agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemdService {
    /// Unit name (e.g. "my-agent.service").
    pub unit: String,
    /// Human-readable description.
    pub description: String,
    /// Current state (active, inactive, failed, etc.).
    pub active_state: String,
    /// Sub-state (running, exited, dead, etc.).
    pub sub_state: String,
    /// Main PID of the service (0 if not running).
    pub main_pid: u32,
    /// Whether the service is enabled at boot.
    pub enabled: bool,
    /// Number of times the unit has been restarted (from systemd).
    pub restart_count: u32,
    /// Timestamp of last restart attempt.
    pub last_restart_time: Option<u64>,
}

/// Result from a systemd operation (restart, stop, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemdResult {
    pub unit: String,
    pub success: bool,
    pub message: String,
    pub duration_ms: u64,
}

// ---------------------------------------------------------------------------
// Systemd manager
// ---------------------------------------------------------------------------

pub struct SystemdManager;

impl SystemdManager {
    /// Discover all systemd services running on the system.
    /// Uses `systemctl list-units --type=service --all --no-legend`.
    #[cfg(target_os = "linux")]
    pub fn discover_services() -> Result<Vec<SystemdService>> {
        use std::process::Command;

        // Get all service units
        let output = Command::new("systemctl")
            .args([
                "list-units",
                "--type=service",
                "--all",
                "--no-legend",
                "--no-pager",
            ])
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to run systemctl: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut services = Vec::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let unit = parts[0].to_string();
                let active_state = parts[1].to_string();
                let sub_state = parts[2].to_string();
                let description = parts[3..].join(" ");

                // Skip non-service units
                if !unit.ends_with(".service") {
                    continue;
                }

                let main_pid = Self::get_service_main_pid(&unit).unwrap_or(0);
                let restart_count = Self::get_service_restart_count(&unit).unwrap_or(0);
                let last_restart = Self::get_service_last_restart(&unit);
                let enabled = Self::is_service_enabled(&unit);

                services.push(SystemdService {
                    unit,
                    description,
                    active_state,
                    sub_state,
                    main_pid,
                    enabled,
                    restart_count,
                    last_restart_time: last_restart,
                });
            }
        }

        Ok(services)
    }

    /// Discover services (non-Linux fallback — returns empty).
    #[cfg(not(target_os = "linux"))]
    pub fn discover_services() -> Result<Vec<SystemdService>> {
        tracing::warn!("Systemd discovery not supported on this platform");
        Ok(Vec::new())
    }

    /// Restart a systemd service.
    pub fn restart_service(unit: &str) -> Result<SystemdResult> {
        let start = std::time::Instant::now();
        let output = std::process::Command::new("systemctl")
            .args(["restart", unit])
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to restart {}: {}", unit, e))?;

        let elapsed = start.elapsed();
        Ok(SystemdResult {
            unit: unit.to_string(),
            success: output.status.success(),
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            duration_ms: elapsed.as_millis() as u64,
        })
    }

    /// Stop a systemd service.
    pub fn stop_service(unit: &str) -> Result<SystemdResult> {
        let start = std::time::Instant::now();
        let output = std::process::Command::new("systemctl")
            .args(["stop", unit])
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to stop {}: {}", unit, e))?;

        let elapsed = start.elapsed();
        Ok(SystemdResult {
            unit: unit.to_string(),
            success: output.status.success(),
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            duration_ms: elapsed.as_millis() as u64,
        })
    }

    /// Start a systemd service.
    pub fn start_service(unit: &str) -> Result<SystemdResult> {
        let start = std::time::Instant::now();
        let output = std::process::Command::new("systemctl")
            .args(["start", unit])
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to start {}: {}", unit, e))?;

        let elapsed = start.elapsed();
        Ok(SystemdResult {
            unit: unit.to_string(),
            success: output.status.success(),
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            duration_ms: elapsed.as_millis() as u64,
        })
    }

    /// Get the status of a service.
    pub fn get_service_status(unit: &str) -> Result<SystemdService> {
        let output = std::process::Command::new("systemctl")
            .args(["show", unit, "--property=Id,Description,ActiveState,SubState,MainPID,NRestarts,ActiveEnterTimestamp"])
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to show {}: {}", unit, e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let props = Self::parse_properties(&stdout);

        Ok(SystemdService {
            unit: props.get("Id").cloned().unwrap_or_default(),
            description: props.get("Description").cloned().unwrap_or_default(),
            active_state: props.get("ActiveState").cloned().unwrap_or_default(),
            sub_state: props.get("SubState").cloned().unwrap_or_default(),
            main_pid: props.get("MainPID").and_then(|v| v.parse().ok()).unwrap_or(0),
            enabled: Self::is_service_enabled(unit),
            restart_count: props.get("NRestarts").and_then(|v| v.parse().ok()).unwrap_or(0),
            last_restart_time: props.get("ActiveEnterTimestamp").and_then(|v| parse_systemd_timestamp(v)),
        })
    }

    /// Check whether a service is running.
    pub fn is_service_running(unit: &str) -> bool {
        let output = std::process::Command::new("systemctl")
            .args(["is-active", "--quiet", unit])
            .output();
        matches!(output, Ok(o) if o.status.success())
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn get_service_main_pid(unit: &str) -> Option<u32> {
        let output = std::process::Command::new("systemctl")
            .args(["show", unit, "--property=MainPID", "--no-pager"])
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let value = stdout.trim().strip_prefix("MainPID=")?;
        value.parse().ok()
    }

    fn get_service_restart_count(unit: &str) -> Option<u32> {
        let output = std::process::Command::new("systemctl")
            .args(["show", unit, "--property=NRestarts", "--no-pager"])
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let value = stdout.trim().strip_prefix("NRestarts=")?;
        value.parse().ok()
    }

    fn get_service_last_restart(unit: &str) -> Option<u64> {
        let output = std::process::Command::new("systemctl")
            .args(["show", unit, "--property=ActiveEnterTimestamp", "--no-pager"])
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let value = stdout.trim().strip_prefix("ActiveEnterTimestamp=")?;
        parse_systemd_timestamp(value)
    }

    fn is_service_enabled(unit: &str) -> bool {
        let output = std::process::Command::new("systemctl")
            .args(["is-enabled", "--quiet", unit])
            .output();
        matches!(output, Ok(o) if o.status.success())
    }

    fn parse_properties(output: &str) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for line in output.lines() {
            if let Some((key, value)) = line.split_once('=') {
                map.insert(key.to_string(), value.to_string());
            }
        }
        map
    }
}

/// Parse a systemd timestamp string (e.g. "Mon 2024-01-15 10:30:00 UTC")
/// into a Unix timestamp (seconds since epoch).
fn parse_systemd_timestamp(s: &str) -> Option<u64> {
    // systemd timestamps have format like "Mon 2024-01-15 10:30:00 UTC"
    // or "Mon 2024-01-15 11:30:00 CET" or just empty/n/a
    if s.is_empty() || s == "n/a" || s.starts_with('-') {
        return None;
    }

    // Strip leading day-of-week prefix (e.g. "Mon ")
    let ts = s.trim();
    let ts = ts.split(' ').skip(1).collect::<Vec<&str>>().join(" ");
    if ts.is_empty() {
        return None;
    }

    // Use Unix `date` command to parse systemd's timestamp format
    let output = std::process::Command::new("date")
        .args(["-d", ts.as_str(), "+%s"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.trim().parse().ok()
}
