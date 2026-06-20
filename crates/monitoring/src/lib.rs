use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Agent health state machine
// ---------------------------------------------------------------------------

/// Agent lifecycle states for the daemon state machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AgentHealthState {
    Unknown,
    Healthy,
    Warning,
    Failed,
    Restarting,
}

impl AgentHealthState {
    /// Return the string representation for persistence.
    pub fn as_str(&self) -> &'static str {
        match self {
            AgentHealthState::Unknown => "unknown",
            AgentHealthState::Healthy => "healthy",
            AgentHealthState::Warning => "warning",
            AgentHealthState::Failed => "failed",
            AgentHealthState::Restarting => "restarting",
        }
    }

    /// Map from a DB status string to a state.
    /// Falls back to Unknown for unrecognised values.
    pub fn from_str(s: &str) -> Self {
        match s {
            "healthy" => AgentHealthState::Healthy,
            "warning" => AgentHealthState::Warning,
            "failed" => AgentHealthState::Failed,
            "restarting" => AgentHealthState::Restarting,
            _ => AgentHealthState::Unknown,
        }
    }
}

// ---------------------------------------------------------------------------
// Health status per agent
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub pid: u32,
    pub name: String,
    pub state: AgentHealthState,
    pub alive: bool,
    pub cpu_percent: f64,
    pub memory_mb: f64,
    pub consecutive_failures: u32,
}

// ---------------------------------------------------------------------------
// Restart engine
// ---------------------------------------------------------------------------

/// Configuration for the restart engine.
#[derive(Debug, Clone)]
pub struct RestartConfig {
    /// Initial backoff duration (e.g. 2 seconds).
    pub initial_backoff: Duration,
    /// Maximum backoff duration (e.g. 5 minutes).
    pub max_backoff: Duration,
    /// Maximum number of restart attempts before giving up.
    /// `None` means unlimited.
    pub max_retries: Option<u32>,
    /// Cooldown period after a successful restart before considering
    /// the agent stable.
    pub cooldown: Duration,
}

impl Default for RestartConfig {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(300), // 5 minutes
            max_retries: Some(5),
            cooldown: Duration::from_secs(30),
        }
    }
}

/// Tracks restart state for a single agent.
#[derive(Debug, Clone)]
pub struct RestartState {
    pub pid: u32,
    pub name: String,
    pub attempt: u32,
    last_attempt: Option<Instant>,
    pub cooldown_until: Option<Instant>,
}

impl RestartState {
    pub fn new(pid: u32, name: String) -> Self {
        Self {
            pid,
            name,
            attempt: 0,
            last_attempt: None,
            cooldown_until: None,
        }
    }

    /// Compute the backoff duration for the next attempt (exponential: 2^n seconds,
    /// capped at `max_backoff`).
    pub fn next_backoff(&self, config: &RestartConfig) -> Duration {
        let secs = config.initial_backoff.as_secs() as u64 * 2u64.pow(self.attempt);
        Duration::from_secs(secs.min(config.max_backoff.as_secs()))
    }

    /// Returns `true` if the agent is allowed to restart now.
    pub fn can_retry(&self, config: &RestartConfig) -> bool {
        if let Some(max) = config.max_retries {
            if self.attempt >= max {
                return false;
            }
        }
        if let Some(cooldown_until) = self.cooldown_until {
            if Instant::now() < cooldown_until {
                return false;
            }
        }
        if let Some(last) = self.last_attempt {
            Instant::now().duration_since(last) >= self.next_backoff(config)
        } else {
            true
        }
    }

    /// Record a restart attempt.
    pub fn record_attempt(&mut self) {
        self.attempt += 1;
        self.last_attempt = Some(Instant::now());
    }

    /// Mark as recovered (reset attempt counter and start cooldown).
    pub fn mark_recovered(&mut self, config: &RestartConfig) {
        self.attempt = 0;
        self.cooldown_until = Some(Instant::now() + config.cooldown);
    }
}

/// The restart engine manages restart attempts per agent.
pub struct RestartEngine {
    agents: HashMap<u32, RestartState>,
    config: RestartConfig,
}

impl Default for RestartEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RestartEngine {
    pub fn new() -> Self {
        Self {
            agents: HashMap::new(),
            config: RestartConfig::default(),
        }
    }

    pub fn with_config(config: RestartConfig) -> Self {
        Self {
            agents: HashMap::new(),
            config,
        }
    }

    pub fn register_agent(&mut self, pid: u32, name: String) {
        self.agents
            .entry(pid)
            .or_insert_with(|| RestartState::new(pid, name));
    }

    pub fn unregister_agent(&mut self, pid: u32) {
        self.agents.remove(&pid);
    }

    /// Returns `true` if the agent should be restarted now.
    pub fn should_restart(&mut self, pid: u32) -> bool {
        let Some(agent) = self.agents.get(&pid) else {
            return false;
        };
        if !agent.can_retry(&self.config) {
            return false;
        }
        true
    }

    /// Record that a restart attempt was made for this agent.
    pub fn record_attempt(&mut self, pid: u32) {
        if let Some(agent) = self.agents.get_mut(&pid) {
            agent.record_attempt();
        }
    }

    /// Mark the agent as recovered (reset backoff, start cooldown).
    pub fn mark_recovered(&mut self, pid: u32) {
        if let Some(agent) = self.agents.get_mut(&pid) {
            agent.mark_recovered(&self.config);
        }
    }

    /// Get the current restart attempt count for an agent.
    pub fn attempt_count(&self, pid: u32) -> u32 {
        self.agents.get(&pid).map(|a| a.attempt).unwrap_or(0)
    }

    /// Returns the list of agent PIDs that should be restarted.
    pub fn pending_restarts(&mut self) -> Vec<(u32, String)> {
        let mut pending = Vec::new();
        let pids: Vec<u32> = self.agents.keys().copied().collect();
        for pid in pids {
            if self.should_restart(pid) {
                if let Some(name) = self.agents.get(&pid).map(|a| a.name.clone()) {
                    pending.push((pid, name));
                }
            }
        }
        pending
    }
}

// ---------------------------------------------------------------------------
// Health monitor
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthEvent {
    AgentDied { pid: u32, name: String },
    AgentUnhealthy { pid: u32, name: String, reason: String },
    AgentRecovered { pid: u32, name: String },
    AgentRestarted { pid: u32, name: String, attempt: u32 },
}

pub struct HealthMonitor {
    agents: HashMap<u32, HealthStatus>,
    failure_threshold: u32,
    /// Last observed CPU ticks (utime + stime) per PID for hang detection
    last_cpu_ticks: HashMap<u32, u64>,
    /// Consecutive cycles with zero CPU delta while process is alive
    zero_delta_cycles: HashMap<u32, u32>,
    /// Number of zero-delta cycles before flagging a process as hung
    hang_threshold_cycles: u32,
}

impl Default for HealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthMonitor {
    pub fn new() -> Self {
        Self {
            agents: HashMap::new(),
            failure_threshold: 3,
            last_cpu_ticks: HashMap::new(),
            zero_delta_cycles: HashMap::new(),
            hang_threshold_cycles: 6, // ~30 seconds at 5s check interval
        }
    }

    pub fn with_failure_threshold(threshold: u32) -> Self {
        Self {
            agents: HashMap::new(),
            failure_threshold: threshold,
            last_cpu_ticks: HashMap::new(),
            zero_delta_cycles: HashMap::new(),
            hang_threshold_cycles: 6,
        }
    }

    pub fn register_agent(&mut self, pid: u32, name: String) {
        self.agents.entry(pid).or_insert_with(|| HealthStatus {
            pid,
            name,
            state: AgentHealthState::Unknown,
            alive: true,
            cpu_percent: 0.0,
            memory_mb: 0.0,
            consecutive_failures: 0,
        });
    }

    pub fn unregister_agent(&mut self, pid: u32) {
        self.agents.remove(&pid);
    }

    /// Manually update the state of an agent (e.g. after a restart attempt).
    pub fn set_agent_state(&mut self, pid: u32, state: AgentHealthState) {
        if let Some(agent) = self.agents.get_mut(&pid) {
            agent.state = state;
        }
    }

    pub fn get_agent_state(&self, pid: u32) -> Option<AgentHealthState> {
        self.agents.get(&pid).map(|a| a.state.clone())
    }

    /// Run a single health check cycle on all registered agents.
    pub fn check_health(&mut self) -> Result<Vec<HealthEvent>> {
        let mut events = Vec::new();
        let pids: Vec<u32> = self.agents.keys().copied().collect();

        for pid in pids {
            let is_alive = check_process_alive(pid);

            let status = self.agents.get_mut(&pid).unwrap();

            if is_alive {
                let was_dead = !status.alive || status.state == AgentHealthState::Failed
                    || status.state == AgentHealthState::Restarting;

                status.alive = true;
                status.consecutive_failures = 0;

                if let Some((cpu, mem)) = get_process_stats(pid) {
                    status.cpu_percent = cpu;
                    status.memory_mb = mem;
                }

                // Hang detection: check CPU tick deltas from /proc/[pid]/stat
                let current_ticks = read_cpu_ticks(pid);
                let is_hung = if let Some(current_ticks) = current_ticks {
                    let last = self.last_cpu_ticks.get(&pid).copied();
                    self.last_cpu_ticks.insert(pid, current_ticks);

                    let delta = last.map(|l| current_ticks.saturating_sub(l)).unwrap_or(1);
                    if delta == 0 {
                        let count = self.zero_delta_cycles.entry(pid).or_insert(0);
                        *count += 1;
                        *count >= self.hang_threshold_cycles
                    } else {
                        self.zero_delta_cycles.remove(&pid);
                        false
                    }
                } else {
                    false
                };

                if is_hung {
                    status.state = AgentHealthState::Warning;
                    events.push(HealthEvent::AgentUnhealthy {
                        pid,
                        name: status.name.clone(),
                        reason: "process appears hung (zero CPU delta)".to_string(),
                    });
                } else {
                    status.state = AgentHealthState::Healthy;
                    if was_dead {
                        events.push(HealthEvent::AgentRecovered {
                            pid,
                            name: status.name.clone(),
                        });
                    }
                }
            } else {
                status.consecutive_failures += 1;
                // Process died — clear hang state
                self.zero_delta_cycles.remove(&pid);
                self.last_cpu_ticks.remove(&pid);

                if status.consecutive_failures >= self.failure_threshold && status.alive {
                    status.alive = false;
                    status.state = AgentHealthState::Failed;
                    events.push(HealthEvent::AgentDied {
                        pid,
                        name: status.name.clone(),
                    });
                } else if status.consecutive_failures >= 1 && status.alive {
                    status.state = AgentHealthState::Warning;
                }
            }
        }

        Ok(events)
    }

    pub fn agent_count(&self) -> usize {
        self.agents.len()
    }

    pub fn alive_count(&self) -> usize {
        self.agents.values().filter(|a| a.alive).count()
    }

    pub fn failed_count(&self) -> usize {
        self.agents
            .values()
            .filter(|a| a.state == AgentHealthState::Failed)
            .count()
    }
}

// ---------------------------------------------------------------------------
// Cross-platform health check primitives
// ---------------------------------------------------------------------------

/// Check if a process is alive by sending signal 0 (no-op).
/// Works on both Linux and macOS.
fn check_process_alive(pid: u32) -> bool {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // Safety: signal 0 is a no-op that only checks if the process exists
        // and we have permission to signal it.
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // Fallback: check /proc existence (Linux-specific but generic fallback)
        std::path::Path::new(&format!("/proc/{}", pid)).exists()
    }
}

/// Get CPU and memory stats for a process.
/// Returns `(cpu_percent, memory_mb)`.
fn get_process_stats(pid: u32) -> Option<(f64, f64)> {
    #[cfg(target_os = "linux")]
    {
        get_process_stats_linux(pid)
    }

    #[cfg(target_os = "macos")]
    {
        get_process_stats_macos(pid)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

#[cfg(target_os = "linux")]
fn get_process_stats_linux(pid: u32) -> Option<(f64, f64)> {
    let status = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    let fields: Vec<&str> = status.split_whitespace().collect();
    if fields.len() >= 22 {
        let utime: f64 = fields[13].parse().ok()?;
        let stime: f64 = fields[14].parse().ok()?;
        let total_ticks = utime + stime;
        // Read system uptime to compute approximate CPU percentage
        let uptime_info = std::fs::read_to_string("/proc/uptime").ok()?;
        let uptime_secs: f64 = uptime_info.split_whitespace().next()?.parse().ok()?;
        // Convert ticks (usually 100 per second on Linux) to seconds
        let clk_tck: f64 = 100.0;
        let process_secs = total_ticks / clk_tck;
        let cpu_percent = if uptime_secs > 0.0 {
            (process_secs / uptime_secs) * 100.0
        } else {
            0.0
        };
        // RSS is field 24 (0-indexed), but commonly field 24 in /proc/pid/stat
        // Actually utime is field 13 (0-indexed), stime is field 14, and RSS is field 23
        // Let me check the correct field: cutime is field 15, cstime is field 16, then priority, nice, num_threads, itrealvalue, starttime, vsize, rss
        // rss is field 24 (0-indexed) in the stat file
        // Actually field 24 is rss (number of pages)
        let rss_pages: f64 = fields.get(23).and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let memory_mb = rss_pages * 4.0 / 1024.0;
        Some((cpu_percent.min(100.0), memory_mb))
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn get_process_stats_macos(pid: u32) -> Option<(f64, f64)> {
    use std::process::Command;

    let output = Command::new("ps")
        .args(["-o", "%cpu=,rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parts: Vec<&str> = stdout.split_whitespace().collect();
    if parts.len() >= 2 {
        let cpu: f64 = parts[0].parse().ok()?;
        let rss_kb: f64 = parts[1].parse().ok()?;
        let memory_mb = rss_kb / 1024.0;
        Some((cpu, memory_mb))
    } else {
        None
    }
}

/// Read raw CPU ticks (utime + stime) from /proc/[pid]/stat.
/// Returns None if the file cannot be read or parsed.
fn read_cpu_ticks(pid: u32) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
        let fields: Vec<&str> = stat.split_whitespace().collect();
        if fields.len() < 15 { return None; }
        let utime: u64 = fields[13].parse().ok()?;
        let stime: u64 = fields[14].parse().ok()?;
        Some(utime + stime)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_restart_state_backoff() {
        let config = RestartConfig::default();
        let mut state = RestartState::new(1, "test".to_string());

        // First attempt: 2 seconds (2 * 2^0)
        assert_eq!(state.next_backoff(&config), Duration::from_secs(2));

        state.attempt = 1;
        // Second attempt: 4 seconds (2 * 2^1)
        assert_eq!(state.next_backoff(&config), Duration::from_secs(4));

        state.attempt = 2;
        // Third attempt: 8 seconds
        assert_eq!(state.next_backoff(&config), Duration::from_secs(8));

        state.attempt = 8;
        // Should be capped at max (300 seconds)
        assert_eq!(state.next_backoff(&config), Duration::from_secs(300));
    }

    #[test]
    fn test_max_retries() {
        // Use a zero initial backoff so retries are not blocked by timing
        let config = RestartConfig {
            initial_backoff: Duration::from_secs(0),
            max_backoff: Duration::from_secs(0),
            max_retries: Some(3),
            ..Default::default()
        };
        let mut state = RestartState::new(1, "test".to_string());

        // Allow first 3 attempts
        assert!(state.can_retry(&config));
        state.record_attempt();
        assert!(state.can_retry(&config));
        state.record_attempt();
        assert!(state.can_retry(&config));
        state.record_attempt();

        // 4th attempt should be blocked
        assert!(!state.can_retry(&config));
    }

    #[test]
    fn test_health_monitor_new() {
        let mut monitor = HealthMonitor::new();
        monitor.register_agent(42, "test-agent".to_string());

        assert_eq!(monitor.agent_count(), 1);
        assert_eq!(monitor.alive_count(), 1);
    }
}
