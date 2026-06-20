use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivitySample {
    pub timestamp: DateTime<Utc>,
    pub cpu_time_ms: u64,
    pub memory_bytes: u64,
    pub fd_count: u32,
    pub thread_count: u32,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityDelta {
    pub cpu_delta: u64,
    pub memory_delta: i64,
    pub fd_delta: i32,
    pub thread_delta: i32,
    pub network_rx_delta: u64,
    pub network_tx_delta: u64,
    pub disk_read_delta: u64,
    pub disk_write_delta: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentActivityTracker {
    pub pid: u32,
    pub agent_name: String,
    pub samples: VecDeque<ActivitySample>,
    pub max_samples: usize,
    pub hang_threshold_secs: u64,
    pub last_heartbeat: DateTime<Utc>,
    pub is_hung: bool,
    pub hung_since: Option<DateTime<Utc>>,
}

impl AgentActivityTracker {
    pub fn new(pid: u32, agent_name: String, hang_threshold_secs: u64) -> Self {
        Self {
            pid,
            agent_name,
            samples: VecDeque::with_capacity(100),
            max_samples: 100,
            hang_threshold_secs,
            last_heartbeat: Utc::now(),
            is_hung: false,
            hung_since: None,
        }
    }

    pub fn record_sample(&mut self, sample: ActivitySample) {
        self.last_heartbeat = Utc::now();
        if self.samples.len() >= self.max_samples {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    pub fn calculate_delta(&self) -> Option<ActivityDelta> {
        if self.samples.len() < 2 {
            return None;
        }

        let current = self.samples.back()?;
        let previous = self.samples.get(self.samples.len() - 2)?;

        Some(ActivityDelta {
            cpu_delta: current.cpu_time_ms.saturating_sub(previous.cpu_time_ms),
            memory_delta: current.memory_bytes as i64 - previous.memory_bytes as i64,
            fd_delta: current.fd_count as i32 - previous.fd_count as i32,
            thread_delta: current.thread_count as i32 - previous.thread_count as i32,
            network_rx_delta: current.network_rx_bytes.saturating_sub(previous.network_rx_bytes),
            network_tx_delta: current.network_tx_bytes.saturating_sub(previous.network_tx_bytes),
            disk_read_delta: current.disk_read_bytes.saturating_sub(previous.disk_read_bytes),
            disk_write_delta: current.disk_write_bytes.saturating_sub(previous.disk_write_bytes),
        })
    }

    pub fn is_activity_significant(&self) -> bool {
        let delta = match self.calculate_delta() {
            Some(d) => d,
            None => return true,
        };

        let cpu_active = delta.cpu_delta > 100;
        let memory_changed = delta.memory_delta.abs() > 1024;
        let fd_changed = delta.fd_delta != 0;
        let thread_changed = delta.thread_delta != 0;
        let network_active = delta.network_rx_delta > 0 || delta.network_tx_delta > 0;
        let disk_active = delta.disk_read_delta > 0 || delta.disk_write_delta > 0;

        cpu_active || memory_changed || fd_changed || thread_changed || network_active || disk_active
    }

    pub fn detect_hang(&mut self) -> bool {
        if self.samples.is_empty() {
            return false;
        }

        let last_sample = self.samples.back().unwrap();
        let elapsed = Utc::now().signed_duration_since(last_sample.timestamp);
        let threshold = chrono::Duration::seconds(self.hang_threshold_secs as i64);

        let hung = !self.is_activity_significant() && elapsed > threshold;

        if hung && !self.is_hung {
            self.is_hung = true;
            self.hung_since = Some(last_sample.timestamp);
            tracing::warn!(
                "Agent {} (PID {}) detected as HUNG - no activity for {}s",
                self.agent_name,
                self.pid,
                elapsed.num_seconds()
            );
        } else if !hung && self.is_hung {
            self.is_hung = false;
            self.hung_since = None;
            tracing::info!(
                "Agent {} (PID {}) recovered from HUNG state",
                self.agent_name,
                self.pid
            );
        }

        self.is_hung
    }

    pub fn get_activity_summary(&self) -> ActivitySummary {
        let samples: Vec<&ActivitySample> = self.samples.iter().collect();
        let count = samples.len();

        if count == 0 {
            return ActivitySummary::default();
        }

        let avg_cpu = samples.iter().map(|s| s.cpu_time_ms).sum::<u64>() / count as u64;
        let avg_memory = samples.iter().map(|s| s.memory_bytes).sum::<u64>() / count as u64;
        let avg_fds = samples.iter().map(|s| s.fd_count).sum::<u32>() / count as u32;
        let avg_threads = samples.iter().map(|s| s.thread_count).sum::<u32>() / count as u32;

        ActivitySummary {
            sample_count: count,
            avg_cpu_time_ms: avg_cpu,
            avg_memory_bytes: avg_memory,
            avg_fd_count: avg_fds,
            avg_thread_count: avg_threads,
            is_hung: self.is_hung,
            hung_since: self.hung_since,
            last_heartbeat: self.last_heartbeat,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActivitySummary {
    pub sample_count: usize,
    pub avg_cpu_time_ms: u64,
    pub avg_memory_bytes: u64,
    pub avg_fd_count: u32,
    pub avg_thread_count: u32,
    pub is_hung: bool,
    pub hung_since: Option<DateTime<Utc>>,
    pub last_heartbeat: DateTime<Utc>,
}
