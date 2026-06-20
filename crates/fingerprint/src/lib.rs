use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Agent fingerprint structure
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestinationFingerprint {
    pub domains: Vec<String>,
    pub ip_ranges: Vec<String>,
    pub ports: HashSet<u16>,
    pub protocols: HashSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficFingerprint {
    pub avg_bytes_in_per_min: f64,
    pub avg_bytes_out_per_min: f64,
    pub std_dev_bytes_in: f64,
    pub std_dev_bytes_out: f64,
    pub avg_connection_count: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingFingerprint {
    pub active_hours: HashSet<u8>,
    pub avg_requests_per_min: f64,
    pub peak_hour: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessFingerprint {
    pub typical_cpu_percent: f64,
    pub typical_memory_mb: f64,
    pub typical_fd_count: u32,
    pub typical_thread_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentFingerprint {
    pub id: Uuid,
    pub pid: u32,
    pub agent_name: String,
    pub version: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub destinations: DestinationFingerprint,
    pub traffic: TrafficFingerprint,
    pub timing: TimingFingerprint,
    pub process: ProcessFingerprint,
    pub confidence_score: f64,
    pub sample_count: u64,
}

// ---------------------------------------------------------------------------
// Fingerprint builder
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FingerprintBuilder {
    pub pid: u32,
    pub agent_name: String,
    domains: Vec<String>,
    ip_ranges: Vec<String>,
    ports: HashSet<u16>,
    protocols: HashSet<String>,
    bytes_in_samples: Vec<f64>,
    bytes_out_samples: Vec<f64>,
    connection_samples: Vec<f64>,
    hourly_samples: HashMap<u8, u64>,
    cpu_samples: Vec<f64>,
    memory_samples: Vec<f64>,
    fd_samples: Vec<u32>,
    thread_samples: Vec<u32>,
    sample_count: u64,
}

impl FingerprintBuilder {
    pub fn new(pid: u32, agent_name: String) -> Self {
        Self {
            pid,
            agent_name,
            domains: Vec::new(),
            ip_ranges: Vec::new(),
            ports: HashSet::new(),
            protocols: HashSet::new(),
            bytes_in_samples: Vec::new(),
            bytes_out_samples: Vec::new(),
            connection_samples: Vec::new(),
            hourly_samples: HashMap::new(),
            cpu_samples: Vec::new(),
            memory_samples: Vec::new(),
            fd_samples: Vec::new(),
            thread_samples: Vec::new(),
            sample_count: 0,
        }
    }

    pub fn record_sample(
        &mut self,
        domains: Vec<String>,
        ip_range: String,
        port: u16,
        protocol: String,
        bytes_in: f64,
        bytes_out: f64,
        connection_count: f64,
        hour: u8,
        cpu_percent: f64,
        memory_mb: f64,
        fd_count: u32,
        thread_count: u32,
    ) {
        self.sample_count += 1;

        for domain in domains {
            if !self.domains.contains(&domain) {
                self.domains.push(domain);
            }
        }
        if !self.ip_ranges.contains(&ip_range) {
            self.ip_ranges.push(ip_range);
        }
        self.ports.insert(port);
        self.protocols.insert(protocol);

        self.bytes_in_samples.push(bytes_in);
        self.bytes_out_samples.push(bytes_out);
        self.connection_samples.push(connection_count);

        *self.hourly_samples.entry(hour).or_insert(0) += 1;

        self.cpu_samples.push(cpu_percent);
        self.memory_samples.push(memory_mb);
        self.fd_samples.push(fd_count);
        self.thread_samples.push(thread_count);
    }

    /// Build the fingerprint from collected samples.
    pub fn build(&self) -> AgentFingerprint {
        let now = Utc::now();

        let (avg_in, std_in) = compute_stats(&self.bytes_in_samples);
        let (avg_out, std_out) = compute_stats(&self.bytes_out_samples);
        let (avg_conn, _) = compute_stats(&self.connection_samples);

        let peak_hour = self
            .hourly_samples
            .iter()
            .max_by_key(|(_, count)| **count)
            .map(|(hour, _)| *hour)
            .unwrap_or(12);

        let active_hours: HashSet<u8> = self
            .hourly_samples
            .iter()
            .filter(|(_, count)| **count > 0)
            .map(|(hour, _)| *hour)
            .collect();

        let (avg_cpu, _) = compute_stats(&self.cpu_samples);
        let (avg_mem, _) = compute_stats(&self.memory_samples);

        let avg_fd = if self.fd_samples.is_empty() {
            0.0
        } else {
            self.fd_samples.iter().sum::<u32>() as f64 / self.fd_samples.len() as f64
        };

        let avg_thread = if self.thread_samples.is_empty() {
            0.0
        } else {
            self.thread_samples.iter().sum::<u32>() as f64 / self.thread_samples.len() as f64
        };

        // Confidence score: 0-100 based on sample count
        let confidence_score = (self.sample_count as f64 / 1000.0 * 100.0).min(100.0);

        AgentFingerprint {
            id: Uuid::new_v4(),
            pid: self.pid,
            agent_name: self.agent_name.clone(),
            version: 1,
            created_at: now,
            updated_at: now,
            destinations: DestinationFingerprint {
                domains: self.domains.clone(),
                ip_ranges: self.ip_ranges.clone(),
                ports: self.ports.clone(),
                protocols: self.protocols.clone(),
            },
            traffic: TrafficFingerprint {
                avg_bytes_in_per_min: avg_in,
                avg_bytes_out_per_min: avg_out,
                std_dev_bytes_in: std_in,
                std_dev_bytes_out: std_out,
                avg_connection_count: avg_conn,
            },
            timing: TimingFingerprint {
                active_hours,
                avg_requests_per_min: avg_conn,
                peak_hour,
            },
            process: ProcessFingerprint {
                typical_cpu_percent: avg_cpu,
                typical_memory_mb: avg_mem,
                typical_fd_count: avg_fd as u32,
                typical_thread_count: avg_thread as u32,
            },
            confidence_score,
            sample_count: self.sample_count,
        }
    }
}

// ---------------------------------------------------------------------------
// Fingerprint version manager
// ---------------------------------------------------------------------------

pub struct FingerprintManager {
    /// Current fingerprints per PID
    fingerprints: HashMap<u32, AgentFingerprint>,
    /// Historical fingerprints per PID (append-only)
    history: HashMap<u32, Vec<AgentFingerprint>>,
    /// Fingerprint builders per PID (in-progress data)
    builders: HashMap<u32, FingerprintBuilder>,
}

impl FingerprintManager {
    pub fn new() -> Self {
        Self {
            fingerprints: HashMap::new(),
            history: HashMap::new(),
            builders: HashMap::new(),
        }
    }

    pub fn register_agent(&mut self, pid: u32, name: String) {
        self.builders
            .entry(pid)
            .or_insert_with(|| FingerprintBuilder::new(pid, name));
    }

    /// Record a sample for fingerprint building.
    pub fn record_sample(
        &mut self,
        pid: u32,
        domains: Vec<String>,
        ip: String,
        port: u16,
        protocol: String,
        bytes_in: f64,
        bytes_out: f64,
        connection_count: f64,
        hour: u8,
        cpu_percent: f64,
        memory_mb: f64,
        fd_count: u32,
        thread_count: u32,
    ) {
        if let Some(builder) = self.builders.get_mut(&pid) {
            builder.record_sample(
                domains,
                ip,
                port,
                protocol,
                bytes_in,
                bytes_out,
                connection_count,
                hour,
                cpu_percent,
                memory_mb,
                fd_count,
                thread_count,
            );
        }
    }

    /// Finalize the current fingerprint and create a new version.
    /// Returns the new fingerprint.
    pub fn finalize_fingerprint(&mut self, pid: u32) -> Option<AgentFingerprint> {
        let builder = self.builders.get(&pid)?;
        let mut fingerprint = builder.build();

        // If there's a previous version, increment version
        if let Some(current) = self.fingerprints.get(&pid) {
            fingerprint.version = current.version + 1;
        }

        // Store in history (append-only)
        self.history
            .entry(pid)
            .or_default()
            .push(fingerprint.clone());

        // Update current fingerprint
        self.fingerprints.insert(pid, fingerprint.clone());

        // Reset builder for next version
        self.builders.insert(
            pid,
            FingerprintBuilder::new(pid, builder.agent_name.clone()),
        );

        Some(fingerprint)
    }

    /// Get the current fingerprint for an agent.
    pub fn get_fingerprint(&self, pid: u32) -> Option<&AgentFingerprint> {
        self.fingerprints.get(&pid)
    }

    /// Get fingerprint history (never overwritten, append-only).
    pub fn get_history(&self, pid: u32) -> Vec<&AgentFingerprint> {
        self.history.get(&pid).map(|v| v.iter().collect()).unwrap_or_default()
    }

    /// Detect fingerprint drift between current and previous version.
    /// Returns a drift score (0-100) with details.
    pub fn detect_drift(&self, pid: u32) -> Option<FingerprintDrift> {
        let history = self.history.get(&pid)?;
        if history.len() < 2 {
            return None;
        }

        let current = history.last()?;
        let previous = history.get(history.len() - 2)?;

        // Calculate drift for each component
        let new_destinations: Vec<&str> = current
            .destinations
            .domains
            .iter()
            .filter(|d| !previous.destinations.domains.contains(d))
            .map(|s| s.as_str())
            .collect();

        let new_ports: Vec<u16> = current
            .destinations
            .ports
            .iter()
            .filter(|p| !previous.destinations.ports.contains(p))
            .copied()
            .collect();

        let traffic_change = if previous.traffic.avg_bytes_in_per_min > 0.0 {
            ((current.traffic.avg_bytes_in_per_min - previous.traffic.avg_bytes_in_per_min)
                / previous.traffic.avg_bytes_in_per_min)
                * 100.0
        } else {
            0.0
        };

        let time_change = if previous.timing.active_hours.is_empty() {
            0.0
        } else {
            let new_hours: HashSet<&u8> = current
                .timing
                .active_hours
                .difference(&previous.timing.active_hours)
                .collect();
            new_hours.len() as f64 / previous.timing.active_hours.len() as f64 * 100.0
        };

        // Overall drift score
        let dest_score = (new_destinations.len() as f64 / previous.destinations.domains.len().max(1) as f64) * 30.0;
        let port_score = (new_ports.len() as f64 / previous.destinations.ports.len().max(1) as f64) * 20.0;
        let traffic_score = (traffic_change.abs() / 200.0).min(1.0) * 30.0;
        let time_score = (time_change / 100.0).min(1.0) * 20.0;

        let drift_score = (dest_score + port_score + traffic_score + time_score).min(100.0);

        Some(FingerprintDrift {
            drift_score,
            new_destinations: new_destinations.iter().map(|s| s.to_string()).collect(),
            traffic_change_percent: traffic_change,
            time_change_percent: time_change,
            dest_score,
            port_score,
            traffic_score,
            time_score,
        })
    }
}

impl Default for FingerprintManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintDrift {
    pub drift_score: f64,
    pub new_destinations: Vec<String>,
    pub traffic_change_percent: f64,
    pub time_change_percent: f64,
    pub dest_score: f64,
    pub port_score: f64,
    pub traffic_score: f64,
    pub time_score: f64,
}

// ---------------------------------------------------------------------------
// Statistics helper
// ---------------------------------------------------------------------------

/// Compute mean and standard deviation of a slice of f64 values.
fn compute_stats(values: &[f64]) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }

    let count = values.len() as f64;
    let mean = values.iter().sum::<f64>() / count;

    if values.len() < 2 {
        return (mean, 0.0);
    }

    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (count - 1.0);
    let std_dev = variance.sqrt();

    (mean, std_dev)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_build() {
        let mut builder = FingerprintBuilder::new(1234, "test-agent".to_string());

        for i in 0..100 {
            builder.record_sample(
                vec!["api.openai.com".to_string()],
                "1.2.3.0/24".to_string(),
                443,
                "tcp".to_string(),
                1000.0,
                500.0,
                3.0,
                10,
                5.0,
                100.0,
                10,
                4,
            );
        }

        let fp = builder.build();
        assert_eq!(fp.pid, 1234);
        assert_eq!(fp.agent_name, "test-agent");
        assert!(!fp.destinations.domains.is_empty());
        assert!(fp.confidence_score > 0.0);
    }

    #[test]
    fn test_fingerprint_versioning() {
        let mut manager = FingerprintManager::new();
        manager.register_agent(1234, "test-agent".to_string());

        // Record samples and finalize version 1
        for _ in 0..50 {
            manager.record_sample(
                1234,
                vec!["api.openai.com".to_string()],
                "1.2.3.0/24".to_string(),
                443,
                "tcp".to_string(),
                1000.0,
                500.0,
                3.0,
                10,
                5.0,
                100.0,
                10,
                4,
            );
        }
        let v1 = manager.finalize_fingerprint(1234).unwrap();
        assert_eq!(v1.version, 1);

        // Record more samples and finalize version 2
        for _ in 0..50 {
            manager.record_sample(
                1234,
                vec!["new-domain.com".to_string()],
                "5.6.7.0/24".to_string(),
                    8080,
                "tcp".to_string(),
                2000.0,
                1000.0,
                5.0,
                14,
                10.0,
                200.0,
                15,
                8,
            );
        }
        let v2 = manager.finalize_fingerprint(1234).unwrap();
        assert_eq!(v2.version, 2);

        // History should have both versions
        let history = manager.get_history(1234);
        assert_eq!(history.len(), 2);
    }

    #[test]
    fn test_drift_detection() {
        let mut manager = FingerprintManager::new();
        manager.register_agent(1234, "test-agent".to_string());

        // Build version 1 with limited destinations
        for _ in 0..50 {
            manager.record_sample(
                1234,
                vec!["api.openai.com".to_string()],
                "1.2.3.0/24".to_string(),
                443,
                "tcp".to_string(),
                1000.0,
                500.0,
                3.0,
                10,
                5.0,
                100.0,
                10,
                4,
            );
        }
        manager.finalize_fingerprint(1234);

        // Build version 2 with new destinations
        for _ in 0..50 {
            manager.record_sample(
                1234,
                vec![
                    "unknown-malicious.com".to_string(),
                    "data-exfil.com".to_string(),
                ],
                "10.0.0.0/8".to_string(),
                8080,
                "tcp".to_string(),
                10000.0,
                50000.0,
                20.0,
                3, // unusual hour
                50.0,
                500.0,
                50,
                20,
            );
        }
        manager.finalize_fingerprint(1234);

        // Detect drift
        let drift = manager.detect_drift(1234);
        assert!(drift.is_some());
        let drift = drift.unwrap();
        assert!(drift.drift_score > 0.0);
        assert!(!drift.new_destinations.is_empty());
    }

    #[test]
    fn test_append_only_history() {
        let mut manager = FingerprintManager::new();
        manager.register_agent(1, "agent".to_string());
        manager.finalize_fingerprint(1);
        manager.finalize_fingerprint(1);
        manager.finalize_fingerprint(1);

        let history = manager.get_history(1);
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].version, 1);
        assert_eq!(history[1].version, 2);
        assert_eq!(history[2].version, 3);
    }

    #[test]
    fn test_confidence_score_scale() {
        let builder = FingerprintBuilder::new(1, "test".to_string());
        let fp = builder.build();

        // With no samples, confidence should be 0
        assert!(fp.confidence_score == 0.0);
    }

    #[test]
    fn test_compute_stats() {
        let values = vec![10.0, 20.0, 30.0, 40.0, 50.0];
        let (mean, std_dev) = compute_stats(&values);
        assert!((mean - 30.0).abs() < 0.001);
        assert!((std_dev - 15.811).abs() < 0.01);

        let (mean, std_dev) = compute_stats(&[]);
        assert_eq!(mean, 0.0);
        assert_eq!(std_dev, 0.0);
    }
}
