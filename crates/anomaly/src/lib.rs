use chrono::{DateTime, Utc};
use omnisec_events::{AnomalyType, BaselineState, RiskLevel};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Anomaly record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyRecord {
    pub id: String,
    pub pid: u32,
    pub agent_name: String,
    pub anomaly_type: AnomalyType,
    pub severity: AnomalySeverity,
    pub description: String,
    pub current_value: f64,
    pub baseline_value: f64,
    pub deviation: f64,
    pub detected_at: DateTime<Utc>,
    pub resolved: bool,
    pub resolved_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
    Critical,
}

// ---------------------------------------------------------------------------
// Anomaly detection configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AnomalyConfig {
    /// Multiplier above baseline to trigger traffic spike
    pub traffic_spike_multiplier: f64,
    /// Outbound/inbound ratio threshold for outbound spike
    pub outbound_ratio_threshold: f64,
    /// Drift score threshold (0-100) to trigger behavioral drift alert
    pub drift_threshold: f64,
    /// Connection count spike multiplier
    pub connection_spike_multiplier: f64,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            traffic_spike_multiplier: 3.0,
            outbound_ratio_threshold: 5.0,
            drift_threshold: 30.0,
            connection_spike_multiplier: 3.0,
        }
    }
}

// ---------------------------------------------------------------------------
// Anomaly detection engine
// ---------------------------------------------------------------------------

pub struct AnomalyDetector {
    config: AnomalyConfig,
    /// Detected anomalies per PID
    anomalies: HashMap<u32, Vec<AnomalyRecord>>,
    /// Baseline values per PID and metric
    baselines: HashMap<u32, HashMap<String, BaselineMetric>>,
}

#[derive(Debug, Clone)]
pub struct BaselineMetric {
    pub mean: f64,
    pub std_dev: f64,
    pub sample_count: u64,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self::with_config(AnomalyConfig::default())
    }

    pub fn with_config(config: AnomalyConfig) -> Self {
        Self {
            config,
            anomalies: HashMap::new(),
            baselines: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // New destination detection
    // -----------------------------------------------------------------------

    /// Check if a destination is new (not in known destinations).
    /// Returns an anomaly if the agent's baseline is established.
    pub fn check_new_destination(
        &mut self,
        pid: u32,
        agent_name: &str,
        destination: &str,
        port: u16,
        known_destinations: &[String],
        baseline_state: &BaselineState,
    ) -> Option<AnomalyRecord> {
        if *baseline_state != BaselineState::Established {
            return None;
        }

        let is_known = known_destinations.iter().any(|d| d == destination);
        if is_known {
            return None;
        }

        let record = AnomalyRecord {
            id: format!("new-dest-{}-{}", pid, Utc::now().timestamp()),
            pid,
            agent_name: agent_name.to_string(),
            anomaly_type: AnomalyType::NewDestination,
            severity: AnomalySeverity::Medium,
            description: format!(
                "Agent connected to unknown destination: {}:{}",
                destination, port
            ),
            current_value: 1.0,
            baseline_value: 0.0,
            deviation: 1.0,
            detected_at: Utc::now(),
            resolved: false,
            resolved_at: None,
        };

        self.anomalies.entry(pid).or_default().push(record.clone());
        Some(record)
    }

    // -----------------------------------------------------------------------
    // Traffic spike detection
    // -----------------------------------------------------------------------

    /// Check if current traffic rate exceeds the baseline by the configured multiplier.
    pub fn check_traffic_spike(
        &mut self,
        pid: u32,
        agent_name: &str,
        current_rate: f64,
        baseline_rate: f64,
        baseline_state: &BaselineState,
    ) -> Option<AnomalyRecord> {
        if *baseline_state == BaselineState::Learning {
            return None;
        }

        if baseline_rate <= 0.0 {
            // No baseline yet, only flag if traffic is very high
            if current_rate < 10_000.0 {
                return None;
            }
        } else if current_rate < baseline_rate * self.config.traffic_spike_multiplier {
            return None;
        }

        let deviation = if baseline_rate > 0.0 {
            current_rate / baseline_rate
        } else {
            current_rate / 1000.0
        };

        let severity = if deviation > 10.0 {
            AnomalySeverity::Critical
        } else if deviation > 5.0 {
            AnomalySeverity::High
        } else {
            AnomalySeverity::Medium
        };

        let record = AnomalyRecord {
            id: format!("traffic-{}-{}", pid, Utc::now().timestamp()),
            pid,
            agent_name: agent_name.to_string(),
            anomaly_type: AnomalyType::TrafficSpike,
            severity,
            description: format!(
                "Traffic spike detected: {:.1} bytes/min (baseline: {:.1})",
                current_rate, baseline_rate
            ),
            current_value: current_rate,
            baseline_value: baseline_rate,
            deviation,
            detected_at: Utc::now(),
            resolved: false,
            resolved_at: None,
        };

        self.anomalies.entry(pid).or_default().push(record.clone());
        Some(record)
    }

    // -----------------------------------------------------------------------
    // Outbound spike detection
    // -----------------------------------------------------------------------

    /// Check if outbound/inbound ratio exceeds threshold.
    pub fn check_outbound_spike(
        &mut self,
        pid: u32,
        agent_name: &str,
        outbound_bytes: u64,
        inbound_bytes: u64,
        baseline_state: &BaselineState,
    ) -> Option<AnomalyRecord> {
        if *baseline_state != BaselineState::Established {
            return None;
        }

        if inbound_bytes > 0 {
            let ratio = outbound_bytes as f64 / inbound_bytes as f64;
            if ratio < self.config.outbound_ratio_threshold {
                return None;
            }

            let record = AnomalyRecord {
                id: format!("outbound-{}-{}", pid, Utc::now().timestamp()),
                pid,
                agent_name: agent_name.to_string(),
                anomaly_type: AnomalyType::OutboundSpike,
                severity: if ratio > 20.0 {
                    AnomalySeverity::Critical
                } else if ratio > 10.0 {
                    AnomalySeverity::High
                } else {
                    AnomalySeverity::Medium
                },
                description: format!(
                    "Outbound traffic spike: {:.1}x outbound/inbound ratio",
                    ratio
                ),
                current_value: ratio,
                baseline_value: 1.0,
                deviation: ratio,
                detected_at: Utc::now(),
                resolved: false,
                resolved_at: None,
            };

            self.anomalies.entry(pid).or_default().push(record.clone());
            return Some(record);
        } else if outbound_bytes > 0 {
            // No inbound at all but outbound is flowing — suspicious
            let record = AnomalyRecord {
                id: format!("outbound-{}-{}", pid, Utc::now().timestamp()),
                pid,
                agent_name: agent_name.to_string(),
                anomaly_type: AnomalyType::OutboundSpike,
                severity: AnomalySeverity::High,
                description: format!(
                    "Outbound traffic with no inbound: {} bytes out",
                    outbound_bytes
                ),
                current_value: outbound_bytes as f64,
                baseline_value: 0.0,
                deviation: 10.0,
                detected_at: Utc::now(),
                resolved: false,
                resolved_at: None,
            };

            self.anomalies.entry(pid).or_default().push(record.clone());
            return Some(record);
        }

        None
    }

    // -----------------------------------------------------------------------
    // Time anomaly detection
    // -----------------------------------------------------------------------

    /// Check if activity at the given hour is anomalous.
    pub fn check_time_anomaly(
        &mut self,
        pid: u32,
        agent_name: &str,
        hour: u8,
        active_hours: &[u8],
        baseline_state: &BaselineState,
    ) -> Option<AnomalyRecord> {
        if *baseline_state != BaselineState::Established {
            return None;
        }

        if active_hours.is_empty() {
            return None;
        }

        let in_window = active_hours.contains(&hour);
        if in_window {
            return None;
        }

        let record = AnomalyRecord {
            id: format!("time-{}-{}", pid, Utc::now().timestamp()),
            pid,
            agent_name: agent_name.to_string(),
            anomaly_type: AnomalyType::ActivityTimeAnomaly,
            severity: AnomalySeverity::Low,
            description: format!(
                "Activity at unusual hour: {:02}:00 (active hours: {:?})",
                hour, active_hours
            ),
            current_value: hour as f64,
            baseline_value: active_hours.iter().map(|h| *h as f64).sum::<f64>()
                / active_hours.len() as f64,
            deviation: 1.0,
            detected_at: Utc::now(),
            resolved: false,
            resolved_at: None,
        };

        self.anomalies.entry(pid).or_default().push(record.clone());
        Some(record)
    }

    // -----------------------------------------------------------------------
    // Fingerprint drift detection
    // -----------------------------------------------------------------------

    /// Check if fingerprint drift score exceeds threshold.
    pub fn check_fingerprint_drift(
        &mut self,
        pid: u32,
        agent_name: &str,
        drift_score: f64,
        new_destinations: &[String],
        baseline_state: &BaselineState,
    ) -> Option<AnomalyRecord> {
        if *baseline_state != BaselineState::Established {
            return None;
        }

        if drift_score < self.config.drift_threshold {
            return None;
        }

        let severity = if drift_score > 70.0 {
            AnomalySeverity::Critical
        } else if drift_score > 50.0 {
            AnomalySeverity::High
        } else {
            AnomalySeverity::Medium
        };

        let record = AnomalyRecord {
            id: format!("drift-{}-{}", pid, Utc::now().timestamp()),
            pid,
            agent_name: agent_name.to_string(),
            anomaly_type: AnomalyType::FingerprintDrift,
            severity,
            description: format!(
                "Behavioral fingerprint drift: {:.1}% with {} new destinations",
                drift_score,
                new_destinations.len()
            ),
            current_value: drift_score,
            baseline_value: 0.0,
            deviation: drift_score / 100.0,
            detected_at: Utc::now(),
            resolved: false,
            resolved_at: None,
        };

        self.anomalies.entry(pid).or_default().push(record.clone());
        Some(record)
    }

    // -----------------------------------------------------------------------
    // Connection count spike
    // -----------------------------------------------------------------------

    /// Check if connection count exceeds baseline by the configured multiplier.
    pub fn check_connection_spike(
        &mut self,
        pid: u32,
        agent_name: &str,
        current_connections: f64,
        avg_connections: f64,
        baseline_state: &BaselineState,
    ) -> Option<AnomalyRecord> {
        if *baseline_state == BaselineState::Learning {
            return None;
        }

        if avg_connections <= 0.0 {
            return None;
        }

        if current_connections < avg_connections * self.config.connection_spike_multiplier {
            return None;
        }

        let deviation = current_connections / avg_connections;

        let record = AnomalyRecord {
            id: format!("conn-{}-{}", pid, Utc::now().timestamp()),
            pid,
            agent_name: agent_name.to_string(),
            anomaly_type: AnomalyType::ConnectionCountSpike,
            severity: if deviation > 5.0 {
                AnomalySeverity::High
            } else {
                AnomalySeverity::Medium
            },
            description: format!(
                "Connection count spike: {} (baseline: {})",
                current_connections as u32, avg_connections as u32
            ),
            current_value: current_connections,
            baseline_value: avg_connections,
            deviation,
            detected_at: Utc::now(),
            resolved: false,
            resolved_at: None,
        };

        self.anomalies.entry(pid).or_default().push(record.clone());
        Some(record)
    }

    // -----------------------------------------------------------------------
    // Query methods
    // -----------------------------------------------------------------------

    /// Get all anomalies for a given PID.
    pub fn get_anomalies(&self, pid: u32) -> Vec<&AnomalyRecord> {
        self.anomalies
            .get(&pid)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Get all unresolved anomalies for a given PID.
    pub fn get_unresolved_anomalies(&self, pid: u32) -> Vec<&AnomalyRecord> {
        self.anomalies
            .get(&pid)
            .map(|v| v.iter().filter(|a| !a.resolved).collect())
            .unwrap_or_default()
    }

    /// Get all anomalies across all agents.
    pub fn get_all_anomalies(&self) -> Vec<&AnomalyRecord> {
        self.anomalies
            .values()
            .flat_map(|v| v.iter())
            .collect()
    }

    /// Mark an anomaly as resolved.
    pub fn resolve_anomaly(&mut self, pid: u32, anomaly_id: &str) -> bool {
        if let Some(anomalies) = self.anomalies.get_mut(&pid) {
            if let Some(anomaly) = anomalies.iter_mut().find(|a| a.id == anomaly_id) {
                anomaly.resolved = true;
                anomaly.resolved_at = Some(Utc::now());
                return true;
            }
        }
        false
    }

    /// Get the number of detected anomalies.
    pub fn anomaly_count(&self) -> usize {
        self.anomalies.values().map(|v| v.len()).sum()
    }
}

impl Default for AnomalyDetector {
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

    #[test]
    fn test_new_destination_detection() {
        let mut detector = AnomalyDetector::new();
        let state = BaselineState::Established;
        let known = vec!["api.openai.com".to_string()];

        // Known destination — no anomaly
        let result = detector.check_new_destination(
            1234,
            "test",
            "api.openai.com",
            443,
            &known,
            &state,
        );
        assert!(result.is_none());

        // Unknown destination — anomaly!
        let result = detector.check_new_destination(
            1234,
            "test",
            "malicious.com",
            8080,
            &known,
            &state,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().anomaly_type, AnomalyType::NewDestination);
    }

    #[test]
    fn test_traffic_spike_detection() {
        let mut detector = AnomalyDetector::new();

        // During learning — no anomaly
        let result = detector.check_traffic_spike(
            1234,
            "test",
            100_000.0,
            1000.0,
            &BaselineState::Learning,
        );
        assert!(result.is_none());

        // Established with spike — anomaly
        let result = detector.check_traffic_spike(
            1234,
            "test",
            100_000.0,
            1000.0,
            &BaselineState::Established,
        );
        assert!(result.is_some());

        // Normal traffic — no anomaly
        let result = detector.check_traffic_spike(
            1234,
            "test",
            1500.0,
            1000.0,
            &BaselineState::Established,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_outbound_spike_detection() {
        let mut detector = AnomalyDetector::new();
        let state = BaselineState::Established;

        // Normal ratio
        let result = detector.check_outbound_spike(1234, "test", 1000, 2000, &state);
        assert!(result.is_none());

        // High outbound ratio
        let result = detector.check_outbound_spike(1234, "test", 100_000, 1000, &state);
        assert!(result.is_some());
        assert_eq!(result.unwrap().anomaly_type, AnomalyType::OutboundSpike);
    }

    #[test]
    fn test_time_anomaly_detection() {
        let mut detector = AnomalyDetector::new();
        let state = BaselineState::Established;
        let active_hours = vec![8, 9, 10, 11, 12, 13, 14, 15, 16, 17];

        // Activity during active hours — no anomaly
        let result = detector.check_time_anomaly(1234, "test", 10, &active_hours, &state);
        assert!(result.is_none());

        // Activity at 3 AM — anomaly
        let result = detector.check_time_anomaly(1234, "test", 3, &active_hours, &state);
        assert!(result.is_some());
        assert_eq!(result.unwrap().anomaly_type, AnomalyType::ActivityTimeAnomaly);
    }

    #[test]
    fn test_fingerprint_drift_detection() {
        let mut detector = AnomalyDetector::new();
        let state = BaselineState::Established;
        let new_dests = vec!["evil.com".to_string(), "exfil.com".to_string()];

        // Below threshold
        let result = detector.check_fingerprint_drift(1234, "test", 10.0, &new_dests, &state);
        assert!(result.is_none());

        // Above threshold
        let result = detector.check_fingerprint_drift(1234, "test", 50.0, &new_dests, &state);
        assert!(result.is_some());
        assert_eq!(result.unwrap().anomaly_type, AnomalyType::FingerprintDrift);
    }

    #[test]
    fn test_connection_spike_detection() {
        let mut detector = AnomalyDetector::new();
        let state = BaselineState::Established;

        // Normal connections
        let result = detector.check_connection_spike(1234, "test", 10.0, 8.0, &state);
        assert!(result.is_none());

        // Spike
        let result = detector.check_connection_spike(1234, "test", 50.0, 8.0, &state);
        assert!(result.is_some());
        assert_eq!(result.unwrap().anomaly_type, AnomalyType::ConnectionCountSpike);
    }

    #[test]
    fn test_learning_suppresses_anomalies() {
        let mut detector = AnomalyDetector::new();

        // All checks should return None during learning
        assert!(detector.check_new_destination(
            1, "test", "unknown.com", 80, &[], &BaselineState::Learning,
        ).is_none());

        assert!(detector.check_traffic_spike(
            1, "test", 1_000_000.0, 100.0, &BaselineState::Learning,
        ).is_none());

        assert!(detector.check_outbound_spike(
            1, "test", 1_000_000, 0, &BaselineState::Learning,
        ).is_none());
    }

    #[test]
    fn test_anomaly_resolution() {
        let mut detector = AnomalyDetector::new();
        let state = BaselineState::Established;

        let anomaly = detector.check_new_destination(
            1, "test", "evil.com", 4443, &[], &state,
        ).unwrap();

        assert_eq!(detector.get_unresolved_anomalies(1).len(), 1);
        assert!(detector.resolve_anomaly(1, &anomaly.id));
        assert_eq!(detector.get_unresolved_anomalies(1).len(), 0);
    }

    #[test]
    fn test_anomaly_severity_scaling() {
        let mut detector = AnomalyDetector::new();
        let state = BaselineState::Established;

        // Traffic deviation > 10x should be Critical
        let critical = detector.check_traffic_spike(
            1, "test", 1_000_000.0, 1000.0, &state,
        ).unwrap();
        assert_eq!(critical.severity, AnomalySeverity::Critical);

        // Deviation 5-10x should be High
        let high = detector.check_traffic_spike(
            1, "test", 7000.0, 1000.0, &state,
        ).unwrap();
        assert_eq!(high.severity, AnomalySeverity::High);
    }
}
