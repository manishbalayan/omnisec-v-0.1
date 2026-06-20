use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReliabilityMetrics {
    pub agent_name: String,
    pub organization_id: Option<String>,
    pub mttr_ms: f64,
    pub mtbf_ms: f64,
    pub availability_percent: f64,
    pub total_incidents: u32,
    pub total_downtime_ms: u64,
    pub total_uptime_ms: u64,
    pub last_incident: Option<DateTime<Utc>>,
    pub last_recovery: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentRecord {
    pub incident_id: String,
    pub agent_name: String,
    pub started_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<f64>,
    pub recovery_method: Option<String>,
}

pub struct ReliabilityMetricsEngine {
    incidents: Vec<IncidentRecord>,
    agent_metrics: HashMap<String, ReliabilityMetrics>,
    system_metrics: ReliabilityMetrics,
}

impl ReliabilityMetricsEngine {
    pub fn new() -> Self {
        Self {
            incidents: Vec::new(),
            agent_metrics: HashMap::new(),
            system_metrics: ReliabilityMetrics {
                agent_name: "_system_".to_string(),
                organization_id: None,
                mttr_ms: 0.0,
                mtbf_ms: 0.0,
                availability_percent: 100.0,
                total_incidents: 0,
                total_downtime_ms: 0,
                total_uptime_ms: 0,
                last_incident: None,
                last_recovery: None,
            },
        }
    }

    pub fn record_incident(
        &mut self,
        incident_id: String,
        agent_name: String,
        started_at: DateTime<Utc>,
    ) {
        let record = IncidentRecord {
            incident_id,
            agent_name: agent_name.clone(),
            started_at,
            resolved_at: None,
            duration_ms: None,
            recovery_method: None,
        };
        self.incidents.push(record);

        let metrics = self.agent_metrics.entry(agent_name.clone()).or_insert_with(|| {
            ReliabilityMetrics {
                agent_name: agent_name.clone(),
                organization_id: None,
                mttr_ms: 0.0,
                mtbf_ms: 0.0,
                availability_percent: 100.0,
                total_incidents: 0,
                total_downtime_ms: 0,
                total_uptime_ms: 0,
                last_incident: None,
                last_recovery: None,
            }
        });
        metrics.total_incidents += 1;
        metrics.last_incident = Some(started_at);

        self.system_metrics.total_incidents += 1;
        self.system_metrics.last_incident = Some(started_at);
    }

    pub fn record_recovery(
        &mut self,
        incident_id: &str,
        resolved_at: DateTime<Utc>,
        recovery_method: Option<String>,
    ) {
        if let Some(record) = self.incidents.iter_mut().find(|i| i.incident_id == incident_id) {
            record.resolved_at = Some(resolved_at);
            record.recovery_method = recovery_method;

            let duration = resolved_at.signed_duration_since(record.started_at);
            record.duration_ms = Some(duration.num_milliseconds() as f64);

            let agent_name = record.agent_name.clone();
            let duration_ms = record.duration_ms.unwrap_or(0.0);

            if let Some(metrics) = self.agent_metrics.get_mut(&agent_name) {
                metrics.total_downtime_ms += duration_ms as u64;
                metrics.last_recovery = Some(resolved_at);
            }

            self.system_metrics.total_downtime_ms += duration_ms as u64;
            self.system_metrics.last_recovery = Some(resolved_at);
        }
    }

    fn calculate_all_metrics(&mut self) {
        let agent_names: Vec<String> = self.agent_metrics.keys().cloned().collect();
        for agent_name in agent_names {
            self.calculate_agent_metrics_for(&agent_name);
        }
        self.calculate_system_metrics();
    }

    fn calculate_agent_metrics_for(&mut self, agent_name: &str) {
        let agent_incidents: Vec<IncidentRecord> = self.incidents
            .iter()
            .filter(|i| i.agent_name == agent_name)
            .cloned()
            .collect();

        let resolved: Vec<&IncidentRecord> = agent_incidents
            .iter()
            .filter(|i| i.resolved_at.is_some())
            .collect();

        if let Some(metrics) = self.agent_metrics.get_mut(agent_name) {
            if resolved.is_empty() {
                metrics.mttr_ms = 0.0;
                metrics.mtbf_ms = 0.0;
                return;
            }

            let total_recovery_time: f64 = resolved
                .iter()
                .filter_map(|i| i.duration_ms)
                .sum();

            metrics.mttr_ms = total_recovery_time / resolved.len() as f64;

            if agent_incidents.len() >= 2 {
                let mut intervals = Vec::new();
                for i in 1..agent_incidents.len() {
                    let prev = agent_incidents[i - 1].started_at;
                    let curr = agent_incidents[i].started_at;
                    let interval = curr.signed_duration_since(prev).num_milliseconds() as f64;
                    intervals.push(interval);
                }
                metrics.mtbf_ms = intervals.iter().sum::<f64>() / intervals.len() as f64;
            } else {
                metrics.mtbf_ms = 0.0;
            }

            let total_time = metrics.total_uptime_ms + metrics.total_downtime_ms;
            metrics.availability_percent = if total_time > 0 {
                (metrics.total_uptime_ms as f64 / total_time as f64) * 100.0
            } else {
                100.0
            };
        }
    }

    fn calculate_system_metrics(&mut self) {
        let resolved: Vec<&IncidentRecord> = self.incidents
            .iter()
            .filter(|i| i.resolved_at.is_some())
            .collect();

        if resolved.is_empty() {
            self.system_metrics.mttr_ms = 0.0;
            self.system_metrics.mtbf_ms = 0.0;
            return;
        }

        let total_recovery_time: f64 = resolved
            .iter()
            .filter_map(|i| i.duration_ms)
            .sum();

        self.system_metrics.mttr_ms = total_recovery_time / resolved.len() as f64;

        if self.incidents.len() >= 2 {
            let mut intervals = Vec::new();
            for i in 1..self.incidents.len() {
                let prev = self.incidents[i - 1].started_at;
                let curr = self.incidents[i].started_at;
                let interval = curr.signed_duration_since(prev).num_milliseconds() as f64;
                intervals.push(interval);
            }
            self.system_metrics.mtbf_ms = intervals.iter().sum::<f64>() / intervals.len() as f64;
        }

        let total_time = self.system_metrics.total_uptime_ms + self.system_metrics.total_downtime_ms;
        self.system_metrics.availability_percent = if total_time > 0 {
            (self.system_metrics.total_uptime_ms as f64 / total_time as f64) * 100.0
        } else {
            100.0
        };
    }

    pub fn get_agent_metrics(&self, agent_name: &str) -> Option<&ReliabilityMetrics> {
        self.agent_metrics.get(agent_name)
    }

    pub fn get_all_agent_metrics(&self) -> Vec<&ReliabilityMetrics> {
        self.agent_metrics.values().collect()
    }

    pub fn get_system_metrics(&self) -> &ReliabilityMetrics {
        &self.system_metrics
    }

    pub fn get_incidents(&self) -> &[IncidentRecord] {
        &self.incidents
    }

    pub fn calculate_availability(&self, agent_name: Option<&str>, period_secs: u64) -> f64 {
        let now = Utc::now();
        let period_start = now - chrono::Duration::seconds(period_secs as i64);

        let relevant_incidents: Vec<&IncidentRecord> = self.incidents
            .iter()
            .filter(|i| {
                let matches_agent = agent_name.map_or(true, |name| i.agent_name == name);
                let in_period = i.started_at >= period_start;
                matches_agent && in_period
            })
            .collect();

        if relevant_incidents.is_empty() {
            return 100.0;
        }

        let total_downtime: f64 = relevant_incidents
            .iter()
            .filter_map(|i| i.duration_ms)
            .sum();

        let total_time = period_secs as f64 * 1000.0;
        ((total_time - total_downtime) / total_time) * 100.0
    }
}

impl Default for ReliabilityMetricsEngine {
    fn default() -> Self {
        Self::new()
    }
}
