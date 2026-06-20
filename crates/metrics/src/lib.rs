use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyMeasurement {
    pub operation: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub duration_ms: Option<f64>,
    pub success: bool,
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSummary {
    pub operation: String,
    pub count: usize,
    pub success_count: usize,
    pub failure_count: usize,
    pub min_latency_ms: Option<f64>,
    pub max_latency_ms: Option<f64>,
    pub avg_latency_ms: Option<f64>,
    pub p50_latency_ms: Option<f64>,
    pub p95_latency_ms: Option<f64>,
    pub p99_latency_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlLoopMetrics {
    pub failure_detection: Option<LatencyMeasurement>,
    pub restart_attempt: Option<LatencyMeasurement>,
    pub alert_delivery: Option<LatencyMeasurement>,
    pub event_propagation: Option<LatencyMeasurement>,
    pub audit_persistence: Option<LatencyMeasurement>,
    pub total_recovery_time_ms: Option<f64>,
}

pub struct MetricsStore {
    measurements: Arc<RwLock<Vec<LatencyMeasurement>>>,
}

impl MetricsStore {
    pub fn new() -> Self {
        Self {
            measurements: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn record(&self, measurement: LatencyMeasurement) {
        let mut measurements = self.measurements.write().await;
        measurements.push(measurement);
    }

    pub async fn summary(&self, operation: &str) -> MetricsSummary {
        let measurements = self.measurements.read().await;
        let op_measurements: Vec<&LatencyMeasurement> = measurements
            .iter()
            .filter(|m| m.operation == operation)
            .collect();

        let count = op_measurements.len();
        let success_count = op_measurements.iter().filter(|m| m.success).count();
        let failure_count = count - success_count;

        let mut durations: Vec<f64> = op_measurements
            .iter()
            .filter_map(|m| m.duration_ms)
            .collect();

        if durations.is_empty() {
            return MetricsSummary {
                operation: operation.to_string(),
                count,
                success_count,
                failure_count,
                min_latency_ms: None,
                max_latency_ms: None,
                avg_latency_ms: None,
                p50_latency_ms: None,
                p95_latency_ms: None,
                p99_latency_ms: None,
            };
        }

        durations.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let min_latency_ms = durations.first().copied();
        let max_latency_ms = durations.last().copied();
        let avg_latency_ms = durations.iter().sum::<f64>() / durations.len() as f64;

        let p50_idx = durations.len() / 2;
        let p95_idx = (durations.len() as f64 * 0.95) as usize;
        let p99_idx = (durations.len() as f64 * 0.99) as usize;

        MetricsSummary {
            operation: operation.to_string(),
            count,
            success_count,
            failure_count,
            min_latency_ms,
            max_latency_ms,
            avg_latency_ms: Some(avg_latency_ms),
            p50_latency_ms: durations.get(p50_idx).copied(),
            p95_latency_ms: durations.get(p95_idx.min(durations.len() - 1)).copied(),
            p99_latency_ms: durations.get(p99_idx.min(durations.len() - 1)).copied(),
        }
    }

    pub async fn all_summaries(&self) -> Vec<MetricsSummary> {
        let measurements = self.measurements.read().await;
        let operations: Vec<String> = measurements
            .iter()
            .map(|m| m.operation.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        drop(measurements);

        let mut summaries = Vec::new();
        for op in operations {
            summaries.push(self.summary(&op).await);
        }
        summaries
    }

    pub async fn control_loop_metrics(&self) -> ControlLoopMetrics {
        let failure_detection = self.summary("failure_detection").await;
        let restart_attempt = self.summary("restart_attempt").await;
        let alert_delivery = self.summary("alert_delivery").await;
        let event_propagation = self.summary("event_propagation").await;
        let audit_persistence = self.summary("audit_persistence").await;

        let total_recovery_time_ms = self.calculate_total_recovery_time().await;

        ControlLoopMetrics {
            failure_detection: self.summary_to_measurement(&failure_detection).await,
            restart_attempt: self.summary_to_measurement(&restart_attempt).await,
            alert_delivery: self.summary_to_measurement(&alert_delivery).await,
            event_propagation: self.summary_to_measurement(&event_propagation).await,
            audit_persistence: self.summary_to_measurement(&audit_persistence).await,
            total_recovery_time_ms,
        }
    }

    async fn calculate_total_recovery_time(&self) -> Option<f64> {
        let measurements = self.measurements.read().await;

        let restarts: Vec<&LatencyMeasurement> = measurements
            .iter()
            .filter(|m| m.operation == "restart_attempt" && m.success)
            .collect();

        if restarts.is_empty() {
            return None;
        }

        let total: f64 = restarts.iter().filter_map(|m| m.duration_ms).sum();
        Some(total)
    }

    async fn summary_to_measurement(&self, summary: &MetricsSummary) -> Option<LatencyMeasurement> {
        if summary.count == 0 {
            return None;
        }

        Some(LatencyMeasurement {
            operation: summary.operation.clone(),
            start_time: Utc::now(),
            end_time: Some(Utc::now()),
            duration_ms: summary.avg_latency_ms,
            success: summary.failure_count == 0,
            labels: HashMap::new(),
        })
    }

    pub async fn to_json(&self) -> String {
        let summaries = self.all_summaries().await;
        serde_json::to_string_pretty(&summaries).unwrap_or_default()
    }

    pub async fn clear(&self) {
        let mut measurements = self.measurements.write().await;
        measurements.clear();
    }
}

impl Default for MetricsStore {
    fn default() -> Self {
        Self::new()
    }
}

pub fn duration_to_ms(duration: Duration) -> f64 {
    duration.as_secs() as f64 * 1000.0 + duration.subsec_nanos() as f64 / 1_000_000.0
}
