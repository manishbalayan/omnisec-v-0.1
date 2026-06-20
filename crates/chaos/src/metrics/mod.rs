use std::time::Instant;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyRecord {
    pub operation: String,
    pub start_epoch_ms: u64,
    pub end_epoch_ms: Option<u64>,
    pub duration_ms: Option<f64>,
    pub success: bool,
    pub metadata: HashMap<String, String>,
    #[serde(skip)]
    pub start: Option<Instant>,
}

impl LatencyRecord {
    pub fn start(operation: &str) -> Self {
        Self {
            operation: operation.to_string(),
            start_epoch_ms: epoch_ms(),
            end_epoch_ms: None,
            duration_ms: None,
            success: false,
            metadata: HashMap::new(),
            start: Some(Instant::now()),
        }
    }

    pub fn finish(&mut self, success: bool) {
        self.end_epoch_ms = Some(epoch_ms());
        self.duration_ms = self.start.map(|s| s.elapsed().as_secs_f64() * 1000.0);
        self.success = success;
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSummary {
    pub operation: String,
    pub count: usize,
    pub success_count: usize,
    pub failure_count: usize,
    pub min_duration: Option<f64>,
    pub max_duration: Option<f64>,
    pub avg_duration: Option<f64>,
    pub p50_duration: Option<f64>,
    pub p95_duration: Option<f64>,
    pub p99_duration: Option<f64>,
}

pub struct MetricsCollector {
    records: Vec<LatencyRecord>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    pub fn record(&mut self, record: LatencyRecord) {
        self.records.push(record);
    }

    pub fn summary(&self, operation: &str) -> MetricsSummary {
        let records: Vec<&LatencyRecord> = self.records
            .iter()
            .filter(|r| r.operation == operation)
            .collect();

        let count = records.len();
        let success_count = records.iter().filter(|r| r.success).count();
        let failure_count = count - success_count;

        let durations: Vec<f64> = records
            .iter()
            .filter_map(|r| r.duration_ms)
            .collect();

        if durations.is_empty() {
            return MetricsSummary {
                operation: operation.to_string(),
                count,
                success_count,
                failure_count,
                min_duration: None,
                max_duration: None,
                avg_duration: None,
                p50_duration: None,
                p95_duration: None,
                p99_duration: None,
            };
        }

        let mut sorted = durations.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let min_duration = sorted.first().copied();
        let max_duration = sorted.last().copied();

        let total: f64 = sorted.iter().sum();
        let avg_duration = Some(total / sorted.len() as f64);

        let p50 = sorted.len() / 2;
        let p95 = (sorted.len() as f64 * 0.95) as usize;
        let p99 = (sorted.len() as f64 * 0.99) as usize;

        MetricsSummary {
            operation: operation.to_string(),
            count,
            success_count,
            failure_count,
            min_duration,
            max_duration,
            avg_duration,
            p50_duration: sorted.get(p50).copied(),
            p95_duration: sorted.get(p95.min(sorted.len() - 1)).copied(),
            p99_duration: sorted.get(p99.min(sorted.len() - 1)).copied(),
        }
    }

    pub fn all_summaries(&self) -> Vec<MetricsSummary> {
        let operations: Vec<String> = self.records
            .iter()
            .map(|r| r.operation.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        operations
            .iter()
            .map(|op| self.summary(op))
            .collect()
    }

    pub fn records(&self) -> &[LatencyRecord] {
        &self.records
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.all_summaries()).unwrap_or_default()
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}
