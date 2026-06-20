use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuSample {
    pub timestamp: DateTime<Utc>,
    pub cpu_percent: f64,
    pub user_time_ms: u64,
    pub system_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuRunawayDetector {
    pub pid: u32,
    pub agent_name: String,
    pub samples: VecDeque<CpuSample>,
    pub max_samples: usize,
    pub window_size: usize,
    pub threshold_percent: f64,
    pub sustained_duration_secs: u64,
    pub is_runaway: bool,
    pub runaway_detected_at: Option<DateTime<Utc>>,
}

impl CpuRunawayDetector {
    pub fn new(
        pid: u32,
        agent_name: String,
        threshold_percent: f64,
        sustained_duration_secs: u64,
    ) -> Self {
        Self {
            pid,
            agent_name,
            samples: VecDeque::with_capacity(100),
            max_samples: 100,
            window_size: 10,
            threshold_percent,
            sustained_duration_secs,
            is_runaway: false,
            runaway_detected_at: None,
        }
    }

    pub fn record_sample(&mut self, sample: CpuSample) {
        if self.samples.len() >= self.max_samples {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    pub fn detect_runaway(&mut self) -> bool {
        if self.samples.len() < self.window_size {
            return false;
        }

        let recent: Vec<&CpuSample> = self.samples
            .iter()
            .rev()
            .take(self.window_size)
            .collect();

        let avg_cpu: f64 = recent.iter().map(|s| s.cpu_percent).sum::<f64>() / recent.len() as f64;

        let all_above_threshold = recent.iter().all(|s| s.cpu_percent > self.threshold_percent);

        let first = recent.last().unwrap();
        let last = recent.first().unwrap();
        let duration = last.timestamp.signed_duration_since(first.timestamp);
        let sustained = duration.num_seconds() as u64 >= self.sustained_duration_secs;

        let runaway = all_above_threshold && sustained && avg_cpu > self.threshold_percent;

        if runaway && !self.is_runaway {
            self.is_runaway = true;
            self.runaway_detected_at = Some(Utc::now());
            tracing::warn!(
                "CPU runaway detected for {} (PID {}): avg {:.1}% over {}s",
                self.agent_name,
                self.pid,
                avg_cpu,
                duration.num_seconds()
            );
        } else if !runaway && self.is_runaway {
            self.is_runaway = false;
            self.runaway_detected_at = None;
            tracing::info!(
                "CPU runaway resolved for {} (PID {})",
                self.agent_name,
                self.pid
            );
        }

        self.is_runaway
    }

    pub fn get_cpu_stats(&self) -> CpuStats {
        let samples: Vec<&CpuSample> = self.samples.iter().collect();
        let count = samples.len();

        if count == 0 {
            return CpuStats::default();
        }

        let avg_cpu = samples.iter().map(|s| s.cpu_percent).sum::<f64>() / count as f64;
        let max_cpu = samples.iter().map(|s| s.cpu_percent).fold(f64::MIN, f64::max);
        let min_cpu = samples.iter().map(|s| s.cpu_percent).fold(f64::MAX, f64::min);

        let recent_start = count.saturating_sub(self.window_size);
        let recent: Vec<&CpuSample> = samples[recent_start..].to_vec();
        let recent_avg = if recent.is_empty() {
            0.0
        } else {
            recent.iter().map(|s| s.cpu_percent).sum::<f64>() / recent.len() as f64
        };

        CpuStats {
            avg_cpu,
            max_cpu,
            min_cpu,
            recent_avg,
            sample_count: count,
            is_runaway: self.is_runaway,
            runaway_detected_at: self.runaway_detected_at,
        }
    }

    pub fn get_rolling_average(&self) -> f64 {
        let count = self.samples.len();
        if count == 0 {
            return 0.0;
        }

        let start = count.saturating_sub(self.window_size);
        let recent: Vec<&CpuSample> = self.samples.iter().skip(start).collect();

        if recent.is_empty() {
            return 0.0;
        }

        recent.iter().map(|s| s.cpu_percent).sum::<f64>() / recent.len() as f64
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CpuStats {
    pub avg_cpu: f64,
    pub max_cpu: f64,
    pub min_cpu: f64,
    pub recent_avg: f64,
    pub sample_count: usize,
    pub is_runaway: bool,
    pub runaway_detected_at: Option<DateTime<Utc>>,
}
