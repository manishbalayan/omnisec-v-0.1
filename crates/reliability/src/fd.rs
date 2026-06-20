use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FdSample {
    pub timestamp: DateTime<Utc>,
    pub fd_count: u32,
    pub fd_limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FdExhaustionDetector {
    pub pid: u32,
    pub agent_name: String,
    pub samples: VecDeque<FdSample>,
    pub max_samples: usize,
    pub threshold_percent: f64,
    pub is_exhausted: bool,
    pub exhaustion_detected_at: Option<DateTime<Utc>>,
}

impl FdExhaustionDetector {
    pub fn new(pid: u32, agent_name: String, threshold_percent: f64) -> Self {
        Self {
            pid,
            agent_name,
            samples: VecDeque::with_capacity(100),
            max_samples: 100,
            threshold_percent,
            is_exhausted: false,
            exhaustion_detected_at: None,
        }
    }

    pub fn record_sample(&mut self, sample: FdSample) {
        if self.samples.len() >= self.max_samples {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    pub fn detect_exhaustion(&mut self) -> bool {
        if let Some(latest) = self.samples.back() {
            let usage_pct = if latest.fd_limit > 0 {
                (latest.fd_count as f64 / latest.fd_limit as f64) * 100.0
            } else {
                0.0
            };

            let exhausted = usage_pct >= self.threshold_percent;

            if exhausted && !self.is_exhausted {
                self.is_exhausted = true;
                self.exhaustion_detected_at = Some(Utc::now());
                tracing::warn!(
                    "FD exhaustion detected for {} (PID {}): {}/{} ({:.1}%)",
                    self.agent_name,
                    self.pid,
                    latest.fd_count,
                    latest.fd_limit,
                    usage_pct
                );
            } else if !exhausted && self.is_exhausted {
                self.is_exhausted = false;
                self.exhaustion_detected_at = None;
                tracing::info!(
                    "FD exhaustion resolved for {} (PID {})",
                    self.agent_name,
                    self.pid
                );
            }

            return self.is_exhausted;
        }

        false
    }

    pub fn get_fd_stats(&self) -> FdStats {
        let samples: Vec<&FdSample> = self.samples.iter().collect();
        let count = samples.len();

        if count == 0 {
            return FdStats::default();
        }

        let avg_count = samples.iter().map(|s| s.fd_count).sum::<u32>() / count as u32;
        let max_count = samples.iter().map(|s| s.fd_count).max().unwrap_or(0);
        let latest = samples.last().unwrap();

        let usage_pct = if latest.fd_limit > 0 {
            (latest.fd_count as f64 / latest.fd_limit as f64) * 100.0
        } else {
            0.0
        };

        FdStats {
            avg_count,
            max_count,
            current_count: latest.fd_count,
            fd_limit: latest.fd_limit,
            usage_percent: usage_pct,
            sample_count: count,
            is_exhausted: self.is_exhausted,
            exhaustion_detected_at: self.exhaustion_detected_at,
        }
    }

    pub fn get_growth_rate(&self) -> f64 {
        if self.samples.len() < 2 {
            return 0.0;
        }

        let recent: Vec<&FdSample> = self.samples.iter().rev().take(5).collect();
        if recent.len() < 2 {
            return 0.0;
        }

        let first = recent.last().unwrap();
        let last = recent.first().unwrap();

        let duration = last.timestamp.signed_duration_since(first.timestamp);
        if duration.num_seconds() == 0 {
            return 0.0;
        }

        let growth = last.fd_count as f64 - first.fd_count as f64;
        growth / duration.num_seconds() as f64
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FdStats {
    pub avg_count: u32,
    pub max_count: u32,
    pub current_count: u32,
    pub fd_limit: u32,
    pub usage_percent: f64,
    pub sample_count: usize,
    pub is_exhausted: bool,
    pub exhaustion_detected_at: Option<DateTime<Utc>>,
}
