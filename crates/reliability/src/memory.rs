use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySample {
    pub timestamp: DateTime<Utc>,
    pub rss_bytes: u64,
    pub vsz_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryLeakDetector {
    pub pid: u32,
    pub agent_name: String,
    pub samples: VecDeque<MemorySample>,
    pub max_samples: usize,
    pub window_size: usize,
    pub growth_threshold_pct: f64,
    pub consecutive_growth_limit: u32,
    pub is_leaking: bool,
    pub leak_detected_at: Option<DateTime<Utc>>,
}

impl MemoryLeakDetector {
    pub fn new(
        pid: u32,
        agent_name: String,
        growth_threshold_pct: f64,
        consecutive_growth_limit: u32,
    ) -> Self {
        Self {
            pid,
            agent_name,
            samples: VecDeque::with_capacity(100),
            max_samples: 100,
            window_size: 10,
            growth_threshold_pct,
            consecutive_growth_limit,
            is_leaking: false,
            leak_detected_at: None,
        }
    }

    pub fn record_sample(&mut self, sample: MemorySample) {
        if self.samples.len() >= self.max_samples {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    pub fn detect_leak(&mut self) -> bool {
        if self.samples.len() < self.window_size + 1 {
            return false;
        }

        let window_start = self.samples.len() - self.window_size - 1;
        let recent_samples: Vec<&MemorySample> = self.samples
            .iter()
            .skip(window_start)
            .collect();

        let mut consecutive_growth = 0u32;
        let mut total_growth_pct = 0.0;

        for i in 1..recent_samples.len() {
            let current = recent_samples[i];
            let previous = recent_samples[i - 1];

            if previous.rss_bytes == 0 {
                continue;
            }

            let growth = current.rss_bytes as f64 - previous.rss_bytes as f64;
            let growth_pct = (growth / previous.rss_bytes as f64) * 100.0;

            if growth_pct > self.growth_threshold_pct {
                consecutive_growth += 1;
                total_growth_pct += growth_pct;
            } else {
                consecutive_growth = 0;
                total_growth_pct = 0.0;
            }
        }

        let leaking = consecutive_growth >= self.consecutive_growth_limit;

        if leaking && !self.is_leaking {
            self.is_leaking = true;
            self.leak_detected_at = Some(Utc::now());
            tracing::warn!(
                "Memory leak detected for {} (PID {}): {}% growth over {} consecutive samples",
                self.agent_name,
                self.pid,
                total_growth_pct as u32,
                consecutive_growth
            );
        } else if !leaking && self.is_leaking {
            self.is_leaking = false;
            self.leak_detected_at = None;
            tracing::info!(
                "Memory leak resolved for {} (PID {})",
                self.agent_name,
                self.pid
            );
        }

        self.is_leaking
    }

    pub fn get_memory_trend(&self) -> MemoryTrend {
        if self.samples.len() < 2 {
            return MemoryTrend::Unknown;
        }

        let recent: Vec<&MemorySample> = self.samples.iter().rev().take(5).collect();
        if recent.len() < 2 {
            return MemoryTrend::Unknown;
        }

        let first = recent.last().unwrap();
        let last = recent.first().unwrap();

        let change = last.rss_bytes as f64 - first.rss_bytes as f64;
        let change_pct = if first.rss_bytes > 0 {
            (change / first.rss_bytes as f64) * 100.0
        } else {
            0.0
        };

        if change_pct > self.growth_threshold_pct * 2.0 {
            MemoryTrend::Increasing
        } else if change_pct < -self.growth_threshold_pct {
            MemoryTrend::Decreasing
        } else {
            MemoryTrend::Stable
        }
    }

    pub fn get_current_rss(&self) -> Option<u64> {
        self.samples.back().map(|s| s.rss_bytes)
    }

    pub fn get_peak_rss(&self) -> Option<u64> {
        self.samples.iter().map(|s| s.rss_bytes).max()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MemoryTrend {
    Increasing,
    Stable,
    Decreasing,
    Unknown,
}
