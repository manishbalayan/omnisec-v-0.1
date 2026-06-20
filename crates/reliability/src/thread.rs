use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadSample {
    pub timestamp: DateTime<Utc>,
    pub thread_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadExplosionDetector {
    pub pid: u32,
    pub agent_name: String,
    pub samples: VecDeque<ThreadSample>,
    pub max_samples: usize,
    pub window_size: usize,
    pub growth_threshold_percent: f64,
    pub max_threads: u32,
    pub is_exploded: bool,
    pub explosion_detected_at: Option<DateTime<Utc>>,
}

impl ThreadExplosionDetector {
    pub fn new(
        pid: u32,
        agent_name: String,
        growth_threshold_percent: f64,
        max_threads: u32,
    ) -> Self {
        Self {
            pid,
            agent_name,
            samples: VecDeque::with_capacity(100),
            max_samples: 100,
            window_size: 10,
            growth_threshold_percent,
            max_threads,
            is_exploded: false,
            explosion_detected_at: None,
        }
    }

    pub fn record_sample(&mut self, sample: ThreadSample) {
        if self.samples.len() >= self.max_samples {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    pub fn detect_explosion(&mut self) -> bool {
        if self.samples.len() < self.window_size {
            return false;
        }

        let recent: Vec<&ThreadSample> = self.samples
            .iter()
            .rev()
            .take(self.window_size)
            .collect();

        let first = recent.last().unwrap();
        let last = recent.first().unwrap();

        let growth = last.thread_count as f64 - first.thread_count as f64;
        let growth_pct = if first.thread_count > 0 {
            (growth / first.thread_count as f64) * 100.0
        } else {
            0.0
        };

        let duration = last.timestamp.signed_duration_since(first.timestamp);
        let rapid_growth = growth_pct > self.growth_threshold_percent && duration.num_seconds() < 60;

        let over_limit = last.thread_count > self.max_threads;

        let exploded = rapid_growth || over_limit;

        if exploded && !self.is_exploded {
            self.is_exploded = true;
            self.explosion_detected_at = Some(Utc::now());
            tracing::warn!(
                "Thread explosion detected for {} (PID {}): {} threads (growth: {:.1}%)",
                self.agent_name,
                self.pid,
                last.thread_count,
                growth_pct
            );
        } else if !exploded && self.is_exploded {
            self.is_exploded = false;
            self.explosion_detected_at = None;
            tracing::info!(
                "Thread explosion resolved for {} (PID {})",
                self.agent_name,
                self.pid
            );
        }

        self.is_exploded
    }

    pub fn get_thread_stats(&self) -> ThreadStats {
        let samples: Vec<&ThreadSample> = self.samples.iter().collect();
        let count = samples.len();

        if count == 0 {
            return ThreadStats::default();
        }

        let avg_count = samples.iter().map(|s| s.thread_count).sum::<u32>() / count as u32;
        let max_count = samples.iter().map(|s| s.thread_count).max().unwrap_or(0);
        let latest = samples.last().unwrap();

        let growth_rate = if samples.len() >= 2 {
            let first = samples.first().unwrap();
            let duration = latest.timestamp.signed_duration_since(first.timestamp);
            if duration.num_seconds() > 0 {
                let growth = latest.thread_count as f64 - first.thread_count as f64;
                growth / duration.num_seconds() as f64
            } else {
                0.0
            }
        } else {
            0.0
        };

        ThreadStats {
            avg_count,
            max_count,
            current_count: latest.thread_count,
            growth_rate,
            sample_count: count,
            is_exploded: self.is_exploded,
            explosion_detected_at: self.explosion_detected_at,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThreadStats {
    pub avg_count: u32,
    pub max_count: u32,
    pub current_count: u32,
    pub growth_rate: f64,
    pub sample_count: usize,
    pub is_exploded: bool,
    pub explosion_detected_at: Option<DateTime<Utc>>,
}
