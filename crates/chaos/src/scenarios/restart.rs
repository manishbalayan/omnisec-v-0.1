use std::time::{Duration, Instant};
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartConfig {
    pub max_retries: u32,
    pub retry_delay: Duration,
    pub backoff_multiplier: f64,
    pub max_backoff: Duration,
}

impl Default for RestartConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_delay: Duration::from_secs(1),
            backoff_multiplier: 2.0,
            max_backoff: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartResult {
    pub success: bool,
    pub attempts: u32,
    pub total_duration: Duration,
    pub new_pid: Option<u32>,
    pub error: Option<String>,
}

pub struct RestartEngine {
    config: RestartConfig,
}

impl RestartEngine {
    pub fn new(config: RestartConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(RestartConfig::default())
    }

    pub async fn attempt_restart<F, Fut>(
        &self,
        agent_name: &str,
        restart_fn: F,
    ) -> RestartResult
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<u32>>,
    {
        let start = Instant::now();
        let mut last_error = None;

        for attempt in 1..=self.config.max_retries {
            tracing::info!(
                "Restart attempt {}/{} for {}",
                attempt,
                self.config.max_retries,
                agent_name
            );

            match restart_fn().await {
                Ok(new_pid) => {
                    tracing::info!(
                        "Restart successful for {} after {} attempts, new_pid={}",
                        agent_name,
                        attempt,
                        new_pid
                    );
                    return RestartResult {
                        success: true,
                        attempts: attempt,
                        total_duration: start.elapsed(),
                        new_pid: Some(new_pid),
                        error: None,
                    };
                }
                Err(e) => {
                    tracing::warn!(
                        "Restart attempt {}/{} failed for {}: {}",
                        attempt,
                        self.config.max_retries,
                        agent_name,
                        e
                    );
                    last_error = Some(e.to_string());

                    let delay = self.calculate_delay(attempt);
                    tokio::time::sleep(delay).await;
                }
            }
        }

        tracing::error!(
            "All restart attempts exhausted for {} after {}",
            agent_name,
            start.elapsed().as_secs_f64()
        );

        RestartResult {
            success: false,
            attempts: self.config.max_retries,
            total_duration: start.elapsed(),
            new_pid: None,
            error: last_error,
        }
    }

    fn calculate_delay(&self, attempt: u32) -> Duration {
        let base_delay = self.config.retry_delay.as_secs_f64();
        let backoff = base_delay * self.config.backoff_multiplier.powi(attempt as i32 - 1);
        let capped = backoff.min(self.config.max_backoff.as_secs_f64());
        Duration::from_secs_f64(capped)
    }
}
