use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartConfig {
    pub max_retries: u32,
    pub retry_delay: Duration,
    pub backoff_multiplier: f64,
    pub max_backoff: Duration,
    pub cooldown_period: Duration,
}

impl Default for RestartConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_delay: Duration::from_secs(1),
            backoff_multiplier: 2.0,
            max_backoff: Duration::from_secs(30),
            cooldown_period: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartAttempt {
    pub id: Uuid,
    pub agent_name: String,
    pub agent_pid: u32,
    pub attempt_number: u32,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub success: bool,
    pub new_pid: Option<u32>,
    pub error: Option<String>,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartResult {
    pub success: bool,
    pub attempts: Vec<RestartAttempt>,
    pub total_duration_ms: u64,
    pub final_pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentState {
    pub name: String,
    pub pid: u32,
    pub restart_count: u32,
    pub last_restart: Option<chrono::DateTime<chrono::Utc>>,
    pub consecutive_failures: u32,
    pub status: AgentStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AgentStatus {
    Healthy,
    Degraded,
    Failed,
    Restarting,
    PermanentlyFailed,
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
        agent: &AgentState,
        restart_fn: F,
    ) -> RestartResult
    where
        F: Fn(u32) -> Fut,
        Fut: std::future::Future<Output = Result<u32>>,
    {
        let start = Instant::now();
        let mut attempts = Vec::new();

        for attempt_num in 1..=self.config.max_retries {
            let attempt_id = Uuid::new_v4();
            let attempt_start = chrono::Utc::now();
            let instant_start = Instant::now();

            tracing::info!(
                "Restart attempt {}/{} for {} (attempt_id={})",
                attempt_num,
                self.config.max_retries,
                agent.name,
                attempt_id
            );

            let result = restart_fn(agent.pid).await;
            let duration_ms = instant_start.elapsed().as_millis() as u64;

            let (success, new_pid, error) = match result {
                Ok(pid) => (true, Some(pid), None),
                Err(e) => (false, None, Some(e.to_string())),
            };

            let attempt = RestartAttempt {
                id: attempt_id,
                agent_name: agent.name.clone(),
                agent_pid: agent.pid,
                attempt_number: attempt_num,
                started_at: attempt_start,
                completed_at: Some(chrono::Utc::now()),
                success,
                new_pid,
                error,
                duration_ms: Some(duration_ms),
            };

            if success {
                tracing::info!(
                    "Restart successful for {} after {} attempts, new_pid={}",
                    agent.name,
                    attempt_num,
                    attempt.new_pid.unwrap_or(0)
                );
                attempts.push(attempt);

                let final_pid = attempts.last().and_then(|a| a.new_pid);

                return RestartResult {
                    success: true,
                    attempts,
                    total_duration_ms: start.elapsed().as_millis() as u64,
                    final_pid,
                };
            }

            tracing::warn!(
                "Restart attempt {}/{} failed for {}: {}",
                attempt_num,
                self.config.max_retries,
                agent.name,
                attempt.error.as_deref().unwrap_or("unknown")
            );
            attempts.push(attempt);

            let delay = self.calculate_delay(attempt_num);
            tracing::info!("Waiting {:?} before next attempt", delay);
            tokio::time::sleep(delay).await;
        }

        tracing::error!(
            "All restart attempts exhausted for {} after {:?}",
            agent.name,
            start.elapsed()
        );

        RestartResult {
            success: false,
            attempts,
            total_duration_ms: start.elapsed().as_millis() as u64,
            final_pid: None,
        }
    }

    fn calculate_delay(&self, attempt: u32) -> Duration {
        let base_delay = self.config.retry_delay.as_secs_f64();
        let backoff = base_delay * self.config.backoff_multiplier.powi(attempt as i32 - 1);
        let capped = backoff.min(self.config.max_backoff.as_secs_f64());
        Duration::from_secs_f64(capped)
    }

    pub fn should_restart(&self, agent: &AgentState) -> bool {
        match agent.status {
            AgentStatus::PermanentlyFailed => false,
            AgentStatus::Restarting => false,
            _ => agent.consecutive_failures > 0,
        }
    }

    pub fn calculate_health(&self, agent: &AgentState) -> AgentStatus {
        if agent.consecutive_failures >= self.config.max_retries * 2 {
            AgentStatus::PermanentlyFailed
        } else if agent.consecutive_failures >= self.config.max_retries {
            AgentStatus::Failed
        } else if agent.consecutive_failures > 0 {
            AgentStatus::Degraded
        } else {
            AgentStatus::Healthy
        }
    }
}
