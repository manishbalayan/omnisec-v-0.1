use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiAgent {
    pub id: Uuid,
    pub name: String,
    pub pid: Option<i32>,
    pub status: String,
    pub framework: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEvent {
    pub id: Uuid,
    pub event_type: String,
    pub severity: String,
    pub message: String,
    pub agent_id: Option<Uuid>,
    pub created_at: String,
}

pub struct OmnisecClient {
    base_url: String,
    http: reqwest::Client,
}

impl OmnisecClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
        }
    }

    pub async fn health_check(&self) -> Result<bool> {
        let resp = self.http.get(format!("{}/", self.base_url)).send().await?;
        Ok(resp.status().is_success())
    }

    pub async fn list_agents(&self) -> Result<Vec<ApiAgent>> {
        let resp = self
            .http
            .get(format!("{}/api/agents", self.base_url))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;
        Ok(serde_json::from_value(resp["agents"].clone())?)
    }

    pub async fn list_events(&self) -> Result<Vec<ApiEvent>> {
        let resp = self
            .http
            .get(format!("{}/api/events", self.base_url))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;
        Ok(serde_json::from_value(resp["events"].clone())?)
    }

    pub async fn discover_agents(&self) -> Result<Vec<serde_json::Value>> {
        let resp = self
            .http
            .post(format!("{}/api/agents/discover", self.base_url))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;
        Ok(resp["agents"].as_array().cloned().unwrap_or_default())
    }

    pub async fn wait_for_event(&self, event_type: &str, timeout: Duration) -> Result<ApiEvent> {
        let deadline = Instant::now() + timeout;
        loop {
            if Instant::now() > deadline {
                anyhow::bail!("Timeout waiting for event: {}", event_type);
            }
            let events = self.list_events().await?;
            if let Some(e) = events.iter().find(|e| e.event_type == event_type) {
                return Ok(e.clone());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    pub async fn wait_for_agent_status(
        &self,
        name: &str,
        status: &str,
        timeout: Duration,
    ) -> Result<ApiAgent> {
        let deadline = Instant::now() + timeout;
        loop {
            if Instant::now() > deadline {
                anyhow::bail!("Timeout waiting for agent {} status={}", name, status);
            }
            let agents = self.list_agents().await?;
            if let Some(a) = agents.iter().find(|a| a.name == name && a.status == status) {
                return Ok(a.clone());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}
