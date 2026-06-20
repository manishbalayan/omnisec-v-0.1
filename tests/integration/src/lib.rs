use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Agent {
    pub id: Uuid,
    pub name: String,
    pub pid: Option<i32>,
    pub status: String,
    pub framework: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Event {
    pub id: Uuid,
    pub event_type: String,
    pub severity: String,
    pub message: String,
    pub agent_id: Option<Uuid>,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Alert {
    pub id: Uuid,
    pub channel: String,
    pub message: String,
    pub status: String,
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
            http: reqwest::Client::new(),
        }
    }

    pub async fn health_check(&self) -> Result<bool, anyhow::Error> {
        let resp = self.http.get(&format!("{}/", self.base_url))
            .send()
            .await?;
        Ok(resp.status().is_success())
    }

    pub async fn list_agents(&self) -> Result<Vec<Agent>, anyhow::Error> {
        let resp = self.http.get(&format!("{}/api/agents", self.base_url))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let agents: Vec<Agent> = serde_json::from_value(resp["agents"].clone())?;
        Ok(agents)
    }

    pub async fn list_events(&self) -> Result<Vec<Event>, anyhow::Error> {
        let resp = self.http.get(&format!("{}/api/events", self.base_url))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let events: Vec<Event> = serde_json::from_value(resp["events"].clone())?;
        Ok(events)
    }

    pub async fn discover_agents(&self) -> Result<Vec<serde_json::Value>, anyhow::Error> {
        let resp = self.http.post(&format!("{}/api/agents/discover", self.base_url))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let agents = resp["agents"].as_array().cloned().unwrap_or_default();
        Ok(agents)
    }

    pub async fn wait_for_event(
        &self,
        event_type: &str,
        timeout: Duration,
    ) -> Result<Event, anyhow::Error> {
        let start = Instant::now();
        let poll_interval = Duration::from_millis(500);

        loop {
            if start.elapsed() > timeout {
                return Err(anyhow::anyhow!(
                    "Timeout waiting for event: {}",
                    event_type
                ));
            }

            let events = self.list_events().await?;
            if let Some(event) = events.iter().find(|e| e.event_type == event_type) {
                return Ok(event.clone());
            }

            tokio::time::sleep(poll_interval).await;
        }
    }

    pub async fn wait_for_agent_status(
        &self,
        agent_name: &str,
        status: &str,
        timeout: Duration,
    ) -> Result<Agent, anyhow::Error> {
        let start = Instant::now();
        let poll_interval = Duration::from_millis(500);

        loop {
            if start.elapsed() > timeout {
                return Err(anyhow::anyhow!(
                    "Timeout waiting for agent {} status={}",
                    agent_name,
                    status
                ));
            }

            let agents = self.list_agents().await?;
            if let Some(agent) = agents.iter().find(|a| a.name == agent_name && a.status == status) {
                return Ok(agent.clone());
            }

            tokio::time::sleep(poll_interval).await;
        }
    }
}
