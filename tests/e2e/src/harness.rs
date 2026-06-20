// E2E test harness — manages infrastructure lifecycle and provides helpers.
//
// Usage:
//   let h = Harness::from_env();           // reads env vars or uses defaults
//   h.wait_healthy(Duration::from_secs(30)).await?;
//   let nats = h.nats().await?;            // direct NATS connection
//   let api  = h.api();                    // OmnisecClient

use anyhow::{bail, Result};
use std::time::{Duration, Instant};
use tokio::time::sleep;

pub struct Harness {
    pub nats_url: String,
    pub api_url: String,
    pub postgres_url: String,
}

impl Harness {
    pub fn from_env() -> Self {
        Self {
            nats_url: std::env::var("NATS_URL")
                .unwrap_or_else(|_| "nats://localhost:4223".to_string()),
            api_url: std::env::var("API_URL")
                .unwrap_or_else(|_| "http://localhost:3003".to_string()),
            postgres_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5433/omnisec_test".to_string()),
        }
    }

    pub fn api(&self) -> crate::client::OmnisecClient {
        crate::client::OmnisecClient::new(&self.api_url)
    }

    pub async fn nats(&self) -> Result<async_nats::Client> {
        let client = async_nats::connect(&self.nats_url).await?;
        Ok(client)
    }

    /// Wait until NATS + API are both reachable.
    pub async fn wait_healthy(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;

        loop {
            if Instant::now() > deadline {
                bail!("Timeout waiting for infrastructure to become healthy");
            }

            let nats_ok = async_nats::connect(&self.nats_url).await.is_ok();
            let api_ok = self.api().health_check().await.unwrap_or(false);

            if nats_ok && api_ok {
                return Ok(());
            }

            sleep(Duration::from_millis(500)).await;
        }
    }

    /// Subscribe to a NATS subject and wait for the first matching message within timeout.
    pub async fn wait_for_nats_message(
        &self,
        subject: &str,
        timeout: Duration,
    ) -> Result<bytes::Bytes> {
        let client = self.nats().await?;
        let mut sub = client.subscribe(subject.to_string()).await?;

        tokio::time::timeout(timeout, async {
            use futures::StreamExt;
            if let Some(msg) = sub.next().await {
                Ok(msg.payload)
            } else {
                bail!("NATS subscription closed before message arrived")
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("Timeout waiting for NATS message on {}", subject))?
    }

    /// Subscribe and wait for any message matching a predicate (parses JSON payload).
    pub async fn wait_for_nats_json<F>(
        &self,
        subject: &str,
        timeout: Duration,
        predicate: F,
    ) -> Result<serde_json::Value>
    where
        F: Fn(&serde_json::Value) -> bool,
    {
        let client = self.nats().await?;
        let mut sub = client.subscribe(subject.to_string()).await?;

        tokio::time::timeout(timeout, async {
            use futures::StreamExt;
            loop {
                if let Some(msg) = sub.next().await {
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&msg.payload) {
                        if predicate(&v) {
                            return Ok(v);
                        }
                    }
                } else {
                    bail!("NATS subscription closed before matching message arrived")
                }
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("Timeout waiting for matching NATS message on {}", subject))?
    }
}
