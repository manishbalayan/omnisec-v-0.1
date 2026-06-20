use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    pub telegram_bot_token: Option<String>,
    pub telegram_chat_id: Option<String>,
    pub email_smtp_host: Option<String>,
    pub email_smtp_port: Option<u16>,
    pub email_username: Option<String>,
    pub email_password: Option<String>,
    pub slack_webhook_url: Option<String>,
}

impl AlertConfig {
    /// Create a config configured for Telegram-only delivery.
    pub fn telegram_only(bot_token: String, chat_id: String) -> Self {
        Self {
            telegram_bot_token: Some(bot_token),
            telegram_chat_id: Some(chat_id),
            email_smtp_host: None,
            email_smtp_port: None,
            email_username: None,
            email_password: None,
            slack_webhook_url: None,
        }
    }
}

/// Ring buffer of recent message fingerprints for deduplication.
#[derive(Debug)]
struct DedupRing {
    /// Fingerprints of recently sent messages, oldest first.
    recent: VecDeque<u64>,
    /// Maximum number of fingerprints to keep.
    capacity: usize,
}

impl DedupRing {
    fn new(capacity: usize) -> Self {
        Self {
            recent: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Returns `true` if this message fingerprint has been seen recently.
    fn is_duplicate(&mut self, fingerprint: u64) -> bool {
        if self.recent.contains(&fingerprint) {
            return true;
        }
        self.recent.push_back(fingerprint);
        if self.recent.len() > self.capacity {
            self.recent.pop_front();
        }
        false
    }
}

pub struct AlertManager {
    config: AlertConfig,
    /// Dedup ring for sent messages (keyed by channel name).
    dedup: HashMap<String, DedupRing>,
    /// Rate limiter: last send time per channel.
    last_sent: HashMap<String, Instant>,
    /// Minimum interval between sends on the same channel.
    min_interval: Duration,
    /// Maximum send retries.
    max_retries: u32,
    /// Shared reqwest client for connection reuse.
    client: reqwest::Client,
}

impl AlertManager {
    pub fn new(config: AlertConfig) -> Self {
        Self {
            config,
            dedup: HashMap::new(),
            last_sent: HashMap::new(),
            min_interval: Duration::from_secs(5), // max 12 messages/minute/channel
            max_retries: 3,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client should build"),
        }
    }

    /// Send an alert with deduplication, rate limiting, and retry logic.
    pub async fn send_alert(&mut self, message: &str, channel: &str) -> Result<()> {
        // Deduplication: skip if we've sent the same message recently
        let fingerprint = self.fingerprint(message);
        let dedup = self.dedup.entry(channel.to_string())
            .or_insert_with(|| DedupRing::new(100));

        if dedup.is_duplicate(fingerprint) {
            tracing::debug!("Deduplicated duplicate alert on channel '{}': {}", channel, message);
            return Ok(());
        }

        // Rate limiting: enforce minimum interval between sends
        if let Some(last) = self.last_sent.get(channel) {
            let elapsed = Instant::now().duration_since(*last);
            if elapsed < self.min_interval {
                let wait = self.min_interval - elapsed;
                tokio::time::sleep(wait).await;
            }
        }

        // Send with retry
        let mut last_error = None;
        for attempt in 1..=self.max_retries {
            match self.send_inner(message, channel).await {
                Ok(()) => {
                    self.last_sent.insert(channel.to_string(), Instant::now());
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(
                        "Alert send attempt {}/{} failed on channel '{}': {}",
                        attempt,
                        self.max_retries,
                        channel,
                        e
                    );
                    last_error = Some(e);
                    if attempt < self.max_retries {
                        let backoff = Duration::from_secs(2u64 * attempt as u64);
                        tokio::time::sleep(backoff).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Alert send failed after {} retries", self.max_retries)))
    }

    /// Simple fingerprint: hash the message string into a u64.
    fn fingerprint(&self, message: &str) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        message.hash(&mut hasher);
        hasher.finish()
    }

    /// Send without dedup, rate limit, or retry (the caller handles those).
    async fn send_inner(&self, message: &str, channel: &str) -> Result<()> {
        match channel {
            "telegram" => self.send_telegram(message).await,
            "email" => self.send_email(message).await,
            "slack" => self.send_slack(message).await,
            _ => Err(anyhow::anyhow!("Unknown channel: {}", channel)),
        }
    }

    async fn send_telegram(&self, message: &str) -> Result<()> {
        let token = self.config.telegram_bot_token.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Telegram bot token not configured"))?;
        let chat_id = self.config.telegram_chat_id.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Telegram chat ID not configured"))?;

        let url = format!("https://api.telegram.org/bot{}/sendMessage", token);

        let resp = self.client
            .post(&url)
            .json(&serde_json::json!({
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "HTML"
            }))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Telegram API error ({}): {}", status, body));
        }

        Ok(())
    }

    async fn send_email(&self, message: &str) -> Result<()> {
        tracing::info!("Email alert: {}", message);
        Ok(())
    }

    async fn send_slack(&self, message: &str) -> Result<()> {
        let webhook_url = self.config.slack_webhook_url.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Slack webhook URL not configured"))?;

        let resp = self.client
            .post(webhook_url)
            .json(&serde_json::json!({
                "text": message
            }))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Slack webhook error ({}): {}", status, body));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dedup_ring() {
        let mut ring = DedupRing::new(3);
        assert!(!ring.is_duplicate(42));
        assert!(ring.is_duplicate(42));
        assert!(!ring.is_duplicate(99));
        assert!(ring.is_duplicate(99));
    }

    #[test]
    fn test_dedup_ring_capacity() {
        let mut ring = DedupRing::new(2);
        assert!(!ring.is_duplicate(1)); // ring: [1]
        assert!(!ring.is_duplicate(2)); // ring: [1, 2]
        // Ring is full; oldest (1) should fall off
        assert!(!ring.is_duplicate(3)); // ring: [2, 3]
        // 1 is no longer in the ring
        assert!(!ring.is_duplicate(1)); // ring: [3, 1]
        // After pushing 1, it should now be recognised as a duplicate
        assert!(ring.is_duplicate(1));  // ring: [3, 1] — 1 is present
        assert!(ring.is_duplicate(3));  // ring: [3, 1] — 3 is present
    }

    #[test]
    fn test_fingerprint() {
        let config = AlertConfig {
            telegram_bot_token: None,
            telegram_chat_id: None,
            email_smtp_host: None,
            email_smtp_port: None,
            email_username: None,
            email_password: None,
            slack_webhook_url: None,
        };
        let manager = AlertManager::new(config);

        let fp1 = manager.fingerprint("hello");
        let fp2 = manager.fingerprint("hello");
        let fp3 = manager.fingerprint("world");

        assert_eq!(fp1, fp2);
        assert_ne!(fp1, fp3);
    }
}
