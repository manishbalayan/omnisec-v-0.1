// Response cache — SHA-256 keyed, Redis-backed, TTL-controlled.
//
// Cache key: hex(SHA-256(method + path + sorted-headers-subset + body)).
// Authorization header is intentionally EXCLUDED from the key (treated as
// pass-through) to ensure the cached value isn't keyed per credential,
// which would defeat the purpose.
//
// Headers included in key: Content-Type only (affects response format).
// Body: full request body bytes.

use anyhow::Result;
use redis::AsyncCommands;
use sha2::{Digest, Sha256};

/// A cached response entry stored in Redis as JSON.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CachedResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body_base64: String,
    pub cached_at: chrono::DateTime<chrono::Utc>,
    /// Original upstream latency when this was first fetched.
    pub upstream_latency_ms: u64,
}

/// Shared cache handle — cheap to clone (Arc inside).
#[derive(Clone)]
pub struct ResponseCache {
    client: redis::Client,
    /// Cache TTL in seconds. Default: 3600 (1 hour).
    ttl_secs: usize,
    /// Namespace prefix to avoid key collisions in shared Redis.
    prefix: String,
}

impl ResponseCache {
    pub fn new(redis_url: &str, ttl_secs: usize) -> Result<Self> {
        let client = redis::Client::open(redis_url)?;
        Ok(Self {
            client,
            ttl_secs,
            prefix: "omnisec:proxy:cache:".to_string(),
        })
    }

    /// Compute a deterministic cache key from the request parts.
    pub fn cache_key(method: &str, path: &str, content_type: Option<&str>, body: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(method.as_bytes());
        hasher.update(b"|");
        hasher.update(path.as_bytes());
        hasher.update(b"|");
        hasher.update(content_type.unwrap_or("").as_bytes());
        hasher.update(b"|");
        hasher.update(body);
        hex::encode(hasher.finalize())
    }

    pub async fn get(&self, key: &str) -> Option<CachedResponse> {
        let mut conn = self.client.get_multiplexed_async_connection().await.ok()?;
        let full_key = format!("{}{}", self.prefix, key);
        let raw: String = conn.get(&full_key).await.ok()?;
        serde_json::from_str(&raw).ok()
    }

    pub async fn set(&self, key: &str, entry: &CachedResponse) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let full_key = format!("{}{}", self.prefix, key);
        let serialized = serde_json::to_string(entry)?;
        conn.set_ex::<_, _, ()>(&full_key, serialized, self.ttl_secs as u64).await?;
        Ok(())
    }

    /// Increment a named counter (for metrics).
    pub async fn incr(&self, counter: &str) -> u64 {
        let Ok(mut conn) = self.client.get_multiplexed_async_connection().await else {
            return 0;
        };
        let key = format!("{}metrics:{}", self.prefix, counter);
        conn.incr::<_, _, u64>(&key, 1_u64).await.unwrap_or(0)
    }

    pub async fn get_counter(&self, counter: &str) -> u64 {
        let Ok(mut conn) = self.client.get_multiplexed_async_connection().await else {
            return 0;
        };
        let key = format!("{}metrics:{}", self.prefix, counter);
        conn.get::<_, u64>(&key).await.unwrap_or(0)
    }

    pub async fn metrics_snapshot(&self) -> CacheMetrics {
        let hits = self.get_counter("hits").await;
        let misses = self.get_counter("misses").await;
        let total = hits + misses;
        let hit_rate = if total > 0 { hits as f64 / total as f64 * 100.0 } else { 0.0 };

        let saved_ms = self.get_counter("saved_latency_ms").await;
        let cost_saved = self.get_counter("cost_units_saved").await;

        CacheMetrics { hits, misses, total, hit_rate, saved_latency_ms: saved_ms, cost_units_saved: cost_saved }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct CacheMetrics {
    pub hits: u64,
    pub misses: u64,
    pub total: u64,
    pub hit_rate: f64,
    pub saved_latency_ms: u64,
    pub cost_units_saved: u64,
}
