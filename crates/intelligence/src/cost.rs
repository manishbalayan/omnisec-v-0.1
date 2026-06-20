// Cost Intelligence Engine
//
// Tracks per-agent, per-model, per-provider cost with no model SDK coupling.
// Token counts come from proxy observations (standard JSON response parsing).
// Cost rates are operator-configured, not hardcoded.

use anyhow::Result;
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestCostRecord {
    pub organization_id: Uuid,
    pub agent_pid: Option<i32>,
    pub agent_name: Option<String>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
    pub cost_microdollars: i64,
    pub http_method: Option<String>,
    pub path: Option<String>,
    pub response_status: Option<i16>,
    pub latency_ms: Option<i32>,
    pub cache_hit: bool,
    pub body_size_bytes: Option<i32>,
    pub response_size_bytes: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostSummary {
    pub provider: Option<String>,
    pub model: Option<String>,
    pub agent_name: Option<String>,
    pub request_count: i64,
    pub total_tokens: i64,
    pub cost_microdollars: i64,
    pub cost_usd: f64,
    pub cache_hits: i64,
    pub cache_hit_rate_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostDashboard {
    pub period: String,
    pub total_cost_usd: f64,
    pub total_tokens: i64,
    pub total_requests: i64,
    pub cache_hit_rate_pct: f64,
    pub by_agent: Vec<CostSummary>,
    pub by_model: Vec<CostSummary>,
    pub by_day: Vec<DailyCost>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyCost {
    pub date: String,
    pub cost_usd: f64,
    pub total_tokens: i64,
    pub request_count: i64,
}

pub struct CostIntelligenceEngine {
    pool: PgPool,
    default_org_id: Uuid,
}

impl CostIntelligenceEngine {
    pub fn new(pool: PgPool, default_org_id: Uuid) -> Self {
        Self { pool, default_org_id }
    }

    /// Record a single proxied API call.
    pub async fn record_request(&self, record: &RequestCostRecord) -> Result<()> {
        sqlx::query(
            "INSERT INTO proxy_request_log \
             (organization_id, agent_pid, agent_name, provider, model, \
              prompt_tokens, completion_tokens, total_tokens, cost_microdollars, \
              http_method, path, response_status, latency_ms, cache_hit, \
              body_size_bytes, response_size_bytes) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
        )
        .bind(record.organization_id)
        .bind(record.agent_pid)
        .bind(&record.agent_name)
        .bind(&record.provider)
        .bind(&record.model)
        .bind(record.prompt_tokens)
        .bind(record.completion_tokens)
        .bind(record.total_tokens)
        .bind(record.cost_microdollars)
        .bind(&record.http_method)
        .bind(&record.path)
        .bind(record.response_status)
        .bind(record.latency_ms)
        .bind(record.cache_hit)
        .bind(record.body_size_bytes)
        .bind(record.response_size_bytes)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Daily dashboard: cost breakdown for a given period.
    pub async fn cost_dashboard(&self, days: i32) -> Result<CostDashboard> {
        let since: DateTime<Utc> = Utc::now() - chrono::Duration::days(days as i64);

        // Totals
        let totals: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT \
               COALESCE(SUM(total_tokens),0), \
               COALESCE(SUM(cost_microdollars),0), \
               COUNT(*), \
               COALESCE(SUM(CASE WHEN cache_hit THEN 1 ELSE 0 END),0) \
             FROM proxy_request_log \
             WHERE organization_id = $1 AND created_at >= $2",
        )
        .bind(self.default_org_id)
        .bind(since)
        .fetch_one(&self.pool)
        .await?;

        let (total_tokens, total_cost_ud, total_requests, cache_hits) = totals;
        let cache_hit_rate = if total_requests > 0 {
            cache_hits as f64 / total_requests as f64 * 100.0
        } else {
            0.0
        };

        // By agent
        let by_agent = self.cost_by_agent(days).await?;
        // By model
        let by_model = self.cost_by_model(days).await?;
        // By day
        let by_day = self.cost_by_day(days).await?;

        Ok(CostDashboard {
            period: format!("last_{}_days", days),
            total_cost_usd: total_cost_ud as f64 / 1_000_000.0,
            total_tokens,
            total_requests,
            cache_hit_rate_pct: cache_hit_rate,
            by_agent,
            by_model,
            by_day,
        })
    }

    async fn cost_by_agent(&self, days: i32) -> Result<Vec<CostSummary>> {
        let since = Utc::now() - chrono::Duration::days(days as i64);
        let rows: Vec<(Option<String>, i64, i64, i64, i64)> = sqlx::query_as(
            "SELECT agent_name, COUNT(*), COALESCE(SUM(total_tokens),0), \
                    COALESCE(SUM(cost_microdollars),0), \
                    COALESCE(SUM(CASE WHEN cache_hit THEN 1 ELSE 0 END),0) \
             FROM proxy_request_log \
             WHERE organization_id = $1 AND created_at >= $2 \
             GROUP BY agent_name ORDER BY SUM(cost_microdollars) DESC LIMIT 50",
        )
        .bind(self.default_org_id)
        .bind(since)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|(agent, reqs, tokens, cost_ud, hits)| {
            let hit_rate = if reqs > 0 { hits as f64 / reqs as f64 * 100.0 } else { 0.0 };
            CostSummary {
                provider: None,
                model: None,
                agent_name: agent,
                request_count: reqs,
                total_tokens: tokens,
                cost_microdollars: cost_ud,
                cost_usd: cost_ud as f64 / 1_000_000.0,
                cache_hits: hits,
                cache_hit_rate_pct: hit_rate,
            }
        }).collect())
    }

    async fn cost_by_model(&self, days: i32) -> Result<Vec<CostSummary>> {
        let since = Utc::now() - chrono::Duration::days(days as i64);
        let rows: Vec<(Option<String>, Option<String>, i64, i64, i64)> = sqlx::query_as(
            "SELECT provider, model, COUNT(*), COALESCE(SUM(total_tokens),0), \
                    COALESCE(SUM(cost_microdollars),0) \
             FROM proxy_request_log \
             WHERE organization_id = $1 AND created_at >= $2 \
             GROUP BY provider, model ORDER BY SUM(cost_microdollars) DESC LIMIT 50",
        )
        .bind(self.default_org_id)
        .bind(since)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|(provider, model, reqs, tokens, cost_ud)| CostSummary {
            provider,
            model,
            agent_name: None,
            request_count: reqs,
            total_tokens: tokens,
            cost_microdollars: cost_ud,
            cost_usd: cost_ud as f64 / 1_000_000.0,
            cache_hits: 0,
            cache_hit_rate_pct: 0.0,
        }).collect())
    }

    async fn cost_by_day(&self, days: i32) -> Result<Vec<DailyCost>> {
        let since = Utc::now() - chrono::Duration::days(days as i64);
        let rows: Vec<(NaiveDate, i64, i64, i64)> = sqlx::query_as(
            "SELECT DATE(created_at), COUNT(*), COALESCE(SUM(total_tokens),0), \
                    COALESCE(SUM(cost_microdollars),0) \
             FROM proxy_request_log \
             WHERE organization_id = $1 AND created_at >= $2 \
             GROUP BY DATE(created_at) ORDER BY DATE(created_at) ASC",
        )
        .bind(self.default_org_id)
        .bind(since)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|(date, reqs, tokens, cost_ud)| DailyCost {
            date: date.to_string(),
            cost_usd: cost_ud as f64 / 1_000_000.0,
            total_tokens: tokens,
            request_count: reqs,
        }).collect())
    }
}
