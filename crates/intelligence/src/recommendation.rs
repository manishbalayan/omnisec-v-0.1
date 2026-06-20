// Model Recommendation Engine
//
// Observes proxy-visible signals (request size, response size, latency) to
// infer task complexity and recommend a more cost-appropriate model.
//
// DOES NOT: read prompt content, auto-route, inject into requests.
// DOES: store recommendations for human review and approval.
//
// Complexity signals (all proxy-observable, no prompt reading):
//   - avg_body_size_bytes:     larger prompts → more complex tasks
//   - avg_response_size_bytes: larger outputs → more reasoning required
//   - avg_latency_ms:          slower models chosen → complex tasks
//   - request_count:           sample size for statistical confidence
//
// Complexity score: 0.0 (simple) → 1.0 (complex)

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentObservations {
    pub agent_name: String,
    pub agent_pid: Option<i32>,
    pub current_model: Option<String>,
    pub current_provider: Option<String>,
    pub request_count: i64,
    pub avg_prompt_tokens: f64,
    pub avg_completion_tokens: f64,
    pub avg_latency_ms: f64,
    pub avg_body_size_bytes: f64,
    pub avg_response_size_bytes: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelRecommendation {
    pub id: Uuid,
    pub agent_name: Option<String>,
    pub agent_pid: Option<i32>,
    pub current_model: Option<String>,
    pub current_provider: Option<String>,
    pub recommended_model: String,
    pub recommended_provider: String,
    pub complexity_score: f64,
    pub estimated_savings_pct: f64,
    pub estimated_monthly_savings_usd: f64,
    pub reasoning: String,
    pub status: String,
}

pub struct RecommendationEngine {
    pool: PgPool,
    default_org_id: Uuid,
    /// Operator-configured cost per 1k tokens for current and alternatives.
    /// Stored as (provider, model, cost_per_1k) tuples — configurable, not hardcoded.
    model_catalog: Vec<ModelEntry>,
}

#[derive(Debug, Clone)]
pub struct ModelEntry {
    pub provider: String,
    pub model: String,
    /// Cost per 1k tokens in USD — operator-configured via DB or env vars.
    pub cost_per_1k: f64,
    /// Maximum complexity score this model is suitable for.
    pub max_complexity: f64,
}

impl RecommendationEngine {
    pub fn new(pool: PgPool, default_org_id: Uuid) -> Self {
        Self {
            pool,
            default_org_id,
            model_catalog: default_model_catalog(),
        }
    }

    /// Add or replace a model entry in the catalog.
    pub fn add_model(&mut self, entry: ModelEntry) {
        self.model_catalog.retain(|e| !(e.provider == entry.provider && e.model == entry.model));
        self.model_catalog.push(entry);
    }

    /// Compute recommendations for all agents with sufficient observations.
    pub async fn compute_recommendations(&self) -> Result<Vec<ModelRecommendation>> {
        let observations = self.fetch_agent_observations().await?;
        let mut recommendations = Vec::new();

        for obs in &observations {
            if obs.request_count < 10 {
                continue; // Need at least 10 samples for meaningful inference
            }

            let complexity = compute_complexity_score(obs);
            if let Some(rec) = self.recommend_model(&obs, complexity).await? {
                recommendations.push(rec);
            }
        }

        Ok(recommendations)
    }

    /// Fetch pending (human-unreviewed) recommendations.
    pub async fn pending_recommendations(&self) -> Result<Vec<ModelRecommendation>> {
        let rows: Vec<(Uuid, Option<String>, Option<i32>, Option<String>, Option<String>,
                        String, String, f64, f64, f64, String, String)> = sqlx::query_as(
            "SELECT id, agent_name, agent_pid, current_model, current_provider, \
                    recommended_model, recommended_provider, complexity_score, \
                    estimated_savings_pct, estimated_monthly_savings_usd, reasoning, status \
             FROM model_recommendations \
             WHERE organization_id = $1 AND status = 'pending' \
             ORDER BY estimated_savings_pct DESC LIMIT 100",
        )
        .bind(self.default_org_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|(id, agent_name, agent_pid, current_model,
                                   current_provider, rec_model, rec_provider,
                                   complexity, savings_pct, savings_usd, reasoning, status)| {
            ModelRecommendation {
                id,
                agent_name,
                agent_pid,
                current_model,
                current_provider,
                recommended_model: rec_model,
                recommended_provider: rec_provider,
                complexity_score: complexity,
                estimated_savings_pct: savings_pct,
                estimated_monthly_savings_usd: savings_usd,
                reasoning,
                status,
            }
        }).collect())
    }

    /// Human approves a recommendation — records the decision, does NOT route.
    pub async fn approve_recommendation(&self, id: Uuid, approved_by: &str) -> Result<()> {
        sqlx::query(
            "UPDATE model_recommendations SET status = 'approved', approved_by = $1, \
             approved_at = NOW(), updated_at = NOW() WHERE id = $2",
        )
        .bind(approved_by)
        .bind(id)
        .execute(&self.pool)
        .await?;

        tracing::info!("Recommendation {} approved by {}", id, approved_by);
        Ok(())
    }

    /// Human rejects a recommendation.
    pub async fn reject_recommendation(&self, id: Uuid, reason: &str) -> Result<()> {
        sqlx::query(
            "UPDATE model_recommendations SET status = 'rejected', \
             reasoning = CONCAT(reasoning, ' | Rejected: ', $1), \
             updated_at = NOW() WHERE id = $2",
        )
        .bind(reason)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn fetch_agent_observations(&self) -> Result<Vec<AgentObservations>> {
        let rows: Vec<(Option<String>, Option<i32>, Option<String>, Option<String>,
                        i64, f64, f64, f64, f64, f64)> = sqlx::query_as(
            "SELECT agent_name, agent_pid, model, provider, COUNT(*), \
                    COALESCE(AVG(prompt_tokens),0), COALESCE(AVG(completion_tokens),0), \
                    COALESCE(AVG(latency_ms),0), COALESCE(AVG(body_size_bytes),0), \
                    COALESCE(AVG(response_size_bytes),0) \
             FROM proxy_request_log \
             WHERE organization_id = $1 AND created_at >= NOW() - INTERVAL '7 days' \
             GROUP BY agent_name, agent_pid, model, provider \
             HAVING COUNT(*) >= 10",
        )
        .bind(self.default_org_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|(agent_name, agent_pid, model, provider,
                                   count, avg_prompt, avg_completion,
                                   avg_latency, avg_body, avg_response)| {
            AgentObservations {
                agent_name: agent_name.unwrap_or_else(|| "unknown".to_string()),
                agent_pid,
                current_model: model,
                current_provider: provider,
                request_count: count,
                avg_prompt_tokens: avg_prompt,
                avg_completion_tokens: avg_completion,
                avg_latency_ms: avg_latency,
                avg_body_size_bytes: avg_body,
                avg_response_size_bytes: avg_response,
            }
        }).collect())
    }

    async fn recommend_model(
        &self,
        obs: &AgentObservations,
        complexity: f64,
    ) -> Result<Option<ModelRecommendation>> {
        // Find the cheapest model that handles this complexity level
        let mut candidates: Vec<&ModelEntry> = self.model_catalog
            .iter()
            .filter(|m| m.max_complexity >= complexity)
            .collect();
        candidates.sort_by(|a, b| a.cost_per_1k.partial_cmp(&b.cost_per_1k).unwrap());

        let best = match candidates.first() {
            Some(m) => m,
            None => return Ok(None),
        };

        // Only recommend if it differs from current and saves >= 10%
        if obs.current_model.as_deref() == Some(&best.model) {
            return Ok(None);
        }

        let current_cost = self.model_catalog
            .iter()
            .find(|m| obs.current_model.as_deref() == Some(&m.model))
            .map(|m| m.cost_per_1k)
            .unwrap_or(0.002);

        let savings_pct = if current_cost > 0.0 {
            (current_cost - best.cost_per_1k) / current_cost * 100.0
        } else {
            0.0
        };

        if savings_pct < 10.0 {
            return Ok(None);
        }

        // Estimate monthly savings based on observed rate
        let daily_tokens = obs.avg_prompt_tokens + obs.avg_completion_tokens;
        let monthly_tokens = daily_tokens * 30.0 * obs.request_count as f64;
        let current_monthly = (monthly_tokens / 1000.0) * current_cost;
        let recommended_monthly = (monthly_tokens / 1000.0) * best.cost_per_1k;
        let monthly_savings = current_monthly - recommended_monthly;

        let reasoning = format!(
            "Agent '{}' observed complexity score: {:.2}. \
             Avg prompt: {:.0} tokens, avg completion: {:.0} tokens, \
             avg latency: {:.0}ms over {} requests. \
             Current model ({}) costs ${:.4}/1k tokens. \
             {} costs ${:.4}/1k tokens — {:.0}% cheaper. \
             Estimated monthly savings: ${:.2}. HUMAN APPROVAL REQUIRED.",
            obs.agent_name, complexity,
            obs.avg_prompt_tokens, obs.avg_completion_tokens,
            obs.avg_latency_ms, obs.request_count,
            obs.current_model.as_deref().unwrap_or("unknown"),
            current_cost,
            best.model, best.cost_per_1k,
            savings_pct, monthly_savings
        );

        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO model_recommendations \
             (id, organization_id, agent_pid, agent_name, current_model, current_provider, \
              recommended_model, recommended_provider, observed_avg_prompt_tokens, \
              observed_avg_completion_tokens, observed_avg_latency_ms, observed_request_count, \
              estimated_savings_pct, estimated_monthly_savings_usd, complexity_score, reasoning) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) \
             ON CONFLICT DO NOTHING",
        )
        .bind(id)
        .bind(self.default_org_id)
        .bind(obs.agent_pid)
        .bind(&obs.agent_name)
        .bind(&obs.current_model)
        .bind(&obs.current_provider)
        .bind(&best.model)
        .bind(&best.provider)
        .bind(obs.avg_prompt_tokens as i32)
        .bind(obs.avg_completion_tokens as i32)
        .bind(obs.avg_latency_ms as i32)
        .bind(obs.request_count as i32)
        .bind(savings_pct)
        .bind(monthly_savings)
        .bind(complexity)
        .bind(&reasoning)
        .execute(&self.pool)
        .await?;

        Ok(Some(ModelRecommendation {
            id,
            agent_name: Some(obs.agent_name.clone()),
            agent_pid: obs.agent_pid,
            current_model: obs.current_model.clone(),
            current_provider: obs.current_provider.clone(),
            recommended_model: best.model.clone(),
            recommended_provider: best.provider.clone(),
            complexity_score: complexity,
            estimated_savings_pct: savings_pct,
            estimated_monthly_savings_usd: monthly_savings,
            reasoning,
            status: "pending".to_string(),
        }))
    }
}

/// Complexity score from proxy-observable signals only (no prompt reading).
fn compute_complexity_score(obs: &AgentObservations) -> f64 {
    // Normalize each signal to [0, 1] with empirical thresholds
    let prompt_score = (obs.avg_prompt_tokens / 4000.0).min(1.0);
    let completion_score = (obs.avg_completion_tokens / 2000.0).min(1.0);
    let latency_score = (obs.avg_latency_ms / 30_000.0).min(1.0);
    let body_score = (obs.avg_body_size_bytes / 16_000.0).min(1.0);

    // Weighted average — prompt size and completion size are strongest signals
    0.35 * prompt_score + 0.30 * completion_score + 0.20 * latency_score + 0.15 * body_score
}

/// Default model catalog — operator should override via DB entries.
/// These are reference data points, not hardcoded pricing commitments.
fn default_model_catalog() -> Vec<ModelEntry> {
    vec![
        ModelEntry { provider: "anthropic".into(), model: "claude-haiku-4-5".into(), cost_per_1k: 0.00025, max_complexity: 0.4 },
        ModelEntry { provider: "openai".into(),    model: "gpt-4o-mini".into(),      cost_per_1k: 0.00015, max_complexity: 0.4 },
        ModelEntry { provider: "anthropic".into(), model: "claude-sonnet-4-6".into(),cost_per_1k: 0.003,   max_complexity: 0.75 },
        ModelEntry { provider: "openai".into(),    model: "gpt-4o".into(),           cost_per_1k: 0.005,   max_complexity: 0.9 },
        ModelEntry { provider: "anthropic".into(), model: "claude-opus-4-7".into(),  cost_per_1k: 0.015,   max_complexity: 1.0 },
    ]
}
