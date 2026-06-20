// Cost extraction from HTTP responses.
//
// Provider-agnostic: reads the standard OpenAI-compatible `usage` JSON field
// that virtually every LLM provider includes in their responses.
// No model SDK. No vendor-specific parsing.
//
// Supported providers (via generic JSON path):
//   - OpenAI, Azure OpenAI
//   - Anthropic (usage.input_tokens + usage.output_tokens)
//   - Google Gemini (usageMetadata)
//   - Any OpenAI-compatible provider
//
// Token cost is operator-configured (COST_PER_1K_TOKENS env var), not hardcoded.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    /// Model identifier as reported by the response, if present.
    pub model: Option<String>,
}

impl TokenUsage {
    /// Estimate cost in microdollars (millionths of a dollar) using the
    /// operator-configured rate. Default: $0.002 / 1k tokens (GPT-3.5 era).
    pub fn estimated_cost_microdollars(&self, cost_per_1k: f64) -> u64 {
        let tokens = self.total_tokens as f64;
        ((tokens / 1000.0) * cost_per_1k * 1_000_000.0) as u64
    }
}

/// Extract token usage from a JSON response body.
/// Tries multiple field layouts to cover the major providers.
pub fn extract_usage(body: &[u8]) -> Option<TokenUsage> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    try_openai_layout(&v)
        .or_else(|| try_anthropic_layout(&v))
        .or_else(|| try_gemini_layout(&v))
}

fn try_openai_layout(v: &serde_json::Value) -> Option<TokenUsage> {
    let usage = v.get("usage")?;
    let total = usage.get("total_tokens")?.as_u64()?;
    let prompt = usage.get("prompt_tokens").and_then(|x| x.as_u64()).unwrap_or(0);
    let completion = usage.get("completion_tokens").and_then(|x| x.as_u64()).unwrap_or(0);
    let model = v.get("model").and_then(|m| m.as_str()).map(str::to_string);
    Some(TokenUsage { prompt_tokens: prompt, completion_tokens: completion, total_tokens: total, model })
}

fn try_anthropic_layout(v: &serde_json::Value) -> Option<TokenUsage> {
    let usage = v.get("usage")?;
    let input = usage.get("input_tokens")?.as_u64()?;
    let output = usage.get("output_tokens").and_then(|x| x.as_u64()).unwrap_or(0);
    let model = v.get("model").and_then(|m| m.as_str()).map(str::to_string);
    Some(TokenUsage {
        prompt_tokens: input,
        completion_tokens: output,
        total_tokens: input + output,
        model,
    })
}

fn try_gemini_layout(v: &serde_json::Value) -> Option<TokenUsage> {
    let meta = v.get("usageMetadata")?;
    let prompt = meta.get("promptTokenCount").and_then(|x| x.as_u64()).unwrap_or(0);
    let candidates = meta.get("candidatesTokenCount").and_then(|x| x.as_u64()).unwrap_or(0);
    let total = meta.get("totalTokenCount")
        .and_then(|x| x.as_u64())
        .unwrap_or(prompt + candidates);
    Some(TokenUsage { prompt_tokens: prompt, completion_tokens: candidates, total_tokens: total, model: None })
}

/// Read the operator-configured cost per 1k tokens.
/// Defaults to $0.002 (GPT-3.5 baseline) — operator should tune this.
pub fn cost_per_1k_tokens() -> f64 {
    std::env::var("COST_PER_1K_TOKENS")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.002)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openai_layout() {
        let body = br#"{"model":"gpt-4","usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150}}"#;
        let u = extract_usage(body).unwrap();
        assert_eq!(u.total_tokens, 150);
        assert_eq!(u.model.as_deref(), Some("gpt-4"));
    }

    #[test]
    fn test_anthropic_layout() {
        let body = br#"{"model":"claude-3","usage":{"input_tokens":80,"output_tokens":40}}"#;
        let u = extract_usage(body).unwrap();
        assert_eq!(u.total_tokens, 120);
        assert_eq!(u.prompt_tokens, 80);
    }

    #[test]
    fn test_gemini_layout() {
        let body = br#"{"usageMetadata":{"promptTokenCount":60,"candidatesTokenCount":30,"totalTokenCount":90}}"#;
        let u = extract_usage(body).unwrap();
        assert_eq!(u.total_tokens, 90);
    }

    #[test]
    fn test_cost_estimate() {
        let u = TokenUsage { total_tokens: 1000, ..Default::default() };
        let cost = u.estimated_cost_microdollars(0.002);
        assert_eq!(cost, 2000); // $0.002 = 2000 microdollars per 1k tokens
    }
}
