// Omnisec Proxy — Transparent HTTP caching layer for AI provider traffic.
//
// Provider-agnostic: routes to PROXY_TARGET (any HTTP/HTTPS endpoint).
// Adds: response caching (Redis), cost extraction, traffic metrics.
// Does NOT: inspect prompt content, inject code, route between models.
//
// Config (env vars):
//   PROXY_TARGET       upstream base URL  (default: https://api.openai.com)
//   PROXY_BIND         listen address     (default: 0.0.0.0:8080)
//   REDIS_URL          Redis connection   (default: redis://localhost:6379)
//   CACHE_TTL_SECS     cache entry TTL    (default: 3600)
//   CACHE_ENABLED      "false" to disable (default: true)
//   COST_PER_1K_TOKENS cost rate          (default: 0.002)

mod cache;
mod cost;

use anyhow::Result;
use axum::{body::Body, extract::State, http::Request, response::Response, Router};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use cache::{CachedResponse, ResponseCache};
use cost::extract_usage;

#[derive(Clone)]
struct ProxyState {
    target_url: String,
    cache: Option<ResponseCache>,
    cost_per_1k: f64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "omnisec_proxy=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Omnisec Proxy (caching layer)");

    let target_url = std::env::var("PROXY_TARGET")
        .unwrap_or_else(|_| "https://api.openai.com".to_string());

    let cache_enabled = std::env::var("CACHE_ENABLED")
        .map(|v| v.to_lowercase() != "false")
        .unwrap_or(true);

    let redis_url = std::env::var("REDIS_URL")
        .unwrap_or_else(|_| "redis://localhost:6379".to_string());

    let ttl: usize = std::env::var("CACHE_TTL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3600);

    let cache = if cache_enabled {
        match ResponseCache::new(&redis_url, ttl) {
            Ok(c) => {
                tracing::info!("Response cache enabled (Redis: {}, TTL: {}s)", redis_url, ttl);
                Some(c)
            }
            Err(e) => {
                tracing::warn!("Cache disabled — Redis unavailable: {}", e);
                None
            }
        }
    } else {
        tracing::info!("Response cache disabled (CACHE_ENABLED=false)");
        None
    };

    let state = Arc::new(ProxyState {
        target_url: target_url.clone(),
        cache,
        cost_per_1k: cost::cost_per_1k_tokens(),
    });

    let app = Router::new()
        .route("/proxy/cache/metrics", axum::routing::get(cache_metrics_handler))
        .fallback(proxy_handler)
        .with_state(state);

    let bind = std::env::var("PROXY_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let addr: SocketAddr = bind.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Proxy listening on {} → {}", bind, target_url);

    axum::serve(listener, app).await?;
    Ok(())
}

async fn proxy_handler(
    State(state): State<Arc<ProxyState>>,
    req: Request<Body>,
) -> Result<Response<Body>, axum::http::StatusCode> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers: Vec<_> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    // Collect body bytes for cache key computation and forwarding.
    let body_bytes: Bytes = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return Err(axum::http::StatusCode::BAD_REQUEST),
    };

    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let content_type = headers
        .iter()
        .find(|(k, _)| k.as_str().eq_ignore_ascii_case("content-type"))
        .and_then(|(_, v)| v.to_str().ok())
        .map(str::to_string);

    // Only cache non-streaming POST requests (streaming responses must not be cached).
    let is_cacheable = method == axum::http::Method::POST
        && !headers.iter().any(|(k, v)| {
            k.as_str().eq_ignore_ascii_case("accept")
                && v.to_str().unwrap_or("").contains("text/event-stream")
        });

    let cache_key = if is_cacheable {
        Some(ResponseCache::cache_key(
            method.as_str(),
            path,
            content_type.as_deref(),
            &body_bytes,
        ))
    } else {
        None
    };

    // ── Cache lookup ────────────────────────────────────────────────────────
    if let (Some(ref key), Some(ref cache)) = (&cache_key, &state.cache) {
        if let Some(cached) = cache.get(key).await {
            tracing::info!("CACHE HIT {} {} (saved {}ms)", method, path, cached.upstream_latency_ms);
            let _ = cache.incr("hits").await;
            let _ = cache.incr(&format!("saved_latency_ms+{}", cached.upstream_latency_ms)).await;

            let body_raw = base64_decode(&cached.body_base64);
            let mut resp = Response::builder().status(cached.status);
            for (k, v) in &cached.headers {
                resp = resp.header(k.as_str(), v.as_str());
            }
            resp = resp.header("X-Omnisec-Cache", "HIT");
            return resp
                .body(Body::from(body_raw))
                .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    // ── Upstream request ─────────────────────────────────────────────────────
    let target = format!("{}{}", state.target_url, uri);
    let client: Client<_, Body> = Client::builder(TokioExecutor::new()).build_http();

    let mut builder = Request::builder().method(method.clone()).uri(&target);
    for (key, value) in &headers {
        builder = builder.header(key, value);
    }
    let upstream_req = builder
        .body(Body::from(body_bytes))
        .map_err(|_| axum::http::StatusCode::BAD_GATEWAY)?;

    let t0 = Instant::now();
    let upstream_resp = match client.request(upstream_req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Upstream error: {}", e);
            return Err(axum::http::StatusCode::BAD_GATEWAY);
        }
    };
    let latency_ms = t0.elapsed().as_millis() as u64;

    let status = upstream_resp.status();
    let resp_headers: Vec<(String, String)> = upstream_resp
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str().ok().map(|vs| (k.to_string(), vs.to_string()))
        })
        .collect();

    let resp_bytes: Bytes = match upstream_resp.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return Err(axum::http::StatusCode::BAD_GATEWAY),
    };

    tracing::info!(
        "UPSTREAM {} {} → {} in {}ms ({} bytes)",
        method, path, status.as_u16(), latency_ms, resp_bytes.len()
    );

    // ── Cost extraction ──────────────────────────────────────────────────────
    if let Some(usage) = extract_usage(&resp_bytes) {
        let cost_ud = usage.estimated_cost_microdollars(state.cost_per_1k);
        tracing::info!(
            "TOKENS model={} total={} prompt={} completion={} cost={}μ$",
            usage.model.as_deref().unwrap_or("unknown"),
            usage.total_tokens, usage.prompt_tokens, usage.completion_tokens, cost_ud
        );
        if let Some(ref cache) = state.cache {
            let _ = cache.incr(&format!("tokens+{}", usage.total_tokens)).await;
            let _ = cache.incr(&format!("cost_units_saved+{}", cost_ud)).await;
        }
    }

    // ── Store in cache ───────────────────────────────────────────────────────
    if let (Some(ref key), Some(ref cache)) = (&cache_key, &state.cache) {
        if status.is_success() {
            let entry = CachedResponse {
                status: status.as_u16(),
                headers: resp_headers.clone(),
                body_base64: base64_encode(&resp_bytes),
                cached_at: chrono::Utc::now(),
                upstream_latency_ms: latency_ms,
            };
            if let Err(e) = cache.set(key, &entry).await {
                tracing::warn!("Cache write failed: {}", e);
            }
        }
        let _ = cache.incr("misses").await;
    }

    // ── Build response ───────────────────────────────────────────────────────
    let mut resp = Response::builder().status(status);
    for (k, v) in &resp_headers {
        resp = resp.header(k.as_str(), v.as_str());
    }
    resp = resp.header("X-Omnisec-Cache", "MISS");
    resp = resp.header("X-Omnisec-Latency-Ms", latency_ms.to_string());

    resp.body(Body::from(resp_bytes))
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
}

async fn cache_metrics_handler(
    State(state): State<Arc<ProxyState>>,
) -> axum::Json<serde_json::Value> {
    if let Some(ref cache) = state.cache {
        let m = cache.metrics_snapshot().await;
        axum::Json(serde_json::json!({
            "cache": {
                "hits": m.hits,
                "misses": m.misses,
                "total": m.total,
                "hit_rate_pct": format!("{:.1}", m.hit_rate),
                "saved_latency_ms": m.saved_latency_ms,
                "cost_units_saved": m.cost_units_saved,
            }
        }))
    } else {
        axum::Json(serde_json::json!({ "cache": { "enabled": false } }))
    }
}

fn base64_encode(data: &[u8]) -> String {
    use std::io::Write;
    let mut enc = Vec::new();
    // Simple base64 via standard alphabets
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut i = 0;
    while i + 2 < data.len() {
        let b0 = data[i] as usize;
        let b1 = data[i + 1] as usize;
        let b2 = data[i + 2] as usize;
        enc.push(alphabet[b0 >> 2]);
        enc.push(alphabet[((b0 & 3) << 4) | (b1 >> 4)]);
        enc.push(alphabet[((b1 & 0xf) << 2) | (b2 >> 6)]);
        enc.push(alphabet[b2 & 0x3f]);
        i += 3;
    }
    if i < data.len() {
        let b0 = data[i] as usize;
        enc.push(alphabet[b0 >> 2]);
        if i + 1 < data.len() {
            let b1 = data[i + 1] as usize;
            enc.push(alphabet[((b0 & 3) << 4) | (b1 >> 4)]);
            enc.push(alphabet[(b1 & 0xf) << 2]);
        } else {
            enc.push(alphabet[(b0 & 3) << 4]);
            enc.push(b'=');
        }
        enc.push(b'=');
    }
    String::from_utf8(enc).unwrap_or_default()
}

fn base64_decode(s: &str) -> Vec<u8> {
    fn val(c: u8) -> u8 {
        match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => 0,
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 3 < bytes.len() {
        let v0 = val(bytes[i]);
        let v1 = val(bytes[i + 1]);
        let v2 = val(bytes[i + 2]);
        let v3 = val(bytes[i + 3]);
        out.push((v0 << 2) | (v1 >> 4));
        if bytes[i + 2] != b'=' { out.push((v1 << 4) | (v2 >> 2)); }
        if bytes[i + 3] != b'=' { out.push((v2 << 6) | v3); }
        i += 4;
    }
    out
}
