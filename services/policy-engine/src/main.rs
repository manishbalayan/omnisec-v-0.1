use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use std::sync::OnceLock;

/// Cached API key — read once from the environment at first request.
static API_KEY: OnceLock<Option<String>> = OnceLock::new();
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Serialize, Deserialize)]
struct Policy {
    id: String,
    name: String,
    conditions: PolicyConditions,
    action: PolicyAction,
    enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct PolicyConditions {
    process_dead: Option<bool>,
    cpu_above: Option<f64>,
    memory_above: Option<f64>,
    destination: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
enum PolicyAction {
    Allow,
    Alert,
    Block,
    Restart,
}

struct PolicyState {
    policies: Vec<Policy>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "omnisec_policy_engine=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Omnisec Policy Engine v0.1.0");

    if std::env::var("OMNISEC_API_KEY").is_err() {
        tracing::warn!(
            "OMNISEC_API_KEY not set. Policy engine authentication is DISABLED. Set this in production."
        );
    }

    let state = Arc::new(RwLock::new(PolicyState {
        policies: Vec::new(),
    }));

    let app = Router::new()
        .route("/", get(health_check))
        .route("/api/policies", get(list_policies))
        .route("/api/policies", post(create_policy))
        .route("/api/evaluate", post(evaluate_policy))
        .layer(middleware::from_fn(auth_middleware))
        .with_state(state);

    let bind = std::env::var("POLICY_ENGINE_BIND")
        .unwrap_or_else(|_| "0.0.0.0:3001".to_string());

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("Policy Engine listening on {}", bind);

    axum::serve(listener, app).await?;

    Ok(())
}

async fn auth_middleware(
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    // Health endpoint is always accessible
    if request.uri().path() == "/" {
        return next.run(request).await;
    }

    let expected = API_KEY.get_or_init(|| std::env::var("OMNISEC_API_KEY").ok());
    let Some(ref expected) = expected else {
        return next.run(request).await;
    };

    let provided = request
        .headers()
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if provided == expected {
        next.run(request).await
    } else {
        tracing::debug!("Rejected request with invalid API key");
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "unauthorized",
                "message": "Valid X-API-Key header required"
            })),
        )
            .into_response()
    }
}

async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "service": "omnisec-policy-engine"
    }))
}

async fn list_policies(
    State(state): State<Arc<RwLock<PolicyState>>>,
) -> Json<Value> {
    let state = state.read().await;
    Json(json!({ "policies": state.policies }))
}

async fn create_policy(
    State(state): State<Arc<RwLock<PolicyState>>>,
    Json(policy): Json<Policy>,
) -> Json<Value> {
    let mut state = state.write().await;
    state.policies.push(policy);
    Json(json!({ "status": "created" }))
}

async fn evaluate_policy(
    State(state): State<Arc<RwLock<PolicyState>>>,
    Json(event): Json<Value>,
) -> Json<Value> {
    let state = state.read().await;

    let mut actions = Vec::new();

    for policy in &state.policies {
        if !policy.enabled {
            continue;
        }

        let mut matches = true;

        if let Some(process_dead) = policy.conditions.process_dead {
            if event.get("process_dead").and_then(|v| v.as_bool()) != Some(process_dead) {
                matches = false;
            }
        }

        if let Some(cpu_above) = policy.conditions.cpu_above {
            if event.get("cpu_percent").and_then(|v| v.as_f64()).unwrap_or(0.0) <= cpu_above {
                matches = false;
            }
        }

        if matches {
            actions.push(json!({
                "policy_id": policy.id,
                "policy_name": policy.name,
                "action": policy.action,
            }));
        }
    }

    Json(json!({ "actions": actions }))
}
