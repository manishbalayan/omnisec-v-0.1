use axum::{
    extract::{Path, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use omnisec_intelligence::{CostIntelligenceEngine, RecommendationEngine};
use std::sync::OnceLock;

/// Cached API key — read once from the environment at first request.
static API_KEY: OnceLock<Option<String>> = OnceLock::new();
use chrono::Utc;
use omnisec_anomaly::AnomalyDetector;
use omnisec_decision::DecisionEngine;
use omnisec_discovery::AgentDiscovery;
use omnisec_enforcement::EnforcementManager;
use omnisec_fingerprint::FingerprintManager;
use omnisec_security::AgentProfileManager;
use omnisec_storage::Storage;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

struct AppState {
    storage: Storage,
    discovery: AgentDiscovery,
    security: SecurityState,
    enforcement: EnforcementState,
}

struct SecurityState {
    profile_manager: AgentProfileManager,
    fingerprint_manager: FingerprintManager,
    anomaly_detector: AnomalyDetector,
}

struct EnforcementState {
    decision_engine: DecisionEngine,
    enforcement_manager: EnforcementManager,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "omnisec_api=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Omnisec API v0.1.0");

    let api_key = std::env::var("OMNISEC_API_KEY").unwrap_or_else(|_| {
        let key = uuid::Uuid::new_v4().to_string();
        tracing::warn!(
            "OMNISEC_API_KEY not set. Generated temporary key: {}. Set OMNISEC_API_KEY in production.",
            key
        );
        key
    });

    // Pre-cache the API key for the auth middleware (ignore error if already set)
    let _ = API_KEY.set(Some(api_key));

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/omnisec".to_string());

    let storage = Storage::new(&database_url).await?;
    storage.run_migrations().await?;

    let state = Arc::new(RwLock::new(AppState {
        storage,
        discovery: AgentDiscovery::new(),
        security: SecurityState {
            profile_manager: AgentProfileManager::new(),
            fingerprint_manager: FingerprintManager::new(),
            anomaly_detector: AnomalyDetector::new(),
        },
        enforcement: {
            let mut decision_engine = DecisionEngine::new();
            for policy in DecisionEngine::default_policies() {
                decision_engine.add_policy(policy);
            }
            EnforcementState {
                decision_engine,
                enforcement_manager: EnforcementManager::new(),
            }
        },
    }));

    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods(tower_http::cors::Any)
        .allow_headers(tower_http::cors::Any);

    let app = Router::new()
        // Health endpoints — always accessible
        .route("/", get(root_health_check))
        .route("/health", get(health_check_handler))
        .route("/api/agents", get(list_agents))
        .route("/api/agents/discover", post(discover_agents))
        .route("/api/events", get(list_events))
        .route("/api/security/risk-scores", get(get_risk_scores))
        .route("/api/security/anomalies", get(get_anomalies))
        .route("/api/security/risk-scores/{pid}", get(get_agent_risk_score))
        .route("/api/security/timeline", get(get_security_timeline))
        .route("/api/security/timeline/{pid}", get(get_agent_timeline))
        .route("/api/security/audit", get(get_security_audit))
        .route("/api/security/incidents", get(get_security_incidents))
        .route("/api/security/correlation", get(get_correlation_alerts))
        .route("/api/security/operations", get(get_security_operations_overview))
        // Enforcement endpoints
        .route("/api/enforcement/decisions", get(get_enforcement_decisions))
        .route("/api/enforcement/actions", get(get_enforcement_actions))
        .route("/api/enforcement/incidents", get(get_enforcement_incidents))
        .route("/api/enforcement/stats", get(get_enforcement_stats))
        .route("/api/enforcement/lists/block", get(get_block_list))
        .route("/api/enforcement/lists/allow", get(get_allow_list))
        .route("/api/enforcement/overrides", get(get_overrides))
        // Intelligence endpoints (cost observability + model recommendations)
        .route("/api/intelligence/cost", get(get_cost_dashboard))
        .route("/api/intelligence/recommendations", get(get_recommendations))
        .route("/api/intelligence/recommendations/{id}/approve", post(approve_recommendation))
        .route("/api/intelligence/recommendations/{id}/reject", post(reject_recommendation))
        // Metrics (Prometheus-compatible text format)
        .route("/metrics", get(prometheus_metrics))
        // CORS must run BEFORE auth so preflight OPTIONS requests are handled
        // without requiring an API key header.
        .layer(middleware::from_fn(auth_middleware))
        .layer(cors)
        .with_state(state);

    let bind =
        std::env::var("API_BIND").unwrap_or_else(|_| "0.0.0.0:3000".to_string());

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("API listening on {}", bind);

    axum::serve(listener, app).await?;

    Ok(())
}

async fn auth_middleware(
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    // Health endpoints and metrics are always accessible
    let path = request.uri().path();
    if path == "/" || path == "/health" || path == "/metrics" {
        return next.run(request).await;
    }

    // Read the expected key once — subsequent requests use the cached value.
    let expected = API_KEY.get_or_init(|| std::env::var("OMNISEC_API_KEY").ok());
    let Some(ref expected) = expected else {
        return next.run(request).await;
    };

    // Accept API key via either X-API-Key header or Authorization: Bearer <key>
    let provided = request
        .headers()
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            request
                .headers()
                .get("Authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .map(|s| s.trim())
        })
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

async fn root_health_check() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "service": "omnisec-api"
    }))
}

async fn health_check_handler() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "service": "omnisec-api",
        "version": "0.2.0",
        "endpoints": [
            "/",
            "/health",
            "/metrics",
            "/api/agents",
            "/api/events",
            "/api/security/*",
            "/api/enforcement/*",
            "/api/intelligence/*"
        ]
    }))
}

async fn list_agents(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let state = state.read().await;
    match state.storage.get_agents().await {
        Ok(agents) => Ok(Json(json!({ "agents": agents }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )),
    }
}

async fn discover_agents(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let state = state.read().await;
    match state.discovery.discover_agents() {
        Ok(agents) => Ok(Json(json!({ "agents": agents }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )),
    }
}

async fn list_events(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let state = state.read().await;
    match state.storage.get_events(None).await {
        Ok(events) => Ok(Json(json!({ "events": events }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )),
    }
}

async fn get_risk_scores(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Json<Value> {
    let state = state.read().await;
    let scores: Vec<Value> = state
        .security
        .profile_manager
        .get_all_risk_scores()
        .iter()
        .map(|s| {
            json!({
                "pid": s.pid,
                "agent_name": s.agent_name,
                "total_score": s.total_score,
                "destination_score": s.destination_score,
                "traffic_score": s.traffic_score,
                "time_score": s.time_score,
                "behavior_score": s.behavior_score,
                "reasons": s.reasons,
                "risk_level": match s.risk_level {
                    omnisec_security::RiskLevel::Normal => "Normal",
                    omnisec_security::RiskLevel::Suspicious => "Suspicious",
                    omnisec_security::RiskLevel::HighRisk => "HighRisk",
                    omnisec_security::RiskLevel::Critical => "Critical",
                },
            })
        })
        .collect();

    Json(json!({ "risk_scores": scores }))
}

async fn get_agent_risk_score(
    State(state): State<Arc<RwLock<AppState>>>,
    Path(pid): Path<u32>,
) -> Json<Value> {
    let state = state.read().await;
    match state.security.profile_manager.get_risk_score(pid) {
        Some(s) => {
            Json(json!({
                "pid": s.pid,
                "agent_name": s.agent_name,
                "total_score": s.total_score,
                "destination_score": s.destination_score,
                "traffic_score": s.traffic_score,
                "time_score": s.time_score,
                "behavior_score": s.behavior_score,
                "reasons": s.reasons,
                "risk_level": match s.risk_level {
                    omnisec_security::RiskLevel::Normal => "Normal",
                    omnisec_security::RiskLevel::Suspicious => "Suspicious",
                    omnisec_security::RiskLevel::HighRisk => "HighRisk",
                    omnisec_security::RiskLevel::Critical => "Critical",
                },
                "destination_profile": state.security.profile_manager
                    .get_destination_profile(pid)
                    .map(|p| json!({
                        "destination_count": p.destination_count(),
                        "known_ports": p.known_ports.iter().collect::<Vec<_>>(),
                    })),
                "baseline": state.security.profile_manager
                    .get_baseline(pid)
                    .map(|b| json!({
                        "state": format!("{:?}", b.state),
                        "days_observed": b.days_observed,
                        "samples_collected": b.samples_collected,
                    })),
            }))
        }
        None => Json(json!({"error": "Agent not found"})),
    }
}

async fn get_anomalies(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Json<Value> {
    let state = state.read().await;
    let anomalies: Vec<Value> = state
        .security
        .anomaly_detector
        .get_all_anomalies()
        .iter()
        .map(|a| {
            json!({
                "id": a.id,
                "pid": a.pid,
                "agent_name": a.agent_name,
                "anomaly_type": format!("{:?}", a.anomaly_type),
                "severity": format!("{:?}", a.severity),
                "description": a.description,
                "current_value": a.current_value,
                "baseline_value": a.baseline_value,
                "deviation": a.deviation,
                "detected_at": a.detected_at.to_rfc3339(),
                "resolved": a.resolved,
                "resolved_at": a.resolved_at.map(|t| t.to_rfc3339()),
            })
        })
        .collect();

    Json(json!({ "anomalies": anomalies }))
}

// =====================================================================
// Security Timeline API
// =====================================================================

async fn get_security_timeline(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Json<Value> {
    let state = state.read().await;
    // Return timeline from storage if available, otherwise return empty
    match state.storage.get_events(None).await {
        Ok(events) => Json(json!({
            "timeline": events,
            "source": "events"
        })),
        Err(_) => Json(json!({
            "timeline": [],
            "source": "memory"
        })),
    }
}

async fn get_agent_timeline(
    State(state): State<Arc<RwLock<AppState>>>,
    Path(pid): Path<u32>,
) -> Json<Value> {
    let state = state.read().await;
    // Return risk score and anomaly history for this agent
    let risk = state.security.profile_manager.get_risk_score(pid);
    let baseline = state.security.profile_manager.get_baseline(pid);
    let profile = state.security.profile_manager.get_destination_profile(pid);
    let anomalies: Vec<Value> = state
        .security
        .anomaly_detector
        .get_anomalies(pid)
        .iter()
        .map(|a| {
            json!({
                "id": a.id,
                "anomaly_type": format!("{:?}", a.anomaly_type),
                "severity": format!("{:?}", a.severity),
                "description": a.description,
                "detected_at": a.detected_at.to_rfc3339(),
                "resolved": a.resolved,
            })
        })
        .collect();

    Json(json!({
        "pid": pid,
        "risk_score": risk.map(|r| json!({
            "total": r.total_score,
            "level": format!("{:?}", r.risk_level),
            "reasons": r.reasons,
        })),
        "baseline": baseline.map(|b| json!({
            "state": format!("{:?}", b.state),
            "days_observed": b.days_observed,
            "samples": b.samples_collected,
            "progress": if b.required_days > 0 { (b.days_observed as f64 / b.required_days as f64 * 100.0).min(100.0) } else { 0.0 },
        })),
        "destinations": profile.map(|p| json!({
            "count": p.destination_count(),
            "known_ports": p.known_ports.iter().collect::<Vec<_>>(),
        })),
        "anomalies": anomalies,
    }))
}

// =====================================================================
// Security Audit API
// =====================================================================

async fn get_security_audit(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Json<Value> {
    let state = state.read().await;
    match state.storage.get_events(None).await {
        Ok(events) => Json(json!({
            "audit_entries": events,
            "total": events.len()
        })),
        Err(e) => Json(json!({
            "audit_entries": [],
            "error": e.to_string()
        })),
    }
}

// =====================================================================
// Security Incidents API
// =====================================================================

async fn get_security_incidents(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Json<Value> {
    let state = state.read().await;
    // Collect security-relevant anomalies as incident data
    let anomalies = state.security.anomaly_detector.get_all_anomalies();
    let unresolved: Vec<Value> = anomalies
        .iter()
        .filter(|a| !a.resolved)
        .map(|a| {
            json!({
                "id": a.id,
                "pid": a.pid,
                "agent_name": a.agent_name,
                "incident_type": format!("{:?}", a.anomaly_type),
                "severity": format!("{:?}", a.severity),
                "description": a.description,
                "deviation": a.deviation,
                "detected_at": a.detected_at.to_rfc3339(),
                "state": "Open",
            })
        })
        .collect();

    let resolved_list: Vec<Value> = anomalies
        .iter()
        .filter(|a| a.resolved)
        .map(|a| {
            json!({
                "id": a.id,
                "pid": a.pid,
                "agent_name": a.agent_name,
                "incident_type": format!("{:?}", a.anomaly_type),
                "severity": format!("{:?}", a.severity),
                "description": a.description,
                "detected_at": a.detected_at.to_rfc3339(),
                "resolved_at": a.resolved_at,
                "state": "Resolved",
            })
        })
        .collect();

    Json(json!({
        "incidents": unresolved,
        "resolved": resolved_list,
        "total": anomalies.len(),
        "unresolved_count": unresolved.len(),
    }))
}

// =====================================================================
// Correlation Alerts API
// =====================================================================

async fn get_correlation_alerts(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Json<Value> {
    let state = state.read().await;
    // Collect risk scores for correlation insights
    let risk_scores = state.security.profile_manager.get_all_risk_scores();
    let high_risk_count = risk_scores.iter().filter(|s| s.total_score > 50).count();
    let total_agents = risk_scores.len();

    // Detect simple correlations from existing data
    let mut correlations: Vec<Value> = Vec::new();

    if high_risk_count >= 3 {
        correlations.push(json!({
            "correlation_type": "MultiAgentRiskEscalation",
            "description": format!("{} agents with elevated risk scores", high_risk_count),
            "severity": "High",
            "affected_agents": risk_scores.iter().filter(|s| s.total_score > 50).map(|s| s.agent_name.clone()).collect::<Vec<_>>(),                    "detected_at": Utc::now().to_rfc3339(),
        }));
    }

    if total_agents > 0 {
        let avg_score = risk_scores.iter().map(|s| s.total_score).sum::<u32>() as f64 / total_agents as f64;
        if avg_score > 50.0 {
            correlations.push(json!({
                "correlation_type": "GlobalRiskElevation",
                "description": format!("Average risk score across {} agents is {:.1}", total_agents, avg_score),
                "severity": "Medium",
                "affected_agents": risk_scores.iter().map(|s| s.agent_name.clone()).collect::<Vec<_>>(),
                "average_score": avg_score,
                "detected_at": chrono::Utc::now().to_rfc3339(),
            }));
        }
    }

    Json(json!({
        "correlation_alerts": correlations,
        "total_agents": total_agents,
        "high_risk_count": high_risk_count,
    }))
}

// =====================================================================
// Security Operations Overview API
// =====================================================================

async fn get_security_operations_overview(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Json<Value> {
    let state = state.read().await;
    let risk_scores = state.security.profile_manager.get_all_risk_scores();
    let anomalies = state.security.anomaly_detector.get_all_anomalies();

    let total_agents = risk_scores.len();
    let total_anomalies = anomalies.len();
    let unresolved_anomalies = anomalies.iter().filter(|a| !a.resolved).count();
    let high_risk_agents = risk_scores.iter().filter(|s| s.total_score > 50).count();
    let critical_risk_agents = risk_scores.iter().filter(|s| s.total_score > 80).count();

    let learning_count = state
        .security
        .profile_manager
        .get_all_risk_scores()
        .iter()
        .filter(|s| {
            state
                .security
                .profile_manager
                .get_baseline(s.pid)
                .map(|b| !b.is_established())
                .unwrap_or(true)
        })
        .count();

    let established_count = total_agents.saturating_sub(learning_count);

    let avg_score = if total_agents > 0 {
        risk_scores.iter().map(|s| s.total_score).sum::<u32>() as f64 / total_agents as f64
    } else {
        0.0
    };

    // Recent anomalies (last 10)
    let mut recent_anomalies: Vec<Value> = anomalies
        .iter()
        .rev()
        .take(10)
        .map(|a| {
            json!({
                "id": a.id,
                "pid": a.pid,
                "agent_name": a.agent_name,
                "type": format!("{:?}", a.anomaly_type),
                "severity": format!("{:?}", a.severity),
                "description": a.description,
                "detected_at": a.detected_at.to_rfc3339(),
                "resolved": a.resolved,
            })
        })
        .collect();
    recent_anomalies.reverse();

    // Top risk agents
    let mut top_risk: Vec<Value> = risk_scores
        .iter()
        .map(|s| {
            json!({
                "pid": s.pid,
                "agent_name": s.agent_name,
                "total_score": s.total_score,
                "risk_level": format!("{:?}", s.risk_level),
            })
        })
        .collect();
    top_risk.sort_by(|a, b| {
        b["total_score"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&a["total_score"].as_u64().unwrap_or(0))
    });
    top_risk.truncate(5);

    Json(json!({
        "total_agents": total_agents,
        "total_anomalies": total_anomalies,
        "unresolved_anomalies": unresolved_anomalies,
        "high_risk_agents": high_risk_agents,
        "critical_risk_agents": critical_risk_agents,
        "learning_count": learning_count,
        "established_count": established_count,
        "average_risk_score": avg_score,
        "recent_anomalies": recent_anomalies,
        "top_risk_agents": top_risk,
    }))
}

// =====================================================================
// Enforcement API Handlers
// =====================================================================

async fn get_enforcement_decisions(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Json<Value> {
    let state = state.read().await;
    let decisions: Vec<Value> = state
        .enforcement
        .decision_engine
        .get_decisions()
        .iter()
        .map(|d| {
            json!({
                "id": d.id.to_string(),
                "pid": d.pid,
                "agent_name": d.agent_name,
                "action": format!("{:?}", d.action),
                "reason": d.reason,
                "rule": d.rule,
                "confidence": d.confidence,
                "policy_name": d.policy_name,
                "policy_version": d.policy_version,
                "timestamp": d.timestamp.to_rfc3339(),
                "context": {
                    "risk_score": d.context.risk_score,
                    "risk_level": d.context.risk_level,
                    "anomaly_type": d.context.anomaly_type,
                    "destination": d.context.destination,
                    "process_name": d.context.process_name,
                    "file_path": d.context.file_path,
                },
            })
        })
        .collect();

    Json(json!({
        "decisions": decisions,
        "total": decisions.len()
    }))
}

async fn get_enforcement_actions(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Json<Value> {
    let state = state.read().await;
    let actions: Vec<Value> = state
        .enforcement
        .enforcement_manager
        .network
        .get_actions()
        .iter()
        .map(|a| {
            json!({
                "id": a.id.to_string(),
                "decision_id": a.decision_id.to_string(),
                "pid": a.pid,
                "agent_name": a.agent_name,
                "action_type": a.action_type,
                "target": a.target,
                "result": format!("{:?}", a.result),
                "timestamp": a.timestamp.to_rfc3339(),
                "details": a.details,
            })
        })
        .collect();

    Json(json!({
        "actions": actions,
        "total": actions.len()
    }))
}

async fn get_enforcement_incidents(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Json<Value> {
    let state = state.read().await;
    let open_incidents: Vec<Value> = state
        .enforcement
        .enforcement_manager
        .get_open_incidents()
        .iter()
        .map(|i| {
            json!({
                "id": i.id.to_string(),
                "decision_id": i.decision_id.to_string(),
                "pid": i.pid,
                "agent_name": i.agent_name,
                "action_type": i.action_type,
                "action_target": i.action_target,
                "result": format!("{:?}", i.result),
                "status": format!("{:?}", i.status),
                "created_at": i.created_at.to_rfc3339(),
            })
        })
        .collect();

    let all_incidents: Vec<Value> = state
        .enforcement
        .enforcement_manager
        .get_incidents()
        .iter()
        .map(|i| {
            json!({
                "id": i.id.to_string(),
                "pid": i.pid,
                "agent_name": i.agent_name,
                "action_type": i.action_type,
                "action_target": i.action_target,
                "status": format!("{:?}", i.status),
                "created_at": i.created_at.to_rfc3339(),
                "resolved_at": i.resolved_at.map(|t| t.to_rfc3339()),
                "resolution": i.resolution,
            })
        })
        .collect();

    Json(json!({
        "open_incidents": open_incidents,
        "all_incidents": all_incidents,
        "total": all_incidents.len(),
        "open_count": open_incidents.len()
    }))
}

async fn get_enforcement_stats(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Json<Value> {
    let state = state.read().await;
    let stats = state.enforcement.enforcement_manager.get_stats();
    let decision_count = state.enforcement.decision_engine.decision_count();
    let overrides = state.enforcement.decision_engine.get_overrides().len();
    let flagged_processes = state.enforcement.enforcement_manager.process.get_flagged_processes().len();

    Json(json!({
        "blocked_destinations": stats.blocked_destinations,
        "allowed_destinations": stats.allowed_destinations,
        "flagged_processes": flagged_processes,
        "file_violations": stats.file_violations,
        "total_incidents": stats.total_incidents,
        "open_incidents": stats.open_incidents,
        "total_actions": stats.total_actions,
        "total_decisions": decision_count,
        "active_overrides": overrides,
    }))
}

async fn get_block_list(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Json<Value> {
    let state = state.read().await;
    let block_list: Vec<String> = state.enforcement.enforcement_manager.network.get_block_list();
    Json(json!({
        "block_list": block_list,
        "total": block_list.len()
    }))
}

async fn get_allow_list(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Json<Value> {
    let state = state.read().await;
    let allow_list: Vec<String> = state.enforcement.enforcement_manager.network.get_allow_list();
    Json(json!({
        "allow_list": allow_list,
        "total": allow_list.len()
    }))
}

async fn get_overrides(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Json<Value> {
    let state = state.read().await;
    let overrides: Vec<Value> = state
        .enforcement
        .decision_engine
        .get_overrides()
        .iter()
        .map(|o| {
            json!({
                "id": o.id.to_string(),
                "decision_id": o.decision_id.to_string(),
                "action": format!("{:?}", o.action),
                "reason": o.reason,
                "created_by": o.created_by,
                "expires_at": o.expires_at.map(|t| t.to_rfc3339()),
                "created_at": o.created_at.to_rfc3339(),
            })
        })
        .collect();

    Json(json!({
        "overrides": overrides,
        "total": overrides.len()
    }))
}

// ---------------------------------------------------------------------------
// Intelligence endpoints
// ---------------------------------------------------------------------------

async fn get_cost_dashboard(
    State(state): State<Arc<RwLock<AppState>>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    let state = state.read().await;
    let days: i32 = params.get("days").and_then(|d| d.parse().ok()).unwrap_or(7);
    let engine = CostIntelligenceEngine::new(
        state.storage.pool().clone(),
        state.storage.default_org_id,
    );
    match engine.cost_dashboard(days).await {
        Ok(dashboard) => Json(serde_json::to_value(&dashboard).unwrap_or(json!({}))),
        Err(e) => Json(json!({ "error": e.to_string() })),
    }
}

async fn get_recommendations(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Json<Value> {
    let state = state.read().await;
    let engine = RecommendationEngine::new(
        state.storage.pool().clone(),
        state.storage.default_org_id,
    );
    match engine.pending_recommendations().await {
        Ok(recs) => Json(json!({ "recommendations": recs, "total": recs.len() })),
        Err(e) => Json(json!({ "error": e.to_string() })),
    }
}

async fn approve_recommendation(
    State(state): State<Arc<RwLock<AppState>>>,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let state = state.read().await;
    let engine = RecommendationEngine::new(
        state.storage.pool().clone(),
        state.storage.default_org_id,
    );
    let approved_by = body.get("approved_by")
        .and_then(|v| v.as_str())
        .unwrap_or("api-user");
    match engine.approve_recommendation(id, approved_by).await {
        Ok(()) => Json(json!({ "status": "approved", "id": id })),
        Err(e) => Json(json!({ "error": e.to_string() })),
    }
}

async fn reject_recommendation(
    State(state): State<Arc<RwLock<AppState>>>,
    Path(id): Path<uuid::Uuid>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let state = state.read().await;
    let engine = RecommendationEngine::new(
        state.storage.pool().clone(),
        state.storage.default_org_id,
    );
    let reason = body.get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("no reason given");
    match engine.reject_recommendation(id, reason).await {
        Ok(()) => Json(json!({ "status": "rejected", "id": id })),
        Err(e) => Json(json!({ "error": e.to_string() })),
    }
}

// ---------------------------------------------------------------------------
// Prometheus metrics endpoint (Phase 5 — operations hardening)
// ---------------------------------------------------------------------------

async fn prometheus_metrics(
    State(state): State<Arc<RwLock<AppState>>>,
) -> impl IntoResponse {
    let state = state.read().await;

    let agents = state.discovery.discover_agents().unwrap_or_default();
    let total_agents = agents.len();
    let running = agents.iter().filter(|a| a.pid > 0).count();

    // Build Prometheus text format (no external crate needed for basic counters)
    let mut out = String::new();
    out.push_str("# HELP omnisec_agents_total Total discovered agents\n");
    out.push_str("# TYPE omnisec_agents_total gauge\n");
    out.push_str(&format!("omnisec_agents_total {}\n\n", total_agents));

    out.push_str("# HELP omnisec_agents_running Agents currently running\n");
    out.push_str("# TYPE omnisec_agents_running gauge\n");
    out.push_str(&format!("omnisec_agents_running {}\n\n", running));

    out.push_str("# HELP omnisec_enforcement_active_rules Active nftables rules\n");
    out.push_str("# TYPE omnisec_enforcement_active_rules gauge\n");
    out.push_str(&format!("omnisec_enforcement_active_rules {}\n\n",
        state.enforcement.enforcement_manager.network.get_block_list().len()));

    out.push_str("# HELP omnisec_info Omnisec daemon info\n");
    out.push_str("# TYPE omnisec_info gauge\n");
    out.push_str("omnisec_info{version=\"0.2.0\",mode=\"production\"} 1\n");

    (
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        out,
    )
}
