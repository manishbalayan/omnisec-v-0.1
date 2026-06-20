use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "event_type", rename_all = "lowercase")]
pub enum EventType {
    AgentDiscovered,
    AgentHeartbeat,
    AgentFailed,
    AgentRestarted,
    AgentStopped,
    PolicyViolation,
    SecurityIncident,
    SystemError,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "event_severity", rename_all = "lowercase")]
pub enum EventSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Event {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub agent_id: Option<Uuid>,
    pub event_type: EventType,
    pub severity: EventSeverity,
    pub message: String,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateEventRequest {
    pub agent_id: Option<Uuid>,
    pub event_type: EventType,
    pub severity: EventSeverity,
    pub message: String,
    pub metadata: Option<serde_json::Value>,
}
