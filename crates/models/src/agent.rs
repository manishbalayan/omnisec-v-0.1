use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "agent_status", rename_all = "lowercase")]
pub enum AgentStatus {
    Unknown,
    Running,
    Stopped,
    Failed,
    Recovering,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Agent {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub process_name: Option<String>,
    pub command_line: Option<String>,
    pub pid: Option<i32>,
    pub status: AgentStatus,
    pub framework: Option<String>,
    pub model_provider: Option<String>,
    pub cpu_usage: Option<f64>,
    pub memory_usage: Option<f64>,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateAgentRequest {
    pub name: String,
    pub process_name: Option<String>,
    pub command_line: Option<String>,
    pub pid: Option<i32>,
    pub framework: Option<String>,
    pub model_provider: Option<String>,
}
