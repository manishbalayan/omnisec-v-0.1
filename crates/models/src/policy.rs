use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "policy_action", rename_all = "lowercase")]
pub enum PolicyAction {
    Allow,
    Alert,
    Block,
    Restart,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Policy {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub conditions: serde_json::Value,
    pub action: PolicyAction,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    pub process_dead: Option<bool>,
    pub cpu_above: Option<f64>,
    pub memory_above: Option<f64>,
    pub destination: Option<String>,
    pub destination_pattern: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub description: Option<String>,
    pub conditions: PolicyCondition,
    pub action: PolicyAction,
    pub priority: Option<i32>,
}
