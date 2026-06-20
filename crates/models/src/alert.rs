use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "alert_status", rename_all = "lowercase")]
pub enum AlertStatus {
    Active,
    Acknowledged,
    Resolved,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "alert_channel", rename_all = "lowercase")]
pub enum AlertChannel {
    Telegram,
    Email,
    Slack,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Alert {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub agent_id: Option<Uuid>,
    pub event_id: Option<Uuid>,
    pub channel: AlertChannel,
    pub status: AlertStatus,
    pub message: String,
    pub sent_at: Option<DateTime<Utc>>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateAlertRequest {
    pub agent_id: Option<Uuid>,
    pub event_id: Option<Uuid>,
    pub channel: AlertChannel,
    pub message: String,
}
