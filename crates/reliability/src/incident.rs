use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IncidentSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IncidentState {
    Open,
    Investigating,
    Recovering,
    Recovered,
    Escalated,
    Resolved,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IncidentType {
    AgentCrash,
    AgentHung,
    MemoryLeak,
    CpuRunaway,
    FdExhaustion,
    ThreadExplosion,
    DependencyFailure,
    PolicyViolation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: Uuid,
    pub agent_id: Option<Uuid>,
    pub agent_name: String,
    pub pid: u32,
    pub incident_type: IncidentType,
    pub severity: IncidentSeverity,
    pub state: IncidentState,
    pub title: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub recovery_actions: Vec<RecoveryAction>,
    pub resolution: Option<String>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryAction {
    pub id: Uuid,
    pub action_type: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub success: bool,
    pub error: Option<String>,
    pub details: Option<String>,
}

pub struct IncidentEngine {
    incidents: Vec<Incident>,
}

impl IncidentEngine {
    pub fn new() -> Self {
        Self {
            incidents: Vec::new(),
        }
    }

    pub fn create_incident(
        &mut self,
        agent_id: Option<Uuid>,
        agent_name: String,
        pid: u32,
        incident_type: IncidentType,
        severity: IncidentSeverity,
        title: String,
        description: String,
    ) -> Incident {
        let incident = Incident {
            id: Uuid::new_v4(),
            agent_id,
            agent_name: agent_name.clone(),
            pid,
            incident_type,
            severity,
            state: IncidentState::Open,
            title: title.clone(),
            description,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            resolved_at: None,
            recovery_actions: Vec::new(),
            resolution: None,
            metadata: serde_json::json!({}),
        };

        tracing::warn!(
            "INCIDENT CREATED: [{}] {} - {} (agent={}, pid={})",
            incident.id,
            title,
            incident.severity_str(),
            agent_name,
            pid
        );

        self.incidents.push(incident.clone());
        incident
    }

    pub fn update_state(&mut self, incident_id: Uuid, new_state: IncidentState) -> bool {
        if let Some(incident) = self.incidents.iter_mut().find(|i| i.id == incident_id) {
            let old_state = incident.state.clone();
            incident.state = new_state.clone();
            incident.updated_at = Utc::now();

            if new_state == IncidentState::Resolved {
                incident.resolved_at = Some(Utc::now());
            }

            tracing::info!(
                "Incident {} state: {:?} -> {:?}",
                incident_id,
                old_state,
                new_state
            );
            return true;
        }
        false
    }

    pub fn add_recovery_action(
        &mut self,
        incident_id: Uuid,
        action_type: String,
        success: bool,
        error: Option<String>,
        details: Option<String>,
    ) -> bool {
        if let Some(incident) = self.incidents.iter_mut().find(|i| i.id == incident_id) {
            let action = RecoveryAction {
                id: Uuid::new_v4(),
                action_type,
                started_at: Utc::now(),
                completed_at: Some(Utc::now()),
                success,
                error,
                details,
            };
            incident.recovery_actions.push(action);
            incident.updated_at = Utc::now();
            return true;
        }
        false
    }

    pub fn resolve_incident(&mut self, incident_id: Uuid, resolution: String) -> bool {
        if let Some(incident) = self.incidents.iter_mut().find(|i| i.id == incident_id) {
            incident.state = IncidentState::Resolved;
            incident.resolution = Some(resolution);
            incident.resolved_at = Some(Utc::now());
            incident.updated_at = Utc::now();

            tracing::info!("Incident {} RESOLVED", incident_id);
            return true;
        }
        false
    }

    pub fn get_incident(&self, incident_id: Uuid) -> Option<&Incident> {
        self.incidents.iter().find(|i| i.id == incident_id)
    }

    pub fn get_open_incidents(&self) -> Vec<&Incident> {
        self.incidents
            .iter()
            .filter(|i| {
                i.state != IncidentState::Resolved && i.state != IncidentState::Recovered
            })
            .collect()
    }

    pub fn get_incidents_for_agent(&self, agent_name: &str) -> Vec<&Incident> {
        self.incidents
            .iter()
            .filter(|i| i.agent_name == agent_name)
            .collect()
    }

    pub fn get_all_incidents(&self) -> &[Incident] {
        &self.incidents
    }

    pub fn get_incident_stats(&self) -> IncidentStats {
        let total = self.incidents.len();
        let open = self.incidents.iter().filter(|i| i.state == IncidentState::Open).count();
        let investigating = self.incidents.iter().filter(|i| i.state == IncidentState::Investigating).count();
        let recovering = self.incidents.iter().filter(|i| i.state == IncidentState::Recovering).count();
        let recovered = self.incidents.iter().filter(|i| i.state == IncidentState::Recovered).count();
        let escalated = self.incidents.iter().filter(|i| i.state == IncidentState::Escalated).count();
        let resolved = self.incidents.iter().filter(|i| i.state == IncidentState::Resolved).count();

        let resolved_incidents: Vec<&Incident> = self.incidents
            .iter()
            .filter(|i| i.resolved_at.is_some())
            .collect();

        let avg_recovery_time_ms = if resolved_incidents.is_empty() {
            0.0
        } else {
            let total_time: i64 = resolved_incidents
                .iter()
                .filter_map(|i| {
                    i.resolved_at.map(|r| r.signed_duration_since(i.created_at).num_milliseconds())
                })
                .sum();
            total_time as f64 / resolved_incidents.len() as f64
        };

        IncidentStats {
            total,
            open,
            investigating,
            recovering,
            recovered,
            escalated,
            resolved,
            avg_recovery_time_ms,
        }
    }
}

impl Incident {
    pub fn severity_str(&self) -> &str {
        match self.severity {
            IncidentSeverity::Low => "LOW",
            IncidentSeverity::Medium => "MEDIUM",
            IncidentSeverity::High => "HIGH",
            IncidentSeverity::Critical => "CRITICAL",
        }
    }

    pub fn state_str(&self) -> &str {
        match self.state {
            IncidentState::Open => "OPEN",
            IncidentState::Investigating => "INVESTIGATING",
            IncidentState::Recovering => "RECOVERING",
            IncidentState::Recovered => "RECOVERED",
            IncidentState::Escalated => "ESCALATED",
            IncidentState::Resolved => "RESOLVED",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IncidentStats {
    pub total: usize,
    pub open: usize,
    pub investigating: usize,
    pub recovering: usize,
    pub recovered: usize,
    pub escalated: usize,
    pub resolved: usize,
    pub avg_recovery_time_ms: f64,
}
