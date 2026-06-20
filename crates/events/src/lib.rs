use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Event version
// ---------------------------------------------------------------------------

pub const EVENT_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Event envelope
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope<T: Serialize> {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub version: u32,
    pub source: String,
    pub organization_id: Option<Uuid>,
    pub payload: T,
}

impl<T: Serialize> EventEnvelope<T> {
    pub fn new(source: &str, payload: T) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            version: EVENT_VERSION,
            source: source.to_string(),
            organization_id: None,
            payload,
        }
    }

    pub fn with_org(mut self, org_id: Uuid) -> Self {
        self.organization_id = Some(org_id);
        self
    }
}

// ---------------------------------------------------------------------------
// NATS subject constants
// ---------------------------------------------------------------------------

pub mod subjects {
    // Agent lifecycle
    pub const AGENT_PREFIX: &str = "omnisec.agent";
    pub const AGENT_DISCOVERED: &str = "omnisec.agent.discovered";
    pub const AGENT_UPDATED: &str = "omnisec.agent.updated";
    pub const AGENT_HEALTH_CHANGED: &str = "omnisec.agent.health_changed";
    pub const AGENT_FAILED: &str = "omnisec.agent.failed";
    pub const AGENT_HUNG: &str = "omnisec.agent.hung";
    pub const AGENT_MEMORY_LEAK: &str = "omnisec.agent.memory_leak";
    pub const AGENT_CPU_RUNAWAY: &str = "omnisec.agent.cpu_runaway";
    pub const AGENT_FD_EXHAUSTION: &str = "omnisec.agent.fd_exhaustion";
    pub const AGENT_THREAD_EXPLOSION: &str = "omnisec.agent.thread_explosion";
    pub const HEARTBEAT_MISSED: &str = "omnisec.agent.heartbeat_missed";
    pub const HEARTBEAT_RECOVERED: &str = "omnisec.agent.heartbeat_recovered";

    // Restart orchestration
    pub const RESTART_PREFIX: &str = "omnisec.restart";
    pub const RESTART_REQUESTED: &str = "omnisec.restart.requested";
    pub const RESTART_STARTED: &str = "omnisec.restart.started";
    pub const RESTART_SUCCEEDED: &str = "omnisec.restart.succeeded";
    pub const RESTART_FAILED: &str = "omnisec.restart.failed";

    // Systemd
    pub const SYSTEMD_PREFIX: &str = "omnisec.systemd";
    pub const SYSTEMD_SERVICE_DISCOVERED: &str = "omnisec.systemd.service_discovered";
    pub const SYSTEMD_RESTART_TRIGGERED: &str = "omnisec.systemd.restart_triggered";
    pub const SYSTEMD_RESTART_SUCCEEDED: &str = "omnisec.systemd.restart_succeeded";
    pub const SYSTEMD_RESTART_FAILED: &str = "omnisec.systemd.restart_failed";

    // Incident
    pub const INCIDENT_PREFIX: &str = "omnisec.incident";
    pub const INCIDENT_CREATED: &str = "omnisec.incident.created";
    pub const INCIDENT_UPDATED: &str = "omnisec.incident.updated";
    pub const INCIDENT_RESOLVED: &str = "omnisec.incident.resolved";

    // Dependency
    pub const DEPENDENCY_FAILURE: &str = "omnisec.dependency.failure";
    pub const DEPENDENCY_RECOVERED: &str = "omnisec.dependency.recovered";

    // Alert
    pub const ALERT_PREFIX: &str = "omnisec.alert";
    pub const ALERT_REQUESTED: &str = "omnisec.alert.requested";
    pub const ALERT_SENT: &str = "omnisec.alert.sent";
    pub const ALERT_FAILED: &str = "omnisec.alert.failed";

    // Policy
    pub const POLICY_VIOLATION: &str = "omnisec.policy.violation";

    // Security events
    pub const SECURITY_PREFIX: &str = "omnisec.security";
    pub const SECURITY_ANOMALY: &str = "omnisec.security.anomaly";
    pub const SECURITY_RISK_CHANGED: &str = "omnisec.security.risk_changed";
    pub const SECURITY_INCIDENT: &str = "omnisec.security.incident";
    pub const SECURITY_BASELINE_CHANGED: &str = "omnisec.security.baseline_changed";
    pub const SECURITY_NEW_DESTINATION: &str = "omnisec.security.new_destination";
    pub const SECURITY_NEW_PORT: &str = "omnisec.security.new_port";

    // Network events
    pub const NETWORK_PREFIX: &str = "omnisec.network";
    pub const NETWORK_CONNECTION: &str = "omnisec.network.connection";
    pub const NETWORK_TRAFFIC_UPDATE: &str = "omnisec.network.traffic_update";

    // Fingerprint events
    pub const FINGERPRINT_PREFIX: &str = "omnisec.fingerprint";
    pub const FINGERPRINT_CREATED: &str = "omnisec.fingerprint.created";
    pub const FINGERPRINT_UPDATED: &str = "omnisec.fingerprint.updated";
    pub const FINGERPRINT_DRIFT_DETECTED: &str = "omnisec.fingerprint.drift_detected";

    // Security profile & correlation events (Runtime Integration)
    pub const SECURITY_PROFILE_UPDATED: &str = "omnisec.security.profile.updated";
    pub const SECURITY_ANOMALY_DETECTED: &str = "omnisec.security.anomaly.detected";
    pub const SECURITY_INCIDENT_CREATED: &str = "omnisec.security.incident.created";
    pub const SECURITY_INCIDENT_RESOLVED: &str = "omnisec.security.incident.resolved";
    pub const SECURITY_CORRELATION_ALERT: &str = "omnisec.security.correlation.alert";
    pub const SECURITY_TIMELINE_EVENT: &str = "omnisec.security.timeline.event";
    pub const SECURITY_LEARNING_UPDATED: &str = "omnisec.security.learning.updated";

    // Enforcement events (Runtime Enforcement Layer)
    pub const ENFORCEMENT_PREFIX: &str = "omnisec.enforcement";
    pub const DECISION_MADE: &str = "omnisec.decision.made";
    pub const ENFORCEMENT_BLOCKED: &str = "omnisec.enforcement.blocked";
    pub const ENFORCEMENT_ALLOWED: &str = "omnisec.enforcement.allowed";
    pub const ENFORCEMENT_FLAGGED: &str = "omnisec.enforcement.flagged";
    pub const PROCESS_BLOCKED: &str = "omnisec.process.blocked";
    pub const PROCESS_FLAGGED: &str = "omnisec.process.flagged";
    pub const FILE_ACCESS_VIOLATION: &str = "omnisec.file.access_violation";
    pub const FILE_ACCESS_BLOCKED: &str = "omnisec.file.access_blocked";
    pub const EXFILTRATION_BLOCKED: &str = "omnisec.exfiltration.blocked";
    pub const ENFORCEMENT_INCIDENT: &str = "omnisec.enforcement.incident";
    pub const ENFORCEMENT_INCIDENT_RESOLVED: &str = "omnisec.enforcement.incident_resolved";
    pub const OVERRIDE_CREATED: &str = "omnisec.override.created";
    pub const OVERRIDE_APPLIED: &str = "omnisec.override.applied";

    // Runtime enforcement events (Linux Runtime Control Sprint)
    pub const RUNTIME_PREFIX: &str = "omnisec.runtime";
    pub const RUNTIME_NETWORK_BLOCKED: &str = "omnisec.runtime.network_blocked";
    pub const RUNTIME_NETWORK_UNBLOCKED: &str = "omnisec.runtime.network_unblocked";
    pub const RUNTIME_RESOURCE_LIMITED: &str = "omnisec.runtime.resource_limited";
    pub const RUNTIME_SERVICE_CONTROL: &str = "omnisec.runtime.service_control";
    pub const RUNTIME_PROCESS_SUSPENDED: &str = "omnisec.runtime.process_suspended";
    pub const RUNTIME_PROCESS_RESUMED: &str = "omnisec.runtime.process_resumed";
    pub const RUNTIME_PROCESS_KILLED: &str = "omnisec.runtime.process_killed";
    pub const RUNTIME_PROCESS_QUARANTINED: &str = "omnisec.runtime.process_quarantined";
    pub const RUNTIME_FILE_ACCESS: &str = "omnisec.runtime.file_access";
    pub const FILE_ACCESS_DETECTED: &str = "omnisec.runtime.file_access_detected";
    pub const RUNTIME_KERNEL_AUDIT: &str = "omnisec.runtime.kernel_audit";
    pub const RUNTIME_RECOVERY: &str = "omnisec.runtime.recovery";
    pub const RUNTIME_ROLLBACK: &str = "omnisec.runtime.rollback";

    // eBPF kernel event subjects (Phase Next)
    pub const EBPF_PREFIX: &str = "omnisec.ebpf";
    pub const PROCESS_EXEC: &str = "omnisec.process.exec";
    pub const PROCESS_EXIT: &str = "omnisec.process.exit";
    pub const PROCESS_FORK: &str = "omnisec.process.fork";
    pub const NETWORK_CONNECT: &str = "omnisec.network.connect";
    pub const NETWORK_LISTEN: &str = "omnisec.network.listen";
    pub const NETWORK_ACCEPT: &str = "omnisec.network.accept";
    pub const FILE_ACCESS: &str = "omnisec.file.access";
    pub const FILE_DELETE: &str = "omnisec.file.delete";
    pub const FILE_MODIFY: &str = "omnisec.file.modify";
    pub const DNS_QUERY: &str = "omnisec.dns.query";
    pub const IDENTITY_PID_MAPPED: &str = "omnisec.identity.pid_mapped";

    // Audit wildcard
    pub const WILDCARD_ALL: &str = "omnisec.>";
}

// ---------------------------------------------------------------------------
// Existing payloads (agent, alert, restart)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDiscoveredPayload {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub command: String,
    pub framework: Option<String>,
    pub model_provider: Option<String>,
    pub cpu_percent: Option<f64>,
    pub memory_mb: Option<f64>,
    pub confidence: u8,
    pub listening_ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentUpdatedPayload {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: Option<f64>,
    pub memory_mb: Option<f64>,
    pub confidence: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthState {
    Unknown,
    Healthy,
    Warning,
    Failed,
    Restarting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHealthChangedPayload {
    pub pid: u32,
    pub name: String,
    pub previous_state: HealthState,
    pub new_state: HealthState,
    pub consecutive_failures: u32,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentFailedPayload {
    pub pid: u32,
    pub name: String,
    pub consecutive_failures: u32,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartRequestedPayload {
    pub pid: u32,
    pub name: String,
    pub attempt: u32,
    pub backoff_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartStartedPayload {
    pub pid: u32,
    pub name: String,
    pub attempt: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartSucceededPayload {
    pub pid: u32,
    pub name: String,
    pub attempt: u32,
    pub new_pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartFailedPayload {
    pub pid: u32,
    pub name: String,
    pub attempt: u32,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRequestedPayload {
    pub channel: String,
    pub message: String,
    pub agent_pid: Option<u32>,
    pub agent_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertSentPayload {
    pub channel: String,
    pub message_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertFailedPayload {
    pub channel: String,
    pub message_preview: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolationPayload {
    pub policy_id: String,
    pub policy_name: String,
    pub agent_pid: Option<u32>,
    pub agent_name: Option<String>,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEventCreatedPayload {
    pub original_subject: String,
    pub original_event_id: Uuid,
    pub event_type: String,
    pub summary: String,
}

// ---------------------------------------------------------------------------
// NEW: Systemd payloads (Phase 1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemdServiceDiscoveredPayload {
    pub unit: String,
    pub description: String,
    pub active_state: String,
    pub sub_state: String,
    pub main_pid: u32,
    pub enabled: bool,
    pub restart_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemdRestartTriggeredPayload {
    pub unit: String,
    pub agent_name: Option<String>,
    pub attempt: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemdRestartResultPayload {
    pub unit: String,
    pub success: bool,
    pub message: String,
    pub duration_ms: u64,
}

// ---------------------------------------------------------------------------
// NEW: Hang detection payloads (Phase 2)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHungPayload {
    pub pid: u32,
    pub name: String,
    pub reason: String,
    pub cpu_frozen_secs: f64,
    pub no_activity_secs: f64,
}

// ---------------------------------------------------------------------------
// NEW: Resource exhaustion payloads (Phase 3)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResourceExhaustionPayload {
    pub pid: u32,
    pub name: String,
    pub resource_type: ResourceType,
    pub current_value: f64,
    pub threshold: f64,
    pub duration_secs: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ResourceType {
    MemoryLeak,
    CpuRunaway,
    FdExhaustion,
    ThreadExplosion,
}

// ---------------------------------------------------------------------------
// NEW: Incident engine payloads (Phase 5)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IncidentState {
    Open,
    Investigating,
    Recovering,
    Recovered,
    Escalated,
    Resolved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentCreatedPayload {
    pub incident_id: Uuid,
    pub agent_pid: Option<u32>,
    pub agent_name: Option<String>,
    pub incident_type: String,
    pub severity: String,
    pub description: String,
    pub state: IncidentState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentUpdatedPayload {
    pub incident_id: Uuid,
    pub previous_state: IncidentState,
    pub new_state: IncidentState,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// NEW: Heartbeat payloads (Phase 7)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatPayload {
    pub pid: u32,
    pub name: String,
    pub interval_secs: u64,
    pub missed_count: u32,
}

// ---------------------------------------------------------------------------
// NEW: Dependency health payloads (Phase 6)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyHealthPayload {
    pub dependency_name: String,
    pub dependency_type: String,
    pub healthy: bool,
    pub error: Option<String>,
    pub latency_ms: Option<f64>,
}

// ---------------------------------------------------------------------------
// SECURITY: Network connection tracking (Phase 1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnectionPayload {
    pub pid: u32,
    pub process_name: String,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_domain: Option<String>,
    pub remote_port: u16,
    pub protocol: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub connection_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTrafficUpdatePayload {
    pub pid: u32,
    pub process_name: String,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub connection_count: u32,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// SECURITY: Destination profiling (Phase 2)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestinationRecordPayload {
    pub pid: u32,
    pub process_name: String,
    pub domain: String,
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub total_bytes: u64,
    pub connection_count: u32,
    pub is_new: bool,
}

// ---------------------------------------------------------------------------
// SECURITY: Anomaly detection (Phase 7)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AnomalyType {
    NewDestination,
    NewPort,
    NewProtocol,
    TrafficSpike,
    OutboundSpike,
    ActivityTimeAnomaly,
    ConnectionCountSpike,
    FingerprintDrift,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyPayload {
    pub pid: u32,
    pub agent_name: String,
    pub anomaly_type: AnomalyType,
    pub severity: String,
    pub description: String,
    pub current_value: f64,
    pub baseline_value: f64,
    pub deviation: f64,
}

// ---------------------------------------------------------------------------
// SECURITY: Risk scoring (Phase 8)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskLevel {
    Normal,
    Suspicious,
    HighRisk,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScoreChangedPayload {
    pub pid: u32,
    pub agent_name: String,
    pub previous_score: u32,
    pub new_score: u32,
    pub risk_level: RiskLevel,
    pub signals: HashMap<String, f64>,
    pub reasons: Vec<String>,
}

// ---------------------------------------------------------------------------
// SECURITY: Baseline learning (Phase 6)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BaselineState {
    Learning,
    Training,
    Established,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineChangedPayload {
    pub pid: u32,
    pub agent_name: String,
    pub previous_state: BaselineState,
    pub new_state: BaselineState,
    pub days_observed: u32,
    pub samples_collected: u32,
}

// ---------------------------------------------------------------------------
// SECURITY: Security incidents (Phase 9)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecurityIncidentType {
    NewDestination,
    TrafficAnomaly,
    BehaviorDrift,
    OutboundSpike,
    TimeAnomaly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIncidentPayload {
    pub incident_id: Uuid,
    pub pid: u32,
    pub agent_name: String,
    pub incident_type: SecurityIncidentType,
    pub risk_score: u32,
    pub description: String,
    pub details: serde_json::Value,
    pub state: String,
}

// ---------------------------------------------------------------------------
// SECURITY: Fingerprint (Phase 5)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintCreatedPayload {
    pub pid: u32,
    pub agent_name: String,
    pub fingerprint_version: u32,
    pub destination_count: u32,
    pub confidence_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintUpdatedPayload {
    pub pid: u32,
    pub agent_name: String,
    pub previous_version: u32,
    pub new_version: u32,
    pub destination_count: u32,
    pub confidence_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintDriftPayload {
    pub pid: u32,
    pub agent_name: String,
    pub drift_score: f64,
    pub new_destinations: Vec<String>,
    pub traffic_change_percent: f64,
    pub time_change_percent: f64,
}

// ---------------------------------------------------------------------------
// eBPF Process Event Payloads (Phase Next — kernel exec/exit/fork)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessExecPayload {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub filename: String,
    pub args: Vec<String>,
    pub timestamp_ns: u64,
    pub agent_id: Option<String>,
    pub ebpf_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessExitPayload {
    pub pid: u32,
    pub exit_code: i32,
    pub timestamp_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessForkPayload {
    pub parent_pid: u32,
    pub child_pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub timestamp_ns: u64,
}

// ---------------------------------------------------------------------------
// eBPF Network Event Payloads (Phase Next — kernel connect/bind/accept)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnectPayload {
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub dest_ip: String,
    pub dest_port: u16,
    pub src_ip: String,
    pub src_port: u16,
    pub protocol: String,        // "tcp" or "udp"
    pub domain: Option<String>,  // resolved from DNS correlation
    pub timestamp_ns: u64,
    pub agent_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkListenPayload {
    pub pid: u32,
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub backlog: u32,
    pub timestamp_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAcceptPayload {
    pub pid: u32,
    pub client_ip: String,
    pub client_port: u16,
    pub server_ip: String,
    pub server_port: u16,
    pub protocol: String,
    pub timestamp_ns: u64,
}

// ---------------------------------------------------------------------------
// eBPF File Access Event Payloads (Phase Next — kernel open/openat/unlink/rename/chmod)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccessPayload {
    pub pid: u32,
    pub uid: u32,
    pub path: String,
    pub operation: String,        // "open", "openat", "unlink", "rename", "chmod"
    pub flags: u32,
    pub mode: u32,
    pub timestamp_ns: u64,
    pub sensitive_match: bool,
    pub agent_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDeletePayload {
    pub pid: u32,
    pub path: String,
    pub timestamp_ns: u64,
    pub agent_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileModifyPayload {
    pub pid: u32,
    pub path: String,
    pub operation: String,        // "chmod", "rename"
    pub timestamp_ns: u64,
    pub agent_id: Option<String>,
}

// ---------------------------------------------------------------------------
// DNS Query Payload (Phase Next)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryPayload {
    pub pid: u32,
    pub domain: String,
    pub query_type: String,       // "A", "AAAA", "TXT", etc.
    pub resolver_ip: String,
    pub response_ips: Vec<String>,
    pub timestamp_ns: u64,
    pub agent_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Identity Engine Payload (Phase Next)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityPidMappedPayload {
    pub pid: u32,
    pub agent_id: String,
    pub parent_agent_id: Option<String>,
    pub process_tree_depth: u32,
    pub comm: String,
    pub is_child_process: bool,
    pub timestamp_ns: u64,
}

// ---------------------------------------------------------------------------
// Serialization helper
// ---------------------------------------------------------------------------

pub fn serialize_envelope<T: Serialize>(source: &str, payload: T) -> Result<Vec<u8>, serde_json::Error> {
    let envelope = EventEnvelope::new(source, payload);
    serde_json::to_vec(&envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_envelope_creation() {
        let payload = AgentFailedPayload {
            pid: 1234,
            name: "test".to_string(),
            consecutive_failures: 3,
            reason: "exit".to_string(),
        };
        let envelope = EventEnvelope::new("test", payload);
        assert_eq!(envelope.version, EVENT_VERSION);
        assert_eq!(envelope.source, "test");
    }

    #[test]
    fn test_serialize_envelope() {
        let payload = AgentHungPayload {
            pid: 1234,
            name: "test".to_string(),
            reason: "cpu frozen".to_string(),
            cpu_frozen_secs: 300.0,
            no_activity_secs: 300.0,
        };
        let bytes = serialize_envelope("test", payload).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["payload"]["reason"], "cpu frozen");
    }

    #[test]
    fn test_incident_state_cycle() {
        assert_eq!(IncidentState::Open as u8, 0u8);
        assert_ne!(IncidentState::Resolved as u8, IncidentState::Open as u8);
    }

    #[test]
    fn test_subject_constants() {
        assert_eq!(subjects::SYSTEMD_SERVICE_DISCOVERED, "omnisec.systemd.service_discovered");
        assert_eq!(subjects::AGENT_HUNG, "omnisec.agent.hung");
        assert_eq!(subjects::AGENT_MEMORY_LEAK, "omnisec.agent.memory_leak");
        assert_eq!(subjects::INCIDENT_CREATED, "omnisec.incident.created");
        assert_eq!(subjects::HEARTBEAT_MISSED, "omnisec.agent.heartbeat_missed");
        assert_eq!(subjects::DEPENDENCY_FAILURE, "omnisec.dependency.failure");
        assert_eq!(subjects::SECURITY_ANOMALY, "omnisec.security.anomaly");
        assert_eq!(subjects::SECURITY_RISK_CHANGED, "omnisec.security.risk_changed");
        assert_eq!(subjects::NETWORK_CONNECTION, "omnisec.network.connection");
        assert_eq!(subjects::FINGERPRINT_CREATED, "omnisec.fingerprint.created");
        assert_eq!(subjects::FINGERPRINT_DRIFT_DETECTED, "omnisec.fingerprint.drift_detected");
    }
}
