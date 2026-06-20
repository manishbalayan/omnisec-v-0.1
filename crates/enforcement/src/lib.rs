use chrono::{DateTime, Utc};
use omnisec_decision::{DecisionAction, EnforcementDecision};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Enforcement action record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementAction {
    pub id: Uuid,
    pub decision_id: Uuid,
    pub pid: u32,
    pub agent_name: String,
    pub action_type: String,
    pub target: String,
    pub result: EnforcementResult,
    pub duration_ms: u64,
    pub timestamp: DateTime<Utc>,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EnforcementResult {
    Applied,
    Failed,
    Skipped,
    Overridden,
}

// ---------------------------------------------------------------------------
// Network enforcement — allow/block lists
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEnforcementEngine {
    /// Destination allow list (domain, ip patterns)
    allow_list: HashSet<String>,
    /// Destination block list
    block_list: HashSet<String>,
    /// Temporarily blocked destinations (with expiry)
    temp_blocks: Vec<TempBlockEntry>,
    /// Enforcement actions recorded
    actions: Vec<EnforcementAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempBlockEntry {
    pub destination: String,
    pub expires_at: DateTime<Utc>,
    pub reason: String,
}

impl NetworkEnforcementEngine {
    pub fn new() -> Self {
        Self {
            allow_list: Self::default_allow_list(),
            block_list: Self::default_block_list(),
            temp_blocks: Vec::new(),
            actions: Vec::new(),
        }
    }

    /// Default safe destinations that are always allowed.
    fn default_allow_list() -> HashSet<String> {
        let mut list = HashSet::new();
        list.insert("api.openai.com".to_string());
        list.insert("api.anthropic.com".to_string());
        list.insert("api.github.com".to_string());
        list.insert("registry.npmjs.org".to_string());
        list.insert("pypi.org".to_string());
        list.insert("files.pythonhosted.org".to_string());
        list.insert("crates.io".to_string());
        list.insert("static.crates.io".to_string());
        list.insert("github.com".to_string());
        list
    }

    /// Default known malicious destinations for blocking.
    fn default_block_list() -> HashSet<String> {
        let mut list = HashSet::new();
        list.insert("malware.test.com".to_string());
        list.insert("evil.c2.com".to_string());
        list.insert("phishing.xyz".to_string());
        list.insert("data-exfil.com".to_string());
        list
    }

    pub fn is_allowed(&self, destination: &str) -> bool {
        self.allow_list.contains(destination)
    }

    pub fn is_blocked(&self, destination: &str) -> bool {
        if self.block_list.contains(destination) {
            return true;
        }
        // Check temp blocks
        let now = Utc::now();
        self.temp_blocks.iter().any(|tb| {
            tb.destination == destination && tb.expires_at > now
        })
    }

    pub fn add_to_block_list(&mut self, destination: String, reason: String) {
        self.block_list.insert(destination.clone());
        tracing::info!("Blocked destination: {} — {}", destination, reason);
    }

    pub fn add_temp_block(&mut self, destination: String, duration_secs: u64, reason: String) {
        self.temp_blocks.push(TempBlockEntry {
            destination,
            expires_at: Utc::now() + chrono::Duration::seconds(duration_secs as i64),
            reason,
        });
    }

    pub fn remove_temp_block(&mut self, destination: &str) {
        self.temp_blocks.retain(|tb| tb.destination != destination);
    }

    pub fn remove_from_block_list(&mut self, destination: &str) {
        self.block_list.remove(destination);
    }

    pub fn add_to_allow_list(&mut self, destination: String) {
        self.allow_list.insert(destination);
    }

    pub fn get_block_list(&self) -> Vec<String> {
        let mut list: Vec<String> = self.block_list.iter().cloned().collect();
        list.sort();
        list
    }

    pub fn get_allow_list(&self) -> Vec<String> {
        let mut list: Vec<String> = self.allow_list.iter().cloned().collect();
        list.sort();
        list
    }

    /// Evaluate a decision and enforce it for network access.
    /// Returns the enforcement action taken.
    pub fn enforce_network(&mut self, decision: &EnforcementDecision) -> EnforcementAction {
        let target = decision.context.destination.clone().unwrap_or_default();
        let action_type = format!("{:?}", decision.action);

        let result = match decision.action {
            DecisionAction::Block => {
                // In production: execute iptables -A OUTPUT -d <dest> -j DROP
                // For now: record the block
                self.add_temp_block(target.clone(), 300, decision.reason.clone());
                if !self.block_list.contains(&target) {
                    self.block_list.insert(target.clone());
                }
                tracing::warn!("ENFORCEMENT BLOCK: {} for agent {} (PID {}) — {}",
                    target, decision.agent_name, decision.pid, decision.reason);
                EnforcementResult::Applied
            }
            DecisionAction::Flag => {
                tracing::info!("ENFORCEMENT FLAG: {} for agent {} (PID {}) — {}",
                    target, decision.agent_name, decision.pid, decision.reason);
                EnforcementResult::Applied
            }
            DecisionAction::Allow => {
                EnforcementResult::Skipped
            }
            DecisionAction::Restart | DecisionAction::Escalate => {
                EnforcementResult::Applied
            }
        };

        let action = EnforcementAction {
            id: Uuid::new_v4(),
            decision_id: decision.id,
            pid: decision.pid,
            agent_name: decision.agent_name.clone(),
            action_type,
            target: target.clone(),
            result,
            duration_ms: 0,
            timestamp: Utc::now(),
            details: decision.reason.clone(),
        };

        self.actions.push(action.clone());
        action
    }

    /// Get all enforcement actions.
    pub fn get_actions(&self) -> Vec<&EnforcementAction> {
        self.actions.iter().collect()
    }

    pub fn action_count(&self) -> usize {
        self.actions.len()
    }
}

impl Default for NetworkEnforcementEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Process enforcement
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEnforcementEngine {
    /// Known/allowed executables
    known_executables: HashSet<String>,
    /// Blocked executables
    blocked_executables: HashSet<String>,
    /// Flagged process launches
    flagged_processes: Vec<FlaggedProcess>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlaggedProcess {
    pub pid: u32,
    pub agent_name: String,
    pub executable: String,
    pub action: String,
    pub timestamp: DateTime<Utc>,
}

impl ProcessEnforcementEngine {
    pub fn new() -> Self {
        Self {
            known_executables: Self::default_known_executables(),
            blocked_executables: Self::default_blocked_executables(),
            flagged_processes: Vec::new(),
        }
    }

    fn default_known_executables() -> HashSet<String> {
        let mut set = HashSet::new();
        set.insert("python".to_string());
        set.insert("python3".to_string());
        set.insert("node".to_string());
        set.insert("npm".to_string());
        set.insert("npx".to_string());
        set.insert("bun".to_string());
        set.insert("deno".to_string());
        set.insert("claude".to_string());
        set.insert("code".to_string());
        set.insert("bash".to_string());
        set.insert("sh".to_string());
        set.insert("zsh".to_string());
        set.insert("git".to_string());
        set.insert("curl".to_string());
        set.insert("wget".to_string());
        set.insert("cargo".to_string());
        set.insert("rustc".to_string());
        set.insert("gcc".to_string());
        set.insert("make".to_string());
        set.insert("docker".to_string());
        set.insert("nvim".to_string());
        set.insert("vim".to_string());
        set
    }

    fn default_blocked_executables() -> HashSet<String> {
        let mut set = HashSet::new();
        set.insert("nc".to_string());
        set.insert("ncat".to_string());
        set.insert("netcat".to_string());
        set.insert("tcpdump".to_string());
        set.insert("tshark".to_string());
        set.insert("nmap".to_string());
        set.insert("socat".to_string());
        set.insert("proxychains".to_string());
        set.insert("tor".to_string());
        set.insert("miner".to_string());
        set.insert("xmrig".to_string());
        set
    }

    /// Check if an executable launch should be flagged or blocked.
    pub fn check_executable(
        &mut self,
        pid: u32,
        agent_name: &str,
        executable: &str,
    ) -> Option<String> {
        let exe_lower = executable.to_lowercase();

        if self.blocked_executables.contains(&exe_lower) {
            self.flagged_processes.push(FlaggedProcess {
                pid,
                agent_name: agent_name.to_string(),
                executable: exe_lower.clone(),
                action: "BLOCK".to_string(),
                timestamp: Utc::now(),
            });
            return Some("BLOCK".to_string());
        }

        if !self.known_executables.contains(&exe_lower) {
            self.flagged_processes.push(FlaggedProcess {
                pid,
                agent_name: agent_name.to_string(),
                executable: exe_lower.clone(),
                action: "FLAG".to_string(),
                timestamp: Utc::now(),
            });
            return Some("FLAG".to_string());
        }

        None
    }

    pub fn is_known_executable(&self, executable: &str) -> bool {
        self.known_executables.contains(&executable.to_lowercase())
    }

    pub fn get_flagged_processes(&self) -> Vec<&FlaggedProcess> {
        self.flagged_processes.iter().collect()
    }
}

impl Default for ProcessEnforcementEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// File access enforcement
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccessEnforcementEngine {
    /// Sensitive file paths that trigger flags
    sensitive_paths: Vec<String>,
    /// File access violations
    violations: Vec<FileAccessViolation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccessViolation {
    pub id: Uuid,
    pub pid: u32,
    pub agent_name: String,
    pub file_path: String,
    pub action: String,
    pub timestamp: DateTime<Utc>,
}

impl FileAccessEnforcementEngine {
    pub fn new() -> Self {
        Self {
            sensitive_paths: Self::default_sensitive_paths(),
            violations: Vec::new(),
        }
    }

    fn default_sensitive_paths() -> Vec<String> {
        vec![
            "/etc/passwd".to_string(),
            "/etc/shadow".to_string(),
            "/etc/sudoers".to_string(),
            "/etc/ssh/".to_string(),
            "/root/.ssh/".to_string(),
            "~/.ssh/".to_string(),
            "/home/".to_string() + &whoami() + "/.ssh/",
            "/var/log/auth.log".to_string(),
            "/var/log/secure".to_string(),
            "/var/log/syslog".to_string(),
            "/etc/kubernetes/".to_string(),
            "/root/.kube/".to_string(),
            "credentials".to_string(),
            ".env".to_string(),
            "token".to_string(),
            "secret".to_string(),
            "key.pem".to_string(),
            "id_rsa".to_string(),
            "id_ed25519".to_string(),
        ]
    }

    /// Check if a file access should be flagged.
    pub fn check_file_access(&mut self, pid: u32, agent_name: &str, file_path: &str) -> Option<String> {
        let path_lower = file_path.to_lowercase();
        let is_sensitive = self.sensitive_paths.iter().any(|sp| path_lower.contains(sp));

        if is_sensitive {
            self.violations.push(FileAccessViolation {
                id: Uuid::new_v4(),
                pid,
                agent_name: agent_name.to_string(),
                file_path: file_path.to_string(),
                action: "FLAG".to_string(),
                timestamp: Utc::now(),
            });
            return Some("FLAG".to_string());
        }

        None
    }

    pub fn get_violations(&self) -> Vec<&FileAccessViolation> {
        self.violations.iter().collect()
    }

    pub fn violation_count(&self) -> usize {
        self.violations.len()
    }
}

// Platform-aware username for default sensitive paths
#[cfg(target_os = "linux")]
fn whoami() -> String {
    std::env::var("USER").unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(not(target_os = "linux"))]
fn whoami() -> String {
    "unknown".to_string()
}

// ---------------------------------------------------------------------------
// Enforcement incident record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementIncident {
    pub id: Uuid,
    pub decision_id: Uuid,
    pub pid: u32,
    pub agent_name: String,
    pub action_type: String,
    pub action_target: String,
    pub result: EnforcementResult,
    pub duration_ms: u64,
    pub status: IncidentStatus,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolution: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IncidentStatus {
    Open,
    Resolved,
    Overridden,
}

// ---------------------------------------------------------------------------
// Aggregate enforcement manager
// ---------------------------------------------------------------------------

pub struct EnforcementManager {
    pub network: NetworkEnforcementEngine,
    pub process: ProcessEnforcementEngine,
    pub file_access: FileAccessEnforcementEngine,
    incidents: Vec<EnforcementIncident>,
}

impl EnforcementManager {
    pub fn new() -> Self {
        Self {
            network: NetworkEnforcementEngine::new(),
            process: ProcessEnforcementEngine::new(),
            file_access: FileAccessEnforcementEngine::new(),
            incidents: Vec::new(),
        }
    }

    /// Execute a decision through the appropriate enforcement engine.
    pub fn execute(&mut self, decision: &EnforcementDecision) -> EnforcementAction {
        let action = self.network.enforce_network(decision);

        // Create enforcement incident
        let incident = EnforcementIncident {
            id: Uuid::new_v4(),
            decision_id: decision.id,
            pid: decision.pid,
            agent_name: decision.agent_name.clone(),
            action_type: action.action_type.clone(),
            action_target: action.target.clone(),
            result: action.result.clone(),
            duration_ms: 0,
            status: IncidentStatus::Open,
            created_at: Utc::now(),
            resolved_at: None,
            resolution: None,
        };
        self.incidents.push(incident);

        action
    }

    pub fn resolve_incident(&mut self, incident_id: Uuid, resolution: String) -> bool {
        if let Some(incident) = self.incidents.iter_mut().find(|i| i.id == incident_id) {
            incident.status = IncidentStatus::Resolved;
            incident.resolved_at = Some(Utc::now());
            incident.resolution = Some(resolution);
            return true;
        }
        false
    }

    pub fn get_incidents(&self) -> Vec<&EnforcementIncident> {
        self.incidents.iter().collect()
    }

    pub fn get_open_incidents(&self) -> Vec<&EnforcementIncident> {
        self.incidents.iter().filter(|i| i.status == IncidentStatus::Open).collect()
    }

    pub fn incident_count(&self) -> usize {
        self.incidents.len()
    }

    pub fn get_stats(&self) -> EnforcementStats {
        EnforcementStats {
            blocked_destinations: self.network.get_block_list().len(),
            allowed_destinations: self.network.get_allow_list().len(),
            flagged_processes: self.process.get_flagged_processes().len(),
            file_violations: self.file_access.violation_count(),
            total_incidents: self.incident_count(),
            open_incidents: self.get_open_incidents().len(),
            total_actions: self.network.action_count(),
        }
    }
}

impl Default for EnforcementManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementStats {
    pub blocked_destinations: usize,
    pub allowed_destinations: usize,
    pub flagged_processes: usize,
    pub file_violations: usize,
    pub total_incidents: usize,
    pub open_incidents: usize,
    pub total_actions: usize,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use omnisec_decision::{DecisionEngine, DecisionAction};

    fn make_decision(engine: &mut DecisionEngine, dest: Option<&str>, risk: u32, level: &str) -> EnforcementDecision {
        engine.evaluate(
            1234, "agent".to_string(),
            risk, level, None, None, None, None,
            dest.map(|d| d.to_string()), None, None,
            &["api.openai.com".to_string()],
        )
    }

    #[test]
    fn test_network_allow_list() {
        let engine = NetworkEnforcementEngine::new();
        assert!(engine.is_allowed("api.openai.com"));
        assert!(engine.is_allowed("github.com"));
        assert!(!engine.is_allowed("evil.com"));
    }

    #[test]
    fn test_network_block_list() {
        let engine = NetworkEnforcementEngine::new();
        assert!(engine.is_blocked("evil.c2.com"));
        assert!(engine.is_blocked("data-exfil.com"));
        assert!(!engine.is_blocked("google.com"));
    }

    #[test]
    fn test_enforce_block() {
        let mut decision_engine = DecisionEngine::new();
        for policy in DecisionEngine::default_policies() {
            decision_engine.add_policy(policy);
        }

        let decision = make_decision(&mut decision_engine, Some("data-exfil.com"), 90, "Critical");

        let mut enforcement = EnforcementManager::new();
        let action = enforcement.execute(&decision);

        assert_eq!(action.result, EnforcementResult::Applied);
        assert!(enforcement.network.is_blocked("data-exfil.com"));
    }

    #[test]
    fn test_process_check() {
        let mut engine = ProcessEnforcementEngine::new();

        // Known executable
        assert!(engine.check_executable(1, "agent", "python").is_none());
        assert!(engine.check_executable(1, "agent", "node").is_none());

        // Unknown executable — flagged
        assert_eq!(engine.check_executable(1, "agent", "random_binary").unwrap(), "FLAG");

        // Blocked executable
        assert_eq!(engine.check_executable(1, "agent", "nmap").unwrap(), "BLOCK");
    }

    #[test]
    fn test_file_access_check() {
        let mut engine = FileAccessEnforcementEngine::new();

        // Sensitive file
        let result = engine.check_file_access(1, "agent", "/etc/passwd");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "FLAG");

        // Normal file — should not trigger
        assert!(engine.check_file_access(1, "agent", "/tmp/test.txt").is_none());

        // SSH key — should trigger
        assert!(engine.check_file_access(1, "agent", "/home/user/.ssh/id_rsa").is_some());
    }

    #[test]
    fn test_enforcement_incident_creation() {
        let mut decision_engine = DecisionEngine::new();
        for policy in DecisionEngine::default_policies() {
            decision_engine.add_policy(policy);
        }

        let decision = make_decision(&mut decision_engine, Some("evil.com"), 85, "Critical");

        let mut enforcement = EnforcementManager::new();
        enforcement.execute(&decision);
        enforcement.execute(&decision);
        enforcement.execute(&decision);

        assert_eq!(enforcement.incident_count(), 3);
        assert_eq!(enforcement.get_open_incidents().len(), 3);

        // Resolve one
        let incident_id = enforcement.incidents[0].id;
        assert!(enforcement.resolve_incident(incident_id, "investigation complete".to_string()));
        assert_eq!(enforcement.get_open_incidents().len(), 2);
    }

    #[test]
    fn test_enforcement_stats() {
        let mut decision_engine = DecisionEngine::new();
        for policy in DecisionEngine::default_policies() {
            decision_engine.add_policy(policy);
        }

        let mut enforcement = EnforcementManager::new();
        enforcement.execute(&make_decision(&mut decision_engine, Some("evil.com"), 85, "Critical"));
        enforcement.execute(&make_decision(&mut decision_engine, Some("api.openai.com"), 10, "Normal"));

        let stats = enforcement.get_stats();
        assert!(stats.total_actions >= 2);
    }

    #[test]
    fn test_temp_block_expiry() {
        let mut decision_engine = DecisionEngine::new();
        for policy in DecisionEngine::default_policies() {
            decision_engine.add_policy(policy);
        }

        let mut enforcement = EnforcementManager::new();
        // Risk score 85+ triggers block_critical_risk rule (priority 90, min=81)
        enforcement.execute(&make_decision(&mut decision_engine, Some("temp-blocked.com"), 85, "Critical"));

        assert!(enforcement.network.is_blocked("temp-blocked.com"));
    }

    #[test]
    fn test_allow_list_mutations() {
        let mut engine = NetworkEnforcementEngine::new();
        engine.add_to_allow_list("custom-allowed.com".to_string());
        assert!(engine.is_allowed("custom-allowed.com"));

        engine.remove_from_block_list("evil.c2.com");
        assert!(!engine.is_blocked("evil.c2.com"));
    }
}
