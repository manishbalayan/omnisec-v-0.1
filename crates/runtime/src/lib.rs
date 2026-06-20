// OMNISEC Linux Runtime Control Layer
//
// Transforms logical enforcement into real Linux kernel enforcement:
//   Decision → Kernel Action → Audit

pub mod network;
pub mod resource;
pub mod systemd;
pub mod process;
pub mod file_monitor;
pub mod recovery;
pub mod audit;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Runtime execution modes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RuntimeMode {
    /// Platform is Linux — nftables, cgroups, inotify all available
    Native,
    /// Fallback — enforcement is logical only (no kernel actions)
    Simulated,
}

/// Detect if we're running on Linux with enforcement capabilities
pub fn detect_runtime_mode() -> RuntimeMode {
    #[cfg(target_os = "linux")]
    {
        // Check if we have root/CAP_NET_ADMIN for nftables
        RuntimeMode::Native
    }

    #[cfg(not(target_os = "linux"))]
    {
        tracing::warn!("Not on Linux — runtime enforcement will be simulated");
        RuntimeMode::Simulated
    }
}

// ---------------------------------------------------------------------------
// Aggregate Runtime Manager
// ---------------------------------------------------------------------------

pub struct RuntimeManager {
    pub network: network::NetworkBlockEngine,
    pub resource: resource::ResourceControlEngine,
    pub systemd: systemd::SystemdControlEngine,
    pub process: process::ProcessContainmentEngine,
    pub file_monitor: file_monitor::FileMonitorEngine,
    pub recovery: recovery::RecoveryEngine,
    pub audit: audit::KernelAuditTrail,
    pub mode: RuntimeMode,
    actions: Vec<RuntimeAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeAction {
    pub id: Uuid,
    pub action_type: String,
    pub target: String,
    pub kernel_command: String,
    pub result: String,
    pub duration_ms: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub verified: bool,
    pub rolled_back: bool,
}

impl RuntimeManager {
    pub fn new() -> Self {
        let mode = detect_runtime_mode();
        tracing::info!("Runtime Manager initialized — mode: {:?}", mode);

        Self {
            network: network::NetworkBlockEngine::new(),
            resource: resource::ResourceControlEngine::new(),
            systemd: systemd::SystemdControlEngine::new(),
            process: process::ProcessContainmentEngine::new(),
            file_monitor: file_monitor::FileMonitorEngine::new(),
            recovery: recovery::RecoveryEngine::new(),
            audit: audit::KernelAuditTrail::new(),
            mode,
            actions: Vec::new(),
        }
    }

    pub fn record_action(&mut self, action: RuntimeAction) {
        // Record the action in the audit trail
        let _ = self.audit.record(
            &action.action_type,
            &action.target,
            &action.result,
            action.duration_ms,
            action.verified,
        );
        self.actions.push(action);
    }

    pub fn get_actions(&self) -> Vec<&RuntimeAction> {
        self.actions.iter().collect()
    }

    pub fn get_stats(&self) -> RuntimeStats {
        RuntimeStats {
            nftables_rules: self.network.active_rule_count(),
            cgroups_active: self.resource.active_cgroup_count(),
            systemd_actions: self.systemd.action_count(),
            contained_processes: self.process.contained_count(),
            quarantined_processes: self.process.quarantined_count(),
            file_monitors_active: self.file_monitor.monitor_count(),
            audit_entries: self.audit.entry_count(),
            total_actions: self.actions.len(),
            mode: format!("{:?}", self.mode),
        }
    }

    /// Execute a decision through the appropriate runtime engine
    pub fn execute(&mut self, decision: &omnisec_decision::EnforcementDecision) -> Vec<RuntimeAction> {
        let mut actions = Vec::new();

        match decision.action {
            omnisec_decision::DecisionAction::Block => {
                // Network block via nftables
                if let Some(ref dest) = decision.context.destination {
                    let action = self.network.block_domain(dest, &decision.reason);
                    actions.push(action);
                }
            }
            omnisec_decision::DecisionAction::Restart => {
                // Process restart
                let action = self.process.restart(decision.pid, &decision.agent_name);
                actions.push(action);
            }
            omnisec_decision::DecisionAction::Escalate => {
                // Quarantine process
                let action = self.process.quarantine(decision.pid, &decision.agent_name, &decision.reason);
                actions.push(action);

                // Throttle network
                if let Some(ref dest) = decision.context.destination {
                    let net_action = self.network.block_domain(dest, &decision.reason);
                    actions.push(net_action);
                }
            }
            _ => {}
        }

        // Audit all actions
        for action in &actions {
            self.record_action(action.clone());
        }

        actions
    }
}

impl Default for RuntimeManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeStats {
    pub nftables_rules: usize,
    pub cgroups_active: usize,
    pub systemd_actions: usize,
    pub contained_processes: usize,
    pub quarantined_processes: usize,
    pub file_monitors_active: usize,
    pub audit_entries: usize,
    pub total_actions: usize,
    pub mode: String,
}
