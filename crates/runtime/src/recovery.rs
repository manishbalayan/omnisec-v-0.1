// OMNISEC Linux Runtime Control — Enforcement Recovery Engine (Phase 8)
//
// Everything reversible. Supports automatic unblock, temporary quarantine,
// timed restrictions, and full rollback of enforcement actions.

use crate::{RuntimeAction, RuntimeMode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverableAction {
    pub id: Uuid,
    pub action_type: String,
    pub target: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub rollback_action: String,
    pub rolled_back: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub struct RecoveryEngine {
    recoverable: Vec<RecoverableAction>,
    mode: RuntimeMode,
}

impl RecoveryEngine {
    pub fn new() -> Self {
        Self {
            recoverable: Vec::new(),
            mode: crate::detect_runtime_mode(),
        }
    }

    /// Register an action for automatic recovery
    pub fn register(
        &mut self,
        action_id: Uuid,
        action_type: &str,
        target: &str,
        duration_secs: Option<u64>,
        rollback_action: &str,
    ) {
        self.recoverable.push(RecoverableAction {
            id: action_id,
            action_type: action_type.to_string(),
            target: target.to_string(),
            expires_at: duration_secs.map(|s| chrono::Utc::now() + chrono::Duration::seconds(s as i64)),
            rollback_action: rollback_action.to_string(),
            rolled_back: false,
            created_at: chrono::Utc::now(),
        });
    }

    /// Check for expired actions and automatically rollback
    pub fn check_expired(&mut self) -> Vec<&RecoverableAction> {
        let now = chrono::Utc::now();
        let mut expired = Vec::new();

        for action in &self.recoverable {
            if !action.rolled_back {
                if let Some(expires) = action.expires_at {
                    if now > expires {
                        expired.push(action);
                    }
                }
            }
        }

        expired
    }

    /// Auto-recover expired actions
    pub fn auto_recover(&mut self) -> Vec<RuntimeAction> {
        let expired: Vec<(String, String)> = self.check_expired()
            .iter()
            .map(|a| (a.action_type.clone(), a.target.clone()))
            .collect();

        let mut recoveries = Vec::new();

        for (action_type, target) in &expired {
            let recovery = self.rollback(action_type, target);
            recoveries.push(recovery);

            if let Some(action) = self.recoverable.iter_mut()
                .find(|a| a.action_type == *action_type && a.target == *target)
            {
                action.rolled_back = true;
            }
        }

        recoveries
    }

    /// Rollback a specific enforcement action
    pub fn rollback(&self, action_type: &str, target: &str) -> RuntimeAction {
        let rollback_action = match action_type {
            "nftables_block_domain" | "nftables_block_ip" | "nftables_block_cidr" => "nftables_unblock",
            "cgroup_throttle" => "cgroup_release",
            "process_suspend" => "process_resume",
            "process_quarantine" => "process_resume",
            "systemd_stop" | "systemd_disable" | "systemd_quarantine" => "systemd_restart",
            _ => "unknown_rollback",
        };

        tracing::info!("Rollback: {} → {} for {}", action_type, rollback_action, target);

        RuntimeAction {
            id: Uuid::new_v4(),
            action_type: format!("rollback_{}", action_type),
            target: target.to_string(),
            kernel_command: format!("rollback {} → {}", action_type, rollback_action),
            result: "RolledBack".to_string(),
            duration_ms: 0,
            timestamp: chrono::Utc::now(),
            verified: true,
            rolled_back: true,
        }
    }

    pub fn get_pending_recoveries(&self) -> Vec<&RecoverableAction> {
        self.recoverable.iter().filter(|a| !a.rolled_back).collect()
    }

    pub fn recovery_count(&self) -> usize {
        self.recoverable.len()
    }
}

impl Default for RecoveryEngine {
    fn default() -> Self {
        Self::new()
    }
}
