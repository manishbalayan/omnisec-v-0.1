// OMNISEC Linux Runtime Control — Kernel Audit Trail (Phase 9)
//
// Records every enforcement action: decision → kernel action → result
// → rollback → duration → verification. All actions permanently traceable.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelAuditEntry {
    pub id: Uuid,
    pub action_type: String,
    pub target: String,
    pub kernel_command: String,
    pub result: String,
    pub duration_ms: u64,
    pub verified: bool,
    pub rolled_back: bool,
    pub rollback_time: Option<chrono::DateTime<chrono::Utc>>,
    pub verification_method: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

pub struct KernelAuditTrail {
    entries: Vec<KernelAuditEntry>,
}

impl KernelAuditTrail {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Record a kernel enforcement action
    pub fn record(
        &mut self,
        action_type: &str,
        target: &str,
        result: &str,
        duration_ms: u64,
        verified: bool,
    ) -> Uuid {
        let id = Uuid::new_v4();

        self.entries.push(KernelAuditEntry {
            id,
            action_type: action_type.to_string(),
            target: target.to_string(),
            kernel_command: format!("{} {}", action_type, target),
            result: result.to_string(),
            duration_ms,
            verified,
            rolled_back: false,
            rollback_time: None,
            verification_method: if verified { "kernel_confirm".to_string() } else { "pending".to_string() },
            timestamp: chrono::Utc::now(),
        });

        tracing::info!(
            "KERNEL AUDIT: {} → {} ({}ms, verified: {})",
            action_type, result, duration_ms, verified
        );

        id
    }

    /// Mark an action as rolled back
    pub fn mark_rolled_back(&mut self, entry_id: Uuid) -> bool {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.id == entry_id) {
            entry.rolled_back = true;
            entry.rollback_time = Some(chrono::Utc::now());
            true
        } else {
            false
        }
    }

    /// Get the full audit trail
    pub fn get_entries(&self) -> Vec<&KernelAuditEntry> {
        self.entries.iter().collect()
    }

    /// Get entries for a specific target (e.g., PID, domain)
    pub fn get_entries_for_target(&self, target: &str) -> Vec<&KernelAuditEntry> {
        self.entries.iter().filter(|e| e.target == target).collect()
    }

    /// Get entries that were verified
    pub fn get_verified_entries(&self) -> Vec<&KernelAuditEntry> {
        self.entries.iter().filter(|e| e.verified).collect()
    }

    /// Get entries that were rolled back
    pub fn get_rolled_back_entries(&self) -> Vec<&KernelAuditEntry> {
        self.entries.iter().filter(|e| e.rolled_back).collect()
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

impl Default for KernelAuditTrail {
    fn default() -> Self {
        Self::new()
    }
}
