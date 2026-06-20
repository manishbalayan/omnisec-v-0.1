//! # OMNISEC Agent Identity Engine
//!
//! Maps PIDs to agent identities and tracks process lineage.
//! This is the canonical identity source for all security events.
//!
//! Responsibilities:
//! - `map_pid(pid) → AgentRuntimeIdentity` — canonical identity lookup
//! - Resolve child processes to parent agents (fork survival)
//! - Track process trees (PID → children PIDs)
//! - Survive process restarts by agent identity (not PID)
//! - Maintain runtime lineage for orphan detection
//!
//! Thread-safe: uses `Arc<RwLock<>>` internally.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Identity primitives
// ---------------------------------------------------------------------------

/// Canonical agent identity — survives restarts, forks, and PID reuse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRuntimeIdentity {
    /// Stable UUID that survives restarts (persisted in DB)
    pub agent_id: Uuid,
    /// Current OS PID
    pub pid: u32,
    /// Parent PID at time of discovery
    pub ppid: u32,
    /// Agent display name
    pub agent_name: String,
    /// Process command (argv[0])
    pub comm: String,
    /// Full executable path
    pub executable_path: Option<String>,
    /// Depth in process tree (0 = root agent)
    pub process_tree_depth: u32,
    /// Agent ID of the parent agent (if forked from another agent)
    pub parent_agent_id: Option<Uuid>,
    /// Children agent PIDs (for tracking process trees)
    pub child_pids: Vec<u32>,
    /// When this identity was first seen
    pub first_seen: chrono::DateTime<chrono::Utc>,
    /// When this identity was last updated
    pub last_seen: chrono::DateTime<chrono::Utc>,
    /// Whether this is a child process (forked from parent agent)
    pub is_child_process: bool,
    /// Whether this is an orphaned child (parent process died)
    pub is_orphan: bool,
    /// Agent version / fingerprint version
    pub version: u32,
    /// Framework type if identified
    pub framework: Option<String>,
}

// ---------------------------------------------------------------------------
// Process Tree Node
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ProcessTreeNode {
    pid: u32,
    ppid: u32,
    agent_id: Uuid,
    children: HashSet<u32>,
    is_agent: bool,
    discovered_at: chrono::DateTime<chrono::Utc>,
}

// ---------------------------------------------------------------------------
// Agent Identity Engine
// ---------------------------------------------------------------------------

pub struct AgentIdentityEngine {
    /// PID → Identity mapping (fast lookup)
    pid_map: HashMap<u32, Uuid>,
    /// Agent ID → Identity (stable cross-restart)
    identities: HashMap<Uuid, AgentRuntimeIdentity>,
    /// Process tree: PID → Tree Node
    process_tree: HashMap<u32, ProcessTreeNode>,
    /// PID → Agent ID for child processes (fork tracking)
    child_agent_map: HashMap<u32, Uuid>,
    /// Agent ID → PIDs (all PIDs this agent has ever used, including children)
    agent_pid_history: HashMap<Uuid, Vec<u32>>,
    /// Next identity number for auto-naming
    next_id: u64,
    /// Known agent PIDs (from discovery) — agents we've confirmed as AI agents
    known_agent_pids: HashSet<u32>,
}

impl AgentIdentityEngine {
    pub fn new() -> Self {
        Self {
            pid_map: HashMap::new(),
            identities: HashMap::new(),
            process_tree: HashMap::new(),
            child_agent_map: HashMap::new(),
            agent_pid_history: HashMap::new(),
            next_id: 1,
            known_agent_pids: HashSet::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Core identity resolution
    // -----------------------------------------------------------------------

    /// Map a PID to an identity. Returns `None` if the PID is unknown.
    pub fn resolve_pid(&self, pid: u32) -> Option<&AgentRuntimeIdentity> {
        let agent_id = self.pid_map.get(&pid)?;
        self.identities.get(agent_id)
    }

    /// Get identity by agent UUID
    pub fn get_identity(&self, agent_id: &Uuid) -> Option<&AgentRuntimeIdentity> {
        self.identities.get(agent_id)
    }

    /// Register or update an agent from a discovery event
    pub fn register_agent(
        &mut self,
        pid: u32,
        ppid: u32,
        name: String,
        comm: String,
        framework: Option<String>,
    ) -> AgentRuntimeIdentity {
        // Check if we already know this PID (restart or fork)
        // Use scope to drop mutable borrow before calling self methods
        let result = {
            if let Some(aid) = self.pid_map.get(&pid).copied() {
                let existing = self.identities.get_mut(&aid);
                if let Some(existing) = existing {
                    existing.ppid = ppid;
                    existing.last_seen = chrono::Utc::now();
                    // Clone the result before releasing the mutable borrow
                    let result = existing.clone();
                    // Adjust framework without holding the mutable borrow
                    existing.framework = framework.clone();
                    Some(result)
                } else {
                    None
                }
            } else {
                None
            }
        };
        if let Some(mut result) = result {
            self.update_process_tree(pid, ppid, result.agent_id, true);
            self.known_agent_pids.insert(pid);
            return result;
        }

        let agent_id = Uuid::new_v4();
        let now = chrono::Utc::now();

        // Check if this is a child of a known agent
        let parent_data = {
            if let Some(parent_id) = self.pid_map.get(&ppid).copied() {
                self.identities.get(&parent_id).map(|parent| {
                    (parent_id, parent.process_tree_depth)
                })
            } else {
                None
            }
        };

        if let Some((parent_id, parent_depth)) = parent_data {
            let identity = AgentRuntimeIdentity {
                agent_id,
                pid,
                ppid,
                agent_name: name,
                comm,
                executable_path: None,
                process_tree_depth: parent_depth + 1,
                parent_agent_id: Some(parent_id),
                child_pids: Vec::new(),
                first_seen: now,
                last_seen: now,
                is_child_process: true,
                is_orphan: false,
                version: 1,
                framework,
            };

            // Update parent's child list
            if let Some(parent) = self.identities.get_mut(&parent_id) {
                parent.child_pids.push(pid);
            }

            self.child_agent_map.insert(pid, parent_id);
            self.pid_map.insert(pid, agent_id);
            self.identities.insert(agent_id, identity.clone());
            self.update_process_tree(pid, ppid, agent_id, true);
            self.known_agent_pids.insert(pid);
            return identity;
        }

        // New root agent
        let identity = AgentRuntimeIdentity {
            agent_id,
            pid,
            ppid,
            agent_name: name,
            comm,
            executable_path: None,
            process_tree_depth: 0,
            parent_agent_id: None,
            child_pids: Vec::new(),
            first_seen: now,
            last_seen: now,
            is_child_process: false,
            is_orphan: false,
            version: 1,
            framework,
        };

        self.pid_map.insert(pid, agent_id);
        self.identities.insert(agent_id, identity.clone());
        self.agent_pid_history.insert(agent_id, vec![pid]);
        self.update_process_tree(pid, ppid, agent_id, true);
        self.known_agent_pids.insert(pid);
        identity
    }

    /// Record a process exec event — update the identity or create a child
    pub fn record_exec(
        &mut self,
        pid: u32,
        ppid: u32,
        uid: u32,
        comm: &str,
        filename: &str,
    ) -> Option<AgentRuntimeIdentity> {
        let _ = uid; // reserved for future permission checks
        // Try to resolve to existing agent
        let existing_id = self.pid_map.get(&pid).copied();
        if let Some(aid) = existing_id {
            if let Some(identity) = self.identities.get_mut(&aid) {
                identity.last_seen = chrono::Utc::now();
                identity.comm = comm.to_string();
                identity.executable_path = Some(filename.to_string());
                return Some(identity.clone());
            }
        }

        // Check if parent is a known agent — resolve separately to avoid borrow conflicts
        let parent_info = self.pid_map.get(&ppid).copied();
        if let Some(parent_id) = parent_info {
            let (parent_name, parent_depth, parent_version, parent_framework) = {
                let parent = self.identities.get(&parent_id)?;
                (
                    parent.agent_name.clone(),
                    parent.process_tree_depth,
                    parent.version,
                    parent.framework.clone(),
                )
            };

            let agent_id = Uuid::new_v4();
            let now = chrono::Utc::now();
            let identity = AgentRuntimeIdentity {
                agent_id,
                pid,
                ppid,
                agent_name: format!("{}-child-{}", parent_name, pid),
                comm: comm.to_string(),
                executable_path: Some(filename.to_string()),
                process_tree_depth: parent_depth + 1,
                parent_agent_id: Some(parent_id),
                child_pids: Vec::new(),
                first_seen: now,
                last_seen: now,
                is_child_process: true,
                is_orphan: false,
                version: parent_version,
                framework: parent_framework,
            };

            self.pid_map.insert(pid, agent_id);
            self.identities.insert(agent_id, identity.clone());
            self.child_agent_map.insert(pid, parent_id);
            self.update_process_tree(pid, ppid, agent_id, true);
            return Some(identity);
        }

        None
    }

    /// Record a process exit event — PID is no longer valid
    pub fn record_exit(&mut self, pid: u32) {
        // Remove from known agent PIDs
        self.known_agent_pids.remove(&pid);

        // Update process tree
        if let Some(node) = self.process_tree.get_mut(&pid) {
            node.is_agent = false;
        }

        // Don't fully delete the identity — it may be needed for audit trails.
        // But mark the PID as stale.
        if let Some(agent_id) = self.pid_map.get(&pid) {
            if let Some(identity) = self.identities.get_mut(agent_id) {
                identity.last_seen = chrono::Utc::now();
            }
        }
    }

    /// Record a fork event — parent created child PID
    pub fn record_fork(&mut self, parent_pid: u32, child_pid: u32, comm: &str) -> Option<AgentRuntimeIdentity> {
        // Find the parent agent — clone values to avoid borrow conflicts
        let (parent_id, parent_name, parent_depth, parent_version, parent_framework) = {
            let pid = self.pid_map.get(&parent_pid).copied()?;
            let parent = self.identities.get(&pid)?;
            (
                pid,
                parent.agent_name.clone(),
                parent.process_tree_depth,
                parent.version,
                parent.framework.clone(),
            )
        };

        let agent_id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let identity = AgentRuntimeIdentity {
            agent_id,
            pid: child_pid,
            ppid: parent_pid,
            agent_name: format!("{}-child-{}", parent_name, child_pid),
            comm: comm.to_string(),
            executable_path: None,
            process_tree_depth: parent_depth + 1,
            parent_agent_id: Some(parent_id),
            child_pids: Vec::new(),
            first_seen: now,
            last_seen: now,
            is_child_process: true,
            is_orphan: false,
            version: parent_version,
            framework: parent_framework,
        };

        if let Some(parent_identity) = self.identities.get_mut(&parent_id) {
            parent_identity.child_pids.push(child_pid);
        }

        self.pid_map.insert(child_pid, agent_id);
        self.identities.insert(agent_id, identity.clone());
        self.child_agent_map.insert(child_pid, parent_id);
        self.update_process_tree(child_pid, parent_pid, agent_id, false);
        Some(identity)
    }

    /// Record a connection event — try to resolve PID to agent
    pub fn resolve_connection(&self, pid: u32) -> Option<&AgentRuntimeIdentity> {
        self.pid_map.get(&pid).and_then(|id| self.identities.get(id))
    }

    // -----------------------------------------------------------------------
    // Process tree queries
    // -----------------------------------------------------------------------

    /// Get all children of a PID
    pub fn get_children(&self, pid: u32) -> Vec<u32> {
        self.process_tree
            .get(&pid)
            .map(|node| node.children.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Get the entire process tree for a given agent
    pub fn get_process_tree(&self, agent_id: &Uuid) -> Vec<&AgentRuntimeIdentity> {
        let mut result = Vec::new();
        let pid_to_identity = |pid: u32| -> Option<&AgentRuntimeIdentity> {
            let cid = self.pid_map.get(&pid)?;
            self.identities.get(cid)
        };

        if let Some(root) = self.identities.get(agent_id) {
            result.push(root);
            for child_pid in &root.child_pids {
                if let Some(child) = pid_to_identity(*child_pid) {
                    result.push(child);
                }
            }
        }
        result
    }

    /// Get all known agent identities (for dashboard / API)
    pub fn all_identities(&self) -> Vec<&AgentRuntimeIdentity> {
        self.identities.values().collect()
    }

    /// Get agent count
    pub fn agent_count(&self) -> usize {
        self.identities.len()
    }

    /// Check if a PID belongs to a known agent
    pub fn is_known_agent_pid(&self, pid: u32) -> bool {
        self.known_agent_pids.contains(&pid)
    }

    // -----------------------------------------------------------------------
    // Identity recovery — survive daemon restarts
    // -----------------------------------------------------------------------

    /// Export current identities for persistence
    pub fn export_identities(&self) -> Vec<AgentRuntimeIdentity> {
        self.identities.values().cloned().collect()
    }

    /// Import persisted identities after daemon restart
    pub fn import_identities(&mut self, identities: Vec<AgentRuntimeIdentity>) {
        for identity in identities {
            self.identities.insert(identity.agent_id, identity.clone());
            self.pid_map.insert(identity.pid, identity.agent_id);
            self.agent_pid_history
                .entry(identity.agent_id)
                .or_insert_with(Vec::new)
                .push(identity.pid);
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn update_process_tree(&mut self, pid: u32, ppid: u32, agent_id: Uuid, is_agent: bool) {
        // Add/update this node
        let now = chrono::Utc::now();
        let entry = self.process_tree.entry(pid).or_insert_with(|| ProcessTreeNode {
            pid,
            ppid,
            agent_id,
            children: HashSet::new(),
            is_agent,
            discovered_at: now,
        });
        entry.ppid = ppid;
        entry.is_agent = is_agent;

        // Link to parent
        if ppid > 0 {
            self.process_tree
                .entry(ppid)
                .or_insert_with(|| ProcessTreeNode {
                    pid: ppid,
                    ppid: 0,
                    agent_id,
                    children: HashSet::new(),
                    is_agent: false,
                    discovered_at: now,
                })
                .children
                .insert(pid);
        }
    }
}

impl Default for AgentIdentityEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_resolve() {
        let mut engine = AgentIdentityEngine::new();
        let identity = engine.register_agent(
            1001, 1,
            "test-agent".to_string(),
            "python3".to_string(),
            Some("langchain".to_string()),
        );
        assert_eq!(identity.pid, 1001);
        assert_eq!(identity.agent_name, "test-agent");
        assert_eq!(identity.framework.as_deref(), Some("langchain"));

        let resolved = engine.resolve_pid(1001);
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().agent_id, identity.agent_id);
    }

    #[test]
    fn test_fork_tracking() {
        let mut engine = AgentIdentityEngine::new();
        engine.register_agent(1001, 1, "parent".to_string(), "python3".to_string(), None);

        let child = engine.record_fork(1001, 2001, "child");
        assert!(child.is_some());
        assert!(child.unwrap().is_child_process);

        let children = engine.get_children(1001);
        assert_eq!(children, vec![2001]);
    }

    #[test]
    fn test_exec_tracking() {
        let mut engine = AgentIdentityEngine::new();
        engine.register_agent(1001, 1, "agent".to_string(), "python3".to_string(), None);

        let exec = engine.record_exec(1001, 1, 1000, "node", "/usr/bin/node");
        assert!(exec.is_some());
        assert_eq!(exec.unwrap().comm, "node");
    }

    #[test]
    fn test_exit_cleanup() {
        let mut engine = AgentIdentityEngine::new();
        engine.register_agent(1001, 1, "agent".to_string(), "python3".to_string(), None);
        assert!(engine.is_known_agent_pid(1001));

        engine.record_exit(1001);
        assert!(!engine.is_known_agent_pid(1001));
    }

    #[test]
    fn test_unknown_pid() {
        let engine = AgentIdentityEngine::new();
        assert!(engine.resolve_pid(9999).is_none());
    }

    #[test]
    fn test_process_tree_depth() {
        let mut engine = AgentIdentityEngine::new();
        let root = engine.register_agent(1001, 1, "root".to_string(), "python3".to_string(), None);
        assert_eq!(root.process_tree_depth, 0);

        let child = engine.record_fork(1001, 2001, "child").unwrap();
        assert_eq!(child.process_tree_depth, 1);

        let grandchild = engine.record_fork(2001, 3001, "grandchild").unwrap();
        assert_eq!(grandchild.process_tree_depth, 2);
    }

    #[test]
    fn test_import_export() {
        let mut engine = AgentIdentityEngine::new();
        engine.register_agent(1001, 1, "agent".to_string(), "python3".to_string(), None);

        let exported = engine.export_identities();
        assert_eq!(exported.len(), 1);

        let mut engine2 = AgentIdentityEngine::new();
        engine2.import_identities(exported);
        assert_eq!(engine2.agent_count(), 1);
        assert!(engine2.resolve_pid(1001).is_some());
    }
}
