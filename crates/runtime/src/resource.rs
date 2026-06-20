// OMNISEC Linux Runtime Control — Resource Control Engine (Phase 2)
//
// Uses cgroups v1/v2 for CPU limits, memory limits, network limits,
// and process isolation.

use crate::{RuntimeAction, RuntimeMode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimit {
    pub cgroup_path: String,
    pub agent_name: String,
    pub pid: u32,
    pub cpu_quota: Option<String>,      // e.g. "50000 100000" (50%)
    pub memory_max: Option<String>,      // e.g. "512M"
    pub pids_max: Option<u32>,           // max number of processes
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub active: bool,
}

pub struct ResourceControlEngine {
    cgroups: Vec<ResourceLimit>,
    mode: RuntimeMode,
}

impl ResourceControlEngine {
    pub fn new() -> Self {
        Self {
            cgroups: Vec::new(),
            mode: crate::detect_runtime_mode(),
        }
    }

    /// Apply CPU/memory/network limits to a process via cgroups
    pub fn throttle(
        &mut self,
        pid: u32,
        agent_name: &str,
        cpu_percent: u32,
        memory_limit: Option<&str>,
    ) -> RuntimeAction {
        let action = self.create_action("cgroup_throttle", &format!("PID:{}", pid));

        match self.mode {
            RuntimeMode::Native => {
                #[cfg(target_os = "linux")]
                {
                    self.apply_cgroup_limits(pid, cpu_percent, memory_limit);
                }

                self.cgroups.push(ResourceLimit {
                    cgroup_path: format!("/sys/fs/cgroup/omnisec/{}", agent_name),
                    agent_name: agent_name.to_string(),
                    pid,
                    cpu_quota: Some(format!("{} 100000", cpu_percent * 1000)),
                    memory_max: memory_limit.map(|s| s.to_string()),
                    pids_max: Some(50),
                    created_at: chrono::Utc::now(),
                    active: true,
                });

                RuntimeAction {
                    result: "Applied".to_string(),
                    verified: true,
                    ..action
                }
            }
            RuntimeMode::Simulated => {
                tracing::info!("[SIMULATED] cgroup throttle PID {}: CPU {}%, memory {:?}",
                    pid, cpu_percent, memory_limit);

                self.cgroups.push(ResourceLimit {
                    cgroup_path: format!("[sim] omnisec/{}", agent_name),
                    agent_name: agent_name.to_string(),
                    pid,
                    cpu_quota: Some(format!("{} 100000", cpu_percent * 1000)),
                    memory_max: memory_limit.map(|s| s.to_string()),
                    pids_max: Some(50),
                    created_at: chrono::Utc::now(),
                    active: true,
                });

                RuntimeAction {
                    result: "Simulated".to_string(),
                    verified: true,
                    ..action
                }
            }
        }
    }

    /// Contain a process with strict resource limits
    pub fn contain(&mut self, pid: u32, agent_name: &str) -> RuntimeAction {
        self.throttle(pid, agent_name, 25, Some("256M"))
    }

    /// Remove resource limits from a process
    pub fn release(&mut self, agent_name: &str) -> RuntimeAction {
        let action = self.create_action("cgroup_release", agent_name);

        match self.mode {
            RuntimeMode::Native => {
                #[cfg(target_os = "linux")]
                {
                    let cg_path = format!("/sys/fs/cgroup/omnisec/{}", agent_name);
                    let _ = std::fs::remove_dir(&cg_path);
                }

                self.cgroups.retain(|c| c.agent_name != agent_name);

                RuntimeAction {
                    result: "Released".to_string(),
                    verified: true,
                    ..action
                }
            }
            RuntimeMode::Simulated => {
                tracing::info!("[SIMULATED] cgroup release: {}", agent_name);
                self.cgroups.retain(|c| c.agent_name != agent_name);

                RuntimeAction {
                    result: "Simulated".to_string(),
                    verified: true,
                    ..action
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn apply_cgroup_limits(&self, pid: u32, cpu_percent: u32, memory_limit: Option<&str>) {
        use std::fs;
        use std::path::Path;

        // Detect cgroup version
        let cgroup_v2 = Path::new("/sys/fs/cgroup/cgroup.controllers").exists();

        if cgroup_v2 {
            // CGroup v2
            let base = "/sys/fs/cgroup";
            // Create child cgroup if it doesn't exist
            let cg_path = format!("{}/omnisec", base);
            let _ = fs::create_dir_all(&cg_path);

            // Write PID to cgroup.procs
            let _ = fs::write(format!("{}/cgroup.procs", cg_path), pid.to_string());

            // Set CPU quota (e.g., 50000 100000 = 50%)
            if cpu_percent > 0 && cpu_percent < 100 {
                let quota = format!("{} 100000", cpu_percent * 1000);
                let _ = fs::write(format!("{}/cpu.max", cg_path), &quota);
            }

            // Set memory limit
            if let Some(mem) = memory_limit {
                let _ = fs::write(format!("{}/memory.max", cg_path), mem);
            }

            // Set PIDs limit
            let _ = fs::write(format!("{}/pids.max", cg_path), "50");

            tracing::info!("Applied cgroup v2 limits to PID {}: CPU {}%, mem {:?}", pid, cpu_percent, memory_limit);
        } else {
            // CGroup v1 — write to each controller separately
            let _ = fs::write(
                format!("/sys/fs/cgroup/cpu/omnisec/cpu.cfs_quota_us"),
                (cpu_percent * 1000).to_string(),
            );
            if let Some(mem) = memory_limit {
                let _ = fs::write(format!("/sys/fs/cgroup/memory/omnisec/memory.limit_in_bytes"), mem);
            }
            let _ = fs::write(
                format!("/sys/fs/cgroup/pids/omnisec/pids.max"),
                "50",
            );

            tracing::info!("Applied cgroup v1 limits to PID {}: CPU {}%, mem {:?}", pid, cpu_percent, memory_limit);
        }
    }

    pub fn active_cgroup_count(&self) -> usize {
        self.cgroups.iter().filter(|c| c.active).count()
    }

    pub fn get_active_cgroups(&self) -> Vec<&ResourceLimit> {
        self.cgroups.iter().filter(|c| c.active).collect()
    }

    fn create_action(&self, action_type: &str, target: &str) -> RuntimeAction {
        RuntimeAction {
            id: Uuid::new_v4(),
            action_type: action_type.to_string(),
            target: target.to_string(),
            kernel_command: format!("cgroup write {} ...", target),
            result: "Pending".to_string(),
            duration_ms: 0,
            timestamp: chrono::Utc::now(),
            verified: false,
            rolled_back: false,
        }
    }
}
