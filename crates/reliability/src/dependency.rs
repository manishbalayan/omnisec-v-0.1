use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DependencyType {
    Postgres,
    Redis,
    Nats,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DependencyStatus {
    Healthy,
    Degraded,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyHealth {
    pub name: String,
    pub dependency_type: DependencyType,
    pub status: DependencyStatus,
    pub last_check: DateTime<Utc>,
    pub latency_ms: Option<f64>,
    pub error: Option<String>,
    pub consecutive_failures: u32,
    pub uptime_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyHealthCheck {
    pub name: String,
    pub dependency_type: DependencyType,
    pub check_interval_secs: u64,
    pub timeout_secs: u64,
    pub failure_threshold: u32,
}

pub struct DependencyHealthMonitor {
    dependencies: HashMap<String, DependencyHealth>,
    checks: Vec<DependencyHealthCheck>,
    total_checks: HashMap<String, u64>,
    successful_checks: HashMap<String, u64>,
}

impl DependencyHealthMonitor {
    pub fn new() -> Self {
        Self {
            dependencies: HashMap::new(),
            checks: Vec::new(),
            total_checks: HashMap::new(),
            successful_checks: HashMap::new(),
        }
    }

    pub fn register_dependency(&mut self, check: DependencyHealthCheck) {
        let health = DependencyHealth {
            name: check.name.clone(),
            dependency_type: check.dependency_type.clone(),
            status: DependencyStatus::Unknown,
            last_check: Utc::now(),
            latency_ms: None,
            error: None,
            consecutive_failures: 0,
            uptime_percent: 100.0,
        };
        self.dependencies.insert(check.name.clone(), health);
        self.checks.push(check);
    }

    pub fn record_check_result(
        &mut self,
        name: &str,
        success: bool,
        latency_ms: Option<f64>,
        error: Option<String>,
    ) {
        let total = self.total_checks.entry(name.to_string()).or_insert(0);
        *total += 1;

        if success {
            let successful = self.successful_checks.entry(name.to_string()).or_insert(0);
            *successful += 1;
        }

        if let Some(health) = self.dependencies.get_mut(name) {
            health.last_check = Utc::now();
            health.latency_ms = latency_ms;
            health.error = error;

            if success {
                health.consecutive_failures = 0;
                health.status = DependencyStatus::Healthy;
            } else {
                health.consecutive_failures += 1;
                let check = self.checks.iter().find(|c| c.name == name);
                let threshold = check.map(|c| c.failure_threshold).unwrap_or(3);

                if health.consecutive_failures >= threshold {
                    health.status = DependencyStatus::Failed;
                } else if health.consecutive_failures > 0 {
                    health.status = DependencyStatus::Degraded;
                }
            }

            let total_checks = *self.total_checks.get(name).unwrap_or(&0);
            let successful = *self.successful_checks.get(name).unwrap_or(&0);
            health.uptime_percent = if total_checks > 0 {
                (successful as f64 / total_checks as f64) * 100.0
            } else {
                100.0
            };
        }
    }

    pub fn get_dependency_health(&self, name: &str) -> Option<&DependencyHealth> {
        self.dependencies.get(name)
    }

    pub fn get_all_health(&self) -> Vec<&DependencyHealth> {
        self.dependencies.values().collect()
    }

    pub fn get_system_status(&self) -> SystemStatus {
        let deps: Vec<&DependencyHealth> = self.dependencies.values().collect();

        if deps.is_empty() {
            return SystemStatus::Unknown;
        }

        let failed = deps.iter().any(|d| d.status == DependencyStatus::Failed);
        let degraded = deps.iter().any(|d| d.status == DependencyStatus::Degraded);

        if failed {
            SystemStatus::Degraded
        } else if degraded {
            SystemStatus::Degraded
        } else {
            SystemStatus::Healthy
        }
    }

    pub fn get_degraded_dependencies(&self) -> Vec<&DependencyHealth> {
        self.dependencies
            .values()
            .filter(|d| d.status != DependencyStatus::Healthy && d.status != DependencyStatus::Unknown)
            .collect()
    }

    pub fn get_overall_uptime(&self) -> f64 {
        if self.dependencies.is_empty() {
            return 100.0;
        }

        let total_uptime: f64 = self.dependencies.values().map(|d| d.uptime_percent).sum();
        total_uptime / self.dependencies.len() as f64
    }
}

impl Default for DependencyHealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SystemStatus {
    Healthy,
    Degraded,
    Failed,
    Unknown,
}
