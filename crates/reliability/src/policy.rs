use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub agent: AgentPolicies,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPolicies {
    pub crash: PolicyAction,
    pub hang: PolicyAction,
    pub memory_leak: PolicyAction,
    pub cpu_runaway: PolicyAction,
    pub fd_exhaustion: PolicyAction,
    pub thread_explosion: PolicyAction,
    pub dependency_failure: PolicyAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAction {
    pub action: ActionType,
    pub max_retries: Option<u32>,
    pub alert_channels: Option<Vec<String>>,
    pub escalate_after: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ActionType {
    Alert,
    Restart,
    SystemdRestart,
    ContainerRestart,
    Escalate,
    Ignore,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            agent: AgentPolicies {
                crash: PolicyAction {
                    action: ActionType::Restart,
                    max_retries: Some(3),
                    alert_channels: Some(vec!["telegram".to_string()]),
                    escalate_after: Some(5),
                },
                hang: PolicyAction {
                    action: ActionType::Restart,
                    max_retries: Some(2),
                    alert_channels: Some(vec!["telegram".to_string()]),
                    escalate_after: Some(3),
                },
                memory_leak: PolicyAction {
                    action: ActionType::Alert,
                    max_retries: None,
                    alert_channels: Some(vec!["telegram".to_string()]),
                    escalate_after: None,
                },
                cpu_runaway: PolicyAction {
                    action: ActionType::Restart,
                    max_retries: Some(2),
                    alert_channels: Some(vec!["telegram".to_string()]),
                    escalate_after: Some(3),
                },
                fd_exhaustion: PolicyAction {
                    action: ActionType::Alert,
                    max_retries: None,
                    alert_channels: Some(vec!["telegram".to_string()]),
                    escalate_after: None,
                },
                thread_explosion: PolicyAction {
                    action: ActionType::Restart,
                    max_retries: Some(2),
                    alert_channels: Some(vec!["telegram".to_string()]),
                    escalate_after: Some(3),
                },
                dependency_failure: PolicyAction {
                    action: ActionType::Escalate,
                    max_retries: None,
                    alert_channels: Some(vec!["telegram".to_string(), "email".to_string()]),
                    escalate_after: Some(1),
                },
            },
        }
    }
}

pub struct PolicyEngine {
    config: PolicyConfig,
    custom_policies: HashMap<String, PolicyAction>,
}

impl PolicyEngine {
    pub fn new(config: PolicyConfig) -> Self {
        Self {
            config,
            custom_policies: HashMap::new(),
        }
    }

    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        let config: PolicyConfig = serde_yaml::from_str(yaml)?;
        Ok(Self::new(config))
    }

    pub fn with_defaults() -> Self {
        Self::new(PolicyConfig::default())
    }

    pub fn get_action(&self, event_type: &str) -> &PolicyAction {
        match event_type {
            "crash" => &self.config.agent.crash,
            "hang" => &self.config.agent.hang,
            "memory_leak" => &self.config.agent.memory_leak,
            "cpu_runaway" => &self.config.agent.cpu_runaway,
            "fd_exhaustion" => &self.config.agent.fd_exhaustion,
            "thread_explosion" => &self.config.agent.thread_explosion,
            "dependency_failure" => &self.config.agent.dependency_failure,
            _ => self.custom_policies.get(event_type).unwrap_or(&self.config.agent.crash),
        }
    }

    pub fn set_custom_policy(&mut self, event_type: String, action: PolicyAction) {
        self.custom_policies.insert(event_type, action);
    }

    pub fn should_restart(&self, event_type: &str) -> bool {
        let action = self.get_action(event_type);
        matches!(
            action.action,
            ActionType::Restart | ActionType::SystemdRestart | ActionType::ContainerRestart
        )
    }

    pub fn should_alert(&self, event_type: &str) -> bool {
        let action = self.get_action(event_type);
        matches!(action.action, ActionType::Alert | ActionType::Escalate)
            || action.alert_channels.is_some()
    }

    pub fn should_escalate(&self, event_type: &str, failure_count: u32) -> bool {
        let action = self.get_action(event_type);
        if let Some(escalate_after) = action.escalate_after {
            failure_count >= escalate_after
        } else {
            false
        }
    }

    pub fn get_max_retries(&self, event_type: &str) -> u32 {
        let action = self.get_action(event_type);
        action.max_retries.unwrap_or(0)
    }

    pub fn get_alert_channels(&self, event_type: &str) -> Vec<String> {
        let action = self.get_action(event_type);
        action.alert_channels.clone().unwrap_or_default()
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::with_defaults()
    }
}
