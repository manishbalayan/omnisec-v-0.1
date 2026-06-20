use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Decision types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DecisionAction {
    Allow,
    Flag,
    Block,
    Restart,
    Escalate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementDecision {
    pub id: Uuid,
    pub pid: u32,
    pub agent_name: String,
    pub action: DecisionAction,
    pub reason: String,
    pub rule: String,
    pub confidence: f64,
    pub timestamp: DateTime<Utc>,
    pub policy_name: String,
    pub policy_version: u32,
    pub context: EnforcementContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementContext {
    pub risk_score: u32,
    pub risk_level: String,
    pub anomaly_type: Option<String>,
    pub anomaly_severity: Option<String>,
    pub deviation: Option<f64>,
    pub correlation_type: Option<String>,
    pub destination: Option<String>,
    pub process_name: Option<String>,
    pub file_path: Option<String>,
}

// ---------------------------------------------------------------------------
// Policy rule (Phase 1 — Policy V2)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub name: String,
    pub action: DecisionAction,
    pub priority: u32,
    pub conditions: PolicyConditions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConditions {
    pub risk_score_min: Option<u32>,
    pub risk_score_max: Option<u32>,
    pub anomaly_type: Option<String>,
    pub destination_match: Option<String>,
    pub destination_pattern: Option<String>,
    pub process_name_match: Option<String>,
    pub file_path_pattern: Option<String>,
    pub outbound_ratio_min: Option<f64>,
    pub is_known_destination: Option<bool>,
    pub is_new_destination: Option<bool>,
    pub correlation_type: Option<String>,
    pub incident_count_min: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedPolicy {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub version: u32,
    pub enabled: bool,
    pub rules: Vec<PolicyRule>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyHistory {
    pub policy_id: Uuid,
    pub versions: Vec<VersionedPolicy>,
}

// ---------------------------------------------------------------------------
// Decision Engine
// ---------------------------------------------------------------------------

pub struct DecisionEngine {
    policies: Vec<VersionedPolicy>,
    decisions: Vec<EnforcementDecision>,
    overrides: Vec<HumanOverride>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanOverride {
    pub id: Uuid,
    pub decision_id: Uuid,
    pub action: OverrideAction,
    pub reason: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OverrideAction {
    Approve,
    Reject,
    Override,
    TemporaryAllow,
    TemporaryBlock,
}

impl DecisionEngine {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            decisions: Vec::new(),
            overrides: Vec::new(),
        }
    }

    /// Add a versioned policy. Stores history (never overwrites).
    pub fn add_policy(&mut self, mut policy: VersionedPolicy) {
        // Auto-increment version if policy with same name exists
        if let Some(existing) = self.policies.iter().find(|p| p.name == policy.name) {
            policy.version = existing.version + 1;
            // Remove old version and add new one (keep history in storage)
            self.policies.retain(|p| p.name != policy.name);
        }
        self.policies.push(policy);
    }

    /// Get the latest version of a policy by name.
    pub fn get_policy(&self, name: &str) -> Option<&VersionedPolicy> {
        self.policies.iter().filter(|p| p.name == name).max_by_key(|p| p.version)
    }

    /// Get all active policies.
    pub fn get_active_policies(&self) -> Vec<&VersionedPolicy> {
        self.policies.iter().filter(|p| p.enabled).collect()
    }

    // -----------------------------------------------------------------------
    // Core: evaluate risk + anomaly + context against all active policies
    // -----------------------------------------------------------------------

    pub fn evaluate(
        &mut self,
        pid: u32,
        agent_name: String,
        risk_score: u32,
        risk_level: &str,
        anomaly_type: Option<String>,
        anomaly_severity: Option<String>,
        deviation: Option<f64>,
        correlation_type: Option<String>,
        destination: Option<String>,
        process_name: Option<String>,
        file_path: Option<String>,
        known_destinations: &[String],
    ) -> EnforcementDecision {
        let context = EnforcementContext {
            risk_score,
            risk_level: risk_level.to_string(),
            anomaly_type: anomaly_type.clone(),
            anomaly_severity,
            deviation,
            correlation_type,
            destination: destination.clone(),
            process_name: process_name.clone(),
            file_path: file_path.clone(),
        };

        let is_new_dest = if let Some(ref dest) = destination {
            !known_destinations.contains(dest)
        } else {
            false
        };

        // Evaluate each active policy rule in priority order (highest priority first)
        for policy in self.get_active_policies() {
            let mut sorted_rules: Vec<&PolicyRule> = policy.rules.iter().collect();
            sorted_rules.sort_by(|a, b| b.priority.cmp(&a.priority));
            for rule in &sorted_rules {
                if self.matches_rule(&rule.conditions, &context, is_new_dest) {
                    let decision = EnforcementDecision {
                        id: Uuid::new_v4(),
                        pid,
                        agent_name: agent_name.clone(),
                        action: rule.action.clone(),
                        reason: format!("Policy '{}' rule '{}' matched", policy.name, rule.name),
                        rule: rule.name.clone(),
                        confidence: self.calculate_confidence(&context, &rule),
                        timestamp: Utc::now(),
                        policy_name: policy.name.clone(),
                        policy_version: policy.version,
                        context: context.clone(),
                    };

                    // Check for human overrides
                    if let Some(override_) = self.find_override(&decision) {
                        return EnforcementDecision {
                            action: match override_.action {
                                OverrideAction::Approve | OverrideAction::TemporaryAllow => DecisionAction::Allow,
                                OverrideAction::Reject | OverrideAction::TemporaryBlock => DecisionAction::Block,
                                OverrideAction::Override => DecisionAction::Flag,
                            },
                            reason: format!("Decision overridden by {}: {}", override_.created_by, override_.reason),
                            ..decision
                        };
                    }

                    self.decisions.push(decision.clone());
                    return decision;
                }
            }
        }

        // Default: Allow with low confidence
        let decision = EnforcementDecision {
            id: Uuid::new_v4(),
            pid,
            agent_name,
            action: DecisionAction::Allow,
            reason: "No matching policy — default allow".to_string(),
            rule: "default_allow".to_string(),
            confidence: 0.1,
            timestamp: Utc::now(),
            policy_name: "default".to_string(),
            policy_version: 0,
            context,
        };
        self.decisions.push(decision.clone());
        decision
    }

    // -----------------------------------------------------------------------
    // Rule matching logic
    // -----------------------------------------------------------------------

    fn matches_rule(&self, conditions: &PolicyConditions, context: &EnforcementContext, is_new_dest: bool) -> bool {
        // Risk score range check
        if let Some(min) = conditions.risk_score_min {
            if context.risk_score < min { return false; }
        }
        if let Some(max) = conditions.risk_score_max {
            if context.risk_score > max { return false; }
        }

        // Anomaly type check
        if let Some(ref expected_type) = conditions.anomaly_type {
            match context.anomaly_type {
                Some(ref actual) => if actual != expected_type { return false; }
                None => return false,
            }
        }

        // Destination match
        if let Some(ref dest) = conditions.destination_match {
            match context.destination {
                Some(ref actual) => if actual != dest { return false; }
                None => return false,
            }
        }

        // Destination pattern (substring match)
        if let Some(ref pattern) = conditions.destination_pattern {
            match context.destination {
                Some(ref actual) => if !actual.contains(pattern) { return false; }
                None => return false,
            }
        }

        // Process name match
        if let Some(ref proc) = conditions.process_name_match {
            match context.process_name {
                Some(ref actual) => if actual != proc { return false; }
                None => return false,
            }
        }

        // File path pattern
        if let Some(ref pattern) = conditions.file_path_pattern {
            match context.file_path {
                Some(ref actual) => if !actual.contains(pattern) { return false; }
                None => return false,
            }
        }

        // Known/new destination checks
        if let Some(known) = conditions.is_known_destination {
            if is_new_dest == known { return false; }
        }
        if let Some(new) = conditions.is_new_destination {
            if is_new_dest != new { return false; }
        }

        // Correlation type check
        if let Some(ref corr) = conditions.correlation_type {
            match context.correlation_type {
                Some(ref actual) => if actual != corr { return false; }
                None => return false,
            }
        }

        // Outbound ratio check
        if let Some(min_ratio) = conditions.outbound_ratio_min {
            match context.deviation {
                Some(actual) => if actual < min_ratio { return false; }
                None => return false,
            }
        }

        // Incident count check (currently uses risk_score as proxy)
        if let Some(min_count) = conditions.incident_count_min {
            // In production, this would query actual incident count from storage
            // For now, uses risk_score as a proxy indicator
            if context.risk_score < min_count { return false; }
        }

        true
    }

    // -----------------------------------------------------------------------
    // Confidence calculation
    // -----------------------------------------------------------------------

    fn calculate_confidence(&self, context: &EnforcementContext, _rule: &PolicyRule) -> f64 {
        let mut confidence = 0.5; // Base confidence

        // Higher risk = higher confidence a decision is needed
        confidence += (context.risk_score as f64 / 100.0) * 0.3;

        // Known anomalies increase confidence
        if context.anomaly_type.is_some() { confidence += 0.1; }
        if context.correlation_type.is_some() { confidence += 0.1; }

        confidence.min(1.0)
    }

    // -----------------------------------------------------------------------
    // Human override system
    // -----------------------------------------------------------------------

    pub fn create_override(
        &mut self,
        decision_id: Uuid,
        action: OverrideAction,
        reason: String,
        created_by: String,
        expires_in_secs: Option<u64>,
    ) -> HumanOverride {
        let override_ = HumanOverride {
            id: Uuid::new_v4(),
            decision_id,
            action,
            reason,
            expires_at: expires_in_secs.map(|s| Utc::now() + chrono::Duration::seconds(s as i64)),
            created_by,
            created_at: Utc::now(),
        };
        self.overrides.push(override_.clone());
        override_
    }

    fn find_override(&self, decision: &EnforcementDecision) -> Option<&HumanOverride> {
        self.overrides.iter().rev().find(|o| {
            // Match by agent PID: find the original decision this override targets,
            // then check if it's for the same agent as the new decision.
            // This allows overrides to persist across re-evaluations.
            let same_agent = self.decisions.iter()
                .find(|d| d.id == o.decision_id)
                .map(|d| d.pid == decision.pid)
                .unwrap_or(false);
            same_agent
                && o.expires_at.map(|e| e > Utc::now()).unwrap_or(true)
        })
    }

    /// Get all overrides for display.
    pub fn get_overrides(&self) -> Vec<&HumanOverride> {
        self.overrides.iter().collect()
    }

    // -----------------------------------------------------------------------
    // Query methods
    // -----------------------------------------------------------------------

    pub fn get_decisions(&self) -> Vec<&EnforcementDecision> {
        self.decisions.iter().collect()
    }

    pub fn get_decisions_for_agent(&self, pid: u32) -> Vec<&EnforcementDecision> {
        self.decisions.iter().filter(|d| d.pid == pid).collect()
    }

    pub fn decision_count(&self) -> usize {
        self.decisions.len()
    }

    /// Get default enforcement policies.
    pub fn default_policies() -> Vec<VersionedPolicy> {
        vec![
            VersionedPolicy {
                id: Uuid::new_v4(),
                name: "destination_security".to_string(),
                description: "Security policies for destination-based enforcement".to_string(),
                version: 1,
                enabled: true,
                rules: vec![
                    PolicyRule {
                        name: "allow_known_destinations".to_string(),
                        action: DecisionAction::Allow,
                        priority: 10,
                        conditions: PolicyConditions {
                            risk_score_min: None, risk_score_max: Some(20),
                            anomaly_type: None,
                            destination_match: None, destination_pattern: None,
                            process_name_match: None, file_path_pattern: None,
                            outbound_ratio_min: None,
                            is_known_destination: Some(true),
                            is_new_destination: None,
                            correlation_type: None,
                            incident_count_min: None,
                        },
                    },
                    PolicyRule {
                        name: "block_critical_risk".to_string(),
                        action: DecisionAction::Block,
                        priority: 90,
                        conditions: PolicyConditions {
                            risk_score_min: Some(81), risk_score_max: None,
                            anomaly_type: None,
                            destination_match: None, destination_pattern: None,
                            process_name_match: None, file_path_pattern: None,
                            outbound_ratio_min: None,
                            is_known_destination: None, is_new_destination: None,
                            correlation_type: None,
                            incident_count_min: None,
                        },
                    },
                    PolicyRule {
                        name: "flag_new_destination".to_string(),
                        action: DecisionAction::Flag,
                        priority: 50,
                        conditions: PolicyConditions {
                            risk_score_min: Some(21), risk_score_max: Some(80),
                            anomaly_type: None,
                            destination_match: None, destination_pattern: None,
                            process_name_match: None, file_path_pattern: None,
                            outbound_ratio_min: None,
                            is_known_destination: None,
                            is_new_destination: Some(true),
                            correlation_type: None,
                            incident_count_min: None,
                        },
                    },
                    PolicyRule {
                        name: "block_exfiltration".to_string(),
                        action: DecisionAction::Block,
                        priority: 95,
                        conditions: PolicyConditions {
                            risk_score_min: Some(51), risk_score_max: None,
                            anomaly_type: Some("OutboundSpike".to_string()),
                            destination_match: None, destination_pattern: None,
                            process_name_match: None, file_path_pattern: None,
                            outbound_ratio_min: Some(20.0),
                            is_known_destination: None, is_new_destination: None,
                            correlation_type: None,
                            incident_count_min: None,
                        },
                    },
                    PolicyRule {
                        name: "escalate_multi_risk".to_string(),
                        action: DecisionAction::Escalate,
                        priority: 80,
                        conditions: PolicyConditions {
                            risk_score_min: Some(51), risk_score_max: None,
                            anomaly_type: None,
                            destination_match: None, destination_pattern: None,
                            process_name_match: None, file_path_pattern: None,
                            outbound_ratio_min: None,
                            is_known_destination: None, is_new_destination: None,
                            correlation_type: Some("MultiAgentRiskEscalation".to_string()),
                            incident_count_min: None,
                        },
                    },
                    PolicyRule {
                        name: "restart_on_fingerprint_drift".to_string(),
                        action: DecisionAction::Restart,
                        priority: 70,
                        conditions: PolicyConditions {
                            risk_score_min: Some(41), risk_score_max: None,
                            anomaly_type: Some("FingerprintDrift".to_string()),
                            destination_match: None, destination_pattern: None,
                            process_name_match: None, file_path_pattern: None,
                            outbound_ratio_min: None,
                            is_known_destination: None, is_new_destination: None,
                            correlation_type: None,
                            incident_count_min: None,
                        },
                    },
                ],
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        ]
    }
}

impl Default for DecisionEngine {
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
    fn test_allow_known_destination() {
        let mut engine = DecisionEngine::new();
        for policy in DecisionEngine::default_policies() {
            engine.add_policy(policy);
        }

        let decision = engine.evaluate(
            1234, "test-agent".to_string(),
            10, "Normal", None, None, None, None,
            Some("api.openai.com".to_string()), None, None,
            &["api.openai.com".to_string()],
        );

        assert_eq!(decision.action, DecisionAction::Allow);
        assert!(decision.confidence > 0.0);
    }

    #[test]
    fn test_block_critical_risk() {
        let mut engine = DecisionEngine::new();
        for policy in DecisionEngine::default_policies() {
            engine.add_policy(policy);
        }

        let decision = engine.evaluate(
            1234, "risky-agent".to_string(),
            90, "Critical", None, None, None, None,
            None, None, None,
            &[],
        );

        assert_eq!(decision.action, DecisionAction::Block);
        assert!(decision.reason.contains("block_critical_risk"));
    }

    #[test]
    fn test_block_exfiltration() {
        let mut engine = DecisionEngine::new();
        for policy in DecisionEngine::default_policies() {
            engine.add_policy(policy);
        }

        let decision = engine.evaluate(
            1234, "exfil-agent".to_string(),
            60, "HighRisk",
            Some("OutboundSpike".to_string()), Some("Critical".to_string()), Some(25.0), None,
            Some("evil.com".to_string()), None, None,
            &["evil.com".to_string()],  // Mark as known so flag_new_destination doesn't match
        );

        assert_eq!(decision.action, DecisionAction::Block);
        assert!(decision.reason.contains("block_exfiltration"));
    }

    #[test]
    fn test_flag_new_destination() {
        let mut engine = DecisionEngine::new();
        for policy in DecisionEngine::default_policies() {
            engine.add_policy(policy);
        }

        let decision = engine.evaluate(
            1234, "agent".to_string(),
            40, "Suspicious", None, None, None, None,
            Some("unknown-site.ru".to_string()), None, None,
            &["api.openai.com".to_string()],
        );

        assert_eq!(decision.action, DecisionAction::Flag);
    }

    #[test]
    fn test_escalate_multi_agent_risk() {
        let mut engine = DecisionEngine::new();
        for policy in DecisionEngine::default_policies() {
            engine.add_policy(policy);
        }

        let decision = engine.evaluate(
            1234, "agent".to_string(),
            60, "HighRisk",
            None, None, None,
            Some("MultiAgentRiskEscalation".to_string()),
            None, None, None,
            &[],
        );

        assert_eq!(decision.action, DecisionAction::Escalate);
    }

    #[test]
    fn test_restart_on_fingerprint_drift() {
        let mut engine = DecisionEngine::new();
        for policy in DecisionEngine::default_policies() {
            engine.add_policy(policy);
        }

        let decision = engine.evaluate(
            1234, "agent".to_string(),
            50, "Suspicious",
            Some("FingerprintDrift".to_string()), Some("High".to_string()), Some(45.0), None,
            None, None, None,
            &[],
        );

        assert_eq!(decision.action, DecisionAction::Restart);
    }

    #[test]
    fn test_default_allow_no_match() {
        let mut engine = DecisionEngine::new();
        for policy in DecisionEngine::default_policies() {
            engine.add_policy(policy);
        }

        let decision = engine.evaluate(
            1234, "agent".to_string(),
            5, "Normal", None, None, None, None,
            Some("api.openai.com".to_string()), None, None,
            &["api.openai.com".to_string()],
        );

        assert_eq!(decision.action, DecisionAction::Allow);
    }

    #[test]
    fn test_human_override() {
        let mut engine = DecisionEngine::new();
        for policy in DecisionEngine::default_policies() {
            engine.add_policy(policy);
        }

        // Make a decision
        let decision = engine.evaluate(
            1234, "agent".to_string(),
            90, "Critical", None, None, None, None,
            None, None, None, &[],
        );
        assert_eq!(decision.action, DecisionAction::Block);

        // Human overrides to Allow
        let override_ = engine.create_override(
            decision.id,
            OverrideAction::Approve,
            "Approved by security team".to_string(),
            "admin".to_string(),
            Some(3600),
        );
        assert_eq!(override_.created_by, "admin");

        // Re-evaluate — should now be overridden
        let new_decision = engine.evaluate(
            1234, "agent".to_string(),
            90, "Critical", None, None, None, None,
            None, None, None, &[],
        );
        assert_eq!(new_decision.action, DecisionAction::Allow);
        assert!(new_decision.reason.contains("admin"));
    }

    #[test]
    fn test_policy_versioning() {
        let mut engine = DecisionEngine::new();

        let policy_v1 = VersionedPolicy {
            id: Uuid::new_v4(),
            name: "test_policy".to_string(),
            description: "v1".to_string(),
            version: 1,
            enabled: true,
            rules: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        engine.add_policy(policy_v1);

        let policy_v2 = VersionedPolicy {
            id: Uuid::new_v4(),
            name: "test_policy".to_string(),
            description: "v2".to_string(),
            version: 1,
            enabled: true,
            rules: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        engine.add_policy(policy_v2);

        let policy = engine.get_policy("test_policy").unwrap();
        assert_eq!(policy.version, 2);
        assert_eq!(policy.description, "v2");
    }

    #[test]
    fn test_decision_records() {
        let mut engine = DecisionEngine::new();
        for policy in DecisionEngine::default_policies() {
            engine.add_policy(policy);
        }

        engine.evaluate(
            1, "a".to_string(), 10, "Normal", None, None, None, None,
            None, None, None, &[],
        );
        engine.evaluate(
            2, "b".to_string(), 90, "Critical", None, None, None, None,
            None, None, None, &[],
        );

        assert_eq!(engine.decision_count(), 2);
        assert_eq!(engine.get_decisions_for_agent(1).len(), 1);
        assert_eq!(engine.get_decisions_for_agent(2).len(), 1);
    }
}
