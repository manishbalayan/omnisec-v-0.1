// OMNISEC Runtime Enforcement Layer — Chaos Tests (Phase 10)
//
// Scenarios:
//   1. Unknown Destination → FLAG
//   2. Known Malicious Destination → BLOCK
//   3. Exfiltration Attempt → BLOCK + Incident
//   4. Unexpected Process → FLAG
//   5. Sensitive File Access → FLAG
//   6. Risk Escalation → ESCALATE
//   7. Fingerprint Drift → RESTART
//   8. Human Override → Overrides Decision
//   9. Decision Audit Trail → All decisions recorded
//  10. Enforcement Persistence → Incidents survive enforcement cycles

use omnisec_decision::{DecisionAction, DecisionEngine, OverrideAction};
use omnisec_enforcement::{EnforcementManager, EnforcementResult, FileAccessEnforcementEngine, ProcessEnforcementEngine};

// =====================================================================
// Scenario 1: Unknown Destination → FLAG
// =====================================================================

#[test]
fn chaos_unknown_destination_flagged() {
    let mut decision_engine = DecisionEngine::new();
    for policy in DecisionEngine::default_policies() {
        decision_engine.add_policy(policy);
    }

    let known = vec!["api.openai.com".to_string(), "api.anthropic.com".to_string()];

    let decision = decision_engine.evaluate(
        1001, "agent-a".to_string(),
        40, "Suspicious", None, None, None, None,
        Some("unknown-site.ru".to_string()), None, None, &known,
    );

    assert_eq!(decision.action, DecisionAction::Flag,
        "Unknown destination should be FLAGGED by new_destination policy");
    assert!(decision.confidence > 0.0, "Decision must have confidence");
}

// =====================================================================
// Scenario 2: Known Malicious Destination → BLOCK
// =====================================================================

#[test]
fn chaos_malicious_destination_blocked() {
    let mut decision_engine = DecisionEngine::new();
    for policy in DecisionEngine::default_policies() {
        decision_engine.add_policy(policy);
    }

    // Critical risk score triggers block
    let decision = decision_engine.evaluate(
        1002, "agent-b".to_string(),
        90, "Critical", None, None, None, None,
        Some("evil.c2.com".to_string()), None, None, &[],
    );

    assert_eq!(decision.action, DecisionAction::Block,
        "Critical risk destination should be BLOCKED");
    assert!(decision.reason.contains("block_critical_risk"),
        "Reason must reference blocking rule");

    // Verify enforcement blocks it
    let mut enforcement = EnforcementManager::new();
    let action = enforcement.execute(&decision);
    assert_eq!(action.result, EnforcementResult::Applied,
        "Block action must be applied");
    assert!(enforcement.network.is_blocked("evil.c2.com"),
        "Enforcement engine must track blocked destinations");
}

// =====================================================================
// Scenario 3: Exfiltration Attempt → BLOCK + Incident
// =====================================================================

#[test]
fn chaos_exfiltration_attempt_blocked() {
    let mut decision_engine = DecisionEngine::new();
    for policy in DecisionEngine::default_policies() {
        decision_engine.add_policy(policy);
    }

    // Outbound spike with high ratio → block_exfiltration rule
    let decision = decision_engine.evaluate(
        1003, "exfil-agent".to_string(),
        60, "HighRisk",
        Some("OutboundSpike".to_string()), Some("Critical".to_string()), Some(25.0), None,
        Some("data-exfil.com".to_string()), None, None,
        &["data-exfil.com".to_string()],  // Known dest so flag_new_destination doesn't preempt
    );

    assert_eq!(decision.action, DecisionAction::Block,
        "Exfiltration attempt should be BLOCKED");

    // Execute enforcement and verify incident created
    let mut enforcement = EnforcementManager::new();
    enforcement.execute(&decision);

    assert_eq!(enforcement.incident_count(), 1,
        "Block action must create enforcement incident");
    assert_eq!(enforcement.get_open_incidents().len(), 1,
        "Incident must be in Open state");
    assert!(enforcement.network.is_blocked("data-exfil.com"),
        "Exfiltration destination must be blocked");
}

// =====================================================================
// Scenario 4: Unexpected Process → FLAG/BLOCK
// =====================================================================

#[test]
fn chaos_unexpected_process_handled() {
    let mut process_engine = ProcessEnforcementEngine::new();

    // Known executables should pass
    assert!(process_engine.check_executable(2001, "agent", "python").is_none(),
        "Known executable should not trigger enforcement");
    assert!(process_engine.check_executable(2002, "agent", "node").is_none(),
        "Known executable should not trigger enforcement");

    // Unknown executable → FLAG
    let result = process_engine.check_executable(2003, "agent", "random_binary");
    assert!(result.is_some(), "Unknown executable must be flagged");
    assert_eq!(result.unwrap(), "FLAG", "Unknown executable should be FLAGGED");

    // Blocked executable → BLOCK
    let result = process_engine.check_executable(2004, "agent", "nmap");
    assert!(result.is_some(), "Blocked executable must be detected");
    assert_eq!(result.unwrap(), "BLOCK", "Blocked executable should result in BLOCK");

    // Verify flagged processes recorded
    let flagged = process_engine.get_flagged_processes();
    assert_eq!(flagged.len(), 2, "Both unknown and blocked executables recorded");
}

// =====================================================================
// Scenario 5: Sensitive File Access → FLAG
// =====================================================================

#[test]
fn chaos_sensitive_file_access_flagged() {
    let mut file_engine = FileAccessEnforcementEngine::new();

    // Sensitive files
    assert!(
        file_engine.check_file_access(3001, "agent", "/etc/passwd").is_some(),
        "Access to /etc/passwd must be flagged"
    );
    assert!(
        file_engine.check_file_access(3002, "agent", "/home/user/.ssh/id_rsa").is_some(),
        "Access to SSH keys must be flagged"
    );
    assert!(
        file_engine.check_file_access(3003, "agent", "/tmp/credentials.json").is_some(),
        "Access to credentials must be flagged"
    );

    // Normal file → no violation
    assert!(
        file_engine.check_file_access(3004, "agent", "/tmp/test.txt").is_none(),
        "Access to normal files should not trigger"
    );

    // Verify violations recorded
    assert_eq!(file_engine.get_violations().len(), 3,
        "All 3 sensitive file accesses should be recorded");
}

// =====================================================================
// Scenario 6: Risk Escalation → ESCALATE
// =====================================================================

#[test]
fn chaos_risk_escalation_triggers_escalate() {
    let mut decision_engine = DecisionEngine::new();
    for policy in DecisionEngine::default_policies() {
        decision_engine.add_policy(policy);
    }

    let decision = decision_engine.evaluate(
        4001, "agent-escalate".to_string(),
        60, "HighRisk",
        None, None, None,
        Some("MultiAgentRiskEscalation".to_string()),
        None, None, None, &[],
    );

    assert_eq!(decision.action, DecisionAction::Escalate,
        "Multi-agent risk escalation should trigger ESCALATE action");
    assert!(decision.confidence > 0.5,
        "Escalation decisions should have high confidence");
}

// =====================================================================
// Scenario 7: Fingerprint Drift → RESTART
// =====================================================================

#[test]
fn chaos_fingerprint_drift_triggers_restart() {
    let mut decision_engine = DecisionEngine::new();
    for policy in DecisionEngine::default_policies() {
        decision_engine.add_policy(policy);
    }

    let decision = decision_engine.evaluate(
        5001, "drift-agent".to_string(),
        50, "Suspicious",
        Some("FingerprintDrift".to_string()), Some("High".to_string()), Some(45.0), None,
        None, None, None, &[],
    );

    assert_eq!(decision.action, DecisionAction::Restart,
        "Fingerprint drift should trigger RESTART action");
    assert!(decision.reason.contains("restart_on_fingerprint_drift"),
        "Reason must reference fingerprint drift rule");
}

// =====================================================================
// Scenario 8: Human Override → Overrides Decision
// =====================================================================

#[test]
fn chaos_human_override_overrides_decision() {
    let mut decision_engine = DecisionEngine::new();
    for policy in DecisionEngine::default_policies() {
        decision_engine.add_policy(policy);
    }

    // Block decision
    let decision = decision_engine.evaluate(
        6001, "override-agent".to_string(),
        90, "Critical", None, None, None, None,
        None, None, None, &[],
    );
    assert_eq!(decision.action, DecisionAction::Block,
        "Critical risk must initially be BLOCKED");

    // Human overrides to Allow
    let override_ = decision_engine.create_override(
        decision.id,
        OverrideAction::Approve,
        "Approved by security team".to_string(),
        "admin".to_string(),
        Some(3600),
    );
    assert_eq!(override_.created_by, "admin",
        "Override must record the operator");

    // Re-evaluate — should now be overridden to Allow
    let new_decision = decision_engine.evaluate(
        6001, "override-agent".to_string(),
        90, "Critical", None, None, None, None,
        None, None, None, &[],
    );
    assert_eq!(new_decision.action, DecisionAction::Allow,
        "After override, decision must be ALLOW");
    assert!(new_decision.reason.contains("admin"),
        "Override reason must reference the operator");
}

// =====================================================================
// Scenario 9: Decision Audit Trail
// =====================================================================

#[test]
fn chaos_decision_audit_trail() {
    let mut decision_engine = DecisionEngine::new();
    for policy in DecisionEngine::default_policies() {
        decision_engine.add_policy(policy);
    }

    // Make several decisions
    decision_engine.evaluate(7001, "audit-1".to_string(), 10, "Normal", None, None, None, None, None, None, None, &[]);
    decision_engine.evaluate(7002, "audit-2".to_string(), 90, "Critical", None, None, None, None, None, None, None, &[]);
    decision_engine.evaluate(7003, "audit-3".to_string(), 40, "Suspicious", None, None, None, None, Some("test.com".to_string()), None, None, &[]);

    // Verify all decisions recorded
    let all_decisions = decision_engine.get_decisions();
    assert_eq!(all_decisions.len(), 3,
        "All decisions must be recorded in the audit trail");

    let decisions_by_agent = decision_engine.get_decisions_for_agent(7001);
    assert_eq!(decisions_by_agent.len(), 1,
        "Agent-specific query must work");

    // Every decision has required fields
    for d in &all_decisions {
        assert!(!d.reason.is_empty(), "Every decision must have a reason");
        assert!(!d.rule.is_empty(), "Every decision must reference a rule");
        assert!(!d.policy_name.is_empty(), "Every decision must reference a policy");
        assert!(d.confidence > 0.0 || d.action == DecisionAction::Allow,
            "All non-default decisions must have confidence");
    }
}

// =====================================================================
// Scenario 10: Enforcement Persistence → Incidents survive
// =====================================================================

#[test]
fn chaos_enforcement_persistence() {
    let mut decision_engine = DecisionEngine::new();
    for policy in DecisionEngine::default_policies() {
        decision_engine.add_policy(policy);
    }

    let mut enforcement = EnforcementManager::new();

    // Execute multiple enforcement actions
    for i in 0..5 {
        let decision = decision_engine.evaluate(
            8000 + i, format!("persist-agent-{}", i),
            80, "HighRisk", None, None, None, None,
            Some(format!("malicious-{}.com", i)), None, None, &[],
        );
        enforcement.execute(&decision);
    }

    // Verify all incidents persisted
    assert_eq!(enforcement.incident_count(), 5,
        "All 5 enforcement actions must create incidents");
    assert_eq!(enforcement.get_open_incidents().len(), 5,
        "All incidents must be in Open state");

    // Collect IDs first, then resolve (avoids borrow checker conflict)
    let incident_ids: Vec<uuid::Uuid> = enforcement.get_incidents().iter().map(|i| i.id).collect();
    assert!(enforcement.resolve_incident(incident_ids[0], "investigation complete".to_string()),
        "Incident resolution must succeed");
    assert!(enforcement.resolve_incident(incident_ids[1], "false positive".to_string()),
        "Incident resolution must succeed");

    assert_eq!(enforcement.get_open_incidents().len(), 3,
        "After resolving 2 incidents, 3 should remain open");
    assert_eq!(enforcement.incident_count(), 5,
        "Total incident count must still be 5 even after resolutions");
}

// =====================================================================
// Scenario 11: End-to-End Enforcement Pipeline
// =====================================================================

#[test]
fn chaos_e2e_enforcement_pipeline() {
    let mut decision_engine = DecisionEngine::new();
    for policy in DecisionEngine::default_policies() {
        decision_engine.add_policy(policy);
    }

    let mut enforcement = EnforcementManager::new();

    // Step 1: Detection — high-risk anomaly
    let decision = decision_engine.evaluate(
        9001, "pipeline-agent".to_string(),
        85, "Critical",
        Some("OutboundSpike".to_string()), Some("Critical".to_string()), Some(30.0), None,
        Some("exfil-attempt.com".to_string()), None, None, &[],
    );

    // Step 2: Decision — must be Block
    assert_eq!(decision.action, DecisionAction::Block,
        "Critical outbound spike must be BLOCKED");
    assert_eq!(decision.context.risk_score, 85, "Context must carry risk score");

    // Step 3: Enforcement — must be Applied
    let action = enforcement.execute(&decision);
    assert_eq!(action.result, EnforcementResult::Applied,
        "Enforcement must be applied");

    // Step 4: Incident — must be created
    assert_eq!(enforcement.incident_count(), 1, "Incident must be created");
    assert_eq!(enforcement.get_open_incidents().len(), 1, "Incident must be Open");

    // Step 5: Network — must be blocked
    assert!(enforcement.network.is_blocked("exfil-attempt.com"),
        "Destination must be on block list");

    // Step 6: Stats — must reflect the enforcement
    let stats = enforcement.get_stats();
    assert!(stats.total_actions >= 1, "Stats must reflect enforcement action");
    assert!(stats.open_incidents >= 1, "Stats must reflect open incident");
}
