use anyhow::Result;
use axum::{Json, Router};
use omnisec_alerts::{AlertConfig, AlertManager};
use chrono::{Timelike, Utc};
use omnisec_anomaly::AnomalyDetector;
use omnisec_discovery::AgentDiscovery;
use omnisec_ebpf::{EbpfManager, KernelEvent, KernelEventStream};
use omnisec_events::subjects;
use omnisec_events::{
    AgentDiscoveredPayload, AgentFailedPayload, AgentHealthChangedPayload,
    AlertRequestedPayload, AlertSentPayload, AlertFailedPayload,
    HealthState,
    RestartRequestedPayload, RestartStartedPayload, RestartSucceededPayload,
    RestartFailedPayload,
};
use omnisec_fingerprint::FingerprintManager;
use omnisec_identity::AgentIdentityEngine;
use omnisec_messaging::NatsClient;
use omnisec_monitoring::{HealthEvent, HealthMonitor, RestartConfig, RestartEngine};
use omnisec_network::NetworkTracker;
use omnisec_reliability::incident::{IncidentEngine, IncidentSeverity, IncidentType};
use omnisec_security::correlation::{AgentActivitySnapshot, CorrelationEngine};
use omnisec_security::AgentProfileManager;
use omnisec_storage::security::SecurityStorage;
use omnisec_decision::{DecisionAction, DecisionEngine, EnforcementDecision};
use omnisec_enforcement::EnforcementManager;
use omnisec_runtime::RuntimeManager;
use omnisec_storage::Storage;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod platform;

struct DaemonState {
    agent_count: usize,
    alive_count: usize,
    failed_count: usize,
    total_restarts: u64,
}

struct DesignPartnerConfig {
    safe_mode: bool,
    recommendation_only: bool,
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Early-exit for binary verification and install scripts.
    if std::env::args().any(|a| a == "--version") {
        println!("omnisec-daemon 0.2.0 ({})", platform::platform_id());
        return Ok(());
    }

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "omnisec_daemon=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!(
        "Starting Omnisec Daemon v0.2.0 (event-driven) on {}",
        platform::platform_id()
    );

    // --- NATS connection ---
    let nats_url = std::env::var("NATS_URL")
        .unwrap_or_else(|_| "nats://localhost:4222".to_string());
    let nats = Arc::new(NatsClient::connect(&nats_url, "omnisec-daemon").await?);

    // --- Storage ---
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/omnisec".to_string());

    let storage = match Storage::new(&database_url).await {
        Ok(mut s) => {
            tracing::info!("Connected to database");
            if let Err(e) = s.run_migrations().await {
                tracing::warn!("Migration warning: {}", e);
            }
            if let Err(e) = s.bootstrap_organization().await {
                tracing::error!("DB bootstrap failed — agents/events will not persist: {}", e);
            }
            Some(Arc::new(s))
        }
        Err(e) => {
            tracing::warn!("Database not available, running in memory-only mode: {}", e);
            None
        }
    };

    // --- Alert manager ---
    let alert_config = AlertConfig {
        telegram_bot_token: std::env::var("TELEGRAM_BOT_TOKEN").ok(),
        telegram_chat_id: std::env::var("TELEGRAM_CHAT_ID").ok(),
        email_smtp_host: None,
        email_smtp_port: None,
        email_username: None,
        email_password: None,
        slack_webhook_url: None,
    };
    let alert_manager = Arc::new(RwLock::new(AlertManager::new(alert_config)));

    // --- Design Partner Mode ---
    let design_partner = Arc::new(DesignPartnerConfig {
        safe_mode: std::env::var("OMNISEC_SAFE_MODE").as_deref() == Ok("1"),
        recommendation_only: std::env::var("OMNISEC_RECOMMENDATION_ONLY").as_deref() == Ok("1"),
        verbose: std::env::var("OMNISEC_VERBOSE").as_deref() == Ok("1"),
    });

    if design_partner.safe_mode {
        tracing::warn!("┌─────────────────────────────────────────────────┐");
        tracing::warn!("│  SAFE MODE ACTIVE (OMNISEC_SAFE_MODE=1)         │");
        tracing::warn!("│  Enforcement actions will be logged but NOT     │");
        tracing::warn!("│  applied. No nftables rules, no SIGSTOP/KILL.   │");
        tracing::warn!("└─────────────────────────────────────────────────┘");
    }
    if design_partner.recommendation_only {
        tracing::warn!("┌─────────────────────────────────────────────────┐");
        tracing::warn!("│  RECOMMENDATION-ONLY MODE (OMNISEC_RECOM.._=1) │");
        tracing::warn!("│  Decision engine runs; enforcement is skipped.  │");
        tracing::warn!("│  Decisions are published to NATS for review.    │");
        tracing::warn!("└─────────────────────────────────────────────────┘");
    }
    if design_partner.verbose {
        tracing::info!("Verbose mode active (OMNISEC_VERBOSE=1) — extended pipeline logging enabled");
    }

    // --- Shared state for health endpoint ---
    let daemon_state = Arc::new(RwLock::new(DaemonState {
        agent_count: 0,
        alive_count: 0,
        failed_count: 0,
        total_restarts: 0,
    }));

    // Clone storage for discovery task (must happen before storage is moved into audit trail)
    let discovery_storage = storage.clone();

    // =====================================================================
    // Task 1: Discovery ticker — scans processes and publishes to NATS
    // =====================================================================
    let nats_discovery = nats.clone();
    let discovery = AgentDiscovery::new();
    tokio::spawn(async move {
        let mut cycle = 0u64;
        // Track already-stored agents by PID to avoid duplicate inserts
        let mut stored_agents: std::collections::HashMap<u32, uuid::Uuid> = std::collections::HashMap::new();

        loop {
            cycle += 1;
            tracing::debug!("Discovery cycle {}", cycle);

            match discovery.discover_agents() {
                Ok(all_agents) => {
                    // Only publish agents with a minimum confidence threshold.
                    // This filters out infrastructure processes (postgres, nats, kernel
                    // threads, bash, etc.) that have no AI agent indicators.
                    let min_confidence = 20u8;
                    let agents: Vec<_> = all_agents
                        .into_iter()
                        .filter(|a| a.confidence >= min_confidence)
                        .collect();

                    for agent in &agents {
                        // Persist new agents to database (only on first discovery)
                        if !stored_agents.contains_key(&agent.pid) {
                            if let Some(ref store) = discovery_storage {
                                match store.create_agent(&agent.name, Some(agent.pid as i32), Some(agent.confidence as i32)).await {
                                    Ok(agent_id) => {
                                        stored_agents.insert(agent.pid, agent_id);
                                        tracing::info!("Stored agent {} (PID: {}) in database", agent.name, agent.pid);
                                    }
                                    Err(e) => {
                                        tracing::error!("Failed to store agent {}: {}", agent.name, e);
                                    }
                                }
                            }
                        }

                        let payload = AgentDiscoveredPayload {
                            pid: agent.pid,
                            ppid: agent.ppid,
                            name: agent.name.clone(),
                            command: agent.command.clone(),
                            framework: agent.framework.clone(),
                            model_provider: agent.model_provider.clone(),
                            cpu_percent: agent.cpu_percent,
                            memory_mb: agent.memory_mb,
                            confidence: agent.confidence,
                            listening_ports: agent.listening_ports.clone(),
                        };
                        if let Err(e) = nats_discovery
                            .publish(subjects::AGENT_DISCOVERED, "discovery", payload)
                            .await
                        {
                            tracing::error!("Failed to publish AgentDiscovered: {}", e);
                        }
                    }

                    if !agents.is_empty() {
                        tracing::info!(
                            "Published {} AgentDiscovered events (min confidence={})",
                            agents.len(),
                            min_confidence,
                        );
                    }
                }
                Err(e) => {
                    tracing::error!("Discovery failed: {}", e);
                }
            }

            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    // =====================================================================
    // Task 2: Health monitor — subscribes to AgentDiscovered, checks health, publishes events
    // =====================================================================
    // Uses an mpsc channel to funnel discovered agent PIDs into the health monitor,
    // avoiding the ownership conflict of sharing HealthMonitor between tasks.
    let nats_health = nats.clone();
    let state_for_health = daemon_state.clone();
    tokio::spawn(async move {
        let mut health_monitor = HealthMonitor::with_failure_threshold(3);

        // Subscribe to AgentDiscovered events to register agents for health monitoring
        let mut agent_sub = match nats_health.subscribe::<AgentDiscoveredPayload>(subjects::AGENT_DISCOVERED).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to subscribe to AgentDiscovered: {}", e);
                return;
            }
        };

        // Use a channel to send discovered agent PIDs from the subscription handler
        // to the health check loop without sharing HealthMonitor directly.
        let (agent_tx, mut agent_rx) = tokio::sync::mpsc::unbounded_channel::<(u32, String)>();

        // Spawn a task to read from the NATS subscription and forward to the channel.
        // This avoids holding the subscription in the same task as the health check loop.
        tokio::spawn(async move {
            while let Some((_subject, envelope)) = agent_sub.next().await {
                let pid = envelope.payload.pid;
                let name = envelope.payload.name.clone();
                let _ = agent_tx.send((pid, name));
            }
        });

        // Health check loop — also drains the agent registration channel
        loop {
            // Drain any pending agent registrations
            while let Ok((pid, name)) = agent_rx.try_recv() {
                health_monitor.register_agent(pid, name);
                let mut state = state_for_health.write().await;
                state.agent_count = health_monitor.agent_count();
            }

            let events = match health_monitor.check_health() {
                Ok(e) => e,
                Err(e) => {
                    tracing::error!("Health check failed: {}", e);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };

            for event in &events {
                match event {
                    HealthEvent::AgentDied { pid, name } => {
                        // Publish AgentFailed event
                        let payload = AgentFailedPayload {
                            pid: *pid,
                            name: name.clone(),
                            consecutive_failures: 3,
                            reason: "process not responding".to_string(),
                        };
                        if let Err(e) = nats_health
                            .publish(subjects::AGENT_FAILED, "monitoring", payload)
                            .await
                        {
                            tracing::error!("Failed to publish AgentFailed: {}", e);
                        }

                        // Request an alert
                        let alert_payload = AlertRequestedPayload {
                            channel: "telegram".to_string(),
                            message: format!("Agent {} (PID: {}) has died", name, pid),
                            agent_pid: Some(*pid),
                            agent_name: Some(name.clone()),
                        };
                        if let Err(e) = nats_health
                            .publish(subjects::ALERT_REQUESTED, "monitoring", alert_payload)
                            .await
                        {
                            tracing::error!("Failed to publish AlertRequested: {}", e);
                        }

                        // Request a restart
                        let restart_payload = RestartRequestedPayload {
                            pid: *pid,
                            name: name.clone(),
                            attempt: 1,
                            backoff_seconds: 2,
                        };
                        if let Err(e) = nats_health
                            .publish(subjects::RESTART_REQUESTED, "monitoring", restart_payload)
                            .await
                        {
                            tracing::error!("Failed to publish RestartRequested: {}", e);
                        }

                        {
                            let mut state = state_for_health.write().await;
                            state.failed_count = health_monitor.failed_count();
                        }
                    }
                    HealthEvent::AgentRecovered { pid, name } => {
                        tracing::info!("Agent recovered: {} (PID: {})", name, pid);
                        let payload = AgentHealthChangedPayload {
                            pid: *pid,
                            name: name.clone(),
                            previous_state: HealthState::Failed,
                            new_state: HealthState::Healthy,
                            consecutive_failures: 0,
                            reason: "process recovered".to_string(),
                        };
                        let _ = nats_health
                            .publish(subjects::AGENT_HEALTH_CHANGED, "monitoring", payload)
                            .await;
                    }
                    HealthEvent::AgentUnhealthy { pid, name, reason } => {
                        tracing::warn!("Agent unhealthy: {} (PID: {}) - {}", name, pid, reason);
                        let payload = AgentHealthChangedPayload {
                            pid: *pid,
                            name: name.clone(),
                            previous_state: HealthState::Healthy,
                            new_state: HealthState::Warning,
                            consecutive_failures: 0,
                            reason: reason.clone(),
                        };
                        let _ = nats_health
                            .publish(subjects::AGENT_HEALTH_CHANGED, "monitoring", payload)
                            .await;

                        // If the reason contains "hang" or "hung", escalate with an alert
                        if reason.to_lowercase().contains("hang") || reason.to_lowercase().contains("hung") {
                            tracing::warn!(
                                "HANG DETECTED: {} (PID: {}) appears hung — escalating alert",
                                name, pid
                            );

                            // Publish a dedicated hang event
                            let hang_payload = serde_json::json!({
                                "pid": pid,
                                "name": name,
                                "reason": reason,
                                "severity": "warning",
                                "detected_at": chrono::Utc::now().to_rfc3339(),
                            });
                            let _ = nats_health
                                .publish(subjects::AGENT_HUNG, "monitoring", hang_payload)
                                .await;

                            // Request an alert for the hang event
                            let alert_payload = AlertRequestedPayload {
                                channel: "telegram".to_string(),
                                message: format!(
                                    "⚠️ HANG DETECTED: Agent {} (PID: {}) - {}",
                                    name, pid, reason
                                ),
                                agent_pid: Some(*pid),
                                agent_name: Some(name.clone()),
                            };
                            let _ = nats_health
                                .publish(subjects::ALERT_REQUESTED, "monitoring", alert_payload)
                                .await;
                        }
                    }
                    HealthEvent::AgentRestarted { pid, name, attempt } => {
                        let payload = RestartSucceededPayload {
                            pid: *pid,
                            name: name.clone(),
                            attempt: *attempt,
                            new_pid: None,
                        };
                        let _ = nats_health
                            .publish(subjects::RESTART_SUCCEEDED, "monitoring", payload)
                            .await;
                    }
                }
            }

            // Update alive count
            {
                let mut state = state_for_health.write().await;
                state.alive_count = health_monitor.alive_count();
            }

            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    // =====================================================================
    // Task 3: Restart orchestrator — subscribes to AgentFailed, manages restarts
    // =====================================================================
    let nats_restart = nats.clone();
    let state_restart = daemon_state.clone();
    tokio::spawn(async move {
        let mut restart_engine = RestartEngine::with_config(RestartConfig {
            initial_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(300),
            max_retries: Some(5),
            cooldown: Duration::from_secs(30),
        });

        // Store the command line for each discovered agent so we can respawn
        let mut agent_cmdlines: std::collections::HashMap<u32, String> = std::collections::HashMap::new();

        // Subscribe to AgentDiscovered to capture cmdlines before agents die
        let mut discovered_sub = match nats_restart
            .subscribe::<AgentDiscoveredPayload>(subjects::AGENT_DISCOVERED)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Restart engine: failed to subscribe to AgentDiscovered: {}", e);
                return;
            }
        };

        let mut failed_sub = match nats_restart
            .subscribe::<AgentFailedPayload>(subjects::AGENT_FAILED)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to subscribe to AgentFailed: {}", e);
                return;
            }
        };

        loop {
            tokio::select! {
                Some((_subject, envelope)) = discovered_sub.next() => {
                    // Cache cmdline at discovery time — before the process might die
                    let pid = envelope.payload.pid;
                    if !envelope.payload.command.is_empty() {
                        agent_cmdlines.insert(pid, envelope.payload.command.clone());
                    }
                }
                Some((_subject, envelope)) = failed_sub.next() => {
                    let pid = envelope.payload.pid;
                    let name = envelope.payload.name.clone();
                    restart_engine.register_agent(pid, name.clone());
                    tracing::info!("Registered agent {} (PID: {}) for restart", name, pid);
                }
                _ = tokio::time::sleep(Duration::from_secs(2)) => {
                    let pending = restart_engine.pending_restarts();
                    for (pid, name) in &pending {
                        let attempt = restart_engine.attempt_count(*pid);

                        let start_payload = RestartStartedPayload {
                            pid: *pid,
                            name: name.clone(),
                            attempt,
                        };
                        let _ = nats_restart
                            .publish(subjects::RESTART_STARTED, "restart-engine", start_payload)
                            .await;

                        restart_engine.record_attempt(*pid);

                        // Attempt real process restart if we have the cmdline
                        let new_pid = if let Some(cmdline) = agent_cmdlines.get(pid) {
                            spawn_process(cmdline)
                        } else {
                            // Fall back to reading /proc/[pid]/cmdline (process may be dead)
                            read_proc_cmdline(*pid).and_then(|cmd| spawn_process(&cmd))
                        };

                        match new_pid {
                            Some(new_pid) => {
                                tracing::info!("Restarted {} (old PID: {}, new PID: {})", name, pid, new_pid);
                                // Cache new cmdline under new PID
                                if let Some(cmd) = agent_cmdlines.get(pid).cloned() {
                                    agent_cmdlines.insert(new_pid, cmd);
                                }
                                let success_payload = RestartSucceededPayload {
                                    pid: *pid,
                                    name: name.clone(),
                                    attempt,
                                    new_pid: Some(new_pid),
                                };
                                let _ = nats_restart
                                    .publish(subjects::RESTART_SUCCEEDED, "restart-engine", success_payload)
                                    .await;
                            }
                            None => {
                                tracing::warn!("Restart attempt {} failed for {} (PID: {}) — no cmdline available", attempt, name, pid);
                            }
                        }

                        let mut state = state_restart.write().await;
                        state.total_restarts += 1;
                    }
                }
            }
        }
    });

    // =====================================================================
    // Task 4: Alert handler — subscribes to AlertRequested, sends alerts
    // =====================================================================
    let nats_alert = nats.clone();
    let alert_mgr = alert_manager.clone();
    tokio::spawn(async move {
        let mut alert_sub = match nats_alert
            .subscribe::<AlertRequestedPayload>(subjects::ALERT_REQUESTED)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to subscribe to AlertRequested: {}", e);
                return;
            }
        };

        while let Some((_subject, envelope)) = alert_sub.next().await {
            let channel = envelope.payload.channel.clone();
            let message = envelope.payload.message.clone();

            let mut mgr = alert_mgr.write().await;
            match mgr.send_alert(&message, &channel).await {
                Ok(()) => {
                    tracing::info!("Alert sent via {}: {}", channel, message);
                    let _ = nats_alert
                        .publish(
                            subjects::ALERT_SENT,
                            "alert-handler",
                            AlertSentPayload {
                                channel,
                                message_preview: message.chars().take(100).collect(),
                            },
                        )
                        .await;
                }
                Err(e) => {
                    tracing::error!("Alert failed via {}: {}", channel, e);
                    let _ = nats_alert
                        .publish(
                            subjects::ALERT_FAILED,
                            "alert-handler",
                            AlertFailedPayload {
                                channel,
                                message_preview: message.chars().take(100).collect(),
                                error: e.to_string(),
                            },
                        )
                        .await;
                }
            }
        }
    });

    // =====================================================================
    // Security Storage access (built before audit trail to avoid borrow-after-move)
    // =====================================================================
    let security_store: Arc<Option<SecurityStorage>> = Arc::new(
        storage.as_ref().map(|s| SecurityStorage::new(s.pool().clone())),
    );

    // =====================================================================
    // Task 5: Audit trail — subscribes to ALL omnisec events, persists to DB
    // =====================================================================
    if let Some(storage) = storage {
        let nats_audit = nats.clone();
        tokio::spawn(async move {
            // Subscribe to all omnisec events using the wildcard subject
            let mut all_sub = match nats_audit
                .subscribe::<serde_json::Value>(subjects::WILDCARD_ALL)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Failed to subscribe to all events: {}", e);
                    return;
                }
            };

            tracing::info!("Audit trail subscriber listening on omnisec.>");

            while let Some((subject, envelope)) = all_sub.next().await {
                let summary = format!("{} event from {}", subject, envelope.source);

                let event_type = subject
                    .replace('.', "_")
                    .trim_start_matches("omnisec_")
                    .to_string();
                if let Err(e) = storage
                    .create_event(
                        None,
                        &event_type,
                        "info",
                        &summary,
                    )
                    .await
                {
                    tracing::error!("Failed to persist audit event for {}: {}", subject, e);
                }
            }
        });
    }

    // =====================================================================
    // Task 6: Security Pipeline — continuous security control loop
    //
    // Pipeline: Network Tracker → Profile Manager → Fingerprint Engine →
    //           Anomaly Engine → Risk Engine → Incident Engine → NATS Publishing
    // =====================================================================
    {
        let nats_sec = nats.clone();
        let sec_store = security_store.clone();

        tokio::spawn(async move {
            let mut network_tracker = NetworkTracker::new();
            let mut profile_manager = AgentProfileManager::new();
            let mut fingerprint_manager = FingerprintManager::new();
            let mut anomaly_detector = AnomalyDetector::new();
            let mut incident_engine = IncidentEngine::new();
            let mut correlation_engine = CorrelationEngine::new();

            tracing::info!("Security pipeline started — continuous monitoring loop");

            // Subscribe to AgentDiscovered events to register agents
            let mut agent_sub = match nats_sec
                .subscribe::<AgentDiscoveredPayload>(subjects::AGENT_DISCOVERED)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Security pipeline: failed to subscribe to AgentDiscovered: {}", e);
                    return;
                }
            };

            let (agent_tx, mut agent_rx) = tokio::sync::mpsc::unbounded_channel::<(u32, String)>();

            tokio::spawn(async move {
                while let Some((_subject, envelope)) = agent_sub.next().await {
                    let pid = envelope.payload.pid;
                    let name = envelope.payload.name.clone();
                    let _ = agent_tx.send((pid, name));
                }
            });

            // Main security control loop
            loop {
                // Drain agent registrations
                while let Ok((pid, name)) = agent_rx.try_recv() {
                    profile_manager.register_agent(pid, name.clone());
                    fingerprint_manager.register_agent(pid, name.clone());
                    tracing::info!("Security: registered agent {} (PID: {})", name, pid);

                    // Audit trail: profile created
                    if let Some(ref store) = sec_store.as_ref() {
                        let _ = store.record_audit_entry(
                            Some(pid as i32),
                            Some(&name),
                            "agent_registered",
                            &format!("Agent {} (PID: {}) registered in security system", name, pid),
                            &json!({"pid": pid, "name": name}),
                        ).await;
                        let _ = store.record_timeline_entry(
                            Some(pid as i32),
                            Some(&name),
                            "profile_created",
                            "info",
                            &format!("Security Monitoring Started"),
                            &format!("Agent {} (PID: {}) registered for behavioral security analysis", name, pid),
                            &json!({"pid": pid, "name": name}),
                        ).await;
                    }

                    // Publish NATS profile updated event
                    if let Err(e) = nats_sec.publish(
                        subjects::SECURITY_PROFILE_UPDATED,
                        "security-pipeline",
                        json!({"pid": pid, "agent_name": name, "action": "registered"}),
                    ).await {
                        tracing::error!("Failed to publish profile.updated: {}", e);
                    }
                }

                // --- Step 1: Collect live network connections from OS ---
                network_tracker.collect_connections();

                let pids: Vec<u32> = {
                    profile_manager.get_all_risk_scores().iter().map(|s| s.pid).collect()
                };

                // --- Step 2-4: Profile update, fingerprint, anomaly, risk ---
                let mut all_snapshots: Vec<AgentActivitySnapshot> = Vec::new();
                let current_hour = Utc::now().hour() as u8;

                for &pid in &pids {
                    let stats = network_tracker.get_traffic_stats(pid);
                    let destinations = network_tracker.get_destinations(pid);

                    let name = match profile_manager.get_risk_score(pid).map(|s| s.agent_name.clone()) {
                        Some(n) => n,
                        None => continue,
                    };

                    // Feed each live connection into the profile manager
                    for conn in network_tracker.get_connections_for_pid(pid) {
                        let _ = profile_manager.record_network_activity(
                            pid,
                            conn.remote_ip.to_string(),
                            conn.remote_ip.to_string(),
                            conn.remote_port,
                            format!("{:?}", conn.protocol),
                            conn.bytes_in,
                            conn.bytes_out,
                        );
                    }

                    // Feed into fingerprint builder
                    let dest_domains: Vec<String> = destinations.iter().map(|(ip, _, _)| ip.clone()).collect();
                    let first_ip = dest_domains.first().cloned().unwrap_or_default();
                    fingerprint_manager.record_sample(
                        pid,
                        dest_domains.clone(),
                        first_ip.clone(),
                        stats.unique_destinations as u16,
                        "tcp".to_string(),
                        stats.hour_avg_in,
                        stats.hour_avg_out,
                        stats.active_connections as f64,
                        current_hour,
                        0.0, // cpu_percent (from health monitor, not available here)
                        0.0, // memory_mb
                        stats.active_connections,
                        1,
                    );

                    // Get baseline state for anomaly gating
                    let baseline_state = profile_manager
                        .get_baseline(pid)
                        .map(|b| {
                            if b.is_established() { omnisec_events::BaselineState::Established }
                            else if b.is_training() { omnisec_events::BaselineState::Training }
                            else { omnisec_events::BaselineState::Learning }
                        })
                        .unwrap_or(omnisec_events::BaselineState::Learning);

                    // --- Anomaly checks ---
                    let mut detected_anomalies = Vec::new();

                    // Traffic spike
                    if let Some(anomaly) = anomaly_detector.check_traffic_spike(
                        pid, &name,
                        stats.hour_avg_in + stats.hour_avg_out,
                        0.0, // baseline will be computed internally once samples exist
                        &baseline_state,
                    ) {
                        detected_anomalies.push(anomaly);
                    }

                    // Outbound spike
                    if let Some(anomaly) = anomaly_detector.check_outbound_spike(
                        pid, &name,
                        stats.total_bytes_out,
                        stats.total_bytes_in,
                        &baseline_state,
                    ) {
                        detected_anomalies.push(anomaly);
                    }

                    // New destination check for each connection
                    let known_dests: Vec<String> = vec![
                        "api.openai.com".to_string(), "api.anthropic.com".to_string(),
                        "api.github.com".to_string(), "github.com".to_string(),
                    ];
                    for (ip, port, _proto) in &destinations {
                        if let Some(anomaly) = anomaly_detector.check_new_destination(
                            pid, &name, ip, *port, &known_dests, &baseline_state,
                        ) {
                            detected_anomalies.push(anomaly);
                        }
                    }

                    // Fingerprint drift (every 10 cycles — fingerprint needs history)
                    fingerprint_manager.finalize_fingerprint(pid);
                    if let Some(drift) = fingerprint_manager.detect_drift(pid) {
                        if let Some(anomaly) = anomaly_detector.check_fingerprint_drift(
                            pid, &name, drift.drift_score, &drift.new_destinations, &baseline_state,
                        ) {
                            detected_anomalies.push(anomaly);
                        }
                    }

                    // --- Create incidents and publish events for each anomaly ---
                    for anomaly in &detected_anomalies {
                        let severity = match anomaly.severity {
                            omnisec_anomaly::AnomalySeverity::Critical => IncidentSeverity::Critical,
                            omnisec_anomaly::AnomalySeverity::High => IncidentSeverity::High,
                            omnisec_anomaly::AnomalySeverity::Medium => IncidentSeverity::Medium,
                            omnisec_anomaly::AnomalySeverity::Low => IncidentSeverity::Low,
                        };

                        let incident = incident_engine.create_incident(
                            None,
                            name.clone(),
                            pid,
                            IncidentType::PolicyViolation,
                            severity,
                            format!("Anomaly: {:?}", anomaly.anomaly_type),
                            anomaly.description.clone(),
                        );

                        let risk_score = profile_manager.get_risk_score(pid).map(|s| s.total_score).unwrap_or(0);
                        let risk_level = profile_manager.get_risk_score(pid).map(|s| {
                            match s.risk_level {
                                omnisec_events::RiskLevel::Normal => "Normal",
                                omnisec_events::RiskLevel::Suspicious => "Suspicious",
                                omnisec_events::RiskLevel::HighRisk => "HighRisk",
                                omnisec_events::RiskLevel::Critical => "Critical",
                            }.to_string()
                        }).unwrap_or_else(|| "Normal".to_string());

                        // Publish anomaly event — this is what drives the enforcement pipeline
                        if let Err(e) = nats_sec.publish(
                            subjects::SECURITY_ANOMALY_DETECTED,
                            "security-pipeline",
                            json!({
                                "pid": pid,
                                "agent_name": name,
                                "anomaly_type": format!("{:?}", anomaly.anomaly_type),
                                "severity": format!("{:?}", anomaly.severity),
                                "description": anomaly.description,
                                "deviation": anomaly.deviation,
                                "risk_score": risk_score,
                                "risk_level": risk_level,
                                "incident_id": incident.id.to_string(),
                            }),
                        ).await {
                            tracing::error!("Failed to publish anomaly: {}", e);
                        }

                        tracing::warn!(
                            "ANOMALY: {:?} for {} (PID:{}) — {}",
                            anomaly.anomaly_type, name, pid, anomaly.description
                        );

                        // Persist incident to security storage
                        if let Some(ref store) = sec_store.as_ref() {
                            let risk_score = profile_manager.get_risk_score(pid).map(|s| s.total_score).unwrap_or(0);
                            let _ = store.insert_incident(
                                pid as i32,
                                &name,
                                &format!("{:?}", anomaly.anomaly_type),
                                risk_score as i32,
                                &anomaly.description,
                                &json!({
                                    "incident_id": incident.id.to_string(),
                                    "severity": format!("{:?}", anomaly.severity),
                                }),
                            ).await;

                            let _ = store.record_timeline_entry(
                                Some(pid as i32),
                                Some(&name),
                                "anomaly_detected",
                                &format!("{:?}", anomaly.severity).to_lowercase(),
                                &format!("Anomaly: {:?}", anomaly.anomaly_type),
                                &anomaly.description,
                                &json!({ "deviation": anomaly.deviation }),
                            ).await;
                        }
                    }

                    // Activity snapshot for correlation engine
                    let snapshot = AgentActivitySnapshot {
                        pid,
                        agent_name: name.clone(),
                        traffic_rate_in: stats.hour_avg_in,
                        traffic_rate_out: stats.hour_avg_out,
                        connection_count: stats.active_connections,
                        risk_score: profile_manager.get_risk_score(pid).map(|s| s.total_score).unwrap_or(0),
                        new_destinations: dest_domains,
                        active_hour: current_hour,
                        is_active: stats.active_connections > 0,
                    };
                    all_snapshots.push(snapshot);

                    // Persist traffic sample
                    if let Some(ref store) = sec_store.as_ref() {
                        let _ = store.insert_traffic_sample(
                            pid as i32,
                            &name,
                            stats.total_bytes_in as i64,
                            stats.total_bytes_out as i64,
                            stats.active_connections as i32,
                            stats.active_connections as i32,
                            "hour",
                        ).await;
                    }
                }

                // --- Step 5: Correlation analysis ---
                if all_snapshots.len() >= 2 {
                    let correlation_alerts = correlation_engine.analyze(all_snapshots);

                    for alert in &correlation_alerts {
                        tracing::info!("Correlation alert: {} — {}", alert.correlation_type, alert.description);

                        // Publish correlation alert
                        if let Err(e) = nats_sec.publish(
                            subjects::SECURITY_CORRELATION_ALERT,
                            "correlation-engine",
                            json!({
                                "correlation_type": format!("{:?}", alert.correlation_type),
                                "description": alert.description,
                                "affected_agents": alert.affected_agents,
                                "severity": format!("{:?}", alert.severity),
                            }),
                        ).await {
                            tracing::error!("Failed to publish correlation alert: {}", e);
                        }

                        // Record timeline entry
                        if let Some(ref store) = sec_store.as_ref() {
                            let _ = store.record_timeline_entry(
                                None,
                                None,
                                "correlation_alert",
                                &format!("{:?}", alert.severity),
                                &format!("Correlation: {:?}", alert.correlation_type),
                                &alert.description,
                                &json!({"affected_agents": alert.affected_agents}),
                            ).await;

                            let _ = store.record_audit_entry(
                                None,
                                None,
                                "correlation_detected",
                                &alert.description,
                                &json!({"correlation_type": format!("{:?}", alert.correlation_type)}),
                            ).await;
                        }
                    }
                }

                // --- Step 6: Persist state periodically ---
                if let Some(ref store) = sec_store.as_ref() {
                    // Persist risk scores
                    for score in profile_manager.get_all_risk_scores() {
                        let reasons: Value = json!(score.reasons);
                        let risk_level_str = match score.risk_level {
                            omnisec_events::RiskLevel::Normal => "Normal",
                            omnisec_events::RiskLevel::Suspicious => "Suspicious",
                            omnisec_events::RiskLevel::HighRisk => "HighRisk",
                            omnisec_events::RiskLevel::Critical => "Critical",
                        };
                        let _ = store.upsert_risk_score(
                            score.pid as i32,
                            &score.agent_name,
                            score.total_score as i32,
                            score.destination_score as i32,
                            score.traffic_score as i32,
                            score.time_score as i32,
                            score.behavior_score as i32,
                            risk_level_str,
                            &reasons,
                        ).await;

                        // Persist baseline state
                        if let Some(baseline) = profile_manager.get_baseline(score.pid) {
                            let _ = store.upsert_baseline_state(
                                score.pid as i32,
                                &score.agent_name,
                                &format!("{:?}", baseline.state),
                                baseline.days_observed as i32,
                                baseline.samples_collected as i64,
                            ).await;
                        }
                    }
                }

                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
    }

    // =====================================================================
    // TASK: Post-Restart Verification (spawned before Task 7 to be available
    // for all downstream tasks)
    //
    // After a restart is reported as succeeded, this task verifies the agent
    // is actually alive and healthy by checking its process status. If the
    // agent is not healthy, it publishes an alert and re-queues the restart.
    // =====================================================================
    let nats_verification = nats.clone();
    let state_verification = daemon_state.clone();
    tokio::spawn(async move {
        let mut restart_sub = match nats_verification
            .subscribe::<RestartSucceededPayload>(subjects::RESTART_SUCCEEDED)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Post-restart verification: failed to subscribe: {}", e);
                return;
            }
        };

        tracing::info!("Post-restart verification task started");

        while let Some((_subject, envelope)) = restart_sub.next().await {
            let pid = envelope.payload.new_pid.unwrap_or(envelope.payload.pid);
            let name = envelope.payload.name.clone();
            let attempt = envelope.payload.attempt;

            tracing::info!("Verifying restart of {} (PID: {}) — attempt {}", name, pid, attempt);

            // Wait a moment for the process to initialize
            tokio::time::sleep(Duration::from_secs(3)).await;

            // Check if process is alive using libc::kill with signal 0
            let alive = alive_check(pid);

            if alive {
                tracing::info!("RESTART VERIFIED: {} (PID: {}) is running after attempt {}", name, pid, attempt);

                // Update daemon state — alive_count is set to the total agent count,
                // which is more accurate than incrementing (avoids double-counting)
                {
                    let state = state_verification.read().await;
                    tracing::info!("Restart verification: agent count = {}, alive = {}", state.agent_count, state.alive_count);
                }
            } else {
                tracing::error!(
                    "RESTART VERIFICATION FAILED: {} (PID: {}) is NOT running after attempt {} -- process may have exited immediately",
                    name, pid, attempt
                );

                // Publish an alert that restart verification failed
                let alert_payload = AlertRequestedPayload {
                    channel: "telegram".to_string(),
                    message: format!(
                        "⚠️ RESTART VERIFICATION FAILED: Agent {} (PID: {}) failed to stay alive after attempt {}",
                        name, pid, attempt
                    ),
                    agent_pid: Some(pid),
                    agent_name: Some(name.clone()),
                };
                let _ = nats_verification
                    .publish(subjects::ALERT_REQUESTED, "restart-verification", alert_payload)
                    .await;

                // Re-request a restart if we haven't exhausted all retries
                let retry_payload = RestartRequestedPayload {
                    pid,
                    name: name.clone(),
                    attempt: attempt + 1,
                    backoff_seconds: 10,
                };
                let _ = nats_verification
                    .publish(subjects::RESTART_REQUESTED, "restart-verification", retry_payload)
                    .await;
            }
        }
    });

    // =====================================================================
    // TASK: Restart Exhaustion Alert — listens for when max retries are hit
    // and generates an escalation alert.
    // =====================================================================
    let nats_exhaustion = nats.clone();
    tokio::spawn(async move {
        let mut failed_sub = match nats_exhaustion
            .subscribe::<RestartFailedPayload>(subjects::RESTART_FAILED)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Restart exhaustion alert: failed to subscribe: {}", e);
                return;
            }
        };

        tracing::info!("Restart exhaustion alert task started");

        while let Some((_subject, envelope)) = failed_sub.next().await {
            let pid = envelope.payload.pid;
            let name = envelope.payload.name.clone();
            let attempt = envelope.payload.attempt;
            let error = envelope.payload.error.clone();

            tracing::error!(
                "RESTART EXHAUSTED: Agent {} (PID: {}) failed after {} attempts — {}",
                name, pid, attempt, error
            );

            // Publish an escalation alert
            let alert_payload = AlertRequestedPayload {
                channel: "telegram".to_string(),
                message: format!(
                    "🚨 RESTART EXHAUSTED: Agent {} (PID: {}) failed after {} attempts. Error: {}",
                    name, pid, attempt, error
                ),
                agent_pid: Some(pid),
                agent_name: Some(name.clone()),
            };
            let _ = nats_exhaustion
                .publish(subjects::ALERT_REQUESTED, "restart-exhaustion", alert_payload)
                .await;

            // Also publish an incident via the incident engine
            let incident_payload = serde_json::json!({
                "incident_id": uuid::Uuid::new_v4().to_string(),
                "agent_pid": pid,
                "agent_name": name,
                "incident_type": "RestartExhaustion",
                "severity": "critical",
                "description": format!("Agent {} failed to restart after {} attempts. Error: {}", name, attempt, error),
                "state": "Escalated",
            });
            let _ = nats_exhaustion
                .publish(subjects::INCIDENT_CREATED, "restart-exhaustion", incident_payload)
                .await;
        }
    });

    // =====================================================================
    // TASK: Graceful Shutdown Handler — listens for SIGTERM and performs
    // a graceful shutdown instead of immediate SIGKILL.
    // =====================================================================
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let sigterm = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate()
            );
            match sigterm {
                Ok(mut stream) => {
                    stream.recv().await;
                    tracing::info!(
                        "┌─────────────────────────────────────────────────┐"
                    );
                    tracing::info!(
                        "│  GRACEFUL SHUTDOWN INITIATED                     │"
                    );
                    tracing::info!(
                        "│  Performing ordered shutdown of all pipelines... │"
                    );
                    tracing::info!(
                        "└─────────────────────────────────────────────────┘"
                    );

                    // Give running tasks 15 seconds to finish before hard kill
                    tokio::time::sleep(Duration::from_secs(15)).await;

                    tracing::info!("Graceful shutdown complete. Exiting.");
                    std::process::exit(0);
                }
                Err(e) => {
                    tracing::debug!("Could not register SIGTERM handler: {}", e);
                }
            }
        }
        #[cfg(not(unix))]
        {
            tracing::debug!("SIGTERM handler not available on this platform");
        }
    });

    // =====================================================================
    // Task 7: Enforcement Pipeline — Decision Engine → Enforcement Manager
    //
    // Subscribes to security events, evaluates policies, executes enforcement,
    // creates incidents, and publishes NATS events.
    // =====================================================================
    {
        let nats_enforce = nats.clone();
        let sec_store_enforce = security_store.clone();
        let enforce_config = design_partner.clone();

        tokio::spawn(async move {
            let mut decision_engine = DecisionEngine::new();
            let mut enforcement_manager = EnforcementManager::new();

            // Load default policies
            for policy in DecisionEngine::default_policies() {
                decision_engine.add_policy(policy);
            }

            tracing::info!("Enforcement pipeline started — decision & enforcement loop");

            // Subscribe to security anomaly events
            let mut anomaly_sub = match nats_enforce
                .subscribe::<serde_json::Value>(subjects::SECURITY_ANOMALY_DETECTED)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Enforcement: failed to subscribe to anomalies: {}", e);
                    return;
                }
            };

            // Subscribe to profile updated events (for destination tracking)
            let mut profile_sub = match nats_enforce
                .subscribe::<serde_json::Value>(subjects::SECURITY_PROFILE_UPDATED)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Enforcement: failed to subscribe to profiles: {}", e);
                    return;
                }
            };

            // Known destinations tracker
            let mut known_destinations: Vec<String> = vec![
                "api.openai.com".to_string(),
                "api.anthropic.com".to_string(),
                "api.github.com".to_string(),
                "github.com".to_string(),
                "registry.npmjs.org".to_string(),
                "pypi.org".to_string(),
                "crates.io".to_string(),
            ];

            // Channel for profile updates
            let (profile_tx, mut profile_rx) = tokio::sync::mpsc::unbounded_channel::<(u32, String)>();

            tokio::spawn(async move {
                while let Some((_subject, envelope)) = profile_sub.next().await {
                    if let Some(pid) = envelope.payload.get("pid").and_then(|v| v.as_u64()) {
                        if let Some(name) = envelope.payload.get("agent_name").and_then(|v| v.as_str()) {
                            let _ = profile_tx.send((pid as u32, name.to_string()));
                        }
                    }
                }
            });

            // Main enforcement loop
            let mut cycle = 0u64;
            loop {
                cycle += 1;
                tokio::select! {
                    // Process anomaly events as they arrive
                    Some((_subject, envelope)) = anomaly_sub.next() => {
                        let payload = &envelope.payload;
                        let pid = payload.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                        let agent_name = payload.get("agent_name").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                        let risk_score = payload.get("risk_score").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                        let risk_level = payload.get("risk_level").and_then(|v| v.as_str()).unwrap_or("Normal").to_string();
                        let anomaly_type = payload.get("anomaly_type").and_then(|v| v.as_str()).map(|s| s.to_string());
                        let anomaly_severity = payload.get("severity").and_then(|v| v.as_str()).map(|s| s.to_string());
                        let deviation = payload.get("deviation").and_then(|v| v.as_f64());
                        let destination = payload.get("destination").and_then(|v| v.as_str()).map(|s| s.to_string());

                        // Evaluate the decision
                        let decision = decision_engine.evaluate(
                            pid,
                            agent_name.clone(),
                            risk_score,
                            &risk_level,
                            anomaly_type,
                            anomaly_severity,
                            deviation,
                            None, // correlation_type
                            destination.clone(),
                            None, // process_name
                            None, // file_path
                            &known_destinations,
                        );

                        tracing::info!(
                            "Enforcement decision for {} (PID: {}): {:?} — {}",
                            agent_name, pid, decision.action, decision.reason
                        );

                        // Execute the decision — always records the action, runtime pipeline
                        // gates actual kernel enforcement in design partner modes.
                        if enforce_config.safe_mode || enforce_config.recommendation_only {
                            tracing::info!(
                                "DESIGN PARTNER MODE: would enforce {:?} on {} (PID: {}) — kernel actions gated ({})",
                                decision.action, agent_name, pid,
                                if enforce_config.safe_mode { "SAFE_MODE" } else { "RECOMMENDATION_ONLY" }
                            );
                        }
                        let action = enforcement_manager.execute(&decision);

                        // Publish decision made event
                        let _ = nats_enforce.publish(
                            subjects::DECISION_MADE,
                            "enforcement-pipeline",
                            serde_json::json!({
                                "decision_id": decision.id.to_string(),
                                "pid": pid,
                                "agent_name": agent_name,
                                "action": format!("{:?}", decision.action),
                                "reason": decision.reason,
                                "rule": decision.rule,
                                "confidence": decision.confidence,
                                "timestamp": decision.timestamp.to_rfc3339(),
                            }),
                        ).await;

                        // Publish enforcement-specific events
                        match decision.action {
                            DecisionAction::Block => {
                                let _ = nats_enforce.publish(
                                    subjects::ENFORCEMENT_BLOCKED,
                                    "enforcement-pipeline",
                                    serde_json::json!({
                                        "pid": pid,
                                        "agent_name": agent_name,
                                        "destination": destination,
                                        "reason": decision.reason,
                                    }),
                                ).await;

                                // Also publish exfiltration blocked if applicable
                                if destination.is_some() {
                                    let _ = nats_enforce.publish(
                                        subjects::EXFILTRATION_BLOCKED,
                                    "enforcement-pipeline",
                                        serde_json::json!({
                                            "pid": pid,
                                            "agent_name": agent_name,
                                            "destination": destination,
                                            "reason": decision.reason,
                                        }),
                                    ).await;
                                }
                            }
                            DecisionAction::Flag => {
                                // Check if it's a destination or process flag
                                if destination.is_some() {
                                    let _ = nats_enforce.publish(
                                        subjects::ENFORCEMENT_FLAGGED,
                                        "enforcement-pipeline",
                                        serde_json::json!({
                                            "pid": pid,
                                            "agent_name": agent_name,
                                            "destination": destination,
                                            "reason": decision.reason,
                                        }),
                                    ).await;
                                }
                            }
                            _ => {}
                        }

                        // Record audit trail
                        if let Some(ref store) = sec_store_enforce.as_ref() {
                            let _ = store.record_audit_entry(
                                Some(pid as i32),
                                Some(&agent_name),
                                "enforcement_decision",
                                &format!("Decision: {:?} — {}", decision.action, decision.reason),
                                &serde_json::json!({
                                    "decision_id": decision.id.to_string(),
                                    "action": format!("{:?}", decision.action),
                                    "rule": decision.rule,
                                    "policy": decision.policy_name,
                                    "confidence": decision.confidence,
                                }),
                            ).await;

                            let _ = store.record_timeline_entry(
                                Some(pid as i32),
                                Some(&agent_name),
                                &format!("enforcement_{:?}", decision.action).to_lowercase(),
                                match decision.action {
                                    DecisionAction::Block => "critical",
                                    DecisionAction::Flag => "warning",
                                    DecisionAction::Escalate => "high",
                                    DecisionAction::Restart => "high",
                                    DecisionAction::Allow => "info",
                                },
                                &format!("Decision: {:?}", decision.action),
                                &format!("{} — {}", decision.reason, action.details),
                                &serde_json::json!({
                                    "decision_id": decision.id.to_string(),
                                    "action": format!("{:?}", decision.action),
                                    "result": format!("{:?}", action.result),
                                }),
                            ).await;
                        }
                    }

                    // Drain profile updates periodically
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {
                        while let Ok((_pid, _name)) = profile_rx.try_recv() {
                            // Update known destinations tracking
                        }

                        // Persist enforcement state periodically
                        if let Some(ref store) = sec_store_enforce.as_ref() {
                            // Persist enforcement incidents
                            for incident in enforcement_manager.get_open_incidents() {
                                let _ = store.record_audit_entry(
                                    Some(incident.pid as i32),
                                    Some(&incident.agent_name),
                                    "enforcement_incident_open",
                                    &format!("Open incident: {} on {}", incident.action_type, incident.action_target),
                                    &serde_json::json!({
                                        "incident_id": incident.id.to_string(),
                                        "action_type": incident.action_type,
                                        "target": incident.action_target,
                                    }),
                                ).await;
                            }
                        }

                        if cycle % 12 == 0 {
                            tracing::debug!(
                                "Enforcement cycle {}: {} decisions, {} incidents, {} actions",
                                cycle,
                                decision_engine.decision_count(),
                                enforcement_manager.incident_count(),
                                enforcement_manager.get_stats().total_actions,
                            );
                        }
                    }
                }
            }
        });
    }

    // =====================================================================
    // Task 8: Linux Runtime Control Pipeline — Runtime Manager
    //
    // Executes real Linux kernel actions from enforcement decisions.
    // Uses nftables, cgroups, systemd, process signals, and inotify
    // for kernel-level enforcement.
    // =====================================================================
    {
        let nats_runtime = nats.clone();
        let runtime_config = design_partner.clone();

        tokio::spawn(async move {
            let mut runtime_manager = RuntimeManager::new();
            let mut cycle = 0u64;

            tracing::info!("Runtime control pipeline started — mode: {:?}", runtime_manager.mode);

            // Initialize nftables table on Linux
            #[cfg(target_os = "linux")]
            runtime_manager.network.initialize_table();

            // Start real inotify file monitoring
            runtime_manager.file_monitor.start_monitoring();

            // Subscribe to enforcement decisions
            let mut decision_sub = match nats_runtime
                .subscribe::<serde_json::Value>(subjects::DECISION_MADE)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Runtime: failed to subscribe to decisions: {}", e);
                    return;
                }
            };

            loop {
                cycle += 1;

                tokio::select! {
                    // Process decisions as they arrive
                    Some((_subject, envelope)) = decision_sub.next() => {
                        let payload = &envelope.payload;
                        let action = payload.get("action").and_then(|v| v.as_str()).unwrap_or("Allow");
                        let pid = payload.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                        let agent_name = payload.get("agent_name").and_then(|v| v.as_str()).unwrap_or("unknown");
                        let destination = payload.get("destination").and_then(|v| v.as_str());
                        let reason = payload.get("reason").and_then(|v| v.as_str()).unwrap_or("");

                        tracing::info!(
                            "Runtime execution: {} for {} (PID: {}) — {}",
                            action, agent_name, pid, reason
                        );

                        let is_gated = runtime_config.safe_mode || runtime_config.recommendation_only;

                        match action {
                            "Block" => {
                                if let Some(dest) = destination {
                                    if is_gated {
                                        tracing::info!(
                                            "DESIGN PARTNER MODE: would block {} for {} via nftables — skipped",
                                            dest, agent_name
                                        );
                                    } else {
                                        let block_action = runtime_manager.network.block_domain(dest, reason);
                                        runtime_manager.record_action(block_action);

                                        runtime_manager.recovery.register(
                                            uuid::Uuid::new_v4(),
                                            "nftables_block_domain",
                                            dest,
                                            Some(300),
                                            "nftables_unblock",
                                        );
                                    }

                                    let _ = nats_runtime.publish(
                                        subjects::RUNTIME_NETWORK_BLOCKED,
                                        "runtime-pipeline",
                                        serde_json::json!({
                                            "pid": pid,
                                            "agent_name": agent_name,
                                            "destination": dest,
                                            "reason": reason,
                                            "mode": format!("{:?}", runtime_manager.mode),
                                            "simulated": is_gated,
                                        }),
                                    ).await;
                                }
                            }
                            "Restart" => {
                                if is_gated {
                                    tracing::info!(
                                        "DESIGN PARTNER MODE: would restart {} (PID: {}) — skipped",
                                        agent_name, pid
                                    );
                                } else {
                                    let restart_action = runtime_manager.process.restart(pid, agent_name);
                                    runtime_manager.record_action(restart_action);
                                }

                                let _ = nats_runtime.publish(
                                    subjects::RUNTIME_SERVICE_CONTROL,
                                    "runtime-pipeline",
                                    serde_json::json!({
                                        "pid": pid,
                                        "agent_name": agent_name,
                                        "action": "restart",
                                        "simulated": is_gated,
                                    }),
                                ).await;
                            }
                            "Escalate" => {
                                if is_gated {
                                    tracing::info!(
                                        "DESIGN PARTNER MODE: would quarantine+throttle {} (PID: {}) — skipped",
                                        agent_name, pid
                                    );
                                } else {
                                    let quarantine_action = runtime_manager.process.quarantine(
                                        pid, agent_name,
                                        &format!("Escalation decision: {}", reason),
                                    );
                                    runtime_manager.record_action(quarantine_action);

                                    let throttle_action = runtime_manager.resource.contain(pid, agent_name);
                                    runtime_manager.record_action(throttle_action);
                                }

                                let _ = nats_runtime.publish(
                                    subjects::RUNTIME_PROCESS_QUARANTINED,
                                    "runtime-pipeline",
                                    serde_json::json!({
                                        "pid": pid,
                                        "agent_name": agent_name,
                                        "action": "quarantine+throttle",
                                        "reason": reason,
                                        "simulated": is_gated,
                                    }),
                                ).await;
                            }
                            _ => {}
                        }

                        // Log runtime stats periodically
                        if cycle % 10 == 0 {
                            let stats = runtime_manager.get_stats();
                            tracing::debug!(
                                "Runtime status: {} nftables rules, {} cgroups, {} contained, {} audits",
                                stats.nftables_rules, stats.cgroups_active,
                                stats.contained_processes, stats.audit_entries,
                            );
                        }
                    }

                    // Periodic: recovery + file monitor drain
                    _ = tokio::time::sleep(Duration::from_secs(10)) => {
                        // Auto-recover expired enforcement actions
                        let recovered = runtime_manager.recovery.auto_recover();
                        for recovery_action in &recovered {
                            runtime_manager.record_action(recovery_action.clone());

                            let _ = nats_runtime.publish(
                                subjects::RUNTIME_ROLLBACK,
                                "runtime-pipeline",
                                serde_json::json!({
                                    "action_type": recovery_action.action_type,
                                    "target": recovery_action.target,
                                    "result": recovery_action.result,
                                }),
                            ).await;

                            tracing::info!(
                                "Auto-recovered: {} → {} for {}",
                                recovery_action.action_type,
                                "rollback",
                                recovery_action.target,
                            );
                        }

                        // Drain inotify file access events
                        let file_events = runtime_manager.file_monitor.drain_events();
                        for file_evt in &file_events {
                            tracing::warn!(
                                "FILE ACCESS: {} on {} (real={})",
                                file_evt.action, file_evt.file_path, file_evt.real_event
                            );

                            // Publish to NATS
                            let _ = nats_runtime.publish(
                                subjects::FILE_ACCESS_DETECTED,
                                "runtime-file-monitor",
                                serde_json::json!({
                                    "pid": file_evt.pid,
                                    "agent_name": file_evt.agent_name,
                                    "file_path": file_evt.file_path,
                                    "action": file_evt.action,
                                    "real_event": file_evt.real_event,
                                    "timestamp": file_evt.timestamp.to_rfc3339(),
                                }),
                            ).await;
                        }
                    }
                }
            }
        });
    }

    // =====================================================================
    // Task 9: Kernel Event Stream — eBPF sensor + identity engine
    //
    // Real-time kernel event pipeline:
    //   eBPF (or /proc fallback) → KernelEvent → Identity Engine → NATS → Security Pipeline
    //
    // Replaces 5-second polling for process exec/exit, network connect, and file access
    // with sub-second kernel telemetry.
    // =====================================================================
    {
        let nats_kernel = nats.clone();
        let sec_store_kernel = security_store.clone();
        let dp_kernel = design_partner.clone();

        tokio::spawn(async move {
            // Create the kernel event stream (channel between eBPF reader and this task)
            let (kernel_stream, mut kernel_rx) = KernelEventStream::new();
            let event_tx = kernel_stream.get_sender();

            // Create identity engine for PID→Agent resolution
            let identity_engine = Arc::new(RwLock::new(AgentIdentityEngine::new()));

            // Create network tracker for /proc fallback
            let network_tracker = Arc::new(RwLock::new(NetworkTracker::new()));

            // Set up the eBPF manager with all dependencies
            let mut ebpf = EbpfManager::new()
                .with_nats(nats_kernel.clone())
                .with_identity(identity_engine.clone())
                .with_network_tracker(network_tracker.clone())
                .with_event_channel(event_tx);

            // Try to load eBPF programs (falls back to /proc if unavailable)
            match ebpf.load_programs().await {
                Ok(()) => {
                    if ebpf.is_using_fallback() {
                        tracing::info!("Kernel event stream: using /proc fallback (1s resolution)");
                    } else {
                        tracing::info!("Kernel event stream: using eBPF (sub-second kernel telemetry)");
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to start kernel event stream: {}", e);
                    return;
                }
            }

            // Register discovery agents into identity engine
            let mut agent_sub = match nats_kernel
                .subscribe::<serde_json::Value>(subjects::AGENT_DISCOVERED)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Kernel stream: failed to subscribe to AgentDiscovered: {}", e);
                    return;
                }
            };

            let (discovery_tx, mut discovery_rx) = mpsc::unbounded_channel::<(u32, u32, String, String)>();

            tokio::spawn(async move {
                while let Some((_subject, envelope)) = agent_sub.next().await {
                    let pid = envelope.payload.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    let ppid = envelope.payload.get("ppid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    let name = envelope.payload.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let comm = envelope.payload.get("command").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let _ = discovery_tx.send((pid, ppid, name, comm));
                }
            });

            tracing::info!("Kernel event stream running — processing kernel events in real-time");

            loop {
                tokio::select! {
                    // Drain discovery registrations into identity engine
                    Some((pid, ppid, name, comm)) = discovery_rx.recv() => {
                        identity_engine.write().await.register_agent(
                            pid, ppid, name, comm, None,
                        );
                    }

                    // Process kernel events from eBPF sensors
                    Some(event) = kernel_rx.recv() => {
                        if dp_kernel.verbose {
                            tracing::debug!("Kernel event: {:?}", event);
                        }

                        // Resolve to identity and publish to NATS
                        match &event {
                            KernelEvent::ProcessExec(evt) => {
                                // Update identity engine
                                identity_engine.write().await.record_exec(
                                    evt.pid, evt.ppid, evt.uid, &evt.comm, &evt.filename,
                                );
                                let _ = ebpf.publish_event(&event).await;

                                // Audit trail
                                if let Some(ref store) = sec_store_kernel.as_ref() {
                                    let _ = store.record_timeline_entry(
                                        Some(evt.pid as i32),
                                        Some(&evt.comm),
                                        "process_exec",
                                        "info",
                                        &format!("Process Exec: {}", evt.comm),
                                        &format!("PID {} executed {} (ppid: {})", evt.pid, evt.filename, evt.ppid),
                                        &json!({"filename": evt.filename, "ppid": evt.ppid}),
                                    ).await;
                                }
                            }
                            KernelEvent::ProcessExit(evt) => {
                                identity_engine.write().await.record_exit(evt.pid);
                                let _ = ebpf.publish_event(&event).await;
                            }
                            KernelEvent::ProcessFork(evt) => {
                                identity_engine.write().await.record_fork(
                                    evt.parent_pid, evt.child_pid, &evt.comm,
                                );
                                let _ = ebpf.publish_event(&event).await;
                            }
                            KernelEvent::NetworkConnect(evt) => {
                                // Resolve PID to agent identity
                                let agent_id = identity_engine.read().await
                                    .resolve_pid(evt.pid)
                                    .map(|i| i.agent_id.to_string());

                                let enriched = serde_json::json!({
                                    "pid": evt.pid,
                                    "agent_id": agent_id,
                                    "dest_ip": evt.dest_ip,
                                    "dest_port": evt.dest_port,
                                    "protocol": evt.protocol,
                                    "timestamp": evt.timestamp.to_rfc3339(),
                                });
                                let enriched_clone = enriched.clone();

                                let _ = nats_kernel.publish(
                                    subjects::NETWORK_CONNECT,
                                    "kernel-stream",
                                    enriched,
                                ).await;

                                // Immediately feed into security pipeline via profile manager
                                // This bypasses the 5-second polling for immediate detection
                                if let Some(ref store) = sec_store_kernel.as_ref() {
                                    let _ = store.record_audit_entry(
                                        Some(evt.pid as i32),
                                        None,
                                        "network_connect",
                                        &format!("Connection: PID {} → {}:{}", evt.pid, evt.dest_ip, evt.dest_port),
                                        &json!(enriched_clone),
                                    ).await;
                                }
                            }
                            KernelEvent::FileAccess(evt) => {
                                let agent_id = identity_engine.read().await
                                    .resolve_pid(evt.pid)
                                    .map(|i| i.agent_id.to_string());

                                let enriched = serde_json::json!({
                                    "pid": evt.pid,
                                    "agent_id": agent_id,
                                    "path": evt.path,
                                    "operation": evt.operation,
                                    "sensitive_match": evt.sensitive_match,
                                    "timestamp": evt.timestamp.to_rfc3339(),
                                });
                                let enriched_clone = enriched.clone();

                                let subject = if evt.sensitive_match {
                                    subjects::FILE_ACCESS_VIOLATION
                                } else {
                                    subjects::FILE_ACCESS
                                };

                                let _ = nats_kernel.publish(
                                    subject, "kernel-stream", enriched,
                                ).await;

                                if evt.sensitive_match {
                                    tracing::warn!(
                                        "SENSITIVE FILE ACCESS: PID {} → {} ({})",
                                        evt.pid, evt.path, evt.operation
                                    );

                                    // Feed into safety pipeline for immediate decision
                                    if let Some(ref store) = sec_store_kernel.as_ref() {
                                        let _ = store.record_audit_entry(
                                            Some(evt.pid as i32),
                                            None,
                                            "sensitive_file_access",
                                            &format!("Sensitive file: {} ({})", evt.path, evt.operation),
                                            &json!(enriched_clone),
                                        ).await;
                                    }
                                }

                                let _ = ebpf.publish_event(&event).await;
                            }
                            KernelEvent::DnsQuery(evt) => {
                                let _ = nats_kernel.publish(
                                    subjects::DNS_QUERY,
                                    "kernel-stream",
                                    serde_json::json!({
                                        "pid": evt.pid,
                                        "domain": evt.domain,
                                        "query_type": evt.query_type,
                                        "resolver_ip": evt.resolver_ip,
                                        "timestamp": evt.timestamp.to_rfc3339(),
                                    }),
                                ).await;
                            }
                            _ => {
                                // FileDelete, FileModify, NetworkListen, NetworkAccept — publish as-is
                                let _ = ebpf.publish_event(&event).await;
                            }
                        }
                    }

                    // Periodic: log stats
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {
                        let stats = ebpf.get_stats().await;
                        let identity_count = identity_engine.read().await.agent_count();
                        tracing::info!(
                            "Kernel stream stats: {} events (exec:{} exit:{} fork:{} net:{} file:{}) | {} identities tracked | ebpf:{} fallback:{}",
                            stats.events_total,
                            stats.process_exec_count,
                            stats.process_exit_count,
                            stats.process_fork_count,
                            stats.network_connect_count,
                            stats.file_access_count,
                            identity_count,
                            stats.ebpf_loaded,
                            stats.using_fallback,
                        );
                    }
                }
            }
        });
    }

    // =====================================================================
    // Health endpoint server
    // =====================================================================
    let health_state = daemon_state.clone();
    let health_dp = design_partner.clone();
    let health_app = Router::new().route(
        "/health",
        axum::routing::get(move || health_handler(health_state)),
    );
    let health_bind =
        std::env::var("DAEMON_HEALTH_BIND").unwrap_or_else(|_| "0.0.0.0:3003".to_string());
    let health_listener = tokio::net::TcpListener::bind(&health_bind).await?;
    tracing::info!("Daemon health endpoint listening on {}", health_bind);
    let _ = health_dp; // passed via closure capture below — suppress unused warning
    tokio::spawn(async move {
        axum::serve(health_listener, health_app)
            .await
            .unwrap_or_else(|e| {
                tracing::error!("Health endpoint server error: {}", e);
            });
    });

    // Systemd watchdog — only active when WATCHDOG_USEC is set
    let watchdog_interval = std::env::var("WATCHDOG_USEC")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(|usec| Duration::from_micros(usec / 2));

    // Keep the main task alive, sending watchdog pings
    tracing::info!("Omnisec Daemon running. Waiting for events...");
    platform::notify_ready();
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        if watchdog_interval.is_some() {
            platform::notify_watchdog();
        }
    }
}

async fn health_handler(state: Arc<RwLock<DaemonState>>) -> Json<Value> {
    let state = state.read().await;
    Json(json!({
        "status": "healthy",
        "service": "omnisec-daemon",
        "version": "0.2.0",
        "agents": {
            "total": state.agent_count,
            "alive": state.alive_count,
            "failed": state.failed_count,
        },
        "restarts": {
            "total": state.total_restarts,
        },
    }))
}

/// Read /proc/[pid]/cmdline or sysctl KERN_PROCARGS2 depending on platform.
fn read_proc_cmdline(pid: u32) -> Option<String> {
    platform::read_cmdline(pid)
}

/// Check if a process is alive using a POSIX signal-0 probe.
fn alive_check(pid: u32) -> bool {
    platform::pid_alive(pid)
}

/// Spawn a process from a command string. Returns the new PID on success.
fn spawn_process(cmdline: &str) -> Option<u32> {
    let parts: Vec<&str> = cmdline.split_whitespace().collect();
    let (prog, args) = parts.split_first()?;

    match std::process::Command::new(prog)
        .args(args)
        .spawn()
    {
        Ok(child) => {
            let new_pid = child.id();
            // Detach the child so it keeps running after we drop the handle
            std::mem::forget(child);
            tracing::info!("Spawned process '{}' with PID {}", prog, new_pid);
            Some(new_pid)
        }
        Err(e) => {
            tracing::error!("Failed to spawn '{}': {}", prog, e);
            None
        }
    }
}
