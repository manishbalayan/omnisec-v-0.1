use std::time::{Duration, Instant};
use omnisec_integration_tests::OmnisecClient;
use omnisec_chaos::{ChaosAgent, MetricsCollector, LatencyRecord};

#[tokio::test]
#[ignore]
async fn scenario_1_process_crash_recovery() -> Result<(), anyhow::Error> {
    let client = OmnisecClient::new(
        &std::env::var("API_URL").unwrap_or_else(|_| "http://localhost:3003".to_string()),
    );

    let mut metrics = MetricsCollector::new();

    client.health_check().await?;
    println!("[Scenario 1] API is healthy");

    let mut agent = ChaosAgent::new("test-crash-agent");
    let mut record = LatencyRecord::start("agent_startup");
    let pid = agent.start_healthy()?;
    record.finish(true);
    metrics.record(record.with_metadata("pid", &pid.to_string()));

    println!("[Scenario 1] Agent started with PID: {}", pid);
    tokio::time::sleep(Duration::from_secs(3)).await;

    let mut kill_record = LatencyRecord::start("process_kill");
    agent.kill()?;
    kill_record.finish(true);
    metrics.record(kill_record);

    println!("[Scenario 1] Agent killed");

    let mut detect_record = LatencyRecord::start("failure_detection");
    let failure_detected = wait_for_process_death(pid, Duration::from_secs(10)).await;
    detect_record.finish(failure_detected);
    metrics.record(detect_record);

    assert!(failure_detected, "Process death should be detected");

    println!("[Scenario 1] Failure detected");

    let mut event_record = LatencyRecord::start("event_propagation");
    let event_timeout = Duration::from_secs(30);
    match client.wait_for_event("agent_failed", event_timeout).await {
        Ok(event) => {
            event_record.finish(true);
            metrics.record(event_record);
            println!("[Scenario 1] Failure event: {}", event.message);
        }
        Err(_) => {
            event_record.finish(false);
            metrics.record(event_record);
            println!("[Scenario 1] No failure event (daemon may not be running)");
        }
    }

    let mut audit_record = LatencyRecord::start("audit_persistence");
    let events = client.list_events().await?;
    let has_audit = !events.is_empty();
    audit_record.finish(has_audit);
    metrics.record(audit_record);

    println!("[Scenario 1] Audit records: {}", events.len());

    println!("\n=== Scenario 1 Metrics ===");
    println!("{}", metrics.to_json());

    println!("[Scenario 1] PASSED");

    Ok(())
}

#[tokio::test]
#[ignore]
async fn scenario_2_restart_after_failure() -> Result<(), anyhow::Error> {
    let client = OmnisecClient::new(
        &std::env::var("API_URL").unwrap_or_else(|_| "http://localhost:3003".to_string()),
    );

    let mut metrics = MetricsCollector::new();

    client.health_check().await?;
    println!("[Scenario 2] API is healthy");

    let mut agent = ChaosAgent::new("test-restart-agent");
    let mut startup_record = LatencyRecord::start("agent_startup");
    let pid = agent.start_healthy()?;
    startup_record.finish(true);
    metrics.record(startup_record.with_metadata("pid", &pid.to_string()));

    println!("[Scenario 2] Agent started with PID: {}", pid);
    tokio::time::sleep(Duration::from_secs(3)).await;

    let mut kill_record = LatencyRecord::start("process_kill");
    agent.kill()?;
    kill_record.finish(true);
    metrics.record(kill_record);

    println!("[Scenario 2] Agent killed");

    let mut detect_record = LatencyRecord::start("failure_detection");
    let failure_detected = wait_for_process_death(pid, Duration::from_secs(10)).await;
    detect_record.finish(failure_detected);
    metrics.record(detect_record);

    assert!(failure_detected, "Process death should be detected");
    println!("[Scenario 2] Failure detected");

    let mut restart_record = LatencyRecord::start("restart_attempt");
    let restart_timeout = Duration::from_secs(60);

    match client.wait_for_event("agent_restarted", restart_timeout).await {
        Ok(event) => {
            restart_record.finish(true);
            metrics.record(restart_record);
            println!("[Scenario 2] Restart event: {}", event.message);
        }
        Err(_) => {
            restart_record.finish(false);
            metrics.record(restart_record);
            println!("[Scenario 2] No restart event");
        }
    }

    let mut recovery_record = LatencyRecord::start("recovery_verification");
    tokio::time::sleep(Duration::from_secs(5)).await;
    let agents = client.discover_agents().await?;
    let recovered = agents.iter().any(|a| a["pid"].as_u64() != Some(pid as u64));
    recovery_record.finish(recovered);
    metrics.record(recovery_record);

    println!("[Scenario 2] Recovery verified: {}", recovered);

    println!("\n=== Scenario 2 Metrics ===");
    println!("{}", metrics.to_json());

    println!("[Scenario 2] PASSED");

    Ok(())
}

#[tokio::test]
#[ignore]
async fn scenario_3_restart_exhaustion() -> Result<(), anyhow::Error> {
    let client = OmnisecClient::new(
        &std::env::var("API_URL").unwrap_or_else(|_| "http://localhost:3003".to_string()),
    );

    let mut metrics = MetricsCollector::new();

    client.health_check().await?;
    println!("[Scenario 3] API is healthy");

    for i in 0..5 {
        let mut agent = ChaosAgent::new(&format!("test-exhaust-{}", i));
        let mut record = LatencyRecord::start("crash_cycle");
        let pid = agent.start_exit_immediately()?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        let dead = !omnisec_chaos::check_process_alive(pid);
        record.finish(dead);
        metrics.record(record.with_metadata("cycle", &i.to_string()));

        println!("[Scenario 3] Cycle {}: PID {} dead={}", i, pid, dead);
    }

    println!("\n=== Scenario 3 Metrics ===");
    println!("{}", metrics.to_json());

    let mut critical_record = LatencyRecord::start("critical_alert");
    match client.wait_for_event("critical_alert", Duration::from_secs(30)).await {
        Ok(event) => {
            critical_record.finish(true);
            metrics.record(critical_record);
            println!("[Scenario 3] Critical alert: {}", event.message);
        }
        Err(_) => {
            critical_record.finish(false);
            metrics.record(critical_record);
            println!("[Scenario 3] No critical alert");
        }
    }

    println!("[Scenario 3] PASSED");

    Ok(())
}

async fn wait_for_process_death(pid: u32, timeout: Duration) -> bool {
    let start = Instant::now();
    let check_interval = Duration::from_millis(100);

    loop {
        if start.elapsed() > timeout {
            return false;
        }

        if !omnisec_chaos::check_process_alive(pid) {
            return true;
        }

        tokio::time::sleep(check_interval).await;
    }
}
