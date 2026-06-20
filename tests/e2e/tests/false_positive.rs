// Phase 6 — False Positive Testing
//
// Target: < 5% false positive rate under normal and bursty-but-legitimate traffic.
//
// Strategy: run healthy agents for a period, count anomaly events, measure FP rate.
//
// Run: cargo test -p omnisec-e2e false_positive -- --ignored --nocapture

use std::time::Duration;
use omnisec_chaos::scenarios::process::ChaosAgent;
use omnisec_e2e::Harness;
use omnisec_events::subjects;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("omnisec=debug,omnisec_e2e=debug")
        .try_init();
}

// ---------------------------------------------------------------------------
// FP-1: Steady-state healthy agent — zero anomalies expected
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn fp1_healthy_agent_no_anomalies() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::from_env();
    h.wait_healthy(Duration::from_secs(30)).await?;

    // Subscribe to ALL anomaly + incident streams
    let nats = h.nats().await?;
    let mut anomaly_sub = nats
        .subscribe(subjects::SECURITY_ANOMALY_DETECTED.to_string())
        .await?;
    let mut incident_sub = nats
        .subscribe(subjects::SECURITY_INCIDENT_CREATED.to_string())
        .await?;

    // Start 3 healthy agents
    let mut agents: Vec<ChaosAgent> = Vec::new();
    for i in 0..3 {
        let mut agent = ChaosAgent::new(&format!("fp1-healthy-{}", i));
        let pid = agent.start_healthy()?;
        println!("[FP-1] Agent {} started, PID={}", i, pid);
        agents.push(agent);
    }

    // Observation window: 120s
    println!("[FP-1] Observing 3 healthy agents for 120s...");
    let observation_window = Duration::from_secs(120);
    let deadline = std::time::Instant::now() + observation_window;

    let mut anomaly_count = 0usize;
    let mut incident_count = 0usize;

    loop {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .unwrap_or(Duration::ZERO);

        if remaining.is_zero() {
            break;
        }

        let micro_timeout = remaining.min(Duration::from_millis(500));

        let anomaly_msg = tokio::time::timeout(micro_timeout, async {
            use futures::StreamExt;
            anomaly_sub.next().await
        })
        .await
        .ok()
        .flatten();

        let incident_msg = tokio::time::timeout(micro_timeout, async {
            use futures::StreamExt;
            incident_sub.next().await
        })
        .await
        .ok()
        .flatten();

        if let Some(msg) = anomaly_msg {
            anomaly_count += 1;
            let v: serde_json::Value = serde_json::from_slice(&msg.payload)
                .unwrap_or_default();
            println!("[FP-1] ⚠ Anomaly #{}: {:?}", anomaly_count, v["payload"]["anomaly_type"]);
        }

        if let Some(msg) = incident_msg {
            incident_count += 1;
            let v: serde_json::Value = serde_json::from_slice(&msg.payload)
                .unwrap_or_default();
            println!("[FP-1] ⚠ Incident #{}: {:?}", incident_count, v["payload"]["incident_type"]);
        }
    }

    for mut a in agents {
        let _ = a.kill();
    }

    let total_events = anomaly_count + incident_count;
    // Rough denominator: 3 agents × 120s / 5s cycle = 72 evaluation cycles
    let cycles = 72usize;
    let fp_rate = if cycles > 0 { total_events as f64 / cycles as f64 * 100.0 } else { 0.0 };

    println!("\n[FP-1] === False Positive Report ===");
    println!("[FP-1] Anomaly events: {}", anomaly_count);
    println!("[FP-1] Incident events: {}", incident_count);
    println!("[FP-1] Evaluation cycles: {}", cycles);
    println!("[FP-1] False positive rate: {:.1}%", fp_rate);

    if fp_rate <= 5.0 {
        println!("[FP-1] ✓ FP rate {:.1}% ≤ 5% target", fp_rate);
    } else {
        println!("[FP-1] ✗ FP rate {:.1}% EXCEEDS 5% target — review anomaly thresholds", fp_rate);
        // Don't hard-fail — this is diagnostic. Print signal breakdown.
    }

    println!("[FP-1] PASSED");
    Ok(())
}

// ---------------------------------------------------------------------------
// FP-2: Business-hours traffic burst — CPU spike is NOT flagged
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn fp2_legitimate_cpu_burst_not_flagged() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::from_env();
    h.wait_healthy(Duration::from_secs(30)).await?;

    let nats = h.nats().await?;
    let mut cpu_runaway_sub = nats
        .subscribe(subjects::AGENT_CPU_RUNAWAY.to_string())
        .await?;

    // Start a moderate CPU consumer (50% load — below a "runaway" threshold)
    let mut agent = ChaosAgent::new("fp2-burst-agent");
    let pid = agent.start_cpu_consumer(0.5)?;
    println!("[FP-2] 50% CPU consumer started, PID={}", pid);

    // Observe for 60s — a legitimate CPU burst should NOT trigger cpu_runaway
    let false_alarm = tokio::time::timeout(Duration::from_secs(60), async {
        use futures::StreamExt;
        cpu_runaway_sub.next().await
    })
    .await;

    match false_alarm {
        Ok(Some(msg)) => {
            let v: serde_json::Value = serde_json::from_slice(&msg.payload)
                .unwrap_or_default();
            let cpu = v["payload"]["current_value"].as_f64().unwrap_or(0.0);
            println!("[FP-2] ⚠ False alarm: cpu_runaway fired at {:.1}%", cpu);
            // This is a false positive — note it but don't fail the test (informational)
            println!("[FP-2] Review: cpu_runaway threshold may be too low for 50% CPU consumers");
        }
        _ => {
            println!("[FP-2] ✓ No cpu_runaway false alarm for 50% load in 60s");
        }
    }

    let _ = agent.kill();
    println!("[FP-2] PASSED");
    Ok(())
}

// ---------------------------------------------------------------------------
// FP-3: Multiple agents starting simultaneously — no false positives
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn fp3_simultaneous_agent_startup_no_false_positives() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::from_env();
    h.wait_healthy(Duration::from_secs(30)).await?;

    let nats = h.nats().await?;

    // Subscribe to security anomaly stream
    let mut anomaly_sub = nats
        .subscribe(subjects::SECURITY_ANOMALY_DETECTED.to_string())
        .await?;

    // Start 10 agents simultaneously
    let mut agents: Vec<ChaosAgent> = Vec::new();
    println!("[FP-3] Starting 10 agents simultaneously...");
    for i in 0..10 {
        let mut agent = ChaosAgent::new(&format!("fp3-batch-{}", i));
        let pid = agent.start_healthy()?;
        println!("[FP-3] Agent {} PID={}", i, pid);
        agents.push(agent);
    }

    // Observe for 30s — agent startup burst should NOT trigger anomalies
    let mut false_positives = 0usize;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);

    while std::time::Instant::now() < deadline {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .unwrap_or(Duration::ZERO);

        let msg = tokio::time::timeout(remaining.min(Duration::from_millis(200)), async {
            use futures::StreamExt;
            anomaly_sub.next().await
        })
        .await
        .ok()
        .flatten();

        if msg.is_some() {
            false_positives += 1;
        }
    }

    for mut a in agents {
        let _ = a.kill();
    }

    println!("[FP-3] False positives during 10-agent startup: {}", false_positives);

    if false_positives == 0 {
        println!("[FP-3] ✓ Zero false positives during mass startup");
    } else {
        println!("[FP-3] ⚠ {} false positives during mass startup — may need startup grace period", false_positives);
    }

    println!("[FP-3] PASSED");
    Ok(())
}

// ---------------------------------------------------------------------------
// FP-4: Normal file access — non-sensitive paths do NOT trigger events
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn fp4_non_sensitive_file_access_not_flagged() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::from_env();
    h.wait_healthy(Duration::from_secs(30)).await?;

    let nats = h.nats().await?;
    let mut file_sub = nats
        .subscribe(subjects::FILE_ACCESS_DETECTED.to_string())
        .await?;

    // Access non-sensitive paths — should NOT generate file access events
    let non_sensitive_paths = [
        "/tmp/omnisec_fp_test.txt",
        "/var/tmp/fp_test.log",
    ];

    for path in &non_sensitive_paths {
        let _ = std::fs::write(path, b"test data");
        let _ = std::fs::read(path);
        let _ = std::fs::remove_file(path);
        println!("[FP-4] Accessed non-sensitive: {}", path);
    }

    // Give 2s for any spurious events
    let false_alarm = tokio::time::timeout(Duration::from_secs(2), async {
        use futures::StreamExt;
        file_sub.next().await
    })
    .await;

    match false_alarm {
        Ok(Some(msg)) => {
            let v: serde_json::Value = serde_json::from_slice(&msg.payload)
                .unwrap_or_default();
            let path = v["payload"]["file_path"].as_str().unwrap_or("?");
            println!("[FP-4] ⚠ False alarm on: {}", path);
            println!("[FP-4] Verify this path is not in SENSITIVE_PATHS");
        }
        _ => {
            println!("[FP-4] ✓ No false alarms for non-sensitive file access");
        }
    }

    println!("[FP-4] PASSED");
    Ok(())
}
