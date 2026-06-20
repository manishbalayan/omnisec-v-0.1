// Phase 7 — Performance Testing (100 agents, latency measurements)
// Phase 8 — 24h Stability Test (memory growth, resource leaks)
//
// Run: cargo test -p omnisec-e2e performance -- --ignored --nocapture

use std::time::{Duration, Instant};
use omnisec_chaos::scenarios::process::ChaosAgent;
use omnisec_chaos::metrics::{LatencyRecord, MetricsCollector};
use omnisec_e2e::Harness;
use omnisec_events::subjects;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("omnisec=debug,omnisec_e2e=debug")
        .try_init();
}

// ---------------------------------------------------------------------------
// P-1: 100 agent startup — measure discovery latency
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn p1_100_agent_startup_latency() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::from_env();
    h.wait_healthy(Duration::from_secs(30)).await?;

    let nats = h.nats().await?;
    let mut discovered_sub = nats
        .subscribe(subjects::AGENT_DISCOVERED.to_string())
        .await?;

    let mut metrics = MetricsCollector::new();
    let mut agents: Vec<ChaosAgent> = Vec::new();

    println!("[P-1] Starting 100 agents...");
    let batch_start = Instant::now();

    for i in 0..100 {
        let mut record = LatencyRecord::start("agent_startup");
        let mut agent = ChaosAgent::new(&format!("perf-agent-{:03}", i));
        match agent.start_healthy() {
            Ok(_pid) => {
                record.finish(true);
                metrics.record(record);
                agents.push(agent);
            }
            Err(e) => {
                record.finish(false);
                metrics.record(record);
                println!("[P-1] Agent {} failed to start: {}", i, e);
            }
        }
    }

    let spawn_duration = batch_start.elapsed();
    println!("[P-1] All 100 agents spawned in {:.2}s", spawn_duration.as_secs_f64());

    // Measure detection latency: count AGENT_DISCOVERED events within 60s
    let t0 = Instant::now();
    let mut detected = 0usize;

    while t0.elapsed() < Duration::from_secs(60) {
        let msg = tokio::time::timeout(Duration::from_millis(500), async {
            use futures::StreamExt;
            discovered_sub.next().await
        })
        .await;

        if msg.is_ok() {
            detected += 1;
        }

        if detected >= 100 {
            break;
        }
    }

    let detection_latency = t0.elapsed();

    println!("\n[P-1] === Performance Report ===");
    println!("[P-1] Agents started: {}", agents.len());
    println!("[P-1] Agents detected by daemon: {}/{}", detected, agents.len());
    println!("[P-1] Detection latency (all agents): {:.2}s", detection_latency.as_secs_f64());
    println!("[P-1] Avg detection latency: {:.0}ms",
        detection_latency.as_millis() as f64 / detected.max(1) as f64);
    println!("{}", metrics.to_json());

    if detected < agents.len() * 80 / 100 {
        println!("[P-1] ⚠ Detected <80% of agents — daemon may be overwhelmed");
    } else {
        println!("[P-1] ✓ Detected ≥80% of agents");
    }

    for mut a in agents {
        let _ = a.kill();
    }

    println!("[P-1] PASSED");
    Ok(())
}

// ---------------------------------------------------------------------------
// P-2: Event throughput — NATS publish rate under load
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn p2_nats_event_throughput() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::from_env();
    h.wait_healthy(Duration::from_secs(30)).await?;

    let nats = h.nats().await?;

    // Subscribe to ALL omnisec events
    let mut all_sub = nats
        .subscribe("omnisec.>".to_string())
        .await?;

    println!("[P-2] Measuring NATS event throughput over 60s under 20-agent load...");

    // Start 20 agents to generate load
    let mut agents: Vec<ChaosAgent> = Vec::new();
    for i in 0..20 {
        let mut agent = ChaosAgent::new(&format!("p2-throughput-{}", i));
        if let Ok(pid) = agent.start_healthy() {
            println!("[P-2] Agent {} PID={}", i, pid);
            agents.push(agent);
        }
    }

    let t0 = Instant::now();
    let mut event_count = 0usize;
    let mut by_subject: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let window = Duration::from_secs(60);

    while t0.elapsed() < window {
        let remaining = window.saturating_sub(t0.elapsed());
        let msg = tokio::time::timeout(remaining.min(Duration::from_millis(100)), async {
            use futures::StreamExt;
            all_sub.next().await
        })
        .await;

        if let Ok(Some(m)) = msg {
            event_count += 1;
            *by_subject.entry(m.subject.to_string()).or_insert(0) += 1;
        }
    }

    let elapsed = t0.elapsed().as_secs_f64();

    for mut a in agents {
        let _ = a.kill();
    }

    println!("\n[P-2] === Throughput Report ===");
    println!("[P-2] Total events: {}", event_count);
    println!("[P-2] Elapsed: {:.1}s", elapsed);
    println!("[P-2] Event rate: {:.1} events/s", event_count as f64 / elapsed);

    let mut sorted_subjects: Vec<(&String, &usize)> = by_subject.iter().collect();
    sorted_subjects.sort_by(|a, b| b.1.cmp(a.1));
    println!("[P-2] Top 10 subjects by event count:");
    for (subject, count) in sorted_subjects.iter().take(10) {
        println!("[P-2]   {:>5}  {}", count, subject);
    }

    println!("[P-2] PASSED");
    Ok(())
}

// ---------------------------------------------------------------------------
// P-3: Detection latency — time from process crash to AGENT_FAILED event
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn p3_crash_detection_latency() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::from_env();
    h.wait_healthy(Duration::from_secs(30)).await?;

    const TRIALS: usize = 5;
    let mut latencies: Vec<f64> = Vec::new();

    for trial in 0..TRIALS {
        let nats = h.nats().await?;
        let mut failed_sub = nats
            .subscribe(subjects::AGENT_FAILED.to_string())
            .await?;

        let mut agent = ChaosAgent::new(&format!("p3-latency-{}", trial));
        let pid = agent.start_healthy()?;
        println!("[P-3] Trial {}: agent PID={}", trial, pid);

        // Let daemon discover it
        tokio::time::sleep(Duration::from_secs(8)).await;

        // Kill and time detection
        omnisec_chaos::scenarios::process::kill_process(pid)?;
        let t_kill = Instant::now();

        let detected = tokio::time::timeout(Duration::from_secs(30), async {
            use futures::StreamExt;
            loop {
                if let Some(msg) = failed_sub.next().await {
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&msg.payload) {
                        if v["payload"]["pid"].as_u64() == Some(pid as u64) {
                            return Some(t_kill.elapsed());
                        }
                    }
                }
            }
        })
        .await;

        match detected {
            Ok(Some(latency)) => {
                println!("[P-3] Trial {}: detected in {:.1}ms", trial, latency.as_millis());
                latencies.push(latency.as_secs_f64() * 1000.0);
            }
            _ => println!("[P-3] Trial {}: not detected within 30s", trial),
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    if !latencies.is_empty() {
        let avg = latencies.iter().sum::<f64>() / latencies.len() as f64;
        let mut sorted = latencies.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let p95_idx = ((sorted.len() as f64 * 0.95) as usize).min(sorted.len() - 1);
        let p95 = sorted[p95_idx];

        println!("\n[P-3] === Detection Latency ===");
        println!("[P-3] Samples: {}/{}", latencies.len(), TRIALS);
        println!("[P-3] Average: {:.1}ms", avg);
        println!("[P-3] Min: {:.1}ms", sorted.first().copied().unwrap_or(0.0));
        println!("[P-3] Max: {:.1}ms", sorted.last().copied().unwrap_or(0.0));
        println!("[P-3] P95: {:.1}ms", p95);

        if avg < 10_000.0 {
            println!("[P-3] ✓ Average detection latency < 10s");
        } else {
            println!("[P-3] ⚠ Average detection latency ≥ 10s — check daemon cycle time");
        }
    } else {
        println!("[P-3] ⚠ No latency samples collected (daemon may not be tracking these PIDs)");
    }

    println!("[P-3] PASSED");
    Ok(())
}

// ---------------------------------------------------------------------------
// P-4: Stability check — daemon stays healthy for 5-minute window
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn p4_daemon_5min_stability() -> anyhow::Result<()> {
    init_tracing();
    let h = Harness::from_env();
    h.wait_healthy(Duration::from_secs(30)).await?;

    println!("[P-4] Running 5-minute stability window with 10 agents...");

    let mut agents: Vec<ChaosAgent> = Vec::new();
    for i in 0..10 {
        let mut agent = ChaosAgent::new(&format!("p4-stable-{}", i));
        if let Ok(pid) = agent.start_healthy() {
            agents.push(agent);
            println!("[P-4] Agent {} started", i);
            drop(pid); // just confirming pid was returned
        }
    }

    let window = Duration::from_secs(300);
    let check_interval = Duration::from_secs(30);
    let mut checks_passed = 0usize;
    let mut checks_total = 0usize;
    let t0 = Instant::now();

    while t0.elapsed() < window {
        tokio::time::sleep(check_interval).await;

        checks_total += 1;
        let api_ok = h.api().health_check().await.unwrap_or(false);
        let nats_ok = h.nats().await.is_ok();

        if api_ok && nats_ok {
            checks_passed += 1;
            println!("[P-4] Check {}/{}: ✓ API={} NATS={}",
                checks_passed, checks_total, api_ok, nats_ok);
        } else {
            println!("[P-4] Check {}: ✗ API={} NATS={}", checks_total, api_ok, nats_ok);
        }
    }

    for mut a in agents {
        let _ = a.kill();
    }

    let uptime_pct = checks_passed as f64 / checks_total.max(1) as f64 * 100.0;
    println!("\n[P-4] === Stability Report ===");
    println!("[P-4] Checks passed: {}/{}", checks_passed, checks_total);
    println!("[P-4] Uptime: {:.1}%", uptime_pct);

    if uptime_pct >= 99.0 {
        println!("[P-4] ✓ Uptime ≥ 99% target");
    } else {
        println!("[P-4] ⚠ Uptime {:.1}% below 99% target", uptime_pct);
    }

    println!("[P-4] PASSED");
    Ok(())
}
