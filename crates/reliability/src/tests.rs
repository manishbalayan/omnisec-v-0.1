use super::*;

#[test]
fn test_hang_detection() {
    let mut tracker = AgentActivityTracker::new(1234, "test-agent".to_string(), 5);

    let sample = ActivitySample {
        timestamp: chrono::Utc::now(),
        cpu_time_ms: 1000,
        memory_bytes: 1024 * 1024,
        fd_count: 10,
        thread_count: 4,
        network_rx_bytes: 100,
        network_tx_bytes: 50,
        disk_read_bytes: 0,
        disk_write_bytes: 0,
    };

    tracker.record_sample(sample);

    assert!(!tracker.detect_hang(), "Should not be hung immediately");

    let old_sample = ActivitySample {
        timestamp: chrono::Utc::now() - chrono::Duration::seconds(10),
        cpu_time_ms: 1000,
        memory_bytes: 1024 * 1024,
        fd_count: 10,
        thread_count: 4,
        network_rx_bytes: 100,
        network_tx_bytes: 50,
        disk_read_bytes: 0,
        disk_write_bytes: 0,
    };

    tracker.samples.clear();
    tracker.record_sample(old_sample);
    tracker.record_sample(ActivitySample {
        timestamp: chrono::Utc::now() - chrono::Duration::seconds(10),
        cpu_time_ms: 1000,
        memory_bytes: 1024 * 1024,
        fd_count: 10,
        thread_count: 4,
        network_rx_bytes: 100,
        network_tx_bytes: 50,
        disk_read_bytes: 0,
        disk_write_bytes: 0,
    });

    assert!(tracker.detect_hang(), "Should be hung after threshold");
    assert!(tracker.is_hung);
}

#[test]
fn test_memory_leak_detection() {
    let mut detector = MemoryLeakDetector::new(1234, "test-agent".to_string(), 5.0, 3);
    detector.window_size = 5;

    let base = 100 * 1024 * 1024u64;
    let increment = 10 * 1024 * 1024u64;

    for i in 0..8 {
        let sample = MemorySample {
            timestamp: chrono::Utc::now() - chrono::Duration::seconds((8 - i) * 10),
            rss_bytes: base + (i as u64 * increment),
            vsz_bytes: 200 * 1024 * 1024,
        };
        detector.record_sample(sample);
    }

    let leaking = detector.detect_leak();
    assert!(leaking, "Should detect memory leak");
    assert!(detector.is_leaking);
}

#[test]
fn test_cpu_runaway_detection() {
    let mut detector = CpuRunawayDetector::new(1234, "test-agent".to_string(), 80.0, 5);

    for i in 0..10 {
        let sample = CpuSample {
            timestamp: chrono::Utc::now() - chrono::Duration::seconds((10 - i) as i64),
            cpu_percent: 95.0,
            user_time_ms: 1000 + i * 100,
            system_time_ms: 100,
        };
        detector.record_sample(sample);
    }

    assert!(detector.detect_runaway(), "Should detect CPU runaway");
    assert!(detector.is_runaway);
}

#[test]
fn test_fd_exhaustion_detection() {
    let mut detector = FdExhaustionDetector::new(1234, "test-agent".to_string(), 80.0);

    let sample = FdSample {
        timestamp: chrono::Utc::now(),
        fd_count: 900,
        fd_limit: 1024,
    };
    detector.record_sample(sample);

    assert!(detector.detect_exhaustion(), "Should detect FD exhaustion");
    assert!(detector.is_exhausted);
}

#[test]
fn test_thread_explosion_detection() {
    let mut detector = ThreadExplosionDetector::new(1234, "test-agent".to_string(), 50.0, 500);

    for i in 0..10 {
        let sample = ThreadSample {
            timestamp: chrono::Utc::now() - chrono::Duration::seconds((10 - i) as i64),
            thread_count: 10 + i * 20,
        };
        detector.record_sample(sample);
    }

    assert!(detector.detect_explosion(), "Should detect thread explosion");
    assert!(detector.is_exploded);
}

#[test]
fn test_incident_engine() {
    let mut engine = IncidentEngine::new();

    let incident = engine.create_incident(
        None,
        "test-agent".to_string(),
        1234,
        IncidentType::AgentCrash,
        IncidentSeverity::High,
        "Agent crashed".to_string(),
        "Process exited unexpectedly".to_string(),
    );

    assert_eq!(incident.state, IncidentState::Open);
    assert_eq!(engine.get_open_incidents().len(), 1);

    engine.update_state(incident.id, IncidentState::Investigating);
    let updated = engine.get_incident(incident.id).unwrap();
    assert_eq!(updated.state, IncidentState::Investigating);

    engine.add_recovery_action(
        incident.id,
        "restart".to_string(),
        true,
        None,
        None,
    );

    engine.resolve_incident(incident.id, "Agent restarted successfully".to_string());
    let resolved = engine.get_incident(incident.id).unwrap();
    assert_eq!(resolved.state, IncidentState::Resolved);
    assert!(resolved.resolved_at.is_some());
}

#[test]
fn test_dependency_health_monitor() {
    let mut monitor = DependencyHealthMonitor::new();

    monitor.register_dependency(DependencyHealthCheck {
        name: "postgres".to_string(),
        dependency_type: DependencyType::Postgres,
        check_interval_secs: 5,
        timeout_secs: 2,
        failure_threshold: 3,
    });

    monitor.record_check_result("postgres", true, Some(1.5), None);
    let health = monitor.get_dependency_health("postgres").unwrap();
    assert_eq!(health.status, DependencyStatus::Healthy);

    for _ in 0..3 {
        monitor.record_check_result("postgres", false, None, Some("connection refused".to_string()));
    }

    let health = monitor.get_dependency_health("postgres").unwrap();
    assert_eq!(health.status, DependencyStatus::Failed);

    assert_eq!(monitor.get_system_status(), SystemStatus::Degraded);
}

#[test]
fn test_policy_engine() {
    let engine = PolicyEngine::with_defaults();

    assert!(engine.should_restart("crash"));
    assert!(engine.should_restart("hang"));
    assert!(!engine.should_restart("memory_leak"));

    assert!(engine.should_alert("crash"));
    assert!(engine.should_alert("memory_leak"));

    assert_eq!(engine.get_max_retries("crash"), 3);
    assert_eq!(engine.get_max_retries("hang"), 2);

    let channels = engine.get_alert_channels("crash");
    assert!(channels.contains(&"telegram".to_string()));
}

#[test]
fn test_reliability_metrics() {
    let mut engine = ReliabilityMetricsEngine::new();

    let now = chrono::Utc::now();
    engine.record_incident(
        "inc-1".to_string(),
        "test-agent".to_string(),
        now - chrono::Duration::minutes(10),
    );

    engine.record_recovery(
        "inc-1",
        now - chrono::Duration::minutes(5),
        Some("restart".to_string()),
    );

    let metrics = engine.get_agent_metrics("test-agent").unwrap();
    assert_eq!(metrics.total_incidents, 1);
    assert!(metrics.total_downtime_ms > 0);
}

#[test]
fn test_activity_delta_calculation() {
    let mut tracker = AgentActivityTracker::new(1234, "test-agent".to_string(), 10);

    tracker.record_sample(ActivitySample {
        timestamp: chrono::Utc::now(),
        cpu_time_ms: 1000,
        memory_bytes: 1024 * 1024,
        fd_count: 10,
        thread_count: 4,
        network_rx_bytes: 100,
        network_tx_bytes: 50,
        disk_read_bytes: 0,
        disk_write_bytes: 0,
    });

    tracker.record_sample(ActivitySample {
        timestamp: chrono::Utc::now(),
        cpu_time_ms: 1500,
        memory_bytes: 2 * 1024 * 1024,
        fd_count: 12,
        thread_count: 5,
        network_rx_bytes: 200,
        network_tx_bytes: 100,
        disk_read_bytes: 1024,
        disk_write_bytes: 512,
    });

    let delta = tracker.calculate_delta().unwrap();
    assert_eq!(delta.cpu_delta, 500);
    assert_eq!(delta.memory_delta, 1024 * 1024);
    assert_eq!(delta.fd_delta, 2);
    assert_eq!(delta.thread_delta, 1);
    assert_eq!(delta.network_rx_delta, 100);
    assert_eq!(delta.network_tx_delta, 50);
}

#[test]
fn test_cpu_rolling_average() {
    let mut detector = CpuRunawayDetector::new(1234, "test-agent".to_string(), 80.0, 5);

    for i in 0..10 {
        detector.record_sample(CpuSample {
            timestamp: chrono::Utc::now() - chrono::Duration::seconds((10 - i) as i64),
            cpu_percent: 50.0 + (i as f64 * 5.0),
            user_time_ms: i * 100,
            system_time_ms: 50,
        });
    }

    let avg = detector.get_rolling_average();
    assert!(avg > 0.0 && avg < 100.0);
}

#[test]
fn test_fd_growth_rate() {
    let mut detector = FdExhaustionDetector::new(1234, "test-agent".to_string(), 80.0);

    for i in 0..5 {
        detector.record_sample(FdSample {
            timestamp: chrono::Utc::now() - chrono::Duration::seconds((5 - i) as i64 * 10),
            fd_count: 100 + i * 50,
            fd_limit: 1024,
        });
    }

    let growth_rate = detector.get_growth_rate();
    assert!(growth_rate > 0.0);
}
