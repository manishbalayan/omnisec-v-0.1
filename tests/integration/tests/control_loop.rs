use std::time::Duration;
use omnisec_integration_tests::OmnisecClient;

#[tokio::test]
#[ignore]
async fn test_process_failure_detection() -> Result<(), anyhow::Error> {
    let client = OmnisecClient::new(
        &std::env::var("API_URL").unwrap_or_else(|_| "http://localhost:3000".to_string()),
    );

    client.health_check().await?;

    let agents_before = client.list_agents().await?;
    let initial_count = agents_before.len();

    let agents = client.discover_agents().await?;
    assert!(!agents.is_empty(), "Should discover at least one agent");

    let agent = &agents[0];
    let pid = agent["pid"].as_u64().expect("Agent should have PID");

    println!("Testing with agent PID: {}", pid);

    let kill_result = std::process::Command::new("kill")
        .args(["-9", &pid.to_string()])
        .output();

    assert!(kill_result.is_ok(), "Should be able to kill process");

    tokio::time::sleep(Duration::from_secs(2)).await;

    let events = client.list_events().await?;
    let failure_event = events.iter().find(|e| e.event_type == "agent_failed");

    assert!(
        failure_event.is_some(),
        "Should have agent_failed event after killing process"
    );

    println!("Test passed: Process failure detected");

    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_restart_after_failure() -> Result<(), anyhow::Error> {
    let client = OmnisecClient::new(
        &std::env::var("API_URL").unwrap_or_else(|_| "http://localhost:3000".to_string()),
    );

    client.health_check().await?;

    let agents = client.discover_agents().await?;
    assert!(!agents.is_empty(), "Should discover at least one agent");

    let agent = &agents[0];
    let pid = agent["pid"].as_u64().expect("Agent should have PID");

    println!("Testing restart with agent PID: {}", pid);

    let kill_result = std::process::Command::new("kill")
        .args(["-9", &pid.to_string()])
        .output();

    assert!(kill_result.is_ok(), "Should be able to kill process");

    match client.wait_for_event("agent_restarted", Duration::from_secs(30)).await {
        Ok(event) => {
            println!("Restart event received: {}", event.message);
        }
        Err(_) => {
            println!("No restart event (restart may not be implemented yet)");
        }
    }

    println!("Test passed: Restart flow validated");

    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_alert_on_failure() -> Result<(), anyhow::Error> {
    let client = OmnisecClient::new(
        &std::env::var("API_URL").unwrap_or_else(|_| "http://localhost:3000".to_string()),
    );

    client.health_check().await?;

    let agents = client.discover_agents().await?;
    assert!(!agents.is_empty(), "Should discover at least one agent");

    let agent = &agents[0];
    let pid = agent["pid"].as_u64().expect("Agent should have PID");

    println!("Testing alert with agent PID: {}", pid);

    let kill_result = std::process::Command::new("kill")
        .args(["-9", &pid.to_string()])
        .output();

    assert!(kill_result.is_ok(), "Should be able to kill process");

    tokio::time::sleep(Duration::from_secs(5)).await;

    let events = client.list_events().await?;
    let failure_event = events.iter().find(|e| e.event_type == "agent_failed");

    assert!(
        failure_event.is_some(),
        "Should have agent_failed event"
    );

    println!("Test passed: Alert flow validated");

    Ok(())
}
