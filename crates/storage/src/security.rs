use anyhow::Result;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// Security-specific storage operations for persistent security state.
pub struct SecurityStorage {
    pool: PgPool,
}

impl SecurityStorage {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // =====================================================================
    // Destination profiles
    // =====================================================================

    pub async fn upsert_destination(
        &self,
        pid: i32,
        agent_name: &str,
        domain: &str,
        ip: &str,
        port: i32,
        protocol: &str,
        bytes: i64,
    ) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO security_destination_profiles (pid, agent_name, domain, ip, port, protocol, last_seen, total_bytes, request_count)
               VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7, 1)
               ON CONFLICT (pid, ip, port, protocol)
               DO UPDATE SET
                   last_seen = NOW(),
                   total_bytes = security_destination_profiles.total_bytes + $7,
                   request_count = security_destination_profiles.request_count + 1"#,
        )
        .bind(pid)
        .bind(agent_name)
        .bind(domain)
        .bind(ip)
        .bind(port)
        .bind(protocol)
        .bind(bytes)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_destinations(&self, pid: i32) -> Result<Vec<Value>> {
        let rows = sqlx::query_scalar::<_, String>(
            r#"SELECT row_to_json(t) FROM (
                SELECT * FROM security_destination_profiles WHERE pid = $1 ORDER BY last_seen DESC
            ) t"#,
        )
        .bind(pid)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().filter_map(|r| serde_json::from_str(r).ok()).collect())
    }

    // =====================================================================
    // Traffic samples
    // =====================================================================

    pub async fn insert_traffic_sample(
        &self,
        pid: i32,
        agent_name: &str,
        bytes_in: i64,
        bytes_out: i64,
        request_count: i32,
        connection_count: i32,
        window_type: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO security_traffic_samples (pid, agent_name, bytes_in, bytes_out, request_count, connection_count, window_type)
               VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
        )
        .bind(pid)
        .bind(agent_name)
        .bind(bytes_in)
        .bind(bytes_out)
        .bind(request_count)
        .bind(connection_count)
        .bind(window_type)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // =====================================================================
    // Hourly activity
    // =====================================================================

    pub async fn record_hourly_activity(&self, pid: i32, agent_name: &str, hour: i32) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO security_hourly_activity (pid, agent_name, hour, activity_count, date)
               VALUES ($1, $2, $3, 1, CURRENT_DATE)
               ON CONFLICT (pid, hour, date)
               DO UPDATE SET activity_count = security_hourly_activity.activity_count + 1"#,
        )
        .bind(pid)
        .bind(agent_name)
        .bind(hour)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // =====================================================================
    // Fingerprints
    // =====================================================================

    pub async fn insert_fingerprint(
        &self,
        pid: i32,
        agent_name: &str,
        version: i32,
        confidence_score: f64,
        sample_count: i64,
        destinations: &Value,
        traffic: &Value,
        timing: &Value,
        process: &Value,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO security_fingerprints (id, pid, agent_name, version, confidence_score, sample_count, destinations, traffic, timing, process)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
        )
        .bind(id)
        .bind(pid)
        .bind(agent_name)
        .bind(version)
        .bind(confidence_score)
        .bind(sample_count)
        .bind(destinations)
        .bind(traffic)
        .bind(timing)
        .bind(process)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn get_fingerprints(&self, pid: i32) -> Result<Vec<Value>> {
        let rows = sqlx::query_scalar::<_, String>(
            r#"SELECT row_to_json(t) FROM (
                SELECT * FROM security_fingerprints WHERE pid = $1 ORDER BY version DESC
            ) t"#,
        )
        .bind(pid)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().filter_map(|r| serde_json::from_str(r).ok()).collect())
    }

    // =====================================================================
    // Risk scores
    // =====================================================================

    pub async fn upsert_risk_score(
        &self,
        pid: i32,
        agent_name: &str,
        total_score: i32,
        destination_score: i32,
        traffic_score: i32,
        time_score: i32,
        behavior_score: i32,
        risk_level: &str,
        reasons: &Value,
    ) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO security_risk_scores (pid, agent_name, total_score, destination_score, traffic_score, time_score, behavior_score, risk_level, reasons)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
               ON CONFLICT (pid)
               DO UPDATE SET
                   total_score = $3, destination_score = $4, traffic_score = $5,
                   time_score = $6, behavior_score = $7, risk_level = $8,
                   reasons = $9, updated_at = NOW()"#,
        )
        .bind(pid)
        .bind(agent_name)
        .bind(total_score)
        .bind(destination_score)
        .bind(traffic_score)
        .bind(time_score)
        .bind(behavior_score)
        .bind(risk_level)
        .bind(reasons)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_risk_scores(&self) -> Result<Vec<Value>> {
        let rows = sqlx::query_scalar::<_, String>(
            r#"SELECT row_to_json(t) FROM (SELECT * FROM security_risk_scores ORDER BY total_score DESC) t"#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().filter_map(|r| serde_json::from_str(r).ok()).collect())
    }

    // =====================================================================
    // Security incidents
    // =====================================================================

    pub async fn insert_incident(
        &self,
        pid: i32,
        agent_name: &str,
        incident_type: &str,
        risk_score: i32,
        description: &str,
        details: &Value,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO security_incidents (id, pid, agent_name, incident_type, risk_score, description, details)
               VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
        )
        .bind(id)
        .bind(pid)
        .bind(agent_name)
        .bind(incident_type)
        .bind(risk_score)
        .bind(description)
        .bind(details)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn resolve_incident(&self, incident_id: Uuid) -> Result<()> {
        sqlx::query(
            r#"UPDATE security_incidents SET state = 'Resolved', resolved_at = NOW(), updated_at = NOW() WHERE id = $1"#,
        )
        .bind(incident_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_incidents(&self, pid: Option<i32>) -> Result<Vec<Value>> {
        let rows = if let Some(pid) = pid {
            sqlx::query_scalar::<_, String>(
                r#"SELECT row_to_json(t) FROM (
                    SELECT * FROM security_incidents WHERE pid = $1 ORDER BY created_at DESC
                ) t"#,
            )
            .bind(pid)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_scalar::<_, String>(
                r#"SELECT row_to_json(t) FROM (SELECT * FROM security_incidents ORDER BY created_at DESC) t"#,
            )
            .fetch_all(&self.pool)
            .await?
        };
        Ok(rows.iter().filter_map(|r| serde_json::from_str(r).ok()).collect())
    }

    // =====================================================================
    // Baseline learning state
    // =====================================================================

    pub async fn upsert_baseline_state(
        &self,
        pid: i32,
        agent_name: &str,
        state: &str,
        days_observed: i32,
        samples_collected: i64,
    ) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO security_baseline_state (pid, agent_name, state, days_observed, samples_collected)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (pid)
               DO UPDATE SET
                   state = $3, days_observed = $4, samples_collected = $5, updated_at = NOW()"#,
        )
        .bind(pid)
        .bind(agent_name)
        .bind(state)
        .bind(days_observed)
        .bind(samples_collected)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_baseline_states(&self) -> Result<Vec<Value>> {
        let rows = sqlx::query_scalar::<_, String>(
            r#"SELECT row_to_json(t) FROM (SELECT * FROM security_baseline_state ORDER BY pid) t"#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().filter_map(|r| serde_json::from_str(r).ok()).collect())
    }

    // =====================================================================
    // Audit trail
    // =====================================================================

    pub async fn record_audit_entry(
        &self,
        pid: Option<i32>,
        agent_name: Option<&str>,
        action_type: &str,
        description: &str,
        details: &Value,
    ) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO security_audit_trail (pid, agent_name, action_type, description, details)
               VALUES ($1, $2, $3, $4, $5)"#,
        )
        .bind(pid)
        .bind(agent_name)
        .bind(action_type)
        .bind(description)
        .bind(details)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_audit_trail(&self, limit: i64) -> Result<Vec<Value>> {
        let rows = sqlx::query_scalar::<_, String>(
            r#"SELECT row_to_json(t) FROM (
                SELECT * FROM security_audit_trail ORDER BY created_at DESC LIMIT $1
            ) t"#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().filter_map(|r| serde_json::from_str(r).ok()).collect())
    }

    // =====================================================================
    // Timeline
    // =====================================================================

    pub async fn record_timeline_entry(
        &self,
        pid: Option<i32>,
        agent_name: Option<&str>,
        event_type: &str,
        severity: &str,
        title: &str,
        description: &str,
        metadata: &Value,
    ) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO security_timeline (pid, agent_name, event_type, severity, title, description, metadata)
               VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
        )
        .bind(pid)
        .bind(agent_name)
        .bind(event_type)
        .bind(severity)
        .bind(title)
        .bind(description)
        .bind(metadata)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_timeline(&self, pid: Option<i32>, limit: i64) -> Result<Vec<Value>> {
        let rows = if let Some(pid) = pid {
            sqlx::query_scalar::<_, String>(
                r#"SELECT row_to_json(t) FROM (
                    SELECT * FROM security_timeline WHERE pid = $1 ORDER BY created_at DESC LIMIT $2
                ) t"#,
            )
            .bind(pid)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_scalar::<_, String>(
                r#"SELECT row_to_json(t) FROM (
                    SELECT * FROM security_timeline ORDER BY created_at DESC LIMIT $1
                ) t"#,
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        };
        Ok(rows.iter().filter_map(|r| serde_json::from_str(r).ok()).collect())
    }

    // =====================================================================
    // Correlation alerts
    // =====================================================================

    pub async fn insert_correlation_alert(
        &self,
        correlation_type: &str,
        description: &str,
        affected_agents: &Value,
        affected_pids: &[i32],
        severity: &str,
        pattern: &Value,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO security_correlation_alerts (id, correlation_type, description, affected_agents, affected_pids, severity, pattern)
               VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
        )
        .bind(id)
        .bind(correlation_type)
        .bind(description)
        .bind(affected_agents)
        .bind(affected_pids)
        .bind(severity)
        .bind(pattern)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn get_correlation_alerts(&self, unresolved_only: bool) -> Result<Vec<Value>> {
        let rows = if unresolved_only {
            sqlx::query_scalar::<_, String>(
                r#"SELECT row_to_json(t) FROM (
                    SELECT * FROM security_correlation_alerts WHERE resolved = false ORDER BY created_at DESC
                ) t"#,
            )
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_scalar::<_, String>(
                r#"SELECT row_to_json(t) FROM (
                    SELECT * FROM security_correlation_alerts ORDER BY created_at DESC LIMIT 100
                ) t"#,
            )
            .fetch_all(&self.pool)
            .await?
        };
        Ok(rows.iter().filter_map(|r| serde_json::from_str(r).ok()).collect())
    }
}
