pub mod security;

use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;
use chrono::Utc;

pub struct Storage {
    pool: PgPool,
    /// Set by bootstrap_organization(); required for agents/events inserts
    pub default_org_id: Uuid,
}

impl Storage {
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = PgPool::connect(database_url).await?;
        Ok(Self { pool, default_org_id: Uuid::nil() })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn run_migrations(&self) -> Result<()> {
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        Ok(())
    }

    /// Ensure a default organization exists and set self.default_org_id.
    /// Must be called after run_migrations() and before any agent/event writes.
    pub async fn bootstrap_organization(&mut self) -> Result<Uuid> {
        let org_name = "default";
        let now = Utc::now();

        // Upsert: insert if not exists, return existing id otherwise
        let row: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM organizations WHERE slug = $1 LIMIT 1"
        )
        .bind(org_name)
        .fetch_optional(&self.pool)
        .await?;

        let org_id = if let Some((id,)) = row {
            id
        } else {
            let id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO organizations (id, name, slug, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (slug) DO NOTHING"
            )
            .bind(id)
            .bind("Default Organization")
            .bind(org_name)
            .bind(now)
            .bind(now)
            .execute(&self.pool)
            .await?;

            // Re-fetch in case a concurrent insert beat us
            sqlx::query_as::<_, (Uuid,)>("SELECT id FROM organizations WHERE slug = $1 LIMIT 1")
                .bind(org_name)
                .fetch_one(&self.pool)
                .await?
                .0
        };

        self.default_org_id = org_id;
        tracing::info!("Bootstrap: default organization id = {}", org_id);
        Ok(org_id)
    }

    pub async fn create_agent(&self, name: &str, pid: Option<i32>) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        if self.default_org_id == Uuid::nil() {
            anyhow::bail!("Storage not bootstrapped: call bootstrap_organization() first");
        }

        sqlx::query(
            "INSERT INTO agents (id, organization_id, name, pid, status, created_at, updated_at) VALUES ($1, $2, $3, $4, 'unknown', $5, $6)"
        )
        .bind(id)
        .bind(self.default_org_id)
        .bind(name)
        .bind(pid)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    pub async fn create_event(&self, agent_id: Option<Uuid>, event_type: &str, severity: &str, message: &str) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        if self.default_org_id == Uuid::nil() {
            anyhow::bail!("Storage not bootstrapped: call bootstrap_organization() first");
        }

        sqlx::query(
            "INSERT INTO events (id, organization_id, agent_id, event_type, severity, message, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind(id)
        .bind(self.default_org_id)
        .bind(agent_id)
        .bind(event_type)
        .bind(severity)
        .bind(message)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    pub async fn get_agents(&self) -> Result<String> {
        let rows = sqlx::query_scalar::<_, String>(
            "SELECT row_to_json(t) FROM (SELECT * FROM agents ORDER BY created_at DESC) t"
        )
        .fetch_all(&self.pool)
        .await?;
        
        Ok(format!("[{}]", rows.join(",")))
    }

    pub async fn update_agent_status(&self, agent_id: Uuid, status: &str) -> Result<()> {
        let now = Utc::now();
        sqlx::query(
            "UPDATE agents SET status = $1, updated_at = $2 WHERE id = $3"
        )
        .bind(status)
        .bind(now)
        .bind(agent_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_agent_heartbeat(&self, agent_id: Uuid, pid: Option<i32>, cpu: Option<f64>, memory: Option<f64>) -> Result<()> {
        let now = Utc::now();
        sqlx::query(
            "UPDATE agents SET last_heartbeat = $1, pid = $2, cpu_usage = $3, memory_usage = $4, updated_at = $5 WHERE id = $6"
        )
        .bind(now)
        .bind(pid)
        .bind(cpu)
        .bind(memory)
        .bind(now)
        .bind(agent_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_events(&self, agent_id: Option<Uuid>) -> Result<String> {
        let rows = if let Some(agent_id) = agent_id {
            sqlx::query_scalar::<_, String>(
                "SELECT row_to_json(t) FROM (SELECT * FROM events WHERE agent_id = $1 ORDER BY created_at DESC LIMIT 100) t"
            )
            .bind(agent_id)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_scalar::<_, String>(
                "SELECT row_to_json(t) FROM (SELECT * FROM events ORDER BY created_at DESC LIMIT 100) t"
            )
            .fetch_all(&self.pool)
            .await?
        };
        
        Ok(format!("[{}]", rows.join(",")))
    }
}
