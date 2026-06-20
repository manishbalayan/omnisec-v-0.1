-- Security Runtime Integration: Persistent Security Storage
-- Phase 3: Move security state from memory to PostgreSQL

-- Destination profiles
CREATE TABLE security_destination_profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pid INTEGER NOT NULL,
    agent_name VARCHAR(255) NOT NULL,
    domain VARCHAR(512) NOT NULL,
    ip VARCHAR(45) NOT NULL,
    port INTEGER NOT NULL,
    protocol VARCHAR(16) NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    total_bytes BIGINT NOT NULL DEFAULT 0,
    request_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(pid, ip, port, protocol)
);

-- Traffic profile samples
CREATE TABLE security_traffic_samples (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pid INTEGER NOT NULL,
    agent_name VARCHAR(255) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    bytes_in BIGINT NOT NULL DEFAULT 0,
    bytes_out BIGINT NOT NULL DEFAULT 0,
    request_count INTEGER NOT NULL DEFAULT 0,
    connection_count INTEGER NOT NULL DEFAULT 0,
    window_type VARCHAR(16) NOT NULL DEFAULT 'hour'
);

-- Temporal profiles (hourly activity)
CREATE TABLE security_hourly_activity (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pid INTEGER NOT NULL,
    agent_name VARCHAR(255) NOT NULL,
    hour INTEGER NOT NULL CHECK (hour >= 0 AND hour < 24),
    activity_count BIGINT NOT NULL DEFAULT 0,
    date DATE NOT NULL DEFAULT CURRENT_DATE,
    UNIQUE(pid, hour, date)
);

-- Fingerprints (versioned, append-only)
CREATE TABLE security_fingerprints (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pid INTEGER NOT NULL,
    agent_name VARCHAR(255) NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    confidence_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    sample_count BIGINT NOT NULL DEFAULT 0,
    destinations JSONB NOT NULL DEFAULT '{}',
    traffic JSONB NOT NULL DEFAULT '{}',
    timing JSONB NOT NULL DEFAULT '{}',
    process JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Risk scores (latest per agent)
CREATE TABLE security_risk_scores (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pid INTEGER NOT NULL UNIQUE,
    agent_name VARCHAR(255) NOT NULL,
    total_score INTEGER NOT NULL DEFAULT 0,
    destination_score INTEGER NOT NULL DEFAULT 0,
    traffic_score INTEGER NOT NULL DEFAULT 0,
    time_score INTEGER NOT NULL DEFAULT 0,
    behavior_score INTEGER NOT NULL DEFAULT 0,
    risk_level VARCHAR(16) NOT NULL DEFAULT 'Normal',
    reasons JSONB NOT NULL DEFAULT '[]',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Security incidents
CREATE TABLE security_incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pid INTEGER NOT NULL,
    agent_name VARCHAR(255) NOT NULL,
    incident_type VARCHAR(32) NOT NULL,
    risk_score INTEGER NOT NULL DEFAULT 0,
    description TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}',
    state VARCHAR(16) NOT NULL DEFAULT 'Open',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

-- Baseline learning state
CREATE TABLE security_baseline_state (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pid INTEGER NOT NULL UNIQUE,
    agent_name VARCHAR(255) NOT NULL,
    state VARCHAR(16) NOT NULL DEFAULT 'Learning',
    learning_started TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    days_observed INTEGER NOT NULL DEFAULT 0,
    samples_collected BIGINT NOT NULL DEFAULT 0,
    required_days INTEGER NOT NULL DEFAULT 7,
    required_samples BIGINT NOT NULL DEFAULT 1000,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Security audit trail (all security actions, append-only)
CREATE TABLE security_audit_trail (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pid INTEGER,
    agent_name VARCHAR(255),
    action_type VARCHAR(32) NOT NULL,
    description TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Security timeline (investigation view)
CREATE TABLE security_timeline (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pid INTEGER,
    agent_name VARCHAR(255),
    event_type VARCHAR(32) NOT NULL,
    severity VARCHAR(16) NOT NULL DEFAULT 'info',
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Correlation alerts
CREATE TABLE security_correlation_alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    correlation_type VARCHAR(32) NOT NULL,
    description TEXT NOT NULL,
    affected_agents JSONB NOT NULL DEFAULT '[]',
    affected_pids INTEGER[] NOT NULL DEFAULT '{}',
    severity VARCHAR(16) NOT NULL DEFAULT 'Medium',
    pattern JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved BOOLEAN NOT NULL DEFAULT false,
    resolved_at TIMESTAMPTZ
);

-- Indexes for performance
CREATE INDEX idx_sec_dest_pid ON security_destination_profiles(pid);
CREATE INDEX idx_sec_traffic_pid ON security_traffic_samples(pid);
CREATE INDEX idx_sec_traffic_time ON security_traffic_samples(timestamp);
CREATE INDEX idx_sec_activity_pid ON security_hourly_activity(pid);
CREATE INDEX idx_sec_fingerprints_pid ON security_fingerprints(pid);
CREATE INDEX idx_sec_risk_pid ON security_risk_scores(pid);
CREATE INDEX idx_sec_incidents_pid ON security_incidents(pid);
CREATE INDEX idx_sec_incidents_state ON security_incidents(state);
CREATE INDEX idx_sec_baseline_pid ON security_baseline_state(pid);
CREATE INDEX idx_sec_audit_created ON security_audit_trail(created_at);
CREATE INDEX idx_sec_timeline_pid ON security_timeline(pid);
CREATE INDEX idx_sec_timeline_created ON security_timeline(created_at);
CREATE INDEX idx_sec_correlation_created ON security_correlation_alerts(created_at);
