-- Runtime Enforcement Layer: Persistence
-- Phases 1-8: Policy rules, enforcement actions, overrides, incidents

-- Enforcement policies (versioned)
CREATE TABLE enforcement_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    version INTEGER NOT NULL DEFAULT 1,
    enabled BOOLEAN NOT NULL DEFAULT true,
    rules JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(name, version)
);

-- Enforcement decisions
CREATE TABLE enforcement_decisions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pid INTEGER NOT NULL,
    agent_name VARCHAR(255) NOT NULL,
    action VARCHAR(16) NOT NULL,
    reason TEXT NOT NULL,
    rule VARCHAR(255) NOT NULL,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    policy_name VARCHAR(255) NOT NULL,
    policy_version INTEGER NOT NULL DEFAULT 0,
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_level VARCHAR(16) NOT NULL DEFAULT 'Normal',
    anomaly_type VARCHAR(64),
    anomaly_severity VARCHAR(16),
    destination VARCHAR(512),
    process_name VARCHAR(255),
    file_path TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enforcement actions (enforcement results)
CREATE TABLE enforcement_actions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    decision_id UUID REFERENCES enforcement_decisions(id),
    pid INTEGER NOT NULL,
    agent_name VARCHAR(255) NOT NULL,
    action_type VARCHAR(16) NOT NULL,
    target VARCHAR(512) NOT NULL,
    result VARCHAR(16) NOT NULL DEFAULT 'Applied',
    duration_ms BIGINT NOT NULL DEFAULT 0,
    details TEXT NOT NULL DEFAULT '',
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enforcement incidents
CREATE TABLE enforcement_incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    decision_id UUID REFERENCES enforcement_decisions(id),
    pid INTEGER NOT NULL,
    agent_name VARCHAR(255) NOT NULL,
    action_type VARCHAR(16) NOT NULL,
    action_target VARCHAR(512) NOT NULL,
    result VARCHAR(16) NOT NULL DEFAULT 'Applied',
    status VARCHAR(16) NOT NULL DEFAULT 'Open',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    resolution TEXT
);

-- Human overrides
CREATE TABLE enforcement_overrides (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    decision_id UUID REFERENCES enforcement_decisions(id),
    action VARCHAR(32) NOT NULL,
    reason TEXT NOT NULL,
    created_by VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Block/allow lists (persistent)
CREATE TABLE enforcement_lists (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    list_type VARCHAR(16) NOT NULL CHECK (list_type IN ('allow', 'block')),
    target VARCHAR(512) NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    created_by VARCHAR(255) NOT NULL DEFAULT 'system',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(list_type, target)
);

-- Indexes
CREATE INDEX idx_enforcement_decisions_pid ON enforcement_decisions(pid);
CREATE INDEX idx_enforcement_decisions_timestamp ON enforcement_decisions(timestamp);
CREATE INDEX idx_enforcement_actions_pid ON enforcement_actions(pid);
CREATE INDEX idx_enforcement_incidents_status ON enforcement_incidents(status);
CREATE INDEX idx_enforcement_incidents_pid ON enforcement_incidents(pid);
CREATE INDEX idx_enforcement_lists_type ON enforcement_lists(list_type);
