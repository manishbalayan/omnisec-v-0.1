CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TYPE agent_status AS ENUM ('unknown', 'running', 'stopped', 'failed', 'recovering');
CREATE TYPE event_type AS ENUM ('agent_discovered', 'agent_heartbeat', 'agent_failed', 'agent_restarted', 'agent_stopped', 'policy_violation', 'security_incident', 'system_error');
CREATE TYPE event_severity AS ENUM ('info', 'warning', 'error', 'critical');
CREATE TYPE alert_status AS ENUM ('active', 'acknowledged', 'resolved');
CREATE TYPE alert_channel AS ENUM ('telegram', 'email', 'slack');
CREATE TYPE policy_action AS ENUM ('allow', 'alert', 'block', 'restart');

CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    settings JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'member',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    process_name VARCHAR(255),
    command_line TEXT,
    pid INTEGER,
    status agent_status NOT NULL DEFAULT 'unknown',
    framework VARCHAR(100),
    model_provider VARCHAR(100),
    cpu_usage DOUBLE PRECISION,
    memory_usage DOUBLE PRECISION,
    last_heartbeat TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    agent_id UUID REFERENCES agents(id),
    event_type event_type NOT NULL,
    severity event_severity NOT NULL,
    message TEXT NOT NULL,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    agent_id UUID REFERENCES agents(id),
    event_id UUID REFERENCES events(id),
    channel alert_channel NOT NULL,
    status alert_status NOT NULL DEFAULT 'active',
    message TEXT NOT NULL,
    sent_at TIMESTAMPTZ,
    acknowledged_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    conditions JSONB NOT NULL,
    action policy_action NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agents_organization ON agents(organization_id);
CREATE INDEX idx_agents_pid ON agents(pid);
CREATE INDEX idx_agents_status ON agents(status);
CREATE INDEX idx_events_organization ON events(organization_id);
CREATE INDEX idx_events_agent ON events(agent_id);
CREATE INDEX idx_events_type ON events(event_type);
CREATE INDEX idx_events_created ON events(created_at);
CREATE INDEX idx_alerts_organization ON alerts(organization_id);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_policies_organization ON policies(organization_id);
