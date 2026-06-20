-- Linux Runtime Control Layer: Persistence
-- Phases 1-9: nftables rules, cgroup limits, systemd actions, process containment, kernel audit trail

-- Runtime audit trail (decision → kernel action → result → rollback → duration → verification)
CREATE TABLE runtime_audit (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    action_type VARCHAR(64) NOT NULL,
    target VARCHAR(512) NOT NULL,
    kernel_command TEXT NOT NULL DEFAULT '',
    result VARCHAR(32) NOT NULL,
    duration_ms BIGINT NOT NULL DEFAULT 0,
    verified BOOLEAN NOT NULL DEFAULT false,
    rolled_back BOOLEAN NOT NULL DEFAULT false,
    rollback_time TIMESTAMPTZ,
    verification_method VARCHAR(64),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- nftables rules
CREATE TABLE runtime_nftables_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target VARCHAR(512) NOT NULL,
    ip VARCHAR(64),
    rule_type VARCHAR(16) NOT NULL DEFAULT 'Domain',
    table_name VARCHAR(64) NOT NULL DEFAULT 'omnisec',
    chain_name VARCHAR(64) NOT NULL DEFAULT 'omnisec-block',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    reason TEXT NOT NULL DEFAULT '',
    removed BOOLEAN NOT NULL DEFAULT false
);

-- CGroup resource limits
CREATE TABLE runtime_cgroups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cgroup_path VARCHAR(512) NOT NULL,
    agent_name VARCHAR(255) NOT NULL,
    pid INTEGER NOT NULL,
    cpu_quota VARCHAR(64),
    memory_max VARCHAR(64),
    pids_max INTEGER DEFAULT 50,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Process containment
CREATE TABLE runtime_contained_processes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pid INTEGER NOT NULL,
    agent_name VARCHAR(255) NOT NULL,
    state VARCHAR(32) NOT NULL DEFAULT 'Suspended',
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    duration_secs BIGINT NOT NULL DEFAULT 0
);

-- File access events
CREATE TABLE runtime_file_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pid INTEGER NOT NULL,
    agent_name VARCHAR(255) NOT NULL,
    file_path TEXT NOT NULL,
    action VARCHAR(16) NOT NULL DEFAULT 'FLAG',
    real_event BOOLEAN NOT NULL DEFAULT false,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Systemd actions
CREATE TABLE runtime_systemd_actions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    unit VARCHAR(255) NOT NULL,
    action VARCHAR(32) NOT NULL,
    result VARCHAR(32) NOT NULL,
    duration_ms BIGINT NOT NULL DEFAULT 0,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_runtime_audit_type ON runtime_audit(action_type);
CREATE INDEX idx_runtime_audit_target ON runtime_audit(target);
CREATE INDEX idx_runtime_audit_timestamp ON runtime_audit(timestamp);
CREATE INDEX idx_runtime_nftables_target ON runtime_nftables_rules(target);
CREATE INDEX idx_runtime_cgroups_pid ON runtime_cgroups(pid);
CREATE INDEX idx_runtime_contained_pid ON runtime_contained_processes(pid);
CREATE INDEX idx_runtime_file_events_pid ON runtime_file_events(pid);
