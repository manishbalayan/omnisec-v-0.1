-- Intelligence Layer: Cost observability + Model recommendations
-- No model vendor coupling — tables store provider/model as free-form strings.

-- Per-request cost tracking (one row per proxied API call)
CREATE TABLE proxy_request_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    agent_pid INTEGER,
    agent_name VARCHAR(255),
    -- Provider and model as reported by the response (never hardcoded)
    provider VARCHAR(100),
    model VARCHAR(255),
    -- Token counts from response body
    prompt_tokens BIGINT NOT NULL DEFAULT 0,
    completion_tokens BIGINT NOT NULL DEFAULT 0,
    total_tokens BIGINT NOT NULL DEFAULT 0,
    -- Cost in microdollars (millionths of a dollar) using operator-configured rate
    cost_microdollars BIGINT NOT NULL DEFAULT 0,
    -- Request metadata
    http_method VARCHAR(10),
    path VARCHAR(500),
    response_status SMALLINT,
    latency_ms INTEGER,
    cache_hit BOOLEAN NOT NULL DEFAULT false,
    request_bytes INTEGER,
    response_bytes INTEGER,
    -- Complexity signals (proxy-observable, no prompt reading)
    body_size_bytes INTEGER,
    response_size_bytes INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_proxy_log_agent ON proxy_request_log(agent_pid);
CREATE INDEX idx_proxy_log_provider ON proxy_request_log(provider);
CREATE INDEX idx_proxy_log_model ON proxy_request_log(model);
CREATE INDEX idx_proxy_log_created ON proxy_request_log(created_at);
CREATE INDEX idx_proxy_log_org ON proxy_request_log(organization_id);

-- Daily cost rollup (maintained by daemon/proxy, queried by dashboard)
CREATE TABLE cost_daily_rollup (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    date DATE NOT NULL,
    provider VARCHAR(100),
    model VARCHAR(255),
    agent_pid INTEGER,
    agent_name VARCHAR(255),
    request_count BIGINT NOT NULL DEFAULT 0,
    total_tokens BIGINT NOT NULL DEFAULT 0,
    cost_microdollars BIGINT NOT NULL DEFAULT 0,
    cache_hits BIGINT NOT NULL DEFAULT 0,
    UNIQUE (organization_id, date, provider, model, agent_name)
);

CREATE INDEX idx_cost_rollup_date ON cost_daily_rollup(date);
CREATE INDEX idx_cost_rollup_org ON cost_daily_rollup(organization_id);

-- Model recommendations (human must approve — no auto-routing)
CREATE TABLE model_recommendations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    agent_pid INTEGER,
    agent_name VARCHAR(255),
    current_model VARCHAR(255),
    current_provider VARCHAR(100),
    recommended_model VARCHAR(255),
    recommended_provider VARCHAR(100),
    -- Observed signals that led to this recommendation
    observed_avg_prompt_tokens INTEGER,
    observed_avg_completion_tokens INTEGER,
    observed_avg_latency_ms INTEGER,
    observed_request_count INTEGER,
    -- Estimated impact (informational only)
    estimated_savings_pct DOUBLE PRECISION,
    estimated_monthly_savings_usd DOUBLE PRECISION,
    -- Complexity inference (request/response size ratios, not prompt content)
    complexity_score DOUBLE PRECISION,  -- 0.0 = simple, 1.0 = complex
    reasoning TEXT,
    -- Lifecycle
    status VARCHAR(50) NOT NULL DEFAULT 'pending',  -- pending, approved, rejected, applied
    approved_by VARCHAR(255),
    approved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_recommendations_agent ON model_recommendations(agent_name);
CREATE INDEX idx_recommendations_status ON model_recommendations(status);
CREATE INDEX idx_recommendations_org ON model_recommendations(organization_id);
