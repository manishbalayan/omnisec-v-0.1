-- Add missing event_type enum values for daemon audit trail
-- These correspond to NATS subjects (e.g., omnisec.alert.requested → alert_requested)
-- that the daemon's wildcard subscriber persists as events.

ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'agent_health_changed';
ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'agent_hung';
ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'alert_requested';
ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'alert_sent';
ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'alert_failed';
ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'restart_requested';
ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'restart_started';
ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'restart_succeeded';
ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'restart_failed';
ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'security_anomaly_detected';
ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'security_correlation_alert';
ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'security_profile_updated';
ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'decision_made';
ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'enforcement_blocked';
ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'enforcement_flagged';
ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'exfiltration_blocked';
ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'incident_created';
ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'file_access_detected';
ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'file_access_violation';
ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'runtime_network_blocked';
ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'runtime_service_control';
ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'runtime_process_quarantined';
ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'runtime_rollback';
ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'network_connect';
ALTER TYPE event_type ADD VALUE IF NOT EXISTS 'dns_query';
