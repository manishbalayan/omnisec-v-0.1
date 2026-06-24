-- Agent Discovery Confidence Scoring
-- Adds confidence score to the agents table so the API can expose
-- the discovery confidence filter transparently in responses.
-- This also enables the Dashboard to show confidence scores for each agent.

ALTER TABLE agents ADD COLUMN IF NOT EXISTS confidence INTEGER NOT NULL DEFAULT 0;
