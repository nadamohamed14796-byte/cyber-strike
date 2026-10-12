-- Create the durable adaptive verification ledger used by verification_attempt.
-- Keep table creation and indexes idempotent for existing installs and clean installs.
CREATE TABLE IF NOT EXISTS verification_attempt (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE,
  hypothesis_key TEXT NOT NULL,
  asset TEXT NOT NULL,
  endpoint TEXT,
  vulnerability_class TEXT NOT NULL,
  strategy_id TEXT NOT NULL,
  variant_key TEXT NOT NULL,
  rationale TEXT NOT NULL,
  result_summary TEXT NOT NULL,
  evidence_ref TEXT,
  valid_conditions INTEGER NOT NULL DEFAULT 0,
  outcome TEXT NOT NULL DEFAULT 'inconclusive',
  time_created INTEGER NOT NULL,
  time_updated INTEGER NOT NULL
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS verification_attempt_session_idx
  ON verification_attempt(session_id);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS verification_attempt_hypothesis_idx
  ON verification_attempt(session_id, hypothesis_key);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS verification_attempt_unique_strategy_idx
  ON verification_attempt(session_id, hypothesis_key, strategy_id, variant_key);
