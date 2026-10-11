CREATE TABLE IF NOT EXISTS finding_validation (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE,
  vulnerability_id TEXT NOT NULL REFERENCES vulnerability(id) ON DELETE CASCADE,
  verdict TEXT NOT NULL,
  confidence INTEGER NOT NULL,
  checks TEXT NOT NULL,
  failed_check_ids TEXT NOT NULL,
  unknown_check_ids TEXT NOT NULL,
  summary TEXT NOT NULL,
  next_step TEXT NOT NULL,
  time_created INTEGER NOT NULL,
  time_updated INTEGER NOT NULL
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS finding_validation_session_time_idx ON finding_validation(session_id, time_created);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS finding_validation_finding_time_idx ON finding_validation(vulnerability_id, time_created);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS finding_validation_verdict_idx ON finding_validation(verdict);
