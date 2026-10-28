-- Persist the combined-impact outcome separately from individual findings and Intel hypotheses.
CREATE TABLE IF NOT EXISTS chain_validation (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE,
  chain_candidate_id TEXT NOT NULL REFERENCES chain_candidate(id) ON DELETE CASCADE,
  outcome TEXT NOT NULL CHECK (outcome IN ('confirmed', 'disproven', 'inconclusive')),
  combined_vulnerability_id TEXT REFERENCES vulnerability(id) ON DELETE SET NULL,
  evidence TEXT NOT NULL,
  validated_by TEXT NOT NULL,
  time_created INTEGER NOT NULL,
  time_updated INTEGER NOT NULL,
  CHECK (outcome <> 'confirmed' OR combined_vulnerability_id IS NOT NULL)
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS chain_validation_session_idx ON chain_validation(session_id);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS chain_validation_chain_time_idx ON chain_validation(chain_candidate_id, time_created);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS chain_validation_finding_idx ON chain_validation(combined_vulnerability_id);
--> statement-breakpoint
CREATE TRIGGER IF NOT EXISTS chain_validation_session_guard
BEFORE INSERT ON chain_validation
WHEN
  COALESCE((SELECT session_id FROM chain_candidate WHERE id = NEW.chain_candidate_id), '') <> NEW.session_id
  OR (NEW.combined_vulnerability_id IS NOT NULL
      AND COALESCE((SELECT session_id FROM vulnerability WHERE id = NEW.combined_vulnerability_id), '') <> NEW.session_id)
BEGIN
  SELECT RAISE(ABORT, 'chain validation must reference rows from the same session');
END;
