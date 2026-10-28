-- Preserve real finding-to-finding relationships without treating Intel entry IDs as vulnerability IDs.
CREATE TABLE IF NOT EXISTS chain_finding_link (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE,
  chain_candidate_id TEXT NOT NULL REFERENCES chain_candidate(id) ON DELETE CASCADE,
  source_vulnerability_id TEXT NOT NULL REFERENCES vulnerability(id) ON DELETE CASCADE,
  target_vulnerability_id TEXT NOT NULL REFERENCES vulnerability(id) ON DELETE CASCADE,
  relation TEXT NOT NULL CHECK (relation IN ('depends_on', 'enables', 'contributes_to')),
  time_created INTEGER NOT NULL,
  time_updated INTEGER NOT NULL,
  CHECK (source_vulnerability_id <> target_vulnerability_id)
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS chain_finding_link_session_idx ON chain_finding_link(session_id);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS chain_finding_link_chain_idx ON chain_finding_link(chain_candidate_id);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS chain_finding_link_source_idx ON chain_finding_link(source_vulnerability_id);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS chain_finding_link_target_idx ON chain_finding_link(target_vulnerability_id);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS chain_finding_link_edge_idx ON chain_finding_link(chain_candidate_id, source_vulnerability_id, target_vulnerability_id, relation);
