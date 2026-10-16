CREATE TABLE IF NOT EXISTS research_cycle_duplicate (
  id TEXT PRIMARY KEY NOT NULL,
  cycle_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  source_url TEXT NOT NULL,
  recorded_at INTEGER NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS research_cycle_duplicate_unique_idx
ON research_cycle_duplicate(cycle_id, source_id, source_url);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS research_cycle_duplicate_cycle_idx
ON research_cycle_duplicate(cycle_id, source_id);
