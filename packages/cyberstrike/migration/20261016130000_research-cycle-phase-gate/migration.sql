CREATE TABLE IF NOT EXISTS research_cycle (
  id TEXT PRIMARY KEY NOT NULL,
  cycle_id TEXT NOT NULL,
  phase TEXT NOT NULL,
  source_ids TEXT NOT NULL DEFAULT '[]',
  source_states TEXT NOT NULL DEFAULT '{}',
  started_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  finished_at INTEGER
);
