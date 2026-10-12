-- Target-specific persistent workspaces and deduplicated notes.
-- Project ownership prevents notes from leaking between unrelated projects.

CREATE TABLE IF NOT EXISTS target_workspace (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES project(id) ON DELETE CASCADE,
  target_key TEXT NOT NULL,
  target_url TEXT NOT NULL,
  hostname TEXT NOT NULL,
  slug TEXT NOT NULL,
  workspace_path TEXT NOT NULL,
  time_created INTEGER NOT NULL,
  time_updated INTEGER NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS target_workspace_project_key_idx
  ON target_workspace(project_id, target_key);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS target_workspace_host_idx
  ON target_workspace(project_id, hostname);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS target_note (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL REFERENCES target_workspace(id) ON DELETE CASCADE,
  kind TEXT NOT NULL DEFAULT 'manual',
  title TEXT,
  content TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'manual',
  source_url TEXT,
  content_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'observed',
  tags TEXT,
  time_created INTEGER NOT NULL,
  time_updated INTEGER NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS target_note_dedup_idx
  ON target_note(target_id, content_hash);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS target_note_target_time_idx
  ON target_note(target_id, time_created);
