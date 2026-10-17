-- Preserve previous versions of current investigation notes when a stable identity is updated.
CREATE TABLE IF NOT EXISTS target_note_revision (
  id TEXT PRIMARY KEY NOT NULL,
  note_id TEXT NOT NULL REFERENCES target_note(id) ON DELETE CASCADE,
  target_id TEXT NOT NULL REFERENCES target_workspace(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  title TEXT,
  content TEXT NOT NULL,
  source TEXT NOT NULL,
  source_url TEXT,
  content_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  tags TEXT NOT NULL DEFAULT '[]',
  time_created INTEGER NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS target_note_revision_dedup_idx ON target_note_revision(note_id, content_hash);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS target_note_revision_note_time_idx ON target_note_revision(note_id, time_created);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS target_note_revision_target_time_idx ON target_note_revision(target_id, time_created);
