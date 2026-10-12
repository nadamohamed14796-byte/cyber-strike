-- Isolate target memory by owner. Non-Git projects share ProjectTable.id="global",
-- so project_id + target_key alone allowed unrelated project directories to see the same notes.
ALTER TABLE target_workspace ADD COLUMN owner_key TEXT NOT NULL DEFAULT 'legacy:unscoped';
--> statement-breakpoint
UPDATE target_workspace
SET owner_key = 'project:' || project_id
WHERE project_id <> 'global';
--> statement-breakpoint
DROP INDEX IF EXISTS target_workspace_project_key_idx;
--> statement-breakpoint
DROP INDEX IF EXISTS target_workspace_host_idx;
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS target_workspace_owner_target_key_idx
  ON target_workspace(owner_key, target_key);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS target_workspace_owner_host_idx
  ON target_workspace(owner_key, hostname);
