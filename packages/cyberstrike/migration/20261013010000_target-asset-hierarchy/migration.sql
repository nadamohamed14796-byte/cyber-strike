-- Add explicit parent/child identity to target workspaces.
ALTER TABLE target_workspace ADD COLUMN parent_target_id TEXT REFERENCES target_workspace(id) ON DELETE SET NULL;
--> statement-breakpoint
ALTER TABLE target_workspace ADD COLUMN asset_type TEXT NOT NULL DEFAULT 'target';
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS target_workspace_parent_idx ON target_workspace(parent_target_id);
