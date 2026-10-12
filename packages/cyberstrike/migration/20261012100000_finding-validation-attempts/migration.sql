ALTER TABLE finding_validation ADD COLUMN attempts TEXT NOT NULL DEFAULT '[]';
--> statement-breakpoint
ALTER TABLE finding_validation ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0;
