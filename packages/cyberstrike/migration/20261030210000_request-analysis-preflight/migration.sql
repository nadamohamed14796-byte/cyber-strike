-- Persist compact preflight metadata and a digest of the full captured response.
-- Original HTML bodies are inspected in memory, not duplicated in the request database.
ALTER TABLE request ADD COLUMN empty_static_html INTEGER NOT NULL DEFAULT 0;
--> statement-breakpoint
ALTER TABLE request ADD COLUMN response_body_hash TEXT;
