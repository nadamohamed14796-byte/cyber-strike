-- Persist only the deterministic empty/static HTML triage result.
-- The original HTML is inspected in memory and is not duplicated in the request database.
ALTER TABLE request ADD COLUMN empty_static_html INTEGER NOT NULL DEFAULT 0;
