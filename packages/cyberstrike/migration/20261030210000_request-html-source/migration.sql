-- Preserve the complete original HTML response separately from the LLM-safe preview.
-- This allows deterministic empty/static-page triage without treating the generic
-- "This is an HTML response" preview as proof that the page has no attack surface.
ALTER TABLE request ADD COLUMN html_source TEXT;
