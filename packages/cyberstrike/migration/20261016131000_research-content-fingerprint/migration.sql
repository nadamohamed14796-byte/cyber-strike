ALTER TABLE research_queue ADD COLUMN content_fingerprint TEXT;
--> statement-breakpoint
UPDATE research_queue
SET content_fingerprint = lower(json_extract(payload, '$.content_fingerprint'))
WHERE content_fingerprint IS NULL
  AND json_valid(payload)
  AND json_type(payload, '$.content_fingerprint') = 'text'
  AND length(json_extract(payload, '$.content_fingerprint')) = 40;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS research_queue_content_fingerprint_idx
ON research_queue(content_fingerprint);
