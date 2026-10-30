-- Keep every captured HTTP transaction as its own analysis item.
-- key_hash is a non-unique grouping key for observations and endpoint correlation.
DROP INDEX IF EXISTS request_keyhash_idx;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS request_keyhash_idx ON request(session_id, key_hash);
