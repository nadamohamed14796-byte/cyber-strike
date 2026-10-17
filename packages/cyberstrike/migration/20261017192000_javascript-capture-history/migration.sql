-- Retain changed JavaScript response bodies even when the ordinary RequestTable dedupes the request.
CREATE TABLE IF NOT EXISTS request_javascript_capture (
  id TEXT PRIMARY KEY NOT NULL,
  session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE,
  request_id TEXT NOT NULL REFERENCES request(id) ON DELETE CASCADE,
  source_url TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  source_content TEXT NOT NULL,
  content_type TEXT,
  response_size INTEGER,
  time_created INTEGER NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS request_javascript_capture_dedup_idx
  ON request_javascript_capture(session_id, request_id, source_url, content_hash);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS request_javascript_capture_session_idx
  ON request_javascript_capture(session_id);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS request_javascript_capture_request_idx
  ON request_javascript_capture(request_id);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS request_javascript_capture_url_idx
  ON request_javascript_capture(session_id, source_url);
