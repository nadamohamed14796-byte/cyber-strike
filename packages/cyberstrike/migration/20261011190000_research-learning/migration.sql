CREATE TABLE IF NOT EXISTS `report_knowledge` (
  `id` text PRIMARY KEY NOT NULL,
  `session_id` text REFERENCES session(id) ON DELETE CASCADE,
  `source_vulnerability_id` text REFERENCES vulnerability(id) ON DELETE SET NULL,
  `fingerprint` text NOT NULL,
  `title` text NOT NULL,
  `vulnerability_class` text,
  `cwe_id` text,
  `severity` text NOT NULL,
  `status` text NOT NULL DEFAULT 'observed',
  `source_kind` text NOT NULL DEFAULT 'finding',
  `source_url` text,
  `program` text,
  `target_pattern` text,
  `endpoint` text,
  `attack_vector` text,
  `impact` text,
  `reproduction` text,
  `poc` text,
  `outcome` text,
  `lesson` text,
  `tags` text,
  `metadata` text,
  `confidence` integer NOT NULL DEFAULT 50,
  `times_seen` integer NOT NULL DEFAULT 1,
  `times_useful` integer NOT NULL DEFAULT 0,
  `times_rejected` integer NOT NULL DEFAULT 0,
  `time_created` integer NOT NULL,
  `time_updated` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `report_knowledge_fingerprint_idx` ON `report_knowledge` (`fingerprint`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `report_knowledge_class_idx` ON `report_knowledge` (`vulnerability_class`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `report_knowledge_cwe_idx` ON `report_knowledge` (`cwe_id`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `report_knowledge_status_idx` ON `report_knowledge` (`status`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `report_knowledge_target_idx` ON `report_knowledge` (`target_pattern`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `report_knowledge_session_idx` ON `report_knowledge` (`session_id`);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `report_knowledge_event` (
  `id` text PRIMARY KEY NOT NULL,
  `report_id` text NOT NULL REFERENCES report_knowledge(id) ON DELETE CASCADE,
  `session_id` text REFERENCES session(id) ON DELETE CASCADE,
  `hook` text NOT NULL,
  `outcome` text NOT NULL,
  `signal` text,
  `evidence` text,
  `metadata` text,
  `time_created` integer NOT NULL,
  `time_updated` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `report_knowledge_event_report_idx` ON `report_knowledge_event` (`report_id`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `report_knowledge_event_session_idx` ON `report_knowledge_event` (`session_id`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `report_knowledge_event_signal_idx` ON `report_knowledge_event` (`signal`);

--> statement-breakpoint
CREATE TABLE IF NOT EXISTS research_queue (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  source_id TEXT NOT NULL,
  source_url TEXT NOT NULL,
  title TEXT,
  payload TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'queued',
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  discovered_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  claimed_at INTEGER,
  completed_at INTEGER,
  lease_owner TEXT,
  lease_until INTEGER
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS research_queue_source_url_idx ON research_queue(source_id, source_url);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS research_queue_status_idx ON research_queue(status);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS research_queue_lease_idx ON research_queue(lease_until);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS research_queue_sequence_idx ON research_queue(sequence);
