CREATE TABLE `false_positive_knowledge` (
  `id` text PRIMARY KEY NOT NULL,
  `fingerprint` text NOT NULL,
  `vulnerability_class` text NOT NULL,
  `title_pattern` text NOT NULL,
  `endpoint_pattern` text,
  `failed_check_ids` text NOT NULL,
  `benign_explanation` text NOT NULL,
  `evidence_summary` text NOT NULL,
  `source_validation_id` text NOT NULL,
  `source_finding_id` text,
  `confidence` integer DEFAULT 50 NOT NULL,
  `occurrences` integer DEFAULT 1 NOT NULL,
  `last_verdict` text DEFAULT 'false_positive' NOT NULL,
  `active` integer DEFAULT 1 NOT NULL,
  `time_created` integer NOT NULL,
  `time_updated` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `false_positive_knowledge_fingerprint_idx` ON `false_positive_knowledge` (`fingerprint`);
--> statement-breakpoint
CREATE INDEX `false_positive_knowledge_class_idx` ON `false_positive_knowledge` (`vulnerability_class`);
--> statement-breakpoint
CREATE INDEX `false_positive_knowledge_title_idx` ON `false_positive_knowledge` (`title_pattern`);
--> statement-breakpoint
CREATE INDEX `false_positive_knowledge_seen_idx` ON `false_positive_knowledge` (`time_updated`);
