ALTER TABLE `assignments` ADD `lease` text;--> statement-breakpoint
ALTER TABLE `assignments` ADD `attempt` integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `evidence` ADD `operation_id` text;--> statement-breakpoint
ALTER TABLE `messages` ADD `reply_to` text;--> statement-breakpoint
ALTER TABLE `project_assets` ADD `prepared` text;--> statement-breakpoint
ALTER TABLE `runs` ADD `source_mode` text DEFAULT 'prepared' NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX `evidence_operation` ON `evidence` (`assignment_id`,`operation_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `run_replies` ON `messages` (`run_id`,`reply_to`);