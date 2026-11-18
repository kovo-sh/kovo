ALTER TABLE `assignments` ADD `checks` text;--> statement-breakpoint
ALTER TABLE `findings` ADD `check_id` text DEFAULT 'hsts' NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX `findings_check` ON `findings` (`run_id`,`asset_id`,`goal_revision`,`check_id`);