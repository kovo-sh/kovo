ALTER TABLE `findings` ADD `case_id` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `project_assets` ADD `access_policy` text;--> statement-breakpoint
DROP INDEX IF EXISTS `findings_check`;--> statement-breakpoint
CREATE UNIQUE INDEX `findings_check_case` ON `findings` (`run_id`,`asset_id`,`goal_revision`,`check_id`,`case_id`);