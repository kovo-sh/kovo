CREATE TABLE `assignments` (
	`id` text PRIMARY KEY,
	`run_id` text NOT NULL,
	`asset_id` text,
	`phase` text NOT NULL,
	`status` text NOT NULL,
	`scope_revision` integer NOT NULL,
	`goal_revision` integer NOT NULL,
	`session_id` text NOT NULL,
	`title` text NOT NULL,
	`objective` text NOT NULL,
	`outcome` text,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_assignments_run_id_runs_id_fk` FOREIGN KEY (`run_id`) REFERENCES `runs`(`id`)
);
--> statement-breakpoint
CREATE TABLE `events` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
	`workspace_id` text NOT NULL,
	`run_id` text,
	`kind` text NOT NULL,
	`message` text NOT NULL,
	`detail` text NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_events_workspace_id_workspaces_id_fk` FOREIGN KEY (`workspace_id`) REFERENCES `workspaces`(`id`),
	CONSTRAINT `fk_events_run_id_runs_id_fk` FOREIGN KEY (`run_id`) REFERENCES `runs`(`id`)
);
--> statement-breakpoint
CREATE TABLE `evidence` (
	`id` text PRIMARY KEY,
	`run_id` text NOT NULL,
	`assignment_id` text NOT NULL,
	`scope_revision` integer NOT NULL,
	`goal_revision` integer NOT NULL,
	`title` text NOT NULL,
	`kind` text NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_evidence_run_id_runs_id_fk` FOREIGN KEY (`run_id`) REFERENCES `runs`(`id`),
	CONSTRAINT `fk_evidence_assignment_id_assignments_id_fk` FOREIGN KEY (`assignment_id`) REFERENCES `assignments`(`id`)
);
--> statement-breakpoint
CREATE TABLE `findings` (
	`id` text PRIMARY KEY,
	`run_id` text NOT NULL,
	`asset_id` text NOT NULL,
	`goal_revision` integer NOT NULL,
	`finding` text NOT NULL,
	CONSTRAINT `fk_findings_run_id_runs_id_fk` FOREIGN KEY (`run_id`) REFERENCES `runs`(`id`)
);
--> statement-breakpoint
CREATE TABLE `messages` (
	`id` text PRIMARY KEY,
	`run_id` text NOT NULL,
	`thread_id` text NOT NULL,
	`role` text NOT NULL,
	`content` text NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_messages_run_id_runs_id_fk` FOREIGN KEY (`run_id`) REFERENCES `runs`(`id`)
);
--> statement-breakpoint
CREATE TABLE `model_config` (
	`workspace_id` text PRIMARY KEY,
	`endpoint` text NOT NULL,
	`model` text NOT NULL,
	`protocol` text NOT NULL,
	`credential_id` text NOT NULL,
	`updated_at` integer NOT NULL,
	CONSTRAINT `fk_model_config_workspace_id_workspaces_id_fk` FOREIGN KEY (`workspace_id`) REFERENCES `workspaces`(`id`)
);
--> statement-breakpoint
CREATE TABLE `operations` (
	`id` text PRIMARY KEY,
	`workspace_id` text NOT NULL,
	`fingerprint` text NOT NULL,
	`result` text NOT NULL,
	CONSTRAINT `fk_operations_workspace_id_workspaces_id_fk` FOREIGN KEY (`workspace_id`) REFERENCES `workspaces`(`id`)
);
--> statement-breakpoint
CREATE TABLE `project_assets` (
	`id` text PRIMARY KEY,
	`project_id` text NOT NULL,
	`origin` text NOT NULL,
	`source` text NOT NULL,
	`third_party` integer NOT NULL,
	CONSTRAINT `fk_project_assets_project_id_projects_id_fk` FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`)
);
--> statement-breakpoint
CREATE TABLE `projects` (
	`id` text PRIMARY KEY,
	`workspace_id` text NOT NULL,
	`name` text NOT NULL,
	`seeds` text NOT NULL,
	`default_scope` text NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_projects_workspace_id_workspaces_id_fk` FOREIGN KEY (`workspace_id`) REFERENCES `workspaces`(`id`)
);
--> statement-breakpoint
CREATE TABLE `reports` (
	`id` text PRIMARY KEY,
	`run_id` text NOT NULL,
	`version` integer NOT NULL,
	`partial` integer NOT NULL,
	`body` text NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_reports_run_id_runs_id_fk` FOREIGN KEY (`run_id`) REFERENCES `runs`(`id`)
);
--> statement-breakpoint
CREATE TABLE `runs` (
	`id` text PRIMARY KEY,
	`project_id` text NOT NULL,
	`workspace_id` text NOT NULL,
	`original_goal` text NOT NULL,
	`goal` text NOT NULL,
	`goal_revision` integer NOT NULL,
	`scope_revision` integer NOT NULL,
	`coordinator_id` text NOT NULL,
	`phase` text NOT NULL,
	`status` text NOT NULL,
	`candidates` text NOT NULL,
	`approved` text NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_runs_project_id_projects_id_fk` FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`),
	CONSTRAINT `fk_runs_workspace_id_workspaces_id_fk` FOREIGN KEY (`workspace_id`) REFERENCES `workspaces`(`id`)
);
--> statement-breakpoint
CREATE TABLE `workspaces` (
	`id` text PRIMARY KEY,
	`name` text NOT NULL,
	`actor_id` text NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `assignments_run` ON `assignments` (`run_id`);--> statement-breakpoint
CREATE INDEX `events_run` ON `events` (`run_id`,`id`);--> statement-breakpoint
CREATE INDEX `evidence_run` ON `evidence` (`run_id`);--> statement-breakpoint
CREATE INDEX `findings_run` ON `findings` (`run_id`);--> statement-breakpoint
CREATE INDEX `thread_messages` ON `messages` (`run_id`,`thread_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `project_assets_origin` ON `project_assets` (`project_id`,`origin`);--> statement-breakpoint
CREATE UNIQUE INDEX `report_version` ON `reports` (`run_id`,`version`);--> statement-breakpoint
CREATE INDEX `runs_project` ON `runs` (`project_id`);