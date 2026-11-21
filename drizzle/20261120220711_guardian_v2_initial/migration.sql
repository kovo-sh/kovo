CREATE TABLE `approval_requests` (
	`id` text PRIMARY KEY,
	`run_id` text NOT NULL,
	`assignment_id` text NOT NULL,
	`scope_revision` integer NOT NULL,
	`origin` text NOT NULL,
	`method` text NOT NULL,
	`path_and_query` text NOT NULL,
	`persona_handle` text,
	`rationale` text NOT NULL,
	`request_preview` text NOT NULL,
	`status` text NOT NULL,
	`decided_by` text,
	`decided_at` integer,
	`expires_at` integer NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_approval_requests_run_id_runs_id_fk` FOREIGN KEY (`run_id`) REFERENCES `runs`(`id`),
	CONSTRAINT `fk_approval_requests_assignment_id_assignments_id_fk` FOREIGN KEY (`assignment_id`) REFERENCES `assignments`(`id`)
);
--> statement-breakpoint
CREATE TABLE `assignments` (
	`id` text PRIMARY KEY,
	`run_id` text NOT NULL,
	`asset_id` text,
	`step_id` text,
	`input_assignment_id` text,
	`phase` text NOT NULL,
	`status` text NOT NULL,
	`scope_revision` integer NOT NULL,
	`goal_revision` integer NOT NULL,
	`session_id` text NOT NULL,
	`lease` text,
	`lease_expires_at` integer,
	`attempt` integer DEFAULT 0 NOT NULL,
	`max_turns` integer DEFAULT 150 NOT NULL,
	`turns_used` integer DEFAULT 0 NOT NULL,
	`requests_used` integer DEFAULT 0 NOT NULL,
	`parent_fact_ids` text NOT NULL,
	`source_origins` text NOT NULL,
	`title` text NOT NULL,
	`objective` text NOT NULL,
	`outcome` text,
	`checks` text,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_assignments_run_id_runs_id_fk` FOREIGN KEY (`run_id`) REFERENCES `runs`(`id`)
);
--> statement-breakpoint
CREATE TABLE `broker_exchanges` (
	`id` text PRIMARY KEY,
	`run_id` text NOT NULL,
	`assignment_id` text NOT NULL,
	`scope_revision` integer NOT NULL,
	`origin` text NOT NULL,
	`final_origin` text NOT NULL,
	`redirect_origins` text NOT NULL,
	`method` text NOT NULL,
	`path_and_query` text NOT NULL,
	`persona_handle` text,
	`status` integer NOT NULL,
	`media_type` text NOT NULL,
	`req_headers` text NOT NULL,
	`resp_headers` text NOT NULL,
	`body_preview` text NOT NULL,
	`body_artifact_id` text,
	`body_sha256` text NOT NULL,
	`duration_ms` integer NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_broker_exchanges_run_id_runs_id_fk` FOREIGN KEY (`run_id`) REFERENCES `runs`(`id`),
	CONSTRAINT `fk_broker_exchanges_assignment_id_assignments_id_fk` FOREIGN KEY (`assignment_id`) REFERENCES `assignments`(`id`)
);
--> statement-breakpoint
CREATE TABLE `canaries` (
	`id` text PRIMARY KEY,
	`run_id` text NOT NULL,
	`assignment_id` text NOT NULL,
	`token` text NOT NULL UNIQUE,
	`purpose` text NOT NULL,
	`triggered` integer DEFAULT false NOT NULL,
	`trigger_detail` text,
	`created_at` integer NOT NULL,
	`triggered_at` integer,
	CONSTRAINT `fk_canaries_run_id_runs_id_fk` FOREIGN KEY (`run_id`) REFERENCES `runs`(`id`)
);
--> statement-breakpoint
CREATE TABLE `chain_steps` (
	`id` text PRIMARY KEY,
	`run_id` text NOT NULL,
	`goal_revision` integer NOT NULL,
	`scope_revision` integer NOT NULL,
	`seq` integer NOT NULL,
	`title` text NOT NULL,
	`hypothesis` text NOT NULL,
	`category` text DEFAULT 'misconfig-exposure' NOT NULL,
	`priority` integer DEFAULT 50 NOT NULL,
	`target_asset_ids` text NOT NULL,
	`skills` text NOT NULL,
	`depends_on_fact_ids` text NOT NULL,
	`depends_on_step_ids` text NOT NULL,
	`status` text NOT NULL,
	`assigned_worker_id` text,
	`source_origins` text NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	CONSTRAINT `fk_chain_steps_run_id_runs_id_fk` FOREIGN KEY (`run_id`) REFERENCES `runs`(`id`)
);
--> statement-breakpoint
CREATE TABLE `coverage_entries` (
	`id` text PRIMARY KEY,
	`run_id` text NOT NULL,
	`scope_revision` integer NOT NULL,
	`goal_revision` integer NOT NULL,
	`origin` text NOT NULL,
	`category` text NOT NULL,
	`status` text NOT NULL,
	`summary` text NOT NULL,
	`assignment_id` text NOT NULL,
	`updated_at` integer NOT NULL,
	CONSTRAINT `fk_coverage_entries_run_id_runs_id_fk` FOREIGN KEY (`run_id`) REFERENCES `runs`(`id`)
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
	`operation_id` text,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_evidence_run_id_runs_id_fk` FOREIGN KEY (`run_id`) REFERENCES `runs`(`id`),
	CONSTRAINT `fk_evidence_assignment_id_assignments_id_fk` FOREIGN KEY (`assignment_id`) REFERENCES `assignments`(`id`)
);
--> statement-breakpoint
CREATE TABLE `facts` (
	`id` text PRIMARY KEY,
	`run_id` text NOT NULL,
	`assignment_id` text NOT NULL,
	`scope_revision` integer NOT NULL,
	`goal_revision` integer NOT NULL,
	`kind` text NOT NULL,
	`origin` text NOT NULL,
	`summary` text NOT NULL,
	`data` text NOT NULL,
	`source_origins` text NOT NULL,
	`evidence_ids` text NOT NULL,
	`exchange_ids` text NOT NULL,
	`tainted` integer DEFAULT false NOT NULL,
	`cold_since_round` integer,
	`digest_id` text,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_facts_run_id_runs_id_fk` FOREIGN KEY (`run_id`) REFERENCES `runs`(`id`),
	CONSTRAINT `fk_facts_assignment_id_assignments_id_fk` FOREIGN KEY (`assignment_id`) REFERENCES `assignments`(`id`)
);
--> statement-breakpoint
CREATE TABLE `findings` (
	`id` text PRIMARY KEY,
	`run_id` text NOT NULL,
	`asset_id` text NOT NULL,
	`goal_revision` integer NOT NULL,
	`check_id` text DEFAULT 'hsts' NOT NULL,
	`case_id` text DEFAULT '' NOT NULL,
	`finding_kind` text DEFAULT 'baseline_check' NOT NULL,
	`replay_spec_id` text,
	`source_origins` text NOT NULL,
	`finding` text NOT NULL,
	CONSTRAINT `fk_findings_run_id_runs_id_fk` FOREIGN KEY (`run_id`) REFERENCES `runs`(`id`)
);
--> statement-breakpoint
CREATE TABLE `graph_digests` (
	`id` text PRIMARY KEY,
	`run_id` text NOT NULL,
	`round_no` integer NOT NULL,
	`level` text NOT NULL,
	`signature_hash` text NOT NULL,
	`summary` text NOT NULL,
	`covered_fact_ids` text NOT NULL,
	`covered_assignment_ids` text NOT NULL,
	`active` integer DEFAULT true NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_graph_digests_run_id_runs_id_fk` FOREIGN KEY (`run_id`) REFERENCES `runs`(`id`)
);
--> statement-breakpoint
CREATE TABLE `graph_edges` (
	`id` text PRIMARY KEY,
	`run_id` text NOT NULL,
	`from_kind` text NOT NULL,
	`from_id` text NOT NULL,
	`to_kind` text NOT NULL,
	`to_id` text NOT NULL,
	`edge_kind` text NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_graph_edges_run_id_runs_id_fk` FOREIGN KEY (`run_id`) REFERENCES `runs`(`id`)
);
--> statement-breakpoint
CREATE TABLE `messages` (
	`id` text PRIMARY KEY,
	`run_id` text NOT NULL,
	`thread_id` text NOT NULL,
	`role` text NOT NULL,
	`content` text NOT NULL,
	`reply_to` text,
	`evidence_ids` text,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_messages_run_id_runs_id_fk` FOREIGN KEY (`run_id`) REFERENCES `runs`(`id`)
);
--> statement-breakpoint
CREATE TABLE `model_profiles` (
	`id` text PRIMARY KEY,
	`workspace_id` text NOT NULL,
	`name` text NOT NULL,
	`endpoint` text NOT NULL,
	`model` text NOT NULL,
	`protocol` text NOT NULL,
	`credential_id` text NOT NULL,
	`priority` integer DEFAULT 100 NOT NULL,
	`enabled` integer DEFAULT true NOT NULL,
	`context_window` integer DEFAULT 131072 NOT NULL,
	`max_tokens` integer DEFAULT 16384 NOT NULL,
	`thinking_level` text DEFAULT 'medium' NOT NULL,
	`input_cost_per_mtok` real DEFAULT 0.25 NOT NULL,
	`output_cost_per_mtok` real DEFAULT 0.9 NOT NULL,
	`health_state` text DEFAULT 'closed' NOT NULL,
	`cooldown_until` integer,
	`last_error` text,
	`updated_at` integer NOT NULL,
	CONSTRAINT `fk_model_profiles_workspace_id_workspaces_id_fk` FOREIGN KEY (`workspace_id`) REFERENCES `workspaces`(`id`)
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
CREATE TABLE `personas` (
	`id` text PRIMARY KEY,
	`project_id` text NOT NULL,
	`workspace_id` text NOT NULL,
	`handle` text NOT NULL,
	`role_label` text NOT NULL,
	`origin_allowlist` text NOT NULL,
	`auth_kind` text NOT NULL,
	`header_name` text,
	`credential_id` text NOT NULL,
	`canary_markers` text NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_personas_project_id_projects_id_fk` FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`),
	CONSTRAINT `fk_personas_workspace_id_workspaces_id_fk` FOREIGN KEY (`workspace_id`) REFERENCES `workspaces`(`id`)
);
--> statement-breakpoint
CREATE TABLE `project_assets` (
	`id` text PRIMARY KEY,
	`project_id` text NOT NULL,
	`origin` text NOT NULL,
	`source` text NOT NULL,
	`third_party` integer NOT NULL,
	`prepared` text,
	`dns_source` text,
	`access_policy` text,
	CONSTRAINT `fk_project_assets_project_id_projects_id_fk` FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`)
);
--> statement-breakpoint
CREATE TABLE `project_specs` (
	`id` text PRIMARY KEY,
	`project_id` text NOT NULL,
	`name` text NOT NULL,
	`kind` text NOT NULL,
	`origin` text,
	`content` text NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_project_specs_project_id_projects_id_fk` FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`)
);
--> statement-breakpoint
CREATE TABLE `projects` (
	`id` text PRIMARY KEY,
	`workspace_id` text NOT NULL,
	`name` text NOT NULL,
	`environment` text DEFAULT 'public' NOT NULL,
	`seeds` text NOT NULL,
	`default_scope` text NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_projects_workspace_id_workspaces_id_fk` FOREIGN KEY (`workspace_id`) REFERENCES `workspaces`(`id`)
);
--> statement-breakpoint
CREATE TABLE `replay_specs` (
	`id` text PRIMARY KEY,
	`run_id` text NOT NULL,
	`finding_id` text NOT NULL,
	`assignment_id` text NOT NULL,
	`scope_revision` integer NOT NULL,
	`goal_revision` integer NOT NULL,
	`spec` text NOT NULL,
	`spec_sha256` text NOT NULL,
	`source_origins` text NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_replay_specs_run_id_runs_id_fk` FOREIGN KEY (`run_id`) REFERENCES `runs`(`id`),
	CONSTRAINT `fk_replay_specs_assignment_id_assignments_id_fk` FOREIGN KEY (`assignment_id`) REFERENCES `assignments`(`id`)
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
CREATE TABLE `retest_runs` (
	`id` text PRIMARY KEY,
	`project_id` text NOT NULL,
	`run_id` text NOT NULL,
	`finding_id` text NOT NULL,
	`replay_spec_id` text NOT NULL,
	`scope_revision` integer NOT NULL,
	`verdict` text NOT NULL,
	`summary` text NOT NULL,
	`evidence_ids` text NOT NULL,
	`exchange_ids` text NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_retest_runs_project_id_projects_id_fk` FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`),
	CONSTRAINT `fk_retest_runs_run_id_runs_id_fk` FOREIGN KEY (`run_id`) REFERENCES `runs`(`id`),
	CONSTRAINT `fk_retest_runs_replay_spec_id_replay_specs_id_fk` FOREIGN KEY (`replay_spec_id`) REFERENCES `replay_specs`(`id`)
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
	`source_mode` text DEFAULT 'public' NOT NULL,
	`capability_tier` integer DEFAULT 1 NOT NULL,
	`approved_persona_ids` text NOT NULL,
	`round_no` integer DEFAULT 0 NOT NULL,
	`budget_usd` real DEFAULT 25 NOT NULL,
	`budget_requests` integer DEFAULT 2500 NOT NULL,
	`spent_usd` real DEFAULT 0 NOT NULL,
	`spent_tokens` integer DEFAULT 0 NOT NULL,
	`spent_requests` integer DEFAULT 0 NOT NULL,
	`turns_used` integer DEFAULT 0 NOT NULL,
	`max_rps_per_origin` integer DEFAULT 5 NOT NULL,
	`worker_concurrency` integer DEFAULT 6 NOT NULL,
	`worker_max_turns` integer DEFAULT 150 NOT NULL,
	`review_plan` text,
	`candidates` text NOT NULL,
	`approved` text NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_runs_project_id_projects_id_fk` FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`),
	CONSTRAINT `fk_runs_workspace_id_workspaces_id_fk` FOREIGN KEY (`workspace_id`) REFERENCES `workspaces`(`id`)
);
--> statement-breakpoint
CREATE TABLE `threat_models` (
	`id` text PRIMARY KEY,
	`run_id` text NOT NULL,
	`scope_revision` integer NOT NULL,
	`goal_revision` integer NOT NULL,
	`entries` text NOT NULL,
	`summary` text NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_threat_models_run_id_runs_id_fk` FOREIGN KEY (`run_id`) REFERENCES `runs`(`id`)
);
--> statement-breakpoint
CREATE TABLE `workspaces` (
	`id` text PRIMARY KEY,
	`name` text NOT NULL,
	`actor_id` text NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `approval_requests_run` ON `approval_requests` (`run_id`,`status`);--> statement-breakpoint
CREATE INDEX `assignments_run` ON `assignments` (`run_id`);--> statement-breakpoint
CREATE INDEX `broker_exchanges_run` ON `broker_exchanges` (`run_id`,`origin`);--> statement-breakpoint
CREATE INDEX `canaries_run` ON `canaries` (`run_id`);--> statement-breakpoint
CREATE INDEX `chain_steps_run` ON `chain_steps` (`run_id`,`status`);--> statement-breakpoint
CREATE UNIQUE INDEX `coverage_origin_cat` ON `coverage_entries` (`run_id`,`goal_revision`,`origin`,`category`);--> statement-breakpoint
CREATE INDEX `events_run` ON `events` (`run_id`,`id`);--> statement-breakpoint
CREATE INDEX `evidence_run` ON `evidence` (`run_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `evidence_operation` ON `evidence` (`assignment_id`,`operation_id`);--> statement-breakpoint
CREATE INDEX `facts_run` ON `facts` (`run_id`,`tainted`);--> statement-breakpoint
CREATE INDEX `findings_run` ON `findings` (`run_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `findings_check_case` ON `findings` (`run_id`,`asset_id`,`goal_revision`,`check_id`,`case_id`);--> statement-breakpoint
CREATE INDEX `graph_digests_run` ON `graph_digests` (`run_id`,`active`);--> statement-breakpoint
CREATE INDEX `graph_edges_run` ON `graph_edges` (`run_id`,`from_id`);--> statement-breakpoint
CREATE INDEX `graph_edges_to` ON `graph_edges` (`run_id`,`to_id`);--> statement-breakpoint
CREATE INDEX `thread_messages` ON `messages` (`run_id`,`thread_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `run_replies` ON `messages` (`run_id`,`reply_to`);--> statement-breakpoint
CREATE INDEX `model_profiles_workspace` ON `model_profiles` (`workspace_id`,`priority`);--> statement-breakpoint
CREATE UNIQUE INDEX `personas_project_handle` ON `personas` (`project_id`,`handle`);--> statement-breakpoint
CREATE UNIQUE INDEX `project_assets_origin` ON `project_assets` (`project_id`,`origin`);--> statement-breakpoint
CREATE INDEX `project_specs_project` ON `project_specs` (`project_id`);--> statement-breakpoint
CREATE INDEX `replay_specs_run` ON `replay_specs` (`run_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `report_version` ON `reports` (`run_id`,`version`);--> statement-breakpoint
CREATE INDEX `retest_runs_finding` ON `retest_runs` (`finding_id`);--> statement-breakpoint
CREATE INDEX `runs_project` ON `runs` (`project_id`);--> statement-breakpoint
CREATE INDEX `threat_models_run` ON `threat_models` (`run_id`);