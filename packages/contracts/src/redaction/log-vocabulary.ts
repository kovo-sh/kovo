// Closed log vocabulary. Changes require review; never derive this from runtime values.
// LOG_EVENT_CODES, LOG_FIELD_KEYS and LOG_ENUM_CODES are the union of the per-area lists in
// ./log-vocabulary/<area>.ts (#9010): static string literals, one per line, sorted, each code in
// exactly one area file. Add a new code to the area file of the code that emits it (create the
// area file and spread it here when none exists); log-vocabulary.test.ts enforces the layout.
import { LOG_ENUM_CODES as ADAPTERS_RESEARCH_FEEDS_ENUM_CODES } from "./log-vocabulary/adapters-research-feeds.js";
import {
  LOG_ENUM_CODES as ADAPTERS_SANDBOX_ENUM_CODES,
  LOG_EVENT_CODES as ADAPTERS_SANDBOX_EVENT_CODES,
} from "./log-vocabulary/adapters-sandbox.js";
import { LOG_EVENT_CODES as ADMIN_APP_EVENT_CODES } from "./log-vocabulary/admin-app.js";
import { LOG_EVENT_CODES as AI_EVENT_CODES } from "./log-vocabulary/ai.js";
import {
  LOG_ENUM_CODES as BILLING_ENUM_CODES,
  LOG_EVENT_CODES as BILLING_EVENT_CODES,
  LOG_FIELD_KEYS as BILLING_FIELD_KEYS,
} from "./log-vocabulary/billing.js";
import {
  LOG_EVENT_CODES as CONTROL_PLANE_API_EVENT_CODES,
  LOG_FIELD_KEYS as CONTROL_PLANE_API_FIELD_KEYS,
} from "./log-vocabulary/control-plane-api.js";
import {
  LOG_ENUM_CODES as CONTROL_PLANE_BIN_ENUM_CODES,
  LOG_EVENT_CODES as CONTROL_PLANE_BIN_EVENT_CODES,
} from "./log-vocabulary/control-plane-bin.js";
import {
  LOG_ENUM_CODES as CONTROL_PLANE_DBOS_ENUM_CODES,
  LOG_EVENT_CODES as CONTROL_PLANE_DBOS_EVENT_CODES,
  LOG_FIELD_KEYS as CONTROL_PLANE_DBOS_FIELD_KEYS,
} from "./log-vocabulary/control-plane-dbos.js";
import {
  LOG_ENUM_CODES as CONTROL_PLANE_ENTRYPOINTS_ENUM_CODES,
  LOG_EVENT_CODES as CONTROL_PLANE_ENTRYPOINTS_EVENT_CODES,
  LOG_FIELD_KEYS as CONTROL_PLANE_ENTRYPOINTS_FIELD_KEYS,
} from "./log-vocabulary/control-plane-entrypoints.js";
import {
  LOG_ENUM_CODES as CONTROL_PLANE_OUTBOX_ENUM_CODES,
  LOG_EVENT_CODES as CONTROL_PLANE_OUTBOX_EVENT_CODES,
} from "./log-vocabulary/control-plane-outbox.js";
import {
  LOG_ENUM_CODES as CONTROL_PLANE_PLATFORM_ENUM_CODES,
  LOG_EVENT_CODES as CONTROL_PLANE_PLATFORM_EVENT_CODES,
  LOG_FIELD_KEYS as CONTROL_PLANE_PLATFORM_FIELD_KEYS,
} from "./log-vocabulary/control-plane-platform.js";
import { LOG_ENUM_CODES as CONTROL_PLANE_PORTS_ENUM_CODES } from "./log-vocabulary/control-plane-ports.js";
import {
  LOG_ENUM_CODES as CONTROL_PLANE_PROXY_ENUM_CODES,
  LOG_EVENT_CODES as CONTROL_PLANE_PROXY_EVENT_CODES,
  LOG_FIELD_KEYS as CONTROL_PLANE_PROXY_FIELD_KEYS,
} from "./log-vocabulary/control-plane-proxy.js";
import { LOG_EVENT_CODES as CONTROL_PLANE_RELAY_EVENT_CODES } from "./log-vocabulary/control-plane-relay.js";
import {
  LOG_ENUM_CODES as CONTROL_PLANE_RELEASE_ENUM_CODES,
  LOG_EVENT_CODES as CONTROL_PLANE_RELEASE_EVENT_CODES,
} from "./log-vocabulary/control-plane-release.js";
import {
  LOG_ENUM_CODES as CONTROL_PLANE_WORKFLOWS_ENUM_CODES,
  LOG_EVENT_CODES as CONTROL_PLANE_WORKFLOWS_EVENT_CODES,
  LOG_FIELD_KEYS as CONTROL_PLANE_WORKFLOWS_FIELD_KEYS,
} from "./log-vocabulary/control-plane-workflows.js";
import { LOG_ENUM_CODES as CORE_LOCKFILE_ENUM_CODES } from "./log-vocabulary/core-lockfile.js";
import { LOG_ENUM_CODES as CORE_POLICY_ENUM_CODES } from "./log-vocabulary/core-policy.js";
import { LOG_ENUM_CODES as DB_ENUM_CODES } from "./log-vocabulary/db.js";
import {
  LOG_ENUM_CODES as DEPENDENCY_GATE_ENUM_CODES,
  LOG_EVENT_CODES as DEPENDENCY_GATE_EVENT_CODES,
} from "./log-vocabulary/dependency-gate.js";
import { LOG_EVENT_CODES as FAILURE_EXCERPTS_EVENT_CODES } from "./log-vocabulary/failure-excerpts.js";
import {
  LOG_ENUM_CODES as GENERATION_ENUM_CODES,
  LOG_EVENT_CODES as GENERATION_EVENT_CODES,
} from "./log-vocabulary/generation.js";
import {
  LOG_ENUM_CODES as GITHUB_ENUM_CODES,
  LOG_EVENT_CODES as GITHUB_EVENT_CODES,
} from "./log-vocabulary/github.js";
import {
  LOG_ENUM_CODES as INCIDENT_BRIDGE_ENUM_CODES,
  LOG_EVENT_CODES as INCIDENT_BRIDGE_EVENT_CODES,
  LOG_FIELD_KEYS as INCIDENT_BRIDGE_FIELD_KEYS,
} from "./log-vocabulary/incident-bridge.js";
import {
  LOG_ENUM_CODES as MERGE_ENUM_CODES,
  LOG_EVENT_CODES as MERGE_EVENT_CODES,
} from "./log-vocabulary/merge.js";
import { LOG_EVENT_CODES as NOTIFICATIONS_EVENT_CODES } from "./log-vocabulary/notifications.js";
import {
  LOG_ENUM_CODES as NPM_PROXY_ENUM_CODES,
  LOG_EVENT_CODES as NPM_PROXY_EVENT_CODES,
} from "./log-vocabulary/npm-proxy.js";
import {
  LOG_ENUM_CODES as OPERATIONS_ENUM_CODES,
  LOG_EVENT_CODES as OPERATIONS_EVENT_CODES,
  LOG_FIELD_KEYS as OPERATIONS_FIELD_KEYS,
} from "./log-vocabulary/operations.js";
import {
  LOG_EVENT_CODES as OUTREACH_EVENT_CODES,
  LOG_FIELD_KEYS as OUTREACH_FIELD_KEYS,
} from "./log-vocabulary/outreach.js";
import { LOG_EVENT_CODES as PATCHES_EVENT_CODES } from "./log-vocabulary/patches.js";
import {
  LOG_ENUM_CODES as RECIPES_ENUM_CODES,
  LOG_EVENT_CODES as RECIPES_EVENT_CODES,
} from "./log-vocabulary/recipes.js";
import { LOG_EVENT_CODES as RETENTION_EVENT_CODES } from "./log-vocabulary/retention.js";
import {
  LOG_ENUM_CODES as RUN_RECORDS_ENUM_CODES,
  LOG_EVENT_CODES as RUN_RECORDS_EVENT_CODES,
} from "./log-vocabulary/run-records.js";
import {
  LOG_ENUM_CODES as SANDBOX_ENUM_CODES,
  LOG_EVENT_CODES as SANDBOX_EVENT_CODES,
  LOG_FIELD_KEYS as SANDBOX_FIELD_KEYS,
} from "./log-vocabulary/sandbox.js";
import {
  LOG_ENUM_CODES as SHARED_ENUM_CODES,
  LOG_EVENT_CODES as SHARED_EVENT_CODES,
  LOG_FIELD_KEYS as SHARED_FIELD_KEYS,
} from "./log-vocabulary/shared.js";
import {
  LOG_ENUM_CODES as SITE_SCANNER_ENUM_CODES,
  LOG_EVENT_CODES as SITE_SCANNER_EVENT_CODES,
} from "./log-vocabulary/site-scanner.js";
import {
  LOG_ENUM_CODES as VERIFICATION_ENUM_CODES,
  LOG_EVENT_CODES as VERIFICATION_EVENT_CODES,
  LOG_FIELD_KEYS as VERIFICATION_FIELD_KEYS,
} from "./log-vocabulary/verification.js";
import { LOG_EVENT_CODES as WEB_EVENT_CODES } from "./log-vocabulary/web.js";

export const LOG_EVENT_CODES = [
  ...ADAPTERS_SANDBOX_EVENT_CODES,
  ...ADMIN_APP_EVENT_CODES,
  ...AI_EVENT_CODES,
  ...BILLING_EVENT_CODES,
  ...CONTROL_PLANE_API_EVENT_CODES,
  ...CONTROL_PLANE_BIN_EVENT_CODES,
  ...CONTROL_PLANE_DBOS_EVENT_CODES,
  ...CONTROL_PLANE_ENTRYPOINTS_EVENT_CODES,
  ...CONTROL_PLANE_OUTBOX_EVENT_CODES,
  ...CONTROL_PLANE_PLATFORM_EVENT_CODES,
  ...CONTROL_PLANE_PROXY_EVENT_CODES,
  ...CONTROL_PLANE_RELAY_EVENT_CODES,
  ...CONTROL_PLANE_RELEASE_EVENT_CODES,
  ...CONTROL_PLANE_WORKFLOWS_EVENT_CODES,
  ...DEPENDENCY_GATE_EVENT_CODES,
  ...FAILURE_EXCERPTS_EVENT_CODES,
  ...GENERATION_EVENT_CODES,
  ...GITHUB_EVENT_CODES,
  ...INCIDENT_BRIDGE_EVENT_CODES,
  ...MERGE_EVENT_CODES,
  ...NOTIFICATIONS_EVENT_CODES,
  ...NPM_PROXY_EVENT_CODES,
  ...OPERATIONS_EVENT_CODES,
  ...OUTREACH_EVENT_CODES,
  ...PATCHES_EVENT_CODES,
  ...RECIPES_EVENT_CODES,
  ...RETENTION_EVENT_CODES,
  ...RUN_RECORDS_EVENT_CODES,
  ...SANDBOX_EVENT_CODES,
  ...SHARED_EVENT_CODES,
  ...SITE_SCANNER_EVENT_CODES,
  ...VERIFICATION_EVENT_CODES,
  ...WEB_EVENT_CODES,
] as const;
export const LOG_FIELD_KEYS = [
  ...BILLING_FIELD_KEYS,
  ...CONTROL_PLANE_API_FIELD_KEYS,
  ...CONTROL_PLANE_DBOS_FIELD_KEYS,
  ...CONTROL_PLANE_ENTRYPOINTS_FIELD_KEYS,
  ...CONTROL_PLANE_PLATFORM_FIELD_KEYS,
  ...CONTROL_PLANE_PROXY_FIELD_KEYS,
  ...CONTROL_PLANE_WORKFLOWS_FIELD_KEYS,
  ...INCIDENT_BRIDGE_FIELD_KEYS,
  ...OPERATIONS_FIELD_KEYS,
  ...OUTREACH_FIELD_KEYS,
  ...SANDBOX_FIELD_KEYS,
  ...SHARED_FIELD_KEYS,
  ...VERIFICATION_FIELD_KEYS,
] as const;
/**
 * Why inventory refused a repository, finer than the coarse `unsupported_reason` it stores
 * (D-267, #2135): the `reason_code` of an `inventory_unsupported_detail` line. Each names the
 * step that refused, never a file's content. `unsupported_pnpm_setting` is a pnpm setting the
 * allowlist refuses; the line's `setting_key` names the key (never the value).
 */
export const INVENTORY_REFUSAL_CODES = [
  // #8491: GitHub answered a file the commit's tree lists as missing on every bounded read.
  "github_content_inconsistent",
  "inventory_npmrc_too_large",
  "inventory_npmrc_unverifiable",
  "inventory_package_manager_override",
  // D-726 fix-only: a package locked at a private registry whose scope `.npmrc` does not declare.
  "inventory_private_registry_undeclared",
  // D-726 fix-only: private scopes under a package manager fix-only does not cover (Yarn).
  "inventory_private_registry_package_manager",
  "inventory_registry_override",
  "inventory_fix_only_refused",
  // #8256: the lockfile parser refused the root; `lockfile_reason` names the parser's reason.
  "inventory_lockfile_refused",
  "inventory_root_detection_refused",
  "inventory_root_lockfile_refused",
  "inventory_root_npmrc_refused",
  "inventory_root_package_json_refused",
  "inventory_root_tree_truncated",
  "inventory_root_version_file_refused",
  // #8256: the one runtime resolver refused the root; `runtime_reason` names the gate.
  "inventory_runtime_refused",
  "inventory_scoped_registry",
  "inventory_workspace_admission_disabled",
  "inventory_workspace_bytes_budget_exceeded",
  "inventory_workspace_command_path_unsupported",
  "inventory_workspace_declares_no_members",
  "inventory_workspace_dependency_path_missing",
  "inventory_workspace_file_digest_mismatch",
  // Reserved, no emitter since #8491: a listed workspace file GitHub answers as missing is now
  // `github_content_inconsistent`. Kept so older log lines and dashboards still name it.
  "inventory_workspace_file_missing",
  "inventory_workspace_file_too_large",
  "inventory_workspace_file_undecodable",
  "inventory_workspace_graph_refused",
  "inventory_workspace_graph_too_large",
  "inventory_workspace_input_absent",
  "inventory_workspace_inventory_invalid",
  "inventory_workspace_inventory_too_large",
  "inventory_workspace_member_runtime_mismatch",
  "inventory_workspace_member_version_file_unreadable",
  "inventory_workspace_read_budget_exceeded",
  "inventory_workspace_root_unresolved",
  "inventory_workspace_runtime_incompatible",
  "inventory_workspace_runtime_unresolved",
  "inventory_workspace_tree_too_large",
  "unsupported_pnpm_setting",
] as const;
/**
 * Why recipe discovery refused a repository, finer than the job's `unsupported_repository`
 * (D-267, #7503): the `reason_code` of a `recipe_discovery_refused` line. Each names the stage
 * that refused, never a file's content or path. `discovery_workspace_layout_refused` carries the
 * core reason in `workspace_reason`; a core detail outside this list is
 * `discovery_detail_unlisted`.
 */
export const DISCOVERY_REFUSAL_CODES = [
  "discovery_ci_budget_exceeded",
  "discovery_detail_unlisted",
  "discovery_invalid_package_json",
  "discovery_lockfile_refused",
  "discovery_missing_package_json",
  "discovery_pnpm_workspace_file",
  "discovery_pnpm_workspace_yaml_not_regular",
  "discovery_project_scope_ambiguous",
  // #8256: the one runtime resolver refused the root; `runtime_reason` names the gate.
  "discovery_runtime_refused",
  "discovery_too_many_ci_steps",
  "discovery_too_many_env_stubs",
  "discovery_too_many_recipe_steps",
  "discovery_tree_too_large",
  "discovery_unsupported_repository",
  "discovery_workspace_admission_proof_mismatch",
  "discovery_workspace_authority_not_regular",
  "discovery_workspace_authority_unread",
  "discovery_workspace_authority_unreadable",
  "discovery_workspace_environment_conflict",
  "discovery_workspace_input_bytes_exceeded",
  "discovery_workspace_inputs_missing",
  "discovery_workspace_inventory_refused",
  "discovery_workspace_layout_refused",
  "discovery_workspace_link_unsafe",
  "discovery_workspace_member_authority_unavailable",
  "discovery_workspace_member_selection_script_missing",
  "discovery_workspace_member_selection_unknown_member",
  "discovery_workspace_member_selection_unsupported",
  "discovery_workspace_orchestration_cache_unproven",
  "discovery_workspace_recipe_resource_limit",
  "discovery_workspaces",
  "discovery_yarn_berry_unsupported",
] as const;
/**
 * Which check of project recipe discovery refused (#8127): the `scope_cause` of a
 * `recipe_discovery_refused` line whose `reason_code` is `discovery_project_scope_ambiguous`.
 * `roots_*` re-reads the install roots, `root_inputs_*` reads one root's recipe inputs, the rest
 * match the stored projects to them. Never a path, name or content.
 */
export const PROJECT_SCOPE_CAUSES = [
  "ci_steps_unbounded",
  "classification_refused",
  "composition_refused",
  "identity_stale",
  "plan_changed",
  "plan_too_large",
  "root_inputs_content_mismatch",
  "root_inputs_link_unsafe",
  "root_inputs_mode_unsupported",
  "root_inputs_not_utf8",
  "root_inputs_path_invalid",
  "root_inputs_read_incomplete",
  "root_inputs_too_many_files",
  "root_inputs_tree_too_large",
  "root_inputs_tree_unavailable",
  "roots_authority_unreadable",
  "roots_budget_exceeded",
  "roots_layout_refused",
  "roots_registry_needs_invalid",
  "roots_tree_unavailable",
  "stored_project_missing",
  "stored_root_missing",
] as const;
export type ProjectScopeCause = (typeof PROJECT_SCOPE_CAUSES)[number];
/**
 * Why a verification or calibration run ended before any step ran (D-267, #7609): the
 * `reason_code` of a `verification_harness_incomplete` line. Each names the harness stage that
 * stopped the run, never a path, command or output. A stage whose sandbox command failed also
 * carries `outcome` (`command_timed_out` or `command_failed`) and `exitCode`.
 */
export const HARNESS_INCOMPLETE_CODES = [
  "command_failed",
  "command_timed_out",
  "harness_checkout_unreadable",
  "harness_chmod_failed",
  "harness_delete_failed",
  "harness_extract_failed",
  "harness_listing_incomplete",
  "harness_mutation_unavailable",
  "harness_plan_refused",
  // D-726 fix-only: the tree's `.npmrc` names a private registry, so Kovo never runs it.
  "harness_private_registry_fix_only",
  "harness_relock_failed",
  // CI-first admission (#8256 R2): Kovo fixed this root but cannot run it (`can_verify` false): a
  // Yarn 4, Bun or lockfile-less root, or a pnpm `.npmrc` setting Kovo's harness cannot model.
  "harness_kovo_cannot_run",
  // Owner D-727 a: a lockfile-less root's generated lockfile could not be made (npm cannot lock the
  // manifest as it is, or the generation gave no usable lockfile); the run falls back to R2.
  "harness_lockfile_generation_failed",
  "harness_lockfile_generation_unsupported",
  "harness_pnpm_setting_unverifiable",
  "harness_runtime_unsupported",
  "harness_source_too_large",
  "harness_workdir_failed",
  "harness_workspace_fix_refused",
  "harness_workspace_graph_missing",
  "harness_workspace_scripts_unreadable",
  "harness_yarn_graph_unreadable",
] as const;
/**
 * Why the recipe gap-fill or the Plus recipe doctor did nothing (D-267, #7753): the `reason_code`
 * of a `recipe_gap_fill_skipped`, `recipe_gap_fill_smoke_missed` or `recipe_doctor_not_triggered`
 * line, with the repository and job IDs only. `gap_fill_<reason>` is the gap-fill's skip reason;
 * a smoke miss is a model that proposed no smoke check (`gap_fill_smoke_not_proposed`) or one
 * validation refused (`gap_fill_smoke_rejected`).
 */
export const RECIPE_GAP_FILL_LOG_CODES = [
  "doctor_reasons_not_repairable",
  "doctor_status_not_considered",
  "gap_fill_ai_unavailable",
  "gap_fill_already_attempted",
  "gap_fill_budget_exhausted",
  "gap_fill_no_ai_entitlement",
  "gap_fill_no_gaps",
  "gap_fill_not_funded",
  "gap_fill_relay_refused",
  "gap_fill_sandbox_unavailable",
  "gap_fill_smoke_not_proposed",
  "gap_fill_smoke_rejected",
] as const;
/**
 * The class of a GitHub content answer's media type (#8491): `raw` is the file itself, `json` a
 * 404 body, directory or submodule metadata. Never the header's value.
 */
export const LOG_CONTENT_TYPE_CLASSES = ["raw", "json", "html", "other", "none"] as const;
/**
 * Which inventory input a GitHub content read was for (#8491): a fixed class, never the path.
 */
export const LOG_CONTENT_PATH_CLASSES = [
  "root_package_json",
  "root_lockfile",
  "root_npmrc",
  "root_version_file",
  "workspace_yaml",
  "member_manifest",
  "member_npmrc",
  "member_version_file",
  "other",
] as const;
/** The core workspace discovery reason (`WORKSPACE_REASONS`) behind a refused workspace graph. */
export const LOG_WORKSPACE_REASONS = [
  "catalog_entry_missing",
  "catalogs_unsupported",
  "conflicting_lockfile",
  "identity_collision",
  "incomplete_graph",
  "incomplete_tree",
  "invalid_catalog",
  "invalid_local_edge",
  "invalid_lockfile",
  "invalid_manifest",
  "invalid_member_identity",
  "invalid_path",
  "invalid_pattern",
  "invalid_workspace_yaml",
  "lockfile_declarations_mismatch",
  "lockfile_members_mismatch",
  "manager_mismatch",
  "missing_manifest",
  "nested_project",
  "out_of_project_scope",
  "project_scope_ambiguous",
  "required_app_unprotected",
  "resource_limit",
  "runtime_mismatch",
  "too_many_projects",
  "unsafe_tree_entry",
  "unsupported_layout",
  "unsupported_workspace_setting",
] as const;
/** The lockfile parser's rejection reason (or workspace check) behind an `invalid_lockfile`. */
export const LOG_LOCKFILE_REASONS = [
  "catalog_protocol",
  "dangling_reference",
  "git_dependency",
  "integrity_conflict",
  "invalid_integrity",
  "invalid_package_name",
  "invalid_package_version",
  "local_path_dependency",
  "lockfile_duplicate_key",
  // Registry-sourced integrity (#7338): the registry lookup failed (network, 404, malformed or
  // no sha512 integrity), a registry other than the public one may serve the package, or more
  // entries than the bound need it.
  "lockfile_integrity_registry_lookup_failed",
  "lockfile_integrity_registry_not_public",
  "lockfile_integrity_registry_too_many",
  "lockfile_invalid",
  "lockfile_not_in_tree",
  "lockfile_syntax",
  "lockfile_too_deep",
  "lockfile_too_large",
  // #8256: the root lockfile is not strict UTF-8 (`inventory_root_lockfile_refused`).
  "lockfile_undecodable",
  "missing_integrity",
  "missing_root",
  "pm_version_unsupported",
  "private_registry_dependency",
  "registry_url_mismatch",
  "remote_tarball_dependency",
  "resolved_conflict",
  "too_many_dependencies",
  "too_many_packages",
  "unsupported_lockfile_version",
  "unsupported_protocol",
  "workspace_packages",
  "workspace_protocol",
] as const;
/**
 * Which gate of the one runtime resolver refused a root (D-267, #8256): the `runtime_reason` of an
 * `inventory_runtime_refused` or `discovery_runtime_refused` line. Equal to `@kovo/core/lockfile`
 * `RUNTIME_REJECTION_REASONS` (a core test keeps the two equal). Never a declared value.
 */
export const LOG_RUNTIME_REASONS = [
  "conflicting_node_declarations",
  "invalid_package_manager_field",
  "lockfile_format_mismatch",
  "node_alias_unresolvable",
  "node_major_unsupported",
  "node_version_unavailable",
  "package_manager_mismatch",
  "package_manager_unsupported",
  "pm_engines_mismatch",
  "pm_major_unsupported",
  "pm_version_unavailable",
  "pnpm_settings_requires_v10",
  "unrecognized_node_declaration",
] as const;
/**
 * Why CI-first admission (#8256 R2) refused a Yarn 4, Bun or lockfile-less root, or a fix in one
 * (D-267, D-441): a closed set, never a value. `@kovo/core/lockfile` `FIX_ONLY_REFUSALS` holds the
 * root refusals (a core test keeps the two equal); `pm_version_unsupported` is a lockfile the
 * pinned Yarn 4 or Bun would rewrite whole, `lockfile_absent_transitive` a transitive finding in a
 * root without a lockfile.
 */
export const LOG_FIX_ONLY_REASONS = [
  "lockfile_absent_transitive",
  "pm_config_unsupported:bunfig_unreadable",
  "pm_config_unsupported:yarn_plugin",
  "pm_config_unsupported:yarn_zero_install",
  "pm_lockfile_unsupported:bun_ambiguous",
  "pm_lockfile_unsupported:bun_lockb",
  "pm_version_unsupported",
] as const;
/** What a rejected setting logs when its key is not one of `LOG_SETTING_KEYS`, or has no `=`. */
export const LOG_SETTING_KEY_UNKNOWN = "unknown_setting";
/**
 * A rejected `.npmrc` / pnpm setting's key as a log field (#2135, D-267): a CLOSED set of the
 * setting names Kovo recognises, never free text. A repository's file is hostile, so any other key
 * (a typo, a pasted token, a bare line) logs `unknown_setting`. A test in @kovo/core keeps every
 * allowlisted pnpm setting and per-registry field in this list. Names only, never a value.
 */
export const LOG_SETTING_KEYS = [
  // The pnpm settings the allowlist admits (`.npmrc` kebab-case spelling), refused on a bad value.
  "audit",
  "auto-install-peers",
  "dedupe-peer-dependents",
  "engine-strict",
  "fund",
  "ignore-scripts",
  "ignored-built-dependencies",
  "lockfile-include-tarball-url",
  "manage-package-manager-versions",
  "minimum-release-age",
  "minimum-release-age-exclude",
  "never-built-dependencies",
  "only-built-dependencies",
  "package-manager-strict",
  "package-manager-strict-version",
  "pm-on-fail",
  "prefer-frozen-lockfile",
  "resolve-peers-from-workspace-root",
  "save-exact",
  "save-prefix",
  "strict-dep-builds",
  "strict-peer-dependencies",
  "trust-policy",
  "trust-policy-exclude",
  "trust-policy-ignore-after",
  "update-notifier",
  // Per-registry fields (`//host/:field`); the host part is never logged.
  "_auth",
  "_authToken",
  "_password",
  "always-auth",
  "certfile",
  "email",
  "keyfile",
  "tokenHelper",
  "username",
  // Common pnpm and npm settings a repository sets that the allowlist refuses.
  "hoist",
  "hoist-pattern",
  "hoist-workspace-packages",
  "link-workspace-packages",
  "node-linker",
  "node-version",
  "package-import-method",
  "public-hoist-pattern",
  "shamefully-hoist",
  "shared-workspace-lockfile",
  "side-effects-cache",
  "store-dir",
  "use-node-version",
  "virtual-store-dir",
  LOG_SETTING_KEY_UNKNOWN,
] as const;
/**
 * Where an inventory's package integrity came from (#7338): the committed lockfile, or the public
 * registry's metadata for an npm workspace entry that recorded none (registry-sourced integrity).
 */
export const LOG_INTEGRITY_SOURCES = ["lockfile", "registry"] as const;
/**
 * Closed codes of the egress gateway's `egress_tunnel` line (D-461): `reason` is the client-visible
 * refusal or the close outcome, `reason_code` the finer cause, `outcome` the authority result.
 * scripts/ops/prod-logs mirrors this list (a test keeps the two in step).
 */
export const EGRESS_TUNNEL_CODES = [
  // Client-visible refusals (tunnel-server.ts refuse(), decideTunnel's deny reasons).
  "too_many_tunnels",
  "invalid_capability",
  "connection_cap",
  "too_many_jobs",
  "too_many_job_tunnels",
  "bad_target",
  "ip_literal",
  "port_not_allowed",
  "invalid_hostname",
  "expired",
  "blocklisted",
  "tombstoned",
  "host_not_allowed",
  "install_binary_hold",
  "dns_failure",
  "private_address",
  "egress_unavailable",
  // Close outcomes after CONNECT was acknowledged.
  "tunnel_closed",
  "client_closed",
  "idle_timeout",
  "peek_timeout",
  "tunnel_expired",
  "ech_refused",
  "sni_mismatch",
  "hello_too_large",
  "budget_denied",
  "upstream_connect_failed",
  "upstream_reset",
  "tunnel_failed",
  // Finer causes: the capability check, the internal authority call and the stage that failed.
  "capability_missing",
  "capability_malformed",
  "capability_duplicated",
  "capability_expired",
  "authority_denied",
  "authority_expiry_mismatch",
  "token_mint_failed",
  "authority_call_timeout",
  "authority_call_network",
  "authority_call_failed",
  "authority_response_invalid",
  "authority_unavailable",
  "accounting_unavailable",
  "dns_resolve_failed",
  // resolveTunnelAddresses' DnsResolveFailure: the failed family and the resolver's class (#6508).
  "dns_resolve_failed_a_timeout",
  "dns_resolve_failed_a_servfail",
  "dns_resolve_failed_a_refused",
  "dns_resolve_failed_a_other",
  "dns_resolve_failed_aaaa_timeout",
  "dns_resolve_failed_aaaa_servfail",
  "dns_resolve_failed_aaaa_refused",
  "dns_resolve_failed_aaaa_other",
  "egress_internal_error",
  // The D-499 WebSocket transport (egress-proxy/websocket-tunnel.ts): a refused upgrade, the
  // pending cap and one line per closed tunnel, with the closed cause as `reason_code`.
  "websocket_refused",
  "too_many_websockets",
  "websocket_closed",
  "websocket_header_invalid",
  "websocket_version_unsupported",
  "websocket_key_invalid",
  "websocket_ended",
  "websocket_setup_timeout",
  "websocket_protocol_error",
  "websocket_frame_too_large",
  "websocket_text_frame",
  "websocket_lifetime_exceeded",
  "websocket_request_invalid",
  // The authority result.
  "granted",
  "refused",
  "failed",
] as const;
/** The class of a failed network call's errno-style code (D-461). */
export const EGRESS_NETWORK_CLASSES = [
  "timeout",
  "refused",
  "reset",
  "dns",
  "tls",
  "unreachable",
  "other",
] as const;
/** The internal authority operations (egress-proxy/http-authority.ts routes). */
export const EGRESS_AUTHORITY_OPERATIONS = [
  "authorize",
  "connections",
  "reserve",
  "release",
  "bytes",
  "observations",
  "canary",
] as const;
/** tunnel-server.ts TunnelStage. */
export const EGRESS_TUNNEL_STAGES = [
  "admission",
  "authorize",
  "accounting",
  "resolve",
  "hello",
  "transfer",
] as const;
/**
 * #8256 R8 (plans/js-coverage-phase2.md §2.6): a `project_closure_fallback_all` line's `reason_code`
 * and its `cause` (`@kovo/contracts` `CLOSURE_FALLBACK_CAUSES`).
 */
export const CLOSURE_FALLBACK_LOG_CODES = [
  "closure_fallback_all",
  "dependency_cycle",
  "graph_unavailable",
  "unknown_importer",
] as const;

/**
 * #8819: the `part` of a `github_reconciliation_skipped_a_failing_part` line (and the `reason`
 * label of `kovo.github.reconciliation_failures`): which part of GitHub reconciliation failed and
 * was skipped (apps/control-plane workflows/github `ReconciliationFailurePart`).
 */
export const GITHUB_RECONCILIATION_PARTS = [
  "cleanup_round",
  "cleanup_settle",
  "delivery_retry",
  "installation",
  "installation_page",
  "nightly_cleanup",
  "permission_cache",
  "protected_repos",
  "protection",
  "settle",
] as const;
export type GithubReconciliationPart = (typeof GITHUB_RECONCILIATION_PARTS)[number];

/**
 * #8819 (D-267): the closed `reason` of a `github_reconciliation_skipped_a_failing_part` line,
 * besides the public `REASON_CODES` a KovoError carries. The failed step's stable reason
 * (`stepFailureReason`): an awaited child's end, a DurableError's own reasons, a coded workflow
 * end, GitHub or Kovo's pacer throttling, an upstream retry stop, a port error kind, a database
 * error kind, or the nightly's own fixed codes. Any other value logs `unclassified_failure`, never
 * free text.
 */
export const GITHUB_RECONCILIATION_FAILURE_REASONS = [
  "ambiguous_outcome",
  "authentication_failed",
  "blocked_destination",
  "check_violation",
  "conflict",
  "connection",
  "db_pool_acquire_timeout",
  "db_pool_draining",
  "db_pooler_wait_timeout",
  "dbos_initialization_failed",
  "deadlock_detected",
  "drill_forced_cancel",
  "foreign_key_violation",
  "installation_suspended",
  "insufficient_privilege",
  "integrity",
  "invalid_request",
  "invalid_workflow_input",
  "isolation_unavailable",
  "limit_exceeded",
  "lock_not_available",
  "no_compliant_provider",
  "not_found",
  "not_null_violation",
  "other",
  "payment_declined",
  "permission_denied",
  "precondition_failed",
  "query_canceled",
  "rate_budget_exhausted",
  "rate_limited",
  "recipe_reconcile_partial",
  "recipe_reconcile_partial_upstream",
  "recipient_inactive",
  "recovery_attempts_exceeded",
  "repo_failure_cap",
  "rls_violation",
  "run_wait_budget_exceeded",
  "secondary_limit_wait",
  "serialization_failure",
  "step_retries_exhausted",
  "throttled_requeued",
  "unavailable",
  "unclassified_failure",
  "unexpected_error",
  "unique_violation",
  "upstream_circuit_open",
  "upstream_rate_limit_wait",
  "upstream_retries_exhausted",
  "validation_failed",
  "wait_exceeds_15_min",
  "workflow_cancelled",
] as const;
export type GithubReconciliationFailureReason =
  (typeof GITHUB_RECONCILIATION_FAILURE_REASONS)[number];

/**
 * #9461 (D-267): the closed `reason_code` of a `github_nightly_throttle_retry` line. The nightly
 * run writes one line per same-night retry attempt at an installation GitHub throttled, when that
 * attempt ends:
 * - `throttle_retry_ran`: the attempt ran unthrottled. Its own outcome is the installation's
 *   nightly stamp and any skipped-part line.
 * - `throttle_retry_throttled_again`: the attempt was throttled again, and the next one is
 *   scheduled after GitHub's reset.
 * - `throttle_retry_attempts_exhausted`: the last attempt was throttled too, so the next night
 *   takes the installation first.
 * - `throttle_retry_past_deadline`: the attempt could not start before the night's run budget
 *   ended, so the next night takes the installation first.
 * The line also carries `installationId`, `attempt`, the bound (`attempts`) and the wait before
 * the attempt (`waitMs`), never content.
 */
export const GITHUB_NIGHTLY_RETRY_CODES = [
  "throttle_retry_ran",
  "throttle_retry_throttled_again",
  "throttle_retry_attempts_exhausted",
  "throttle_retry_past_deadline",
] as const;
export type GithubNightlyRetryCode = (typeof GITHUB_NIGHTLY_RETRY_CODES)[number];

/**
 * Why the calibration snapshot janitor job failed (#9375, D-267): the `reason_code` of its
 * `calibration_snapshot_janitor_failed` line. The step that failed (config, key read) or, for the
 * provider listing, the provider's status class: a 4xx, a 5xx, a timeout or lost connection, an
 * auth refusal (401/403), or a listing Kovo could not read. Never provider error text or a
 * snapshot name. scripts/ops/prod-logs mirrors this list.
 */
export const CALIBRATION_JANITOR_FAILURE_REASONS = [
  "calibration_janitor_config_invalid",
  "calibration_janitor_key_unavailable",
  "calibration_janitor_provider_4xx",
  "calibration_janitor_provider_5xx",
  "calibration_janitor_provider_timeout",
  "calibration_janitor_auth_refused",
  "calibration_janitor_list_unparseable",
  "calibration_janitor_list_unbounded",
  "calibration_janitor_other",
] as const;
export type CalibrationJanitorFailureReason = (typeof CALIBRATION_JANITOR_FAILURE_REASONS)[number];

export const LOG_ENUM_CODES = [
  ...ADAPTERS_RESEARCH_FEEDS_ENUM_CODES,
  ...ADAPTERS_SANDBOX_ENUM_CODES,
  ...BILLING_ENUM_CODES,
  ...CONTROL_PLANE_BIN_ENUM_CODES,
  ...CONTROL_PLANE_DBOS_ENUM_CODES,
  ...CONTROL_PLANE_ENTRYPOINTS_ENUM_CODES,
  ...CONTROL_PLANE_OUTBOX_ENUM_CODES,
  ...CONTROL_PLANE_PLATFORM_ENUM_CODES,
  ...CONTROL_PLANE_PORTS_ENUM_CODES,
  ...CONTROL_PLANE_PROXY_ENUM_CODES,
  ...CONTROL_PLANE_RELEASE_ENUM_CODES,
  ...CONTROL_PLANE_WORKFLOWS_ENUM_CODES,
  ...CORE_LOCKFILE_ENUM_CODES,
  ...CORE_POLICY_ENUM_CODES,
  ...DB_ENUM_CODES,
  ...DEPENDENCY_GATE_ENUM_CODES,
  ...GENERATION_ENUM_CODES,
  ...GITHUB_ENUM_CODES,
  ...INCIDENT_BRIDGE_ENUM_CODES,
  ...MERGE_ENUM_CODES,
  ...NPM_PROXY_ENUM_CODES,
  ...OPERATIONS_ENUM_CODES,
  ...RECIPES_ENUM_CODES,
  ...RUN_RECORDS_ENUM_CODES,
  ...SANDBOX_ENUM_CODES,
  ...SHARED_ENUM_CODES,
  ...SITE_SCANNER_ENUM_CODES,
  ...VERIFICATION_ENUM_CODES,
  ...CALIBRATION_JANITOR_FAILURE_REASONS,
  ...CLOSURE_FALLBACK_LOG_CODES,
  ...DISCOVERY_REFUSAL_CODES,
  ...EGRESS_TUNNEL_CODES,
  ...GITHUB_NIGHTLY_RETRY_CODES,
  ...GITHUB_RECONCILIATION_FAILURE_REASONS,
  ...GITHUB_RECONCILIATION_PARTS,
  ...HARNESS_INCOMPLETE_CODES,
  ...INVENTORY_REFUSAL_CODES,
  ...RECIPE_GAP_FILL_LOG_CODES,
] as const;

/**
 * The `db_round_trip` probe line (#8283): which connection path the `select 1` round trip timed
 * (`db_path`: PlanetScale's PgBouncer on 6432, or a direct 5432 login) and how it ended
 * (`round_trip_outcome`). packages/db/src/round-trip-probe.ts emits exactly these.
 */
export const LOG_DB_ROUND_TRIP_PATHS = ["pgbouncer", "direct"] as const;
export const LOG_DB_ROUND_TRIP_OUTCOMES = ["ok", "timeout", "error"] as const;

/**
 * The `fix_pipeline_stage` line (#8256, #5500): how far an advisory got on its way to a fix, in
 * pipeline order (`fix_stage`). The OSV poll stored it, a reclassification started, the advisory
 * matched a repository's dependency, the package's fix enqueue decided, and that decision created
 * a fix row. Sandboxes keep their own `sandbox_created` line. IDs and counts ride beside it.
 */
export const LOG_FIX_PIPELINE_STAGES = [
  "advisory_ingested",
  "reclassify_started",
  "matched_direct_dependency",
  "fix_enqueued",
  "fix_row_created",
] as const;
/** What a fix enqueue decided (`enqueue_outcome`): `EnqueueFixOutcome`'s statuses. */
export const LOG_FIX_ENQUEUE_OUTCOMES = [
  "created",
  "updated_existing",
  "held",
  "merge_inventory_pending",
  "no_actionable_findings",
  "declined",
  "repo_inactive",
  "identity_overlap",
] as const;

/**
 * The protocol phase of a `database_pool_long_hold` line's slowest statement
 * (`slowest_statement_phase`, #8283), as packages/db/src/statement-count.ts names it. `begin`,
 * `commit` and `rollback` are transaction control, named by kind whatever their spans (behind a
 * transaction pooler, `begin` includes the server assignment). Any other statement is named by
 * its longest span: `execute` until the first answer that precedes its first row (the request in
 * transit, the pooler's queue, the server's parse, bind and execute, waiting for the first row),
 * `rows` from it to the command's
 * completion (waiting for and receiving rows), `settle` from the completion to the caller's
 * promise settling (the client's own processing).
 */
export const LOG_DB_STATEMENT_PHASES = [
  "begin",
  "execute",
  "rows",
  "settle",
  "commit",
  "rollback",
] as const;

/**
 * The `holder_operation` a `database_pool_long_hold` or `database_pool_acquire_timeout` line
 * carries when no loggable unit-of-work operation names the holder (#5500, D-267), so the field is
 * never empty. The lane and the registered step or workflow (`holder_step`, `holder_workflow`) say
 * where; these say which acquire path held the connection outside a named transaction.
 */
export const POOL_HOLDER_FALLBACK_OPERATIONS = [
  // An operation name is set but is not a loggable transaction name.
  "pool.unloggableOperation",
  // A direct pool query or transaction inside a registered step, outside any unit of work.
  "pool.stepDirect",
  // A direct pool query or transaction in a workflow body, outside any step or unit of work.
  "pool.workflowDirect",
  // A direct pool acquire outside any registered durable body and any unit of work.
  "pool.outsideUnitOfWork",
] as const;

/**
 * The `blocker_operation` of a `database_pool_long_hold` line when the backend blocking the holder
 * is not held through an observed pool in the same process (another instance, service or session),
 * so no unit-of-work name is known for it (#5500).
 */
export const POOL_BLOCKER_EXTERNAL_OPERATION = "pool.otherBackend";

/**
 * The `blocker_operation` when the blocking backend fits the transaction age of an open pooled
 * hold in this process, but that hold also fits another backend, so naming it would be a guess
 * (#5500).
 */
export const POOL_BLOCKER_AMBIGUOUS_OPERATION = "pool.blockerAmbiguous";

/**
 * The `wait_sample` outcome of a `database_pool_long_hold` line (#5500): what one sample of
 * `pg_stat_activity` and `pg_locks`, taken while the hold was still open at the long-hold
 * threshold, found for the holding backend. Metadata only: never query text or parameters.
 */
export const POOL_WAIT_SAMPLE_OUTCOMES = [
  // The holding backend was read by its process ID (a direct, unpooled connection).
  "db_wait_sample_exact",
  // Behind the transaction pooler, the one backend of this login whose transaction age matches
  // the hold's age.
  "db_wait_sample_matched",
  // Behind the transaction pooler, several backends' transaction ages match; none is reported.
  "db_wait_sample_ambiguous",
  // No backend was in a transaction for the hold: the holder sat outside a database transaction
  // (application time) or was queued in the pooler.
  "db_wait_sample_no_backend",
  // The hold ended before the sample answered.
  "db_wait_sample_pending",
  // The hold reached the threshold, but the sample never started (the event loop was stalled).
  "db_wait_sample_missed",
  // The sample did not answer within its deadline.
  "db_wait_sample_timeout",
  // The sample could not connect.
  "db_wait_sample_connect_failed",
  // The sample query failed.
  "db_wait_sample_query_failed",
  // The sample answered with rows of an unexpected shape.
  "db_wait_sample_invalid",
] as const;

/** Postgres `pg_stat_activity.wait_event_type` values (the server's fixed list). */
export const PG_WAIT_EVENT_TYPES = [
  "Activity",
  "BufferPin",
  "Client",
  "Extension",
  "InjectionPoint",
  "IO",
  "IPC",
  "Lock",
  "LWLock",
  "Timeout",
] as const;

/** Postgres `pg_stat_activity.state`, as log codes (`idle in transaction` → `idle_in_transaction`). */
export const PG_BACKEND_STATES = [
  "active",
  "idle",
  "idle_in_transaction",
  "idle_in_transaction_aborted",
  "fastpath_function_call",
  "disabled",
] as const;

/**
 * The dependency a `dependency_failure` names (#5667, D-267), set at the call site
 * (`KovoErrorInit.dependency`) or derived from the adapter (`PortError.service`, the database
 * error kind), never from error text. `other` is the fallback a lint keeps rare.
 */
export const LOG_DEPENDENCIES = [
  "db",
  "support_mailbox",
  "db_pool",
  "github_api",
  "github_app_token",
  "secret_manager",
  "stripe",
  "daytona",
  "gcs",
  "bigquery",
  "pubsub",
  "cloud_tasks",
  "egress_proxy",
  "kms",
  "email",
  "model_provider",
  "npm_registry",
  "osv",
  "kev",
  "malware_scanner",
  "sandbox",
  "analytics",
  "workload_identity",
  "iap",
  "site_fetch",
  "docs",
  "webhook_destination",
  "dns",
  // Kovo's own bounded capacity (in-flight caps, body byte budgets): not an outside service.
  "local_capacity",
  // The restore gate holding customer requests until reconciliation finishes.
  "restore_gate",
  "other",
] as const;

/**
 * What ended a webhook redelivery tick's delivery-log listing (#5669; `listing_failure` on
 * `github_delivery_reconcile_failed`), from the port error's own closed fields only.
 */
export const LOG_LISTING_FAILURES = [
  "timeout",
  "network",
  "http_5xx",
  "http_4xx",
  "auth",
  "rate_limited",
  "body_unreadable",
  "schema_mismatch",
  "circuit_open",
  "other",
] as const;

/** The oldest listed delivery's age on a redelivery tick (#5669; `oldest_age_bucket`). */
export const LOG_DELIVERY_AGE_BUCKETS = [
  "none",
  "lt_6h",
  "6h_24h",
  "24h_48h",
  "48h_70h",
  "gte_70h",
] as const;

/**
 * Why a redelivery tick restarted its backward pass (#5669 N1; `walk_reset_reason`): GitHub
 * refused the saved cursor (400/422), no longer knows it (404/410), or failed it on several ticks
 * in a row (5xx, timeout or network).
 */
export const LOG_WALK_RESET_REASONS = [
  "none",
  "cursor_refused",
  "cursor_gone",
  "cursor_unavailable",
] as const;

/**
 * Why the run-records janitor did not schedule a KMS key version's destruction, or `scheduled`
 * when it did (#7194, D-267; `skip_reason` on `run_records_janitor_key_version`). Each value is
 * one check of `sweepRunRecords` in its order; `failed` is a check that threw (its own failure
 * line carries the stage and class). scripts/ops/prod-logs mirrors this list.
 */
export const RUN_RECORD_KEY_VERSION_SKIP_REASONS = [
  "unknown_bindings",
  "primary",
  "state",
  "newest",
  "retired_unknown",
  "successor_margin",
  "unexpired_bound_records",
  "primary_at_destroy",
  "failed",
  "scheduled",
] as const;

/** The Cloud KMS key version states (`KeyVersion["state"]`), logged as `key_version_state`. */
export const KMS_KEY_VERSION_STATES = [
  "PENDING_GENERATION",
  "ENABLED",
  "DISABLED",
  "DESTROY_SCHEDULED",
  "DESTROYED",
  "IMPORT_FAILED",
  "PENDING_IMPORT",
  "GENERATION_FAILED",
] as const;

/** How the named dependency failed, from the adapter's own error classification (#5667). */
export const LOG_DEPENDENCY_STATUSES = [
  "timeout",
  "refused",
  "5xx",
  "4xx",
  "quota",
  "unknown",
] as const;

// A billing provider refusal (#5500, D-267). Closed lists: anything else is logged only as the
// sha256 in `code_hash` or `param_hash` (compare with `printf %s <value> | sha256sum`).
/** The billing port operations (`StripeBillingAdapter` and its fake), logged as `operation`. */
export const BILLING_PROVIDER_OPERATIONS = [
  "cancelSubscriptionNow",
  "createCheckoutProbeCustomer",
  "createCheckoutProbeSession",
  "createCheckoutSession",
  "createCoupon",
  "createCustomer",
  "createInvoiceForPendingItems",
  "createInvoiceItem",
  "createPortalSession",
  "createPromotionCode",
  "creditAccountPause",
  "deactivatePromotionCode",
  "expireCheckoutSession",
  "findCheckoutProbeCustomers",
  "findCustomersByAccount",
  "isCheckoutProbeCustomer",
  "listEvents",
  "listInvoiceItems",
  "listInvoices",
  "listOpenCheckoutSessions",
  "listOverageUsageSummaries",
  "listPaymentMethodConfigurations",
  "listPendingInvoiceItems",
  "listSubscriptions",
  "previewProration",
  "reportOverageUsage",
  "retrieveCharge",
  "retrieveCheckoutSession",
  "retrieveDispute",
  "retrieveInvoice",
  "retrieveInvoicePaymentPage",
  "retrieveObjectStatus",
  "retrieveOveragePrice",
  "retrievePrice",
  "retrievePromotionCode",
  "retrieveSubscription",
  "retrieveSubscriptionDiscounts",
  "setAccountCollectionPaused",
  "setCancelAtPeriodEnd",
  "updateExtraRepoQuantity",
  "voidOpenInvoice",
] as const;
/**
 * Stripe's documented error codes, the SDK error classes (the code when Stripe sent none) and the
 * billing adapter's own codes, logged as `code`.
 */
export const BILLING_PROVIDER_CODES = [
  // The billing adapter's own codes (packages/adapters/src/stripe).
  "base_product_shared",
  "checkout_no_payment_methods",
  "checkout_product_tax_code_missing",
  "overage_meter_unconfigured",
  "timestamp_out_of_range",
  "subscription_customer_mismatch",
  "idempotency_key_reused",
  "authentication_required",
  "network",
  // The SDK error class, when Stripe sent no code.
  "StripeInvalidRequestError",
  "StripeAPIError",
  "StripeCardError",
  "StripeIdempotencyError",
  "StripeRateLimitError",
  "StripeAuthenticationError",
  "StripePermissionError",
  "StripeConnectionError",
  "invalid_request_error",
  // Stripe error codes (https://docs.stripe.com/error-codes).
  "account_invalid",
  "api_key_expired",
  "card_declined",
  "checkout_session_not_open",
  "coupon_expired",
  "customer_max_subscriptions",
  "customer_tax_location_invalid",
  "email_invalid",
  "expired_card",
  "idempotency_key_in_use",
  "invalid_characters",
  "invoice_no_customer_line_items",
  "invoice_no_subscription_line_items",
  "invoice_not_editable",
  "invoice_payment_intent_requires_action",
  "invoice_upcoming_none",
  "livemode_mismatch",
  "lock_timeout",
  "parameter_invalid",
  "parameter_invalid_empty",
  "parameter_invalid_integer",
  "parameter_invalid_string_blank",
  "parameter_invalid_string_empty",
  "parameter_missing",
  "parameter_unknown",
  "parameters_exclusive",
  "payment_intent_action_required",
  "platform_api_key_expired",
  "resource_already_exists",
  "resource_missing",
  "secret_key_required",
  "subscription_payment_intent_requires_action",
  "tax_id_invalid",
  "testmode_charges_only",
  "url_invalid",
] as const;
/**
 * The live Checkout probe's outcome (#5514, #9122), logged as `probe_outcome` on every
 * `checkout_probe_checked` line. A closed code, never free text: the money-correct SLO counts a
 * failed probe by it.
 */
export const CHECKOUT_PROBE_OUTCOMES = [
  "checkout_probe_passed",
  "checkout_probe_failed",
  "checkout_no_payment_methods",
] as const;
/** A Stripe price's `recurring.interval`, logged as `price_interval` (#5514). */
export const STRIPE_PRICE_INTERVALS = ["day", "week", "month", "year"] as const;
/** A Stripe price's `recurring.usage_type`, logged as `price_usage_type` (#5514). */
export const STRIPE_PRICE_USAGE_TYPES = ["licensed", "metered"] as const;
/** A Stripe price's `tax_behavior`, logged as `tax_behavior` (#5514). */
export const STRIPE_PRICE_TAX_BEHAVIORS = ["exclusive", "inclusive", "unspecified"] as const;
/**
 * The terms the worker checks on the metered AI-overage price (#5514), logged as comma lists in
 * `checks_passed` and `checks_failed`.
 */
export const OVERAGE_PRICE_CHECKS = [
  "active",
  "interval",
  "usage_type",
  "meter",
  "unit_amount",
  "currency",
  "tax_behavior",
  "product",
] as const;
/** The request parameters the billing adapter sends, logged as `param` (a name, never a value). */
export const BILLING_PROVIDER_PARAMS = [
  "mode",
  "managed_payments",
  "managed_payments[enabled]",
  "customer",
  "client_reference_id",
  "line_items",
  "line_items[0][price]",
  "line_items[0][quantity]",
  "line_items[1][price]",
  "line_items[1][quantity]",
  "subscription_data",
  "subscription_data[metadata]",
  "metadata",
  "success_url",
  "cancel_url",
  "discounts",
  "discounts[0][promotion_code]",
  "email",
  "return_url",
  "configuration",
  "subscription",
  "invoice",
  "items",
  "items[0][id]",
  "items[0][quantity]",
  "price",
  "quantity",
  "currency",
  "amount",
  "description",
  "proration_behavior",
  "proration_date",
  "payment_behavior",
  "cancel_at_period_end",
  "pause_collection",
  "pause_collection[behavior]",
  "collection_method",
  "auto_advance",
  "pending_invoice_items_behavior",
  "coupon",
  "promotion_code",
  "code",
  "max_redemptions",
  "restrictions",
  "applies_to",
  "percent_off",
  "duration",
  "duration_in_months",
  "starting_after",
  "limit",
  "query",
  "page",
  "status",
  "expand",
  "created",
  "type",
  "types",
  // The AI-overage meter (plans/stripe-managed-payments.md §3.1) and the metered Checkout line.
  "line_items[2][price]",
  "event_name",
  "identifier",
  "timestamp",
  "payload",
  "payload[stripe_customer_id]",
  "payload[value]",
  "start_time",
  "end_time",
  // The live Checkout probe's customer and session (plans/stripe-managed-payments.md §6.5).
  "name",
  "expires_at",
  "metadata[kovo_probe]",
] as const;

/**
 * The type Stripe puts on an error (https://docs.stripe.com/api/errors#errors-type), logged as
 * `stripe_error_type`. Anything else is `other`.
 */
export const STRIPE_ERROR_TYPES = [
  "invalid_request_error",
  "api_error",
  "api_connection_error",
  "card_error",
  "authentication_error",
  "permission_error",
  "rate_limit_error",
  "idempotency_error",
  "other",
] as const;
/** The stable D-267 reason of a Stripe refusal, logged as `stripe_reason`. */
export const STRIPE_ERROR_REASONS = [
  "stripe_invalid_request",
  "stripe_rate_limited",
  "stripe_auth_failed",
  "stripe_api_error",
  "stripe_idempotency_error",
  "stripe_other",
] as const;
/**
 * The shape of a logged Stripe error code or parameter name (`parameter_invalid_integer`,
 * `line_items.0.price`): lower-case words, digits, `_` and `.`. A value of another shape is logged
 * as the word `invalid`.
 */
export const STRIPE_ERROR_NAME = /^[a-z0-9_.]{1,64}$/;

/**
 * The closed set of packages a vendor console line may be attributed to (the `emitter` log field).
 * The console boundary derives it from the package name in a stack frame's `node_modules` path
 * (never the message, the stack text or any other path) and logs `unknown` when no frame names a
 * package listed here. `node` is the runtime itself. Add a package here to name it.
 * Never list a worker runtime SDK (`workerPackages` in
 * apps/control-plane/src/entrypoints/testing/import-graph.ts): this module is in the api and proxy
 * startup graph, and the import-isolation guard rejects any literal naming one. Worker SDK lines log
 * `unknown`.
 */
export const LOG_VENDOR_EMITTERS = [
  "@hono/node-server",
  "@opentelemetry/api",
  "@opentelemetry/sdk-node",
  "@sentry/node",
  "better-auth",
  "drizzle-orm",
  "hono",
  "node",
  "pg",
  "pino",
  "posthog-node",
  "stripe",
  "undici",
  "unknown",
  "valibot",
  "ws",
  "zod",
] as const;
