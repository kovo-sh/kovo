import { randomUUID } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { mkdirSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { drizzle } from 'drizzle-orm/node-sqlite'
import { getTableConfig, type SQLiteTable } from 'drizzle-orm/sqlite-core'
import {
  DEFAULT_APPROVAL_LEASE_TTL_MS,
  DEFAULT_HOST_LEASE_MAX_USES,
  DEFAULT_ROUTE_LEASE_MAX_USES,
  HOST_NONDESTRUCTIVE_LEASE_METHOD,
  HOST_NONDESTRUCTIVE_LEASE_PATTERN,
} from '../domain.ts'
import { purgeExpiredArtifacts } from './artifact-ttl.ts'
import type { ArtifactTtlPolicy, ArtifactTtlPurgeResult } from './artifact-ttl.ts'
import {
  CapabilityLedger,
  initCapabilityLedgerSchema,
  type CapabilityLedgerOptions,
} from './capability-ledger.ts'
import { validateCitingColumnsAgainstTables } from './evidence-citations.ts'
import { FindingCodec } from './finding-codec.ts'
import { cancelOobDrainForRun, isDeletedRunRaceError, isOobDrainActive } from './oob-drain.ts'
import { listProjectPersonas } from './persona-vault.ts'
import * as tables from './schema.ts'
import { FindingsRepository } from './store-findings.ts'
import { ProjectsRepository } from './store-projects.ts'
import { RunsRepository } from './store-runs.ts'
import {
  DEFAULT_EXCHANGE_RETENTION_DAYS,
  DEFAULT_FTS_MAX_BODY_BYTES,
  DEFAULT_FTS_MODE,
  DEFAULT_MAX_FULL_FTS_DB_BYTES,
  FtsModeRefusedError,
  InvariantError,
  MAX_FTS_MAX_BODY_BYTES,
  MIN_FTS_MAX_BODY_BYTES,
  SQLITE_DEFAULT_BUSY_TIMEOUT_MS,
  SQLITE_JOURNAL_SIZE_LIMIT_BYTES,
  STORE_SCHEMA_VERSION,
  StoreSession,
  TenantIsolationError,
  TenantScopedSession,
  assertConfirmedVerificationClass,
  assessmentAssignments,
  dataDirectory,
  ftsModes,
  openSqliteDatabase,
  replayVerdictConfirmsRuntime,
  resolvePageLimit,
  resolvePageOffset,
  runSqliteMigrations,
  safeFileSize,
  verificationClassForFinding,
  type DbSession,
  type FtsMode,
  type MigrationContext,
  type MigrationRunReport,
  type MigrationStep,
  type StoreOptions,
} from './store-session.ts'

export {
  collectionPathFor,
  extractResourceRefsFromExchange,
  isOpaqueResourceId,
  type ExtractedResourceRef,
  type ResourceHarvestExchange,
  type ResourceSampleRow,
} from './resource-harvest.ts'

export {
  DEFAULT_EXCHANGE_RETENTION_DAYS,
  DEFAULT_FTS_MAX_BODY_BYTES,
  DEFAULT_FTS_MODE,
  DEFAULT_MAX_FULL_FTS_DB_BYTES,
  FtsModeRefusedError,
  InvariantError,
  MAX_FTS_MAX_BODY_BYTES,
  MIN_FTS_MAX_BODY_BYTES,
  STORE_SCHEMA_VERSION,
  TenantIsolationError,
  assertConfirmedVerificationClass,
  assessmentAssignments,
  dataDirectory,
  ftsModes,
  replayVerdictConfirmsRuntime,
  resolvePageLimit,
  resolvePageOffset,
  verificationClassForFinding,
  type AgentScriptProofRecord,
  type ApiDependencyRow,
  type AppendTenantAuditLogInput,
  type ApprovalLeaseRow,
  type ApprovalRequest,
  type Assignment,
  type BenchmarkRunRow,
  type BoardMemberRow,
  type BoardMessageRow,
  type BrokerExchange,
  type CanaryRow,
  type ChainStep,
  type ConfirmationEvidence,
  type CoverageEntry,
  type DbSession,
  type EndpointParamRow,
  type EndpointRow,
  type Evidence,
  type ExchangeSummary,
  type Fact,
  type FactKind,
  type FindingProvenanceOptions,
  type FtsMode,
  type GraphDigest,
  type GraphEdge,
  type JsonValue,
  type LabContainerRow,
  type LabTelemetryRow,
  type MessageRow,
  type PaginationOptions,
  type PatchProposal,
  type Project,
  type ProjectSpec,
  type ProjectSpecSummary,
  type PruneExchangesOptions,
  type PruneExchangesResult,
  type PruneOptions,
  type PruneResult,
  type RecoveryReport,
  type ReplaySpecRow,
  type ReportRow,
  type ResourceSampleTableRow,
  type RetestRun,
  type Run,
  type RunDetailOptions,
  type RunEventPayload,
  type RunShellIndexEntry,
  type RunShellSummary,
  type SastRun,
  type SecondOrderCanaryRow,
  type SerializableFact,
  type SerializableReplaySpecRow,
  type StoreFootprint,
  type StoreOptions,
  type SurfaceProbe,
  type TenantAuditLogEntry,
  type TenantAuditOutcome,
  type ThreatModel,
  type WorkspaceProjectLatestRun,
  type WorkspaceProjectSummary,
  type WorkspaceRecentRunSummary,
  type WorkspaceSummary,
} from './store-session.ts'

/**
 * Runtime columns added lazily by `RunsRepository` (`ensureDeclinedOriginsColumn`, `ensureRunLabelColumn`).
 * Allowed by `Store.verifySchema()` on reopened DBs so existing user data dirs remain valid without
 * relaxing drift detection on any unexpected column.
 */
const ALLOWED_LAZY_RUNTIME_COLUMNS: Readonly<Record<string, ReadonlySet<string>>> = {
  runs: new Set(['declined_origins', 'label']),
  approval_requests: new Set([
    'original_judge_decision',
    'original_risk_level',
    'host_floor',
    'fail_safe_reason',
  ]),
}

/**
 * Probe SQLite JSON1 (`json_extract` + `json_type`) capability once cleanly instead of catching
 * and swallowing trigger `syntax error` failures at install time.
 */
function hasSqliteJsonSupport(client: DatabaseSync): boolean {
  try {
    const row = client.prepare(
      `SELECT json_extract('{"ok":true}', '$.ok') AS ok, json_type('{"ok":true}', '$.ok') AS kind`,
    ).get() as { ok?: unknown; kind?: unknown } | undefined
    return Number(row?.ok) === 1 && row?.kind === 'true'
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error)
    if (/no such function:\s*json_(?:extract|type)/i.test(msg)) return false
    throw error
  }
}

/**
 * Install fail-closed confirmation-evidence triggers on `findings`.
 *
 * Parity contract with TS `FindingsRepository.assertConfirmationEvidence`:
 *  - Agrees strictly on baseline checks, confirmed `last_verification_diff.verdict = 'confirmed'`,
 *    same-run `replay_specs` single (`receipt` object + `verification.confirmed === true`) and
 *    composite (`compositeReceipt` object + `compositeVerification.confirmed === true`) receipts,
 *    and uncontradicted `oob.receipt_confirmed` events.
 *  - Deliberately STRICTER than TS on legacy `floor_artifact` rows (which lack a confirming spec
 *    diff): raw SQL cannot spoof `provenance = 'floor'` without a confirming spec or OOB receipt.
 *  - Never swallows `syntax error`; fails closed if trigger DDL is invalid.
 */
function installConfirmationGuards(ctx: MigrationContext, jsonSupported = hasSqliteJsonSupport(ctx.client)): void {
  if (!ctx.tableExists('findings') || !ctx.tableExists('replay_specs')) return
  if (!jsonSupported) return
  const guard = (name: string, event: 'INSERT' | 'UPDATE OF verification_class, replay_spec_id, finding, verification_tier') => `
    DROP TRIGGER IF EXISTS ${name};
    CREATE TRIGGER ${name}
    BEFORE ${event} ON findings
    WHEN NEW.verification_class = 'runtime_confirmed'
      AND json_extract(NEW.finding, '$.status') = 'confirmed'
      AND coalesce(NEW.finding_kind, '') <> 'baseline_check'
      AND coalesce(NEW.verification_tier, json_extract(NEW.finding, '$.verificationTier'), '') <> 'baseline_confirmed'
      AND NOT EXISTS (
        SELECT 1 FROM replay_specs s
        WHERE s.id = NEW.replay_spec_id
          AND s.run_id = NEW.run_id
          AND (
            json_extract(s.last_verification_diff, '$.verdict') = 'confirmed'
            OR (
              json_extract(s.last_verification_diff, '$.verdict') IS NULL
              AND (
                (
                  json_type(s.proof_receipt, '$.receipt') = 'object'
                  AND json_type(s.proof_receipt, '$.verification.confirmed') = 'true'
                )
                OR (
                  json_type(s.proof_receipt, '$.compositeReceipt') = 'object'
                  AND json_type(s.proof_receipt, '$.compositeVerification.confirmed') = 'true'
                )
              )
            )
          )
      )
      ${ctx.tableExists('events') ? `AND NOT (
        EXISTS (
          SELECT 1 FROM events e
          WHERE e.run_id = NEW.run_id
            AND e.kind = 'oob.receipt_confirmed'
            AND json_extract(e.detail, '$.findingId') = NEW.id
        )
        AND NOT EXISTS (
          SELECT 1 FROM replay_specs s
          WHERE s.id = NEW.replay_spec_id
            AND s.run_id = NEW.run_id
            AND json_extract(s.last_verification_diff, '$.verdict') IS NOT NULL
            AND json_extract(s.last_verification_diff, '$.verdict') <> 'confirmed'
        )
      )` : ''}
    BEGIN
      SELECT RAISE(ABORT, 'invariant.confirmation_evidence');
    END;
  `
  ctx.client.exec(guard('findings_confirmation_evidence_insert', 'INSERT'))
  ctx.client.exec(guard('findings_confirmation_evidence_update', 'UPDATE OF verification_class, replay_spec_id, finding, verification_tier'))
}

function installPromotedFindingSyncTriggers(ctx: MigrationContext, jsonSupported = hasSqliteJsonSupport(ctx.client)): void {
  if (!ctx.tableExists('findings')) return
  if (!jsonSupported) return
  const statusExpr = `CASE
    WHEN json_extract(NEW.finding, '$.status') IN ('pending', 'confirmed', 'static_verified', 'dismissed', 'inconclusive')
      THEN json_extract(NEW.finding, '$.status')
    ELSE 'pending'
  END`
  const severityExpr = `CASE
    WHEN json_extract(NEW.finding, '$.severity') IN ('critical', 'high', 'medium', 'low', 'informational')
      THEN json_extract(NEW.finding, '$.severity')
    ELSE 'medium'
  END`
  const cweExpr = `NULLIF(trim(coalesce(json_extract(NEW.finding, '$.cwe'), '')), '')`
  const originExpr = `trim(coalesce(json_extract(NEW.finding, '$.origin'), ''))`
  const triageExpr = `CASE
    WHEN json_extract(NEW.finding, '$.operatorTriage.status') IN ('open', 'confirmed_by_operator', 'accepted_risk', 'false_positive', 'fixed')
      THEN json_extract(NEW.finding, '$.operatorTriage.status')
    ELSE 'open'
  END`
  const buildTrigger = (name: string, event: 'INSERT' | 'UPDATE OF finding') => `
    DROP TRIGGER IF EXISTS ${name};
    CREATE TRIGGER ${name}
    AFTER ${event} ON findings
    WHEN NEW.status IS NULL OR NEW.status <> (${statusExpr})
      OR NEW.severity IS NULL OR NEW.severity <> (${severityExpr})
      OR coalesce(NEW.cwe, '') <> coalesce((${cweExpr}), '')
      OR NEW.origin IS NULL OR NEW.origin <> (${originExpr})
      OR NEW.triage_status IS NULL OR NEW.triage_status <> (${triageExpr})
    BEGIN
      UPDATE findings
      SET status = (${statusExpr}),
          severity = (${severityExpr}),
          cwe = (${cweExpr}),
          origin = (${originExpr}),
          triage_status = (${triageExpr})
      WHERE id = NEW.id;
    END;
  `
  ctx.client.exec(buildTrigger('findings_sync_promoted_insert', 'INSERT'))
  ctx.client.exec(buildTrigger('findings_sync_promoted_update', 'UPDATE OF finding'))
}

function getDrizzleSchemaTables(): Array<ReturnType<typeof getTableConfig>> {
  const results: Array<ReturnType<typeof getTableConfig>> = []
  for (const value of Object.values(tables)) {
    if (!value || typeof value !== 'object') continue
    try {
      const config = getTableConfig(value as SQLiteTable)
      if (config && typeof config.name === 'string' && Array.isArray(config.columns) && config.columns.length > 0) {
        results.push(config)
      }
    } catch {
      // Non-table exports (constants, types)
    }
  }
  return results
}

function buildAdHocMigrationContext(client: DatabaseSync): MigrationContext {
  return {
    client,
    tableExists(table: string): boolean {
      const row = client.prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
      ).get(table) as { name?: string } | undefined
      return Boolean(row?.name)
    },
    existingColumns(table: string): Set<string> {
      const rows = client.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>
      return new Set(rows.map(r => r.name))
    },
    ensureColumn(table: string, column: string, definition: string): boolean {
      if (!this.existingColumns(table).has(column)) {
        client.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition};`)
        return true
      }
      return false
    },
  }
}

/**
 * Idempotent startup repair for existing user data directories that may have been stamped at
 * v10/v11 prior to R2-12 (missing historical v10 promoted columns / ops created_at / v11 lease
 * columns, or pre-R2-12 confirmation triggers). Deliberately scoped to known historical columns
 * so unexpected / injected schema drift still fails closed in `Store.verifySchema()`.
 */
function repairKnownSchemaDrift(client: DatabaseSync, jsonSupported: boolean): void {
  const ctx = buildAdHocMigrationContext(client)
  if (ctx.tableExists('operations')) {
    const addedCreatedAt = ctx.ensureColumn('operations', 'created_at', 'INTEGER NOT NULL DEFAULT 0')
    if (addedCreatedAt) {
      client.prepare('UPDATE operations SET created_at = ? WHERE created_at = 0').run(Date.now())
      client.exec('CREATE INDEX IF NOT EXISTS operations_created ON operations (created_at);')
    }
  }
  if (ctx.tableExists('findings')) {
    const addedPromoted = [
      ctx.ensureColumn('findings', 'status', "TEXT NOT NULL DEFAULT 'pending'"),
      ctx.ensureColumn('findings', 'severity', "TEXT NOT NULL DEFAULT 'medium'"),
      ctx.ensureColumn('findings', 'cwe', 'TEXT'),
      ctx.ensureColumn('findings', 'origin', "TEXT NOT NULL DEFAULT ''"),
      ctx.ensureColumn('findings', 'triage_status', "TEXT NOT NULL DEFAULT 'open'"),
    ].some(Boolean)
    if (addedPromoted) {
      FindingCodec.backfillPromotedColumns(client)
      client.exec(`
        CREATE INDEX IF NOT EXISTS findings_run_verified
          ON findings (run_id, verification_class, superseded_by_finding_id);
        CREATE INDEX IF NOT EXISTS findings_run_status_severity
          ON findings (run_id, status, severity);
        CREATE INDEX IF NOT EXISTS findings_run_triage
          ON findings (run_id, triage_status);
        CREATE INDEX IF NOT EXISTS findings_run_origin_cwe
          ON findings (run_id, origin, cwe);
      `)
      installPromotedFindingSyncTriggers(ctx, jsonSupported)
    }
  }
  if (ctx.tableExists('approval_leases')) {
    ctx.ensureColumn(
      'approval_leases',
      'lease_scope',
      "TEXT NOT NULL DEFAULT 'route' CHECK (lease_scope IN ('route', 'prefix', 'host_nondestructive'))",
    )
    ctx.ensureColumn('approval_leases', 'max_uses', 'INTEGER')
    ctx.ensureColumn('approval_leases', 'cross_persona', 'INTEGER NOT NULL DEFAULT 0')
  }
  if (ctx.tableExists('personas')) {
    ctx.ensureColumn('personas', 'tenant_ref', 'TEXT')
    ctx.ensureColumn('personas', 'privilege', 'TEXT')
  }
  // Always ensure confirmation triggers match the current strict R2-12 SQL definition.
  installConfirmationGuards(ctx, jsonSupported)
}

/**
 * Fail-closed schema verification comparing live SQLite `PRAGMA table_info(...)` against every
 * Drizzle table in `src/server/schema.ts` plus the shared `CITING_COLUMNS` registry.
 */
function verifyStoreSchema(client: DatabaseSync): void {
  const schemaTables = getDrizzleSchemaTables()
  const drift: string[] = []

  for (const config of schemaTables) {
    const rows = client.prepare(`PRAGMA table_info(${config.name})`).all() as Array<{
      name: string
      notnull: number
      pk: number
    }>
    if (rows.length === 0) {
      drift.push(`missing table "${config.name}"`)
      continue
    }
    const sqliteByName = new Map(rows.map(r => [r.name, r]))
    const drizzleByName = new Map(config.columns.map(c => [c.name, c]))
    const allowedLazy = ALLOWED_LAZY_RUNTIME_COLUMNS[config.name]

    for (const [colName, drCol] of drizzleByName) {
      const sqCol = sqliteByName.get(colName)
      if (!sqCol) {
        drift.push(`missing column "${config.name}.${colName}"`)
        continue
      }
      const expectedNotNull = Boolean(drCol.notNull || drCol.primary)
      const actualNotNull = Boolean(sqCol.notnull || sqCol.pk)
      if (expectedNotNull !== actualNotNull) {
        drift.push(
          `NOT NULL mismatch on "${config.name}.${colName}" (expected ${expectedNotNull ? 'NOT NULL' : 'NULL'}, got ${actualNotNull ? 'NOT NULL' : 'NULL'})`,
        )
      }
    }

    for (const colName of sqliteByName.keys()) {
      if (!drizzleByName.has(colName) && !allowedLazy?.has(colName)) {
        drift.push(`unexpected column "${config.name}.${colName}"`)
      }
    }
  }

  for (const violation of validateCitingColumnsAgainstTables(schemaTables)) {
    drift.push(violation)
  }

  if (drift.length > 0) {
    throw new Error(
      `Schema verification failed (fail-closed on ${drift.length} drift issue${drift.length === 1 ? '' : 's'}): ${drift.join('; ')}`,
    )
  }
}

/**
 * Move S5 — Ordered transactional schema migrations (`v -> v+1`).
 * Each step runs atomically inside `BEGIN EXCLUSIVE` with data backfill executed BEFORE
 * constraints and `PRAGMA user_version` stamped inside the same transaction.
 */
const STORE_MIGRATIONS: readonly MigrationStep[] = [
  {
    version: 1,
    name: 'core_schema',
    up(ctx) {
      ctx.client.exec(`
        CREATE TABLE IF NOT EXISTS workspaces (
          id TEXT PRIMARY KEY NOT NULL,
          name TEXT NOT NULL,
          actor_id TEXT NOT NULL,
          created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS model_profiles (
          id TEXT PRIMARY KEY NOT NULL,
          workspace_id TEXT NOT NULL REFERENCES workspaces(id),
          name TEXT NOT NULL,
          endpoint TEXT NOT NULL,
          model TEXT NOT NULL,
          protocol TEXT NOT NULL,
          credential_id TEXT NOT NULL,
          priority INTEGER NOT NULL DEFAULT 100,
          enabled INTEGER NOT NULL DEFAULT 1,
          context_window INTEGER NOT NULL DEFAULT 1048576,
          max_tokens INTEGER NOT NULL DEFAULT 16384,
          thinking_level TEXT NOT NULL DEFAULT 'medium',
          role_affinity TEXT NOT NULL DEFAULT 'any',
          input_cost_per_mtok REAL NOT NULL DEFAULT 0.15,
          cached_input_cost_per_mtok REAL NOT NULL DEFAULT 0.003,
          output_cost_per_mtok REAL NOT NULL DEFAULT 0.6,
          health_state TEXT NOT NULL DEFAULT 'closed',
          cooldown_until INTEGER,
          last_error TEXT,
          updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS model_profiles_workspace ON model_profiles (workspace_id, priority);

        CREATE TABLE IF NOT EXISTS projects (
          id TEXT PRIMARY KEY NOT NULL,
          workspace_id TEXT NOT NULL REFERENCES workspaces(id),
          tenant_id TEXT NOT NULL DEFAULT 'default',
          name TEXT NOT NULL,
          environment TEXT NOT NULL DEFAULT 'public',
          seeds TEXT NOT NULL,
          default_scope TEXT NOT NULL,
          lab_config TEXT,
          sandbox_write_allowlist TEXT NOT NULL DEFAULT '[]',
          created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS project_assets (
          id TEXT PRIMARY KEY NOT NULL,
          project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
          origin TEXT NOT NULL,
          source TEXT NOT NULL,
          third_party INTEGER NOT NULL,
          include_subdomains INTEGER NOT NULL DEFAULT 0,
          prepared TEXT,
          dns_source TEXT,
          access_policy TEXT
        );
        CREATE UNIQUE INDEX IF NOT EXISTS project_assets_origin ON project_assets (project_id, origin);

        CREATE TABLE IF NOT EXISTS project_specs (
          id TEXT PRIMARY KEY NOT NULL,
          project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
          name TEXT NOT NULL,
          kind TEXT NOT NULL,
          origin TEXT,
          content TEXT NOT NULL,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS project_specs_project ON project_specs (project_id);

        CREATE TABLE IF NOT EXISTS personas (
          id TEXT PRIMARY KEY NOT NULL,
          project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
          workspace_id TEXT NOT NULL REFERENCES workspaces(id),
          handle TEXT NOT NULL,
          role_label TEXT NOT NULL,
          tenant_ref TEXT,
          privilege TEXT,
          origin_allowlist TEXT NOT NULL,
          auth_kind TEXT NOT NULL,
          header_name TEXT,
          login_config TEXT,
          credential_id TEXT NOT NULL,
          canary_markers TEXT NOT NULL,
          created_at INTEGER NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS personas_project_handle ON personas (project_id, handle);

        CREATE TABLE IF NOT EXISTS runs (
          id TEXT PRIMARY KEY NOT NULL,
          project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
          workspace_id TEXT NOT NULL REFERENCES workspaces(id),
          tenant_id TEXT NOT NULL DEFAULT 'default',
          original_goal TEXT NOT NULL,
          goal TEXT NOT NULL,
          goal_revision INTEGER NOT NULL,
          scope_revision INTEGER NOT NULL,
          coordinator_id TEXT NOT NULL,
          phase TEXT NOT NULL,
          status TEXT NOT NULL,
          source_mode TEXT NOT NULL DEFAULT 'public',
          capability_tier INTEGER NOT NULL DEFAULT 1,
          approval_policy TEXT NOT NULL DEFAULT 'auto_review',
          approved_endpoint_patterns TEXT NOT NULL DEFAULT '[]',
          approved_persona_ids TEXT NOT NULL,
          round_no INTEGER NOT NULL DEFAULT 0,
          budget_usd REAL NOT NULL DEFAULT 25,
          budget_requests INTEGER NOT NULL DEFAULT 0,
          spent_usd REAL NOT NULL DEFAULT 0,
          spent_tokens INTEGER NOT NULL DEFAULT 0,
          spent_requests INTEGER NOT NULL DEFAULT 0,
          turns_used INTEGER NOT NULL DEFAULT 0,
          max_rps_per_origin INTEGER NOT NULL DEFAULT 5,
          worker_concurrency INTEGER NOT NULL DEFAULT 6,
          worker_max_turns INTEGER NOT NULL DEFAULT 150,
          dynamic_step_budget INTEGER,
          multi_trial_enabled INTEGER NOT NULL DEFAULT 1,
          phase0_completed_at INTEGER,
          review_plan TEXT,
          candidates TEXT NOT NULL,
          approved TEXT NOT NULL,
          auth_origins TEXT NOT NULL DEFAULT '[]',
          asset_origins TEXT NOT NULL DEFAULT '[]',
          environment_mode TEXT NOT NULL DEFAULT 'prod_readonly',
          route_denylist TEXT NOT NULL DEFAULT '[]',
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS runs_project ON runs (project_id);

        CREATE TABLE IF NOT EXISTS threat_models (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          scope_revision INTEGER NOT NULL,
          goal_revision INTEGER NOT NULL,
          entries TEXT NOT NULL,
          summary TEXT NOT NULL,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS threat_models_run ON threat_models (run_id);

        CREATE TABLE IF NOT EXISTS chain_steps (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          goal_revision INTEGER NOT NULL,
          scope_revision INTEGER NOT NULL,
          seq INTEGER NOT NULL,
          title TEXT NOT NULL,
          hypothesis TEXT NOT NULL,
          category TEXT NOT NULL DEFAULT 'misconfig-exposure',
          priority INTEGER NOT NULL DEFAULT 50,
          target_asset_ids TEXT NOT NULL,
          skills TEXT NOT NULL,
          depends_on_fact_ids TEXT NOT NULL,
          depends_on_step_ids TEXT NOT NULL,
          status TEXT NOT NULL,
          assigned_worker_id TEXT,
          specialist_profile TEXT,
          trial_group_id TEXT,
          trial_index INTEGER NOT NULL DEFAULT 0,
          source_origins TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS chain_steps_run ON chain_steps (run_id, status);
        CREATE UNIQUE INDEX IF NOT EXISTS chain_steps_run_seq ON chain_steps (run_id, seq);

        CREATE TABLE IF NOT EXISTS assignments (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          asset_id TEXT,
          step_id TEXT,
          input_assignment_id TEXT,
          phase TEXT NOT NULL,
          status TEXT NOT NULL,
          scope_revision INTEGER NOT NULL,
          goal_revision INTEGER NOT NULL,
          session_id TEXT NOT NULL,
          lease TEXT,
          lease_expires_at INTEGER,
          approval_parked_at INTEGER,
          attempt INTEGER NOT NULL DEFAULT 0,
          max_turns INTEGER NOT NULL DEFAULT 150,
          turns_used INTEGER NOT NULL DEFAULT 0,
          requests_used INTEGER NOT NULL DEFAULT 0,
          parent_fact_ids TEXT NOT NULL,
          source_origins TEXT NOT NULL,
          title TEXT NOT NULL,
          objective TEXT NOT NULL,
          outcome TEXT,
          checks TEXT,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS assignments_run ON assignments (run_id);

        CREATE TABLE IF NOT EXISTS facts (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          assignment_id TEXT NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
          scope_revision INTEGER NOT NULL,
          goal_revision INTEGER NOT NULL,
          kind TEXT NOT NULL,
          origin TEXT NOT NULL,
          summary TEXT NOT NULL,
          data TEXT NOT NULL,
          source_origins TEXT NOT NULL,
          evidence_ids TEXT NOT NULL,
          exchange_ids TEXT NOT NULL,
          tainted INTEGER NOT NULL DEFAULT 0,
          cold_since_round INTEGER,
          digest_id TEXT,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS facts_run ON facts (run_id, tainted);

        CREATE TABLE IF NOT EXISTS graph_edges (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          from_kind TEXT NOT NULL,
          from_id TEXT NOT NULL,
          to_kind TEXT NOT NULL,
          to_id TEXT NOT NULL,
          edge_kind TEXT NOT NULL,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS graph_edges_run ON graph_edges (run_id, from_id);
        CREATE INDEX IF NOT EXISTS graph_edges_to ON graph_edges (run_id, to_id);

        CREATE TABLE IF NOT EXISTS graph_digests (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          round_no INTEGER NOT NULL,
          level TEXT NOT NULL,
          signature_hash TEXT NOT NULL,
          summary TEXT NOT NULL,
          covered_fact_ids TEXT NOT NULL,
          covered_assignment_ids TEXT NOT NULL,
          active INTEGER NOT NULL DEFAULT 1,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS graph_digests_run ON graph_digests (run_id, active);

        CREATE TABLE IF NOT EXISTS broker_exchanges (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          assignment_id TEXT NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
          scope_revision INTEGER NOT NULL,
          origin TEXT NOT NULL,
          final_origin TEXT NOT NULL,
          redirect_origins TEXT NOT NULL,
          method TEXT NOT NULL,
          path_and_query TEXT NOT NULL,
          persona_handle TEXT,
          status INTEGER NOT NULL,
          media_type TEXT NOT NULL,
          req_headers TEXT NOT NULL,
          resp_headers TEXT NOT NULL,
          body_preview TEXT NOT NULL,
          body_artifact_id TEXT,
          body_sha256 TEXT NOT NULL,
          secret_matches TEXT NOT NULL DEFAULT '[]',
          duration_ms INTEGER NOT NULL,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS broker_exchanges_run ON broker_exchanges (run_id, origin);

        CREATE TABLE IF NOT EXISTS approval_requests (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          assignment_id TEXT NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
          scope_revision INTEGER NOT NULL,
          origin TEXT NOT NULL,
          method TEXT NOT NULL,
          path_and_query TEXT NOT NULL,
          persona_handle TEXT,
          rationale TEXT NOT NULL,
          request_preview TEXT NOT NULL,
          status TEXT NOT NULL,
          decided_by TEXT,
          decided_at INTEGER,
          policy_note TEXT,
          risk_level TEXT,
          expires_at INTEGER NOT NULL,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS approval_requests_run ON approval_requests (run_id, status);

        CREATE TABLE IF NOT EXISTS replay_specs (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          finding_id TEXT NOT NULL,
          assignment_id TEXT NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
          scope_revision INTEGER NOT NULL,
          goal_revision INTEGER NOT NULL,
          spec TEXT NOT NULL,
          spec_sha256 TEXT NOT NULL,
          source_origins TEXT NOT NULL,
          attempt_count INTEGER NOT NULL DEFAULT 1,
          verified_inline INTEGER NOT NULL DEFAULT 0,
          last_verification_diff TEXT,
          proof_kind TEXT,
          proof_verdict TEXT,
          proof_runtime TEXT,
          proof_script_sha256 TEXT,
          proof_artifact_id TEXT,
          proof_receipt TEXT,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS replay_specs_run ON replay_specs (run_id);

        CREATE TABLE IF NOT EXISTS retest_runs (
          id TEXT PRIMARY KEY NOT NULL,
          project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          finding_id TEXT NOT NULL,
          replay_spec_id TEXT NOT NULL REFERENCES replay_specs(id) ON DELETE CASCADE,
          scope_revision INTEGER NOT NULL,
          verdict TEXT NOT NULL,
          summary TEXT NOT NULL,
          evidence_ids TEXT NOT NULL,
          exchange_ids TEXT NOT NULL,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS retest_runs_finding ON retest_runs (finding_id);

        CREATE TABLE IF NOT EXISTS coverage_entries (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          scope_revision INTEGER NOT NULL,
          goal_revision INTEGER NOT NULL,
          origin TEXT NOT NULL,
          category TEXT NOT NULL,
          status TEXT NOT NULL,
          summary TEXT NOT NULL,
          enforcing_control TEXT,
          proof_gap_reason TEXT,
          linked_finding_id TEXT,
          assignment_id TEXT NOT NULL,
          updated_at INTEGER NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS coverage_origin_cat ON coverage_entries (run_id, goal_revision, origin, category);

        CREATE TABLE IF NOT EXISTS canaries (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          assignment_id TEXT NOT NULL,
          token TEXT NOT NULL UNIQUE,
          purpose TEXT NOT NULL,
          protocol TEXT NOT NULL DEFAULT 'http',
          dns_host TEXT,
          hit_count INTEGER NOT NULL DEFAULT 0,
          triggered INTEGER NOT NULL DEFAULT 0,
          trigger_detail TEXT,
          created_at INTEGER NOT NULL,
          triggered_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS canaries_run ON canaries (run_id);

        CREATE TABLE IF NOT EXISTS evidence (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          assignment_id TEXT NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
          scope_revision INTEGER NOT NULL,
          goal_revision INTEGER NOT NULL,
          title TEXT NOT NULL,
          kind TEXT NOT NULL,
          operation_id TEXT,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS evidence_run ON evidence (run_id);
        CREATE UNIQUE INDEX IF NOT EXISTS evidence_operation ON evidence (assignment_id, operation_id);

        CREATE TABLE IF NOT EXISTS findings (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          asset_id TEXT NOT NULL,
          goal_revision INTEGER NOT NULL,
          check_id TEXT NOT NULL DEFAULT 'hsts',
          case_id TEXT NOT NULL DEFAULT '',
          finding_kind TEXT NOT NULL DEFAULT 'baseline_check',
          replay_spec_id TEXT,
          provenance TEXT NOT NULL DEFAULT 'agent_only' CHECK (provenance IN ('floor', 'agent_only', 'chain_from_floor')),
          parent_finding_ids TEXT,
          verification_class TEXT NOT NULL DEFAULT 'runtime_confirmed'
            CHECK (verification_class IN ('runtime_confirmed', 'pending_oob', 'static_advisory', 'open_proof_gap', 'dismissed'))
            CHECK (json_extract(finding, '$.status') <> 'confirmed' OR verification_class = 'runtime_confirmed')
            CHECK (json_extract(finding, '$.status') <> 'confirmed' OR verification_tier IS NULL OR verification_tier <> 'static_verified'),
          source_origins TEXT NOT NULL,
          verification_tier TEXT,
          fingerprint_hash TEXT,
          superseded_by_finding_id TEXT,
          counterevidence TEXT,
          confidence_rationale TEXT,
          severity_change_conditions TEXT,
          code_locations TEXT,
          status TEXT NOT NULL DEFAULT 'pending',
          severity TEXT NOT NULL DEFAULT 'medium',
          cwe TEXT,
          origin TEXT NOT NULL DEFAULT '',
          triage_status TEXT NOT NULL DEFAULT 'open',
          finding TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS findings_run ON findings (run_id);
        CREATE UNIQUE INDEX IF NOT EXISTS findings_check_case ON findings (run_id, asset_id, goal_revision, check_id, case_id);

        CREATE TABLE IF NOT EXISTS reports (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          version INTEGER NOT NULL,
          partial INTEGER NOT NULL,
          body TEXT NOT NULL,
          created_at INTEGER NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS report_version ON reports (run_id, version);

        CREATE TABLE IF NOT EXISTS messages (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          thread_id TEXT NOT NULL,
          role TEXT NOT NULL,
          content TEXT NOT NULL,
          reply_to TEXT,
          evidence_ids TEXT,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS thread_messages ON messages (run_id, thread_id);
        CREATE UNIQUE INDEX IF NOT EXISTS run_replies ON messages (run_id, reply_to);

        CREATE TABLE IF NOT EXISTS events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          workspace_id TEXT NOT NULL REFERENCES workspaces(id),
          run_id TEXT REFERENCES runs(id) ON DELETE CASCADE,
          kind TEXT NOT NULL,
          message TEXT NOT NULL,
          detail TEXT NOT NULL,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS events_run ON events (run_id, id);

        CREATE TABLE IF NOT EXISTS operations (
          id TEXT PRIMARY KEY NOT NULL,
          workspace_id TEXT NOT NULL REFERENCES workspaces(id),
          fingerprint TEXT NOT NULL,
          result TEXT NOT NULL,
          created_at INTEGER NOT NULL DEFAULT 0
        );
      `)
    },
  },
  {
    version: 2,
    name: 'v3_sast_surface_patches',
    up(ctx) {
      ctx.ensureColumn('model_profiles', 'cached_input_cost_per_mtok', 'REAL NOT NULL DEFAULT 0.003')
      ctx.ensureColumn('projects', 'lab_config', 'TEXT')
      ctx.ensureColumn('personas', 'login_config', 'TEXT')
      ctx.ensureColumn('runs', 'approval_policy', "TEXT NOT NULL DEFAULT 'auto_review'")
      ctx.ensureColumn('runs', 'approved_endpoint_patterns', "TEXT NOT NULL DEFAULT '[]'")
      ctx.ensureColumn('approval_requests', 'policy_note', 'TEXT')
      ctx.ensureColumn('approval_requests', 'risk_level', 'TEXT')
      ctx.ensureColumn('findings', 'verification_tier', 'TEXT')
      ctx.ensureColumn('findings', 'fingerprint_hash', 'TEXT')
      ctx.ensureColumn('findings', 'superseded_by_finding_id', 'TEXT')
      ctx.ensureColumn('findings', 'counterevidence', 'TEXT')
      ctx.ensureColumn('findings', 'confidence_rationale', 'TEXT')
      ctx.ensureColumn('findings', 'severity_change_conditions', 'TEXT')
      ctx.ensureColumn('findings', 'code_locations', 'TEXT')
      ctx.ensureColumn('coverage_entries', 'enforcing_control', 'TEXT')
      ctx.ensureColumn('coverage_entries', 'proof_gap_reason', 'TEXT')
      ctx.ensureColumn('coverage_entries', 'linked_finding_id', 'TEXT')
      ctx.ensureColumn('canaries', 'protocol', "TEXT NOT NULL DEFAULT 'http'")
      ctx.ensureColumn('canaries', 'dns_host', 'TEXT')
      ctx.ensureColumn('canaries', 'hit_count', 'INTEGER NOT NULL DEFAULT 0')
      ctx.ensureColumn('broker_exchanges', 'secret_matches', "TEXT NOT NULL DEFAULT '[]'")
      ctx.client.exec(`
        CREATE INDEX IF NOT EXISTS findings_fingerprint ON findings (run_id, fingerprint_hash);

        CREATE TABLE IF NOT EXISTS sast_runs (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          assignment_id TEXT NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
          repo TEXT NOT NULL,
          engine TEXT NOT NULL,
          raw_artifact_id TEXT,
          finding_count INTEGER NOT NULL DEFAULT 0,
          duration_ms INTEGER NOT NULL DEFAULT 0,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS sast_runs_run ON sast_runs (run_id);

        CREATE TABLE IF NOT EXISTS surface_probes (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          assignment_id TEXT NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
          scope_revision INTEGER NOT NULL,
          origin TEXT NOT NULL,
          probe_kind TEXT NOT NULL,
          requests_sent INTEGER NOT NULL DEFAULT 0,
          anomalies_found INTEGER NOT NULL DEFAULT 0,
          baseline_signature TEXT,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS surface_probes_run ON surface_probes (run_id, origin);

        CREATE TABLE IF NOT EXISTS patch_proposals (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          finding_id TEXT NOT NULL,
          repo TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'draft',
          caller_compatibility TEXT NOT NULL DEFAULT 'attacker_only',
          diff TEXT NOT NULL,
          code_locations TEXT NOT NULL,
          review_notes TEXT NOT NULL DEFAULT '',
          dynamic_retest_verdict TEXT NOT NULL DEFAULT 'skipped',
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS patch_proposals_run ON patch_proposals (run_id, finding_id);
      `)
    },
  },
  {
    version: 3,
    name: 'v4_state_graph_and_telemetry',
    up(ctx) {
      ctx.ensureColumn('model_profiles', 'role_affinity', "TEXT NOT NULL DEFAULT 'any'")
      ctx.ensureColumn('projects', 'sandbox_write_allowlist', "TEXT NOT NULL DEFAULT '[]'")
      ctx.ensureColumn('runs', 'dynamic_step_budget', 'INTEGER')
      ctx.ensureColumn('runs', 'multi_trial_enabled', 'INTEGER NOT NULL DEFAULT 1')
      ctx.ensureColumn('runs', 'phase0_completed_at', 'INTEGER')
      ctx.ensureColumn('chain_steps', 'specialist_profile', 'TEXT')
      ctx.ensureColumn('chain_steps', 'trial_group_id', 'TEXT')
      ctx.ensureColumn('chain_steps', 'trial_index', 'INTEGER NOT NULL DEFAULT 0')
      ctx.ensureColumn('replay_specs', 'attempt_count', 'INTEGER NOT NULL DEFAULT 1')
      ctx.ensureColumn('replay_specs', 'verified_inline', 'INTEGER NOT NULL DEFAULT 0')
      ctx.ensureColumn('replay_specs', 'last_verification_diff', 'TEXT')
      ctx.client.exec(`
        CREATE TABLE IF NOT EXISTS endpoints (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          scope_revision INTEGER NOT NULL,
          origin TEXT NOT NULL,
          method TEXT NOT NULL,
          path_template TEXT NOT NULL,
          source TEXT NOT NULL,
          framework TEXT,
          auth_requirement TEXT,
          ownership_guard TEXT,
          sink_kinds TEXT NOT NULL DEFAULT '[]',
          tested_classes TEXT NOT NULL DEFAULT '[]',
          coverage_pct REAL,
          risk_score INTEGER NOT NULL DEFAULT 50,
          code_location TEXT,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS endpoints_run_route ON endpoints (run_id, origin, method, path_template);
        CREATE INDEX IF NOT EXISTS endpoints_run_risk ON endpoints (run_id, risk_score);

        CREATE TABLE IF NOT EXISTS endpoint_params (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
          name TEXT NOT NULL,
          location TEXT NOT NULL,
          inferred_type TEXT,
          is_csrf INTEGER NOT NULL DEFAULT 0,
          is_object_id INTEGER NOT NULL DEFAULT 0,
          source TEXT NOT NULL,
          created_at INTEGER NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS endpoint_params_unique ON endpoint_params (endpoint_id, name, location);
        CREATE INDEX IF NOT EXISTS endpoint_params_run ON endpoint_params (run_id, endpoint_id);

        CREATE TABLE IF NOT EXISTS api_dependencies (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          producer_endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
          consumer_endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
          resource_key TEXT NOT NULL,
          sample_resource_id_hash TEXT,
          persona_handle TEXT,
          observed_transitions TEXT NOT NULL DEFAULT '[]',
          tested_bola INTEGER NOT NULL DEFAULT 0,
          created_at INTEGER NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS api_dependencies_edge ON api_dependencies (run_id, producer_endpoint_id, consumer_endpoint_id, resource_key);
        CREATE INDEX IF NOT EXISTS api_dependencies_run ON api_dependencies (run_id, tested_bola);

        CREATE TABLE IF NOT EXISTS second_order_canaries (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          assignment_id TEXT NOT NULL,
          marker TEXT NOT NULL UNIQUE,
          injected_origin TEXT NOT NULL,
          injected_endpoint TEXT NOT NULL,
          injected_param TEXT NOT NULL,
          injected_persona TEXT,
          surfaced_origin TEXT,
          surfaced_endpoint TEXT,
          surfaced_persona TEXT,
          surfaced_exchange_id TEXT,
          status TEXT NOT NULL DEFAULT 'planted',
          created_at INTEGER NOT NULL,
          surfaced_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS second_order_canaries_run ON second_order_canaries (run_id, status);

        CREATE TABLE IF NOT EXISTS lab_telemetry (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          exchange_id TEXT NOT NULL,
          trace_id TEXT NOT NULL,
          routes_hit TEXT NOT NULL DEFAULT '[]',
          new_lines_covered INTEGER NOT NULL DEFAULT 0,
          sink_events_count INTEGER NOT NULL DEFAULT 0,
          has_unhandled_exception INTEGER NOT NULL DEFAULT 0,
          artifact_id TEXT NOT NULL,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS lab_telemetry_run ON lab_telemetry (run_id, created_at);
        CREATE UNIQUE INDEX IF NOT EXISTS lab_telemetry_trace ON lab_telemetry (run_id, trace_id);

        CREATE TABLE IF NOT EXISTS benchmark_runs (
          id TEXT PRIMARY KEY NOT NULL,
          suite TEXT NOT NULL,
          git_sha TEXT NOT NULL,
          model_routing_config TEXT NOT NULL DEFAULT '{}',
          targets_total INTEGER NOT NULL,
          confirmed_count INTEGER NOT NULL,
          false_positive_count INTEGER NOT NULL,
          funnel_counts TEXT NOT NULL,
          failure_taxonomy TEXT NOT NULL,
          total_cost_usd REAL NOT NULL DEFAULT 0,
          duration_ms INTEGER NOT NULL DEFAULT 0,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS benchmark_runs_suite ON benchmark_runs (suite, created_at);
      `)
    },
  },
  {
    version: 4,
    name: 'v5_swarm_board_and_resource_samples',
    up(ctx) {
      ctx.client.exec(`
        CREATE TABLE IF NOT EXISTS board_members (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          handle TEXT NOT NULL,
          role TEXT NOT NULL,
          specialist_profile TEXT,
          session_id TEXT NOT NULL,
          active_assignment_id TEXT,
          state TEXT NOT NULL,
          role_affinity TEXT,
          last_read_seq INTEGER NOT NULL DEFAULT 0,
          turns_used INTEGER NOT NULL DEFAULT 0,
          posts_count INTEGER NOT NULL DEFAULT 0,
          peer_hops_used INTEGER NOT NULL DEFAULT 0,
          scope_revision INTEGER NOT NULL,
          goal_revision INTEGER NOT NULL,
          source_origins TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS board_members_run_handle ON board_members (run_id, handle);
        CREATE INDEX IF NOT EXISTS board_members_run_state ON board_members (run_id, state);

        CREATE TABLE IF NOT EXISTS board_messages (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          seq INTEGER NOT NULL,
          author_handle TEXT NOT NULL,
          author_role TEXT NOT NULL,
          kind TEXT NOT NULL,
          mentions TEXT NOT NULL,
          body TEXT NOT NULL,
          ref_fact_ids TEXT NOT NULL,
          ref_exchange_ids TEXT NOT NULL,
          ref_finding_ids TEXT NOT NULL,
          ref_step_id TEXT,
          ref_approval_id TEXT,
          reply_to_seq INTEGER,
          scope_revision INTEGER NOT NULL,
          goal_revision INTEGER NOT NULL,
          source_origins TEXT NOT NULL,
          tainted INTEGER NOT NULL DEFAULT 0,
          created_at INTEGER NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS board_messages_run_seq ON board_messages (run_id, seq);
        CREATE INDEX IF NOT EXISTS board_messages_run_tainted ON board_messages (run_id, tainted, seq);

        CREATE TABLE IF NOT EXISTS resource_samples (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          owner_persona TEXT NOT NULL,
          resource_key TEXT NOT NULL,
          collection_path TEXT NOT NULL DEFAULT '',
          resource_id TEXT NOT NULL,
          origin TEXT NOT NULL,
          endpoint TEXT NOT NULL,
          method TEXT NOT NULL,
          media_type TEXT,
          authenticated INTEGER NOT NULL DEFAULT 0,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS resource_samples_key ON resource_samples (run_id, owner_persona, origin, collection_path, resource_key);
        CREATE INDEX IF NOT EXISTS resource_samples_run ON resource_samples (run_id, resource_key);
      `)
      for (const [column, definition] of [
        ['role_affinity', 'TEXT'],
        ['last_read_seq', 'INTEGER NOT NULL DEFAULT 0'],
        ['turns_used', 'INTEGER NOT NULL DEFAULT 0'],
        ['posts_count', 'INTEGER NOT NULL DEFAULT 0'],
        ['peer_hops_used', 'INTEGER NOT NULL DEFAULT 0'],
        ['active_assignment_id', 'TEXT'],
        ['updated_at', 'INTEGER NOT NULL DEFAULT 0'],
      ] as const) {
        ctx.ensureColumn('board_members', column, definition)
      }
      for (const [column, definition] of [
        ['ref_fact_ids', "TEXT NOT NULL DEFAULT '[]'"],
        ['ref_exchange_ids', "TEXT NOT NULL DEFAULT '[]'"],
        ['ref_finding_ids', "TEXT NOT NULL DEFAULT '[]'"],
        ['ref_step_id', 'TEXT'],
        ['ref_approval_id', 'TEXT'],
        ['reply_to_seq', 'INTEGER'],
        ['tainted', 'INTEGER NOT NULL DEFAULT 0'],
      ] as const) {
        ctx.ensureColumn('board_messages', column, definition)
      }
      ctx.client.exec(`
        INSERT OR IGNORE INTO board_members
          (id, run_id, handle, role, session_id, state, scope_revision, goal_revision, source_origins, created_at, updated_at)
        SELECT lower(hex(randomblob(16))), id, 'coordinator', 'coordinator', coordinator_id, 'waiting', scope_revision, goal_revision, '[]', created_at, created_at FROM runs;
        INSERT OR IGNORE INTO board_members
          (id, run_id, handle, role, session_id, state, scope_revision, goal_revision, source_origins, created_at, updated_at)
        SELECT lower(hex(randomblob(16))), id, 'verifier', 'verifier', 'system:verifier', 'waiting', scope_revision, goal_revision, '[]', created_at, created_at FROM runs;
        INSERT OR IGNORE INTO board_members
          (id, run_id, handle, role, session_id, state, scope_revision, goal_revision, source_origins, created_at, updated_at)
        SELECT lower(hex(randomblob(16))), id, 'broker', 'system', 'system:broker', 'waiting', scope_revision, goal_revision, '[]', created_at, created_at FROM runs;
        INSERT OR IGNORE INTO board_members
          (id, run_id, handle, role, session_id, state, scope_revision, goal_revision, source_origins, created_at, updated_at)
        SELECT lower(hex(randomblob(16))), id, 'canary', 'system', 'system:canary', 'waiting', scope_revision, goal_revision, '[]', created_at, created_at FROM runs;
      `)
    },
  },
  {
    version: 5,
    name: 'v6_scale_scope_and_leases',
    up(ctx) {
      ctx.ensureColumn('resource_samples', 'collection_path', "TEXT NOT NULL DEFAULT ''")
      ctx.client.exec("UPDATE resource_samples SET collection_path = '' WHERE collection_path IS NULL")

      const hadEnvironmentMode = ctx.existingColumns('runs').has('environment_mode')
      ctx.ensureColumn('runs', 'auth_origins', "TEXT NOT NULL DEFAULT '[]'")
      ctx.ensureColumn('runs', 'asset_origins', "TEXT NOT NULL DEFAULT '[]'")
      ctx.ensureColumn('runs', 'environment_mode', "TEXT NOT NULL DEFAULT 'prod_readonly'")
      ctx.ensureColumn('runs', 'route_denylist', "TEXT NOT NULL DEFAULT '[]'")
      ctx.ensureColumn('assignments', 'approval_parked_at', 'INTEGER')
      if (!hadEnvironmentMode) {
        ctx.client.exec(`
          UPDATE runs SET environment_mode = 'ephemeral_lab'
          WHERE project_id IN (SELECT id FROM projects WHERE environment = 'local-lab')
        `)
      }

      const desiredColumns = ['run_id', 'owner_persona', 'origin', 'collection_path', 'resource_key']
      const currentColumns = (ctx.client.prepare('PRAGMA index_info(resource_samples_key)').all() as Array<{ name: string }>)
        .map(row => row.name)
      if (currentColumns.join(',') !== desiredColumns.join(',')) {
        ctx.client.exec(`
          DROP INDEX IF EXISTS resource_samples_key;
          CREATE UNIQUE INDEX resource_samples_key ON resource_samples (run_id, owner_persona, origin, collection_path, resource_key);
        `)
      }

      ctx.client.exec(`
        CREATE TABLE IF NOT EXISTS lab_containers (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          assignment_id TEXT,
          container_name TEXT NOT NULL,
          image_name TEXT,
          status TEXT NOT NULL DEFAULT 'running',
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS lab_containers_name ON lab_containers (run_id, container_name);
        CREATE INDEX IF NOT EXISTS lab_containers_run ON lab_containers (run_id, status);

        CREATE TABLE IF NOT EXISTS approval_leases (
          id TEXT PRIMARY KEY NOT NULL,
          run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
          scope_revision INTEGER NOT NULL,
          origin TEXT NOT NULL,
          method TEXT NOT NULL,
          route_pattern TEXT NOT NULL,
          lease_scope TEXT NOT NULL DEFAULT 'route' CHECK (lease_scope IN ('route', 'prefix', 'host_nondestructive')),
          persona_handle TEXT,
          cross_persona INTEGER NOT NULL DEFAULT 0,
          status TEXT NOT NULL,
          source_approval_id TEXT,
          created_by TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          expires_at INTEGER,
          uses INTEGER NOT NULL DEFAULT 0,
          max_uses INTEGER,
          last_used_at INTEGER
        );
        CREATE UNIQUE INDEX IF NOT EXISTS approval_leases_route
          ON approval_leases (run_id, origin, method, route_pattern, scope_revision);
        CREATE INDEX IF NOT EXISTS approval_leases_run ON approval_leases (run_id, status);

        CREATE INDEX IF NOT EXISTS broker_exchanges_run_created ON broker_exchanges (run_id, created_at);
        CREATE INDEX IF NOT EXISTS broker_exchanges_body_artifact ON broker_exchanges (body_artifact_id);
        CREATE INDEX IF NOT EXISTS facts_run_created ON facts (run_id, created_at);
        CREATE INDEX IF NOT EXISTS endpoints_run_updated ON endpoints (run_id, updated_at);
        CREATE INDEX IF NOT EXISTS evidence_run_created ON evidence (run_id, created_at);

        CREATE TABLE IF NOT EXISTS store_settings (
          key TEXT PRIMARY KEY NOT NULL,
          value TEXT NOT NULL,
          updated_at INTEGER NOT NULL
        );
      `)
    },
  },
  {
    version: 6,
    name: 'v6_findings_provenance_and_guards',
    up(ctx) {
      if (ctx.tableExists('findings')) {
        // Data backfill BEFORE constraints: normalize legacy static_verified + confirmed rows
        // before attaching verification_class CHECK constraints so older DBs never wedge on upgrade.
        ctx.client.exec(`
          UPDATE findings
          SET finding = json_set(finding, '$.status', 'static_verified')
          WHERE verification_tier = 'static_verified'
            AND json_extract(finding, '$.status') = 'confirmed';
        `)
        ctx.ensureColumn(
          'findings',
          'provenance',
          "TEXT NOT NULL DEFAULT 'agent_only' CHECK (provenance IN ('floor', 'agent_only', 'chain_from_floor'))",
        )
        ctx.ensureColumn('findings', 'parent_finding_ids', 'TEXT')
        ctx.ensureColumn(
          'findings',
          'verification_class',
          "TEXT NOT NULL DEFAULT 'runtime_confirmed' CHECK (verification_class IN ('runtime_confirmed', 'pending_oob', 'static_advisory', 'open_proof_gap', 'dismissed')) "
          + "CHECK (json_extract(finding, '$.status') <> 'confirmed' OR verification_class = 'runtime_confirmed') "
          + "CHECK (json_extract(finding, '$.status') <> 'confirmed' OR verification_tier IS NULL OR verification_tier <> 'static_verified')",
        )
        ctx.client.exec(`
          UPDATE findings
          SET verification_class = 'static_advisory'
          WHERE verification_class <> 'static_advisory'
            AND (json_extract(finding, '$.status') = 'static_verified' OR verification_tier = 'static_verified');

          UPDATE findings
          SET verification_class = 'dismissed'
          WHERE verification_class <> 'dismissed'
            AND json_extract(finding, '$.status') = 'dismissed';

          UPDATE findings
          SET verification_class = 'pending_oob'
          WHERE verification_class NOT IN ('pending_oob', 'dismissed')
            AND json_extract(finding, '$.status') IN ('pending', 'inconclusive')
            AND lower(coalesce(json_extract(finding, '$.runtimeProofGap'), '') || ' '
              || coalesce(json_extract(finding, '$.verification'), '') || ' '
              || coalesce(json_extract(finding, '$.reason'), '')) GLOB '*pending*oob*';

          UPDATE findings
          SET verification_class = 'open_proof_gap'
          WHERE verification_class = 'runtime_confirmed'
            AND json_extract(finding, '$.status') IN ('pending', 'inconclusive');
        `)
        if (ctx.tableExists('events')) {
          ctx.client.exec(`
            UPDATE findings
            SET provenance = 'floor'
            WHERE provenance = 'agent_only'
              AND EXISTS (
                SELECT 1 FROM events e
                WHERE e.run_id = findings.run_id
                  AND e.kind = 'deterministic_engine.confirmed'
                  AND json_extract(e.detail, '$.findingId') = findings.id
              );
          `)
        }
        ctx.client.exec('CREATE INDEX IF NOT EXISTS findings_provenance ON findings (run_id, provenance);')
      }
      installConfirmationGuards(ctx)
    },
  },
  {
    version: 7,
    name: 'v7_tenant_isolation_and_audit',
    up(ctx) {
      ctx.ensureColumn('project_assets', 'include_subdomains', 'INTEGER NOT NULL DEFAULT 0')
      ctx.ensureColumn('projects', 'tenant_id', "TEXT NOT NULL DEFAULT 'default'")
      ctx.ensureColumn('runs', 'tenant_id', "TEXT NOT NULL DEFAULT 'default'")
      ctx.client.exec(`
        CREATE INDEX IF NOT EXISTS projects_tenant ON projects (tenant_id);
        CREATE INDEX IF NOT EXISTS runs_tenant ON runs (tenant_id);
        -- CRITICAL SAFETY INVARIANT: append-only audit log intentionally has NO foreign key and
        -- NO ON DELETE CASCADE so audit entries survive run and project deletion.
        CREATE TABLE IF NOT EXISTS tenant_audit_log (
          seq INTEGER PRIMARY KEY AUTOINCREMENT,
          id TEXT NOT NULL UNIQUE,
          tenant_id TEXT NOT NULL,
          run_id TEXT,
          actor TEXT NOT NULL,
          action TEXT NOT NULL,
          resource_kind TEXT NOT NULL,
          resource_id TEXT,
          outcome TEXT NOT NULL,
          detail TEXT NOT NULL,
          prev_hash TEXT NOT NULL,
          entry_hash TEXT NOT NULL,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS tenant_audit_log_tenant ON tenant_audit_log (tenant_id, seq);
        CREATE TRIGGER IF NOT EXISTS tenant_audit_log_no_update
          BEFORE UPDATE ON tenant_audit_log
          BEGIN
            SELECT RAISE(ABORT, 'invariant.audit_log_append_only');
          END;
        CREATE TRIGGER IF NOT EXISTS tenant_audit_log_no_delete
          BEFORE DELETE ON tenant_audit_log
          BEGIN
            SELECT RAISE(ABORT, 'invariant.audit_log_append_only');
          END;
      `)
      try {
        ctx.client.exec(
          'CREATE UNIQUE INDEX IF NOT EXISTS tenant_audit_log_chain_unique ON tenant_audit_log (tenant_id, prev_hash);',
        )
      } catch (error) {
        if (!/UNIQUE constraint failed/i.test((error as Error).message)) throw error
      }
      try {
        ctx.client.exec(
          'CREATE UNIQUE INDEX IF NOT EXISTS chain_steps_run_seq ON chain_steps (run_id, seq);',
        )
      } catch (error) {
        if (!/UNIQUE constraint failed/i.test((error as Error).message)) throw error
      }
    },
  },
  {
    version: 8,
    name: 'v8_capability_ledger',
    up(ctx) {
      initCapabilityLedgerSchema(ctx.client)
      ctx.client.exec(`
        CREATE TRIGGER IF NOT EXISTS runs_after_delete_capability_ledger
          AFTER DELETE ON runs
          BEGIN
            DELETE FROM capability_causal_edges WHERE run_id = OLD.id;
            DELETE FROM capability_negative_edges WHERE run_id = OLD.id;
            DELETE FROM capability_nodes WHERE run_id = OLD.id;
          END;
      `)
    },
  },
  {
    version: 9,
    name: 'v9_agent_script_proofs',
    up(ctx) {
      ctx.ensureColumn('replay_specs', 'proof_kind', 'TEXT')
      ctx.ensureColumn('replay_specs', 'proof_verdict', 'TEXT')
      ctx.ensureColumn('replay_specs', 'proof_runtime', 'TEXT')
      ctx.ensureColumn('replay_specs', 'proof_script_sha256', 'TEXT')
      ctx.ensureColumn('replay_specs', 'proof_artifact_id', 'TEXT')
      ctx.ensureColumn('replay_specs', 'proof_receipt', 'TEXT')
      ctx.client.exec('CREATE INDEX IF NOT EXISTS replay_specs_proof ON replay_specs (run_id, proof_kind);')
    },
  },
  {
    version: 10,
    name: 'v10_promoted_finding_columns_and_ops_ttl',
    up(ctx) {
      if (ctx.tableExists('operations')) {
        ctx.ensureColumn('operations', 'created_at', 'INTEGER NOT NULL DEFAULT 0')
        ctx.client.prepare('UPDATE operations SET created_at = ? WHERE created_at = 0').run(Date.now())
        ctx.client.exec('CREATE INDEX IF NOT EXISTS operations_created ON operations (created_at);')
      }
      if (ctx.tableExists('findings')) {
        ctx.ensureColumn('findings', 'status', "TEXT NOT NULL DEFAULT 'pending'")
        ctx.ensureColumn('findings', 'severity', "TEXT NOT NULL DEFAULT 'medium'")
        ctx.ensureColumn('findings', 'cwe', 'TEXT')
        ctx.ensureColumn('findings', 'origin', "TEXT NOT NULL DEFAULT ''")
        ctx.ensureColumn('findings', 'triage_status', "TEXT NOT NULL DEFAULT 'open'")
        FindingCodec.backfillPromotedColumns(ctx.client)
        ctx.client.exec(`
          CREATE INDEX IF NOT EXISTS findings_run_verified
            ON findings (run_id, verification_class, superseded_by_finding_id);
          CREATE INDEX IF NOT EXISTS findings_run_status_severity
            ON findings (run_id, status, severity);
          CREATE INDEX IF NOT EXISTS findings_run_triage
            ON findings (run_id, triage_status);
          CREATE INDEX IF NOT EXISTS findings_run_origin_cwe
            ON findings (run_id, origin, cwe);
        `)
        installPromotedFindingSyncTriggers(ctx)
      }
      installConfirmationGuards(ctx)
    },
  },
  {
    version: 11,
    name: 'v11_bounded_approval_leases',
    up(ctx) {
      if (!ctx.tableExists('approval_leases')) return
      ctx.ensureColumn(
        'approval_leases',
        'lease_scope',
        "TEXT NOT NULL DEFAULT 'route' CHECK (lease_scope IN ('route', 'prefix', 'host_nondestructive'))",
      )
      ctx.ensureColumn('approval_leases', 'max_uses', 'INTEGER')
      ctx.ensureColumn('approval_leases', 'cross_persona', 'INTEGER NOT NULL DEFAULT 0')

      // Conservative backfill (R2-09):
      // Only explicit host non-destructive sentinel rows map to 'host_nondestructive'.
      // Pre-migration rows — including legacy '/x/**'-shaped route_pattern rows — stay
      // conservatively typed as 'route' (NEVER widened into 'prefix').
      ctx.client.prepare(`
        UPDATE approval_leases
        SET lease_scope = 'host_nondestructive'
        WHERE lease_scope = 'route' AND upper(trim(method)) = ? AND trim(route_pattern) = ?
      `).run(HOST_NONDESTRUCTIVE_LEASE_METHOD, HOST_NONDESTRUCTIVE_LEASE_PATTERN)

      // Backfill finite bounds onto any legacy leases missing expires_at or max_uses.
      ctx.client.prepare(`
        UPDATE approval_leases
        SET expires_at = created_at + ?
        WHERE expires_at IS NULL AND status = 'active'
      `).run(DEFAULT_APPROVAL_LEASE_TTL_MS)
      ctx.client.prepare(`
        UPDATE approval_leases
        SET max_uses = CASE
          WHEN lease_scope = 'route' THEN ?
          ELSE ?
        END
        WHERE max_uses IS NULL
      `).run(DEFAULT_ROUTE_LEASE_MAX_USES, DEFAULT_HOST_LEASE_MAX_USES)
    },
  },
  {
    version: 12,
    name: 'v12_typed_persona_identity',
    up(ctx) {
      if (!ctx.tableExists('personas')) return
      ctx.ensureColumn('personas', 'tenant_ref', 'TEXT')
      ctx.ensureColumn('personas', 'privilege', 'TEXT')
    },
  },
]

export class Store {
  /** Ordered transactional SQLite schema migrations (`v -> v+1`). */
  static readonly migrations: readonly MigrationStep[] = STORE_MIGRATIONS

  /** Execute transactional migrations against a raw `DatabaseSync` handle (also exposed for tests). */
  static runMigrations(client: DatabaseSync, steps: readonly MigrationStep[] = STORE_MIGRATIONS): MigrationRunReport {
    return runSqliteMigrations(client, steps)
  }

  /** Verify live SQLite `PRAGMA table_info(...)` matches `src/server/schema.ts` and fail closed on drift. */
  static verifySchema(client: DatabaseSync): void {
    verifyStoreSchema(client)
  }

  readonly db
  readonly client: DatabaseSync
  readonly workspace
  readonly directory: string
  /** FTS indexing mode recorded in `store_settings` and honoured on every exchange write. */
  readonly ftsMode: FtsMode
  /** Bounded per-exchange body cap handed to FTS. */
  readonly ftsMaxBodyBytes: number
  /** DB size threshold above which `ftsMode: 'full'` is refused (unless forced). */
  readonly maxFullFtsDbBytes: number
  /** Migration execution summary for this open. */
  readonly migrationReport: MigrationRunReport
  /** Shared persistence session backing all domain repositories. */
  readonly session: DbSession
  readonly projectsRepo: ProjectsRepository
  readonly findingsRepo: FindingsRepository
  readonly runsRepo: RunsRepository
  private readonly processLock: DatabaseSync
  private readonly emitter = new EventEmitter()
  private ftsAvailable = false
  /** True whenever the FTS5 virtual table exists, even if the active mode is `off`. */
  private ftsTableExists = false

  constructor(directory: string, options: StoreOptions = {}) {
    this.directory = directory
    const requestedMode = options.ftsMode ?? DEFAULT_FTS_MODE
    if (!ftsModes.includes(requestedMode)) {
      throw new Error(`Invalid ftsMode '${String(requestedMode)}' (expected ${ftsModes.join('|')}).`)
    }
    this.ftsMode = requestedMode
    this.ftsMaxBodyBytes = Math.round(Math.min(
      MAX_FTS_MAX_BODY_BYTES,
      Math.max(MIN_FTS_MAX_BODY_BYTES, options.ftsMaxBodyBytes ?? DEFAULT_FTS_MAX_BODY_BYTES),
    ))
    this.maxFullFtsDbBytes = Math.max(0, options.maxFullFtsDbBytes ?? DEFAULT_MAX_FULL_FTS_DB_BYTES)
    this.emitter.setMaxListeners(256)
    mkdirSync(directory, { recursive: true, mode: 0o700 })
    mkdirSync(join(directory, 'artifacts'), { recursive: true, mode: 0o700 })
    mkdirSync(join(directory, 'credentials'), { recursive: true, mode: 0o700 })
    this.processLock = new DatabaseSync(join(directory, 'process-lock.sqlite'))
    try {
      this.processLock.exec('BEGIN EXCLUSIVE')
    } catch {
      this.processLock.close()
      throw new Error('Another Kovo Hunter server is using this data directory.')
    }
    let rawClient: DatabaseSync | null = null
    try {
      const path = join(directory, 'kovo.sqlite')
      // Unified SQLite connection hygiene: WAL keeps readers non-blocking under the batched writer;
      // NORMAL skips per-commit fsync; busy_timeout = 5000 lets concurrent readers wait cleanly;
      // journal_size_limit = 64 MiB bounds WAL file size after checkpoints; foreign_keys = ON.
      rawClient = openSqliteDatabase(path, {
        busyTimeoutMs: SQLITE_DEFAULT_BUSY_TIMEOUT_MS,
        journalSizeLimitBytes: SQLITE_JOURNAL_SIZE_LIMIT_BYTES,
        foreignKeys: true,
      })
      // Transparent read-after-write safety: any direct `client.prepare/exec` (including engine code
      // and tests that bypass Store helpers) flushes queued exchanges first. Flush/transaction
      // internals are guarded, so this never recurses.
      this.client = new Proxy(rawClient, {
        get: (target, property) => {
          const value = Reflect.get(target, property, target)
          if (typeof value !== 'function') return value
          if (property === 'prepare' || property === 'exec') {
            return (...args: unknown[]) => {
              if (this.session && !this.session.isFlushing && this.session.txDepth === 0) {
                this.session.flushNow()
              }
              return (value as (...params: unknown[]) => unknown).apply(target, args)
            }
          }
          return value.bind(target)
        },
      }) as DatabaseSync
      this.db = drizzle({ client: this.client })
      this.migrationReport = runSqliteMigrations(rawClient, STORE_MIGRATIONS)
      const jsonSupported = hasSqliteJsonSupport(rawClient)
      repairKnownSchemaDrift(rawClient, jsonSupported)
      Store.verifySchema(rawClient)
      // v6.2 full-body FTS size guard: refuse to switch on an expensive index over a database that is
      // already large unless the operator explicitly forced it. Release the process lock so a
      // subsequent correctly-configured reopen can proceed.
      if (this.ftsMode === 'full' && !options.forceFullFts) {
        const dbBytes = safeFileSize(path)
        if (dbBytes > this.maxFullFtsDbBytes) {
          throw new FtsModeRefusedError(dbBytes, this.maxFullFtsDbBytes)
        }
      }
      this.initFts()
      const current = this.db.select().from(tables.workspaces).limit(1).get()
      this.workspace = current ?? this.db.insert(tables.workspaces).values({
        id: randomUUID(),
        actorId: randomUUID(),
        name: 'Personal workspace',
        createdAt: Date.now(),
      }).returning().get()
      this.recordStoreSettings()
      this.session = new StoreSession({
        db: this.db,
        client: this.client,
        rawClient,
        workspace: this.workspace,
        directory: this.directory,
        emitter: this.emitter,
        ftsMode: this.ftsMode,
        ftsMaxBodyBytes: this.ftsMaxBodyBytes,
        maxFullFtsDbBytes: this.maxFullFtsDbBytes,
        ftsAvailable: this.ftsAvailable,
        ftsTableExists: this.ftsTableExists,
        listProjectPersonas: projectId => listProjectPersonas(this, projectId),
      })
      this.projectsRepo = new ProjectsRepository(this.session)
      this.findingsRepo = new FindingsRepository(this.session)
      this.runsRepo = new RunsRepository(this.session, this.projectsRepo, this.findingsRepo)
      this.recover()
    } catch (error) {
      if (rawClient) {
        try { rawClient.close() } catch { /* teardown is best-effort */ }
      }
      try { this.processLock.exec('ROLLBACK') } catch { /* ignore */ }
      try { this.processLock.close() } catch { /* ignore */ }
      throw error
    }
  }

  /**
   * Return a run-scoped v8 `CapabilityLedger` bound directly to this Store's shared WAL
   * `DatabaseSync` handle (zero extra SQLite connections; closing the returned view is a no-op).
   */
  capabilityLedger(runId: string, options: Omit<CapabilityLedgerOptions, 'runId'> = {}): CapabilityLedger {
    return new CapabilityLedger(this.client, { ...options, runId })
  }

  /** Durably record the storage/FTS configuration this DB was opened with. */
  private recordStoreSettings() {
    const upsert = this.client.prepare(
      'INSERT INTO store_settings (key, value, updated_at) VALUES (?, ?, ?) '
      + 'ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at',
    )
    const now = Date.now()
    upsert.run('fts_mode', this.ftsMode, now)
    upsert.run('fts_max_body_bytes', String(this.ftsMaxBodyBytes), now)
  }

  private initFts() {
    // Mode `off`: do not create a new index and do not write/query FTS rows. A pre-existing table
    // (from an earlier `preview`/`full` process) is preserved so re-enabling search is lossless.
    if (this.ftsMode === 'off') {
      const existing = this.client.prepare(
        "SELECT count(*) AS c FROM sqlite_master WHERE type = 'table' AND name = 'broker_exchanges_fts'",
      ).get() as { c?: number } | undefined
      this.ftsTableExists = Number(existing?.c ?? 0) > 0
      this.ftsAvailable = false
      if (this.ftsTableExists) this.ensureFtsCascadeTrigger()
      return
    }
    try {
      this.client.exec(`
        CREATE VIRTUAL TABLE IF NOT EXISTS broker_exchanges_fts USING fts5(
          exchange_id UNINDEXED,
          run_id UNINDEXED,
          origin,
          method,
          path_and_query,
          req_headers,
          resp_headers,
          body_preview,
          tokenize='trigram'
        );
      `)
      this.ftsAvailable = true
    } catch {
      try {
        this.client.exec(`
          CREATE VIRTUAL TABLE IF NOT EXISTS broker_exchanges_fts USING fts5(
            exchange_id UNINDEXED,
            run_id UNINDEXED,
            origin,
            method,
            path_and_query,
            req_headers,
            resp_headers,
            body_preview
          );
        `)
        this.ftsAvailable = true
      } catch {
        this.ftsAvailable = false
      }
    }
    this.ftsTableExists = this.ftsAvailable
    if (this.ftsTableExists) this.ensureFtsCascadeTrigger()
  }

  private ensureFtsCascadeTrigger() {
    this.client.exec(`
      CREATE TRIGGER IF NOT EXISTS runs_after_delete_fts
        AFTER DELETE ON runs
        BEGIN
          DELETE FROM broker_exchanges_fts WHERE run_id = OLD.id;
        END;
    `)
  }


  close() {
    try { this.flushNow() } catch { /* teardown is best-effort */ }
    try { this.client.close() } catch { /* ignore */ }
    try { this.processLock.exec('ROLLBACK') } catch { /* ignore */ }
    try { this.processLock.close() } catch { /* ignore */ }
    const registry = (globalThis as Record<symbol, Map<string, Store> | undefined>)[STORE_SINGLETON_SYMBOL]
    const resolvedDir = resolve(this.directory)
    if (registry?.get(resolvedDir) === this) {
      registry.delete(resolvedDir)
    }
  }

  // --- Shared DbSession Facade ---

  flushNow(): void { return this.session.flushNow() }

  transaction<T>(fn: () => T, options?: { behavior?: 'deferred' | 'immediate' | 'exclusive' }): T {
    return this.session.transaction(fn, options)
  }

  afterCommit(fn: () => void): void {
    this.session.afterCommit(fn)
  }

  operate<Result extends { id: string }>(input: { requestId: string }, apply: () => Result): Result
  operate(input: { requestId: string }, apply: () => { id: string }): { id: string } {
    return this.session.operate(input, apply)
  }

  hasCascadeSchema(): boolean { return this.session.hasCascadeSchema() }
  verifySchema(): void { Store.verifySchema(this.client) }
  onRunEvent(...args: Parameters<DbSession['onRunEvent']>) { return this.session.onRunEvent(...args) }
  onWake(...args: Parameters<DbSession['onWake']>) { return this.session.onWake(...args) }
  emitWake() { return this.session.emitWake() }
  event(...args: Parameters<DbSession['event']>) { return this.session.event(...args) }
  message(...args: Parameters<DbSession['message']>) { return this.session.message(...args) }
  writeBlob(...args: Parameters<DbSession['writeBlob']>) { return this.session.writeBlob(...args) }
  readBlob(...args: Parameters<DbSession['readBlob']>) { return this.session.readBlob(...args) }

  // --- Projects Repository Facade ---

  project(...args: Parameters<ProjectsRepository['project']>) { return this.projectsRepo.project(...args) }
  listWorkspace() { return this.projectsRepo.listWorkspace() }
  workspaceSummary(...args: Parameters<ProjectsRepository['workspaceSummary']>) {
    const summary = this.projectsRepo.workspaceSummary(...args)
    const runIds = [
      ...summary.projects.map(p => p.latestRun?.id).filter((id): id is string => Boolean(id)),
      ...summary.recentRuns.map(r => r.id),
    ]
    if (!runIds.length) return summary
    const rollups = this.findingsRepo.rollupFindingCountsByRunIds(runIds)
    return {
      ...summary,
      projects: summary.projects.map(project => {
        if (!project.latestRun) return project
        const rollup = rollups.get(project.latestRun.id)
        if (!rollup) return project
        return {
          ...project,
          latestRun: {
            ...project.latestRun,
            confirmedCount: rollup.confirmedCount,
            findingCount: rollup.findingCount,
          },
        }
      }),
      recentRuns: summary.recentRuns.map(run => {
        const rollup = rollups.get(run.id)
        if (!rollup) return run
        return {
          ...run,
          confirmedCount: rollup.confirmedCount,
          findings: rollup.findingCount,
        }
      }),
    }
  }
  listProjectSpecs(...args: Parameters<ProjectsRepository['listProjectSpecs']>) { return this.projectsRepo.listProjectSpecs(...args) }
  listProjectSpecsFull(...args: Parameters<ProjectsRepository['listProjectSpecsFull']>) { return this.projectsRepo.listProjectSpecsFull(...args) }
  getProjectSpec(...args: Parameters<ProjectsRepository['getProjectSpec']>) { return this.projectsRepo.getProjectSpec(...args) }
  importProjectSpec(...args: Parameters<ProjectsRepository['importProjectSpec']>) { return this.projectsRepo.importProjectSpec(...args) }
  upsertProjectSpecRaw(...args: Parameters<ProjectsRepository['upsertProjectSpecRaw']>) { return this.projectsRepo.upsertProjectSpecRaw(...args) }
  deleteProjectSpec(...args: Parameters<ProjectsRepository['deleteProjectSpec']>) { return this.projectsRepo.deleteProjectSpec(...args) }
  projectDetail(...args: Parameters<ProjectsRepository['projectDetail']>) {
    const detail = this.projectsRepo.projectDetail(...args)
    if (!detail.runs.length) return detail
    const rollups = this.findingsRepo.rollupFindingCountsByRunIds(detail.runs.map(r => r.id))
    return {
      ...detail,
      runs: detail.runs.map(run => {
        const rollup = rollups.get(run.id)
        if (!rollup) return run
        return {
          ...run,
          confirmedCount: rollup.confirmedCount,
          findingCount: rollup.findingCount,
        }
      }),
    }
  }
  deleteProject(...args: Parameters<ProjectsRepository['deleteProject']>) { return this.projectsRepo.deleteProject(...args) }
  createProject(...args: Parameters<ProjectsRepository['createProject']>) { return this.projectsRepo.createProject(...args) }
  updateProjectLabConfig(...args: Parameters<ProjectsRepository['updateProjectLabConfig']>) { return this.projectsRepo.updateProjectLabConfig(...args) }
  updateProjectSandboxWriteAllowlist(...args: Parameters<ProjectsRepository['updateProjectSandboxWriteAllowlist']>) { return this.projectsRepo.updateProjectSandboxWriteAllowlist(...args) }
  addProjectAsset(...args: Parameters<ProjectsRepository['addProjectAsset']>) { return this.projectsRepo.addProjectAsset(...args) }
  updateProjectAssetScope(...args: Parameters<ProjectsRepository['updateProjectAssetScope']>) { return this.projectsRepo.updateProjectAssetScope(...args) }
  importProjectDns(...args: Parameters<ProjectsRepository['importProjectDns']>) { return this.projectsRepo.importProjectDns(...args) }
  importProjectAccessPolicy(...args: Parameters<ProjectsRepository['importProjectAccessPolicy']>) { return this.projectsRepo.importProjectAccessPolicy(...args) }
  setProjectTenant(...args: Parameters<ProjectsRepository['setProjectTenant']>) { return this.projectsRepo.setProjectTenant(...args) }
  getProjectTenant(...args: Parameters<ProjectsRepository['getProjectTenant']>) { return this.projectsRepo.getProjectTenant(...args) }
  listProjectsForTenant(...args: Parameters<ProjectsRepository['listProjectsForTenant']>) { return this.projectsRepo.listProjectsForTenant(...args) }

  // --- Runs Repository Facade ---

  run(...args: Parameters<RunsRepository['run']>) { return this.runsRepo.run(...args) }
  recover(...args: Parameters<RunsRepository['recover']>) { return this.runsRepo.recover(...args) }
  recordLabContainer(...args: Parameters<RunsRepository['recordLabContainer']>) { return this.runsRepo.recordLabContainer(...args) }
  markLabContainerOrphaned(...args: Parameters<RunsRepository['markLabContainerOrphaned']>) { return this.runsRepo.markLabContainerOrphaned(...args) }
  listLabContainers(...args: Parameters<RunsRepository['listLabContainers']>) { return this.runsRepo.listLabContainers(...args) }
  scopePolicy(...args: Parameters<RunsRepository['scopePolicy']>) { return this.runsRepo.scopePolicy(...args) }
  hasExplicitEnvironmentMode(...args: Parameters<RunsRepository['hasExplicitEnvironmentMode']>) { return this.runsRepo.hasExplicitEnvironmentMode(...args) }
  setEnvironmentMode(...args: Parameters<RunsRepository['setEnvironmentMode']>) { return this.runsRepo.setEnvironmentMode(...args) }
  setRouteDenylist(...args: Parameters<RunsRepository['setRouteDenylist']>) { return this.runsRepo.setRouteDenylist(...args) }
  setOriginRole(...args: Parameters<RunsRepository['setOriginRole']>) { return this.runsRepo.setOriginRole(...args) }
  boardMember(...args: Parameters<RunsRepository['boardMember']>) { return this.runsRepo.boardMember(...args) }
  listBoardMembers(...args: Parameters<RunsRepository['listBoardMembers']>) { return this.runsRepo.listBoardMembers(...args) }
  upsertBoardMember(...args: Parameters<RunsRepository['upsertBoardMember']>) { return this.runsRepo.upsertBoardMember(...args) }
  updateBoardMemberState(...args: Parameters<RunsRepository['updateBoardMemberState']>) { return this.runsRepo.updateBoardMemberState(...args) }
  retireBoardMember(...args: Parameters<RunsRepository['retireBoardMember']>) { return this.runsRepo.retireBoardMember(...args) }
  postBoardMessage(...args: Parameters<RunsRepository['postBoardMessage']>) { return this.runsRepo.postBoardMessage(...args) }
  listBoardMessages(...args: Parameters<RunsRepository['listBoardMessages']>) { return this.runsRepo.listBoardMessages(...args) }
  taintBoardMessagesForRevokedOrigins(...args: Parameters<RunsRepository['taintBoardMessagesForRevokedOrigins']>) { return this.runsRepo.taintBoardMessagesForRevokedOrigins(...args) }
  eventsAfter(...args: Parameters<RunsRepository['eventsAfter']>) { return this.runsRepo.eventsAfter(...args) }
  runShellSummary(...args: Parameters<RunsRepository['runShellSummary']>) { return this.runsRepo.runShellSummary(...args) }
  isRunActive(...args: Parameters<RunsRepository['isRunActive']>) { return this.runsRepo.isRunActive(...args) }
  listActiveRunIdsForProject(...args: Parameters<RunsRepository['listActiveRunIdsForProject']>) { return this.runsRepo.listActiveRunIdsForProject(...args) }
  deleteRun(...args: Parameters<RunsRepository['deleteRun']>) {
    cancelOobDrainForRun(args[0])
    return this.runsRepo.deleteRun(...args)
  }
  runDetail(...args: Parameters<RunsRepository['runDetail']>) { return this.runsRepo.runDetail(...args) }
  workerList(...args: Parameters<RunsRepository['workerList']>) { return this.runsRepo.workerList(...args) }
  runnable() { return this.runsRepo.runnable() }
  runsWithPendingRetests() { return this.runsRepo.runsWithPendingRetests() }
  worker(...args: Parameters<RunsRepository['worker']>) { return this.runsRepo.worker(...args) }
  saveThreatModel(...args: Parameters<RunsRepository['saveThreatModel']>) { return this.runsRepo.saveThreatModel(...args) }
  latestThreatModel(...args: Parameters<RunsRepository['latestThreatModel']>) { return this.runsRepo.latestThreatModel(...args) }
  listChainSteps(...args: Parameters<RunsRepository['listChainSteps']>) { return this.runsRepo.listChainSteps(...args) }
  addChainStep(...args: Parameters<RunsRepository['addChainStep']>) { return this.runsRepo.addChainStep(...args) }
  updateChainStep(...args: Parameters<RunsRepository['updateChainStep']>) { return this.runsRepo.updateChainStep(...args) }
  refreshReadyChainSteps(...args: Parameters<RunsRepository['refreshReadyChainSteps']>) { return this.runsRepo.refreshReadyChainSteps(...args) }
  listDigests(...args: Parameters<RunsRepository['listDigests']>) { return this.runsRepo.listDigests(...args) }
  getDigest(...args: Parameters<RunsRepository['getDigest']>) { return this.runsRepo.getDigest(...args) }
  saveDigest(...args: Parameters<RunsRepository['saveDigest']>) { return this.runsRepo.saveDigest(...args) }
  createApprovalRequest(...args: Parameters<RunsRepository['createApprovalRequest']>) { return this.runsRepo.createApprovalRequest(...args) }
  recordAutoApprovalDecision(...args: Parameters<RunsRepository['recordAutoApprovalDecision']>) { return this.runsRepo.recordAutoApprovalDecision(...args) }
  getApprovalRequest(...args: Parameters<RunsRepository['getApprovalRequest']>) { return this.runsRepo.getApprovalRequest(...args) }
  listApprovalRequests(...args: Parameters<RunsRepository['listApprovalRequests']>) { return this.runsRepo.listApprovalRequests(...args) }
  grantApprovalLease(...args: Parameters<RunsRepository['grantApprovalLease']>) { return this.runsRepo.grantApprovalLease(...args) }
  listApprovalLeases(...args: Parameters<RunsRepository['listApprovalLeases']>) { return this.runsRepo.listApprovalLeases(...args) }
  revokeApprovalLease(...args: Parameters<RunsRepository['revokeApprovalLease']>) { return this.runsRepo.revokeApprovalLease(...args) }
  extendApprovalLease(...args: Parameters<RunsRepository['extendApprovalLease']>) { return this.runsRepo.extendApprovalLease(...args) }
  revokeApprovalLeasesForOrigin(...args: Parameters<RunsRepository['revokeApprovalLeasesForOrigin']>) { return this.runsRepo.revokeApprovalLeasesForOrigin(...args) }
  leaseAuthorizes(...args: Parameters<RunsRepository['leaseAuthorizes']>) { return this.runsRepo.leaseAuthorizes(...args) }
  approvalLeaseAuthorizer(...args: Parameters<RunsRepository['approvalLeaseAuthorizer']>) { return this.runsRepo.approvalLeaseAuthorizer(...args) }
  parkWorkerForApproval(...args: Parameters<RunsRepository['parkWorkerForApproval']>) { return this.runsRepo.parkWorkerForApproval(...args) }
  resumeParkedWorker(...args: Parameters<RunsRepository['resumeParkedWorker']>) { return this.runsRepo.resumeParkedWorker(...args) }
  parkedWorkerCount(...args: Parameters<RunsRepository['parkedWorkerCount']>) { return this.runsRepo.parkedWorkerCount(...args) }
  decideApproval(...args: Parameters<RunsRepository['decideApproval']>) { return this.runsRepo.decideApproval(...args) }
  setApprovalPolicy(...args: Parameters<RunsRepository['setApprovalPolicy']>) { return this.runsRepo.setApprovalPolicy(...args) }
  approveSimilarEndpoint(...args: Parameters<RunsRepository['approveSimilarEndpoint']>) { return this.runsRepo.approveSimilarEndpoint(...args) }
  approveAllPending(...args: Parameters<RunsRepository['approveAllPending']>) { return this.runsRepo.approveAllPending(...args) }
  recordLlmSpend(...args: Parameters<RunsRepository['recordLlmSpend']>) { return this.runsRepo.recordLlmSpend(...args) }
  checkBudgetExceeded(...args: Parameters<RunsRepository['checkBudgetExceeded']>) { return this.runsRepo.checkBudgetExceeded(...args) }
  createRun(...args: Parameters<RunsRepository['createRun']>) { return this.runsRepo.createRun(...args) }
  suggestCandidateHost(...args: Parameters<RunsRepository['suggestCandidateHost']>) { return this.runsRepo.suggestCandidateHost(...args) }
  makeWorker(...args: Parameters<RunsRepository['makeWorker']>) { return this.runsRepo.makeWorker(...args) }
  commitReviewPlan(...args: Parameters<RunsRepository['commitReviewPlan']>) { return this.runsRepo.commitReviewPlan(...args) }
  updateRun(...args: Parameters<RunsRepository['updateRun']>) { return this.runsRepo.updateRun(...args) }
  updateWorker(...args: Parameters<RunsRepository['updateWorker']>) { return this.runsRepo.updateWorker(...args) }
  setStatus(...args: Parameters<RunsRepository['setStatus']>) { return this.runsRepo.setStatus(...args) }
  writeReport(...args: Parameters<RunsRepository['writeReport']>) { return this.runsRepo.writeReport(...args) }
  command(...args: Parameters<RunsRepository['command']>) { return this.runsRepo.command(...args) }
  updateRunPhase0Completed(...args: Parameters<RunsRepository['updateRunPhase0Completed']>) { return this.runsRepo.updateRunPhase0Completed(...args) }
  updateRunDynamicStepBudget(...args: Parameters<RunsRepository['updateRunDynamicStepBudget']>) { return this.runsRepo.updateRunDynamicStepBudget(...args) }
  setRunTenant(...args: Parameters<RunsRepository['setRunTenant']>) { return this.runsRepo.setRunTenant(...args) }
  getRunTenant(...args: Parameters<RunsRepository['getRunTenant']>) { return this.runsRepo.getRunTenant(...args) }
  assertRunTenantAccess(...args: Parameters<RunsRepository['assertRunTenantAccess']>) { return this.runsRepo.assertRunTenantAccess(...args) }
  listRunsForTenant(...args: Parameters<RunsRepository['listRunsForTenant']>) { return this.runsRepo.listRunsForTenant(...args) }
  appendTenantAuditLog(...args: Parameters<RunsRepository['appendTenantAuditLog']>) { return this.runsRepo.appendTenantAuditLog(...args) }
  listTenantAuditLog(...args: Parameters<RunsRepository['listTenantAuditLog']>) { return this.runsRepo.listTenantAuditLog(...args) }
  verifyTenantAuditLogChain(...args: Parameters<RunsRepository['verifyTenantAuditLogChain']>) { return this.runsRepo.verifyTenantAuditLogChain(...args) }

  // --- Findings Repository Facade ---

  assignmentEvidence(...args: Parameters<FindingsRepository['assignmentEvidence']>) { return this.findingsRepo.assignmentEvidence(...args) }
  assignmentObservation(...args: Parameters<FindingsRepository['assignmentObservation']>) { return this.findingsRepo.assignmentObservation(...args) }
  brokerOrigins(...args: Parameters<FindingsRepository['brokerOrigins']>) { return this.findingsRepo.brokerOrigins(...args) }
  artifact(...args: Parameters<FindingsRepository['artifact']>) { return this.findingsRepo.artifact(...args) }
  addArtifact(...args: Parameters<FindingsRepository['addArtifact']>) { return this.findingsRepo.addArtifact(...args) }
  recordExchange(...args: Parameters<FindingsRepository['recordExchange']>) { return this.findingsRepo.recordExchange(...args) }
  getExchange(...args: Parameters<FindingsRepository['getExchange']>) { return this.findingsRepo.getExchange(...args) }
  searchExchanges(...args: Parameters<FindingsRepository['searchExchanges']>) { return this.findingsRepo.searchExchanges(...args) }
  pruneExchanges(...args: Parameters<FindingsRepository['pruneExchanges']>) { return this.findingsRepo.pruneExchanges(...args) }
  prune(...args: Parameters<FindingsRepository['prune']>) { return this.findingsRepo.prune(...args) }
  storeFootprint() { return this.findingsRepo.storeFootprint() }
  addFact(...args: Parameters<FindingsRepository['addFact']>) { return this.findingsRepo.addFact(...args) }
  listFacts(...args: Parameters<FindingsRepository['listFacts']>) { return this.findingsRepo.listFacts(...args) }
  addGraphEdge(...args: Parameters<FindingsRepository['addGraphEdge']>) { return this.findingsRepo.addGraphEdge(...args) }
  listGraphEdges(...args: Parameters<FindingsRepository['listGraphEdges']>) { return this.findingsRepo.listGraphEdges(...args) }
  createReplaySpec(...args: Parameters<FindingsRepository['createReplaySpec']>) { return this.findingsRepo.createReplaySpec(...args) }
  setReplaySpecProof(...args: Parameters<FindingsRepository['setReplaySpecProof']>) { return this.findingsRepo.setReplaySpecProof(...args) }
  replaySpecProof(...args: Parameters<FindingsRepository['replaySpecProof']>) { return this.findingsRepo.replaySpecProof(...args) }
  agentProofForFinding(...args: Parameters<FindingsRepository['agentProofForFinding']>) { return this.findingsRepo.agentProofForFinding(...args) }
  getReplaySpec(...args: Parameters<FindingsRepository['getReplaySpec']>) { return this.findingsRepo.getReplaySpec(...args) }
  listReplaySpecs(...args: Parameters<FindingsRepository['listReplaySpecs']>) { return this.findingsRepo.listReplaySpecs(...args) }
  listReplaySpecsForFinding(...args: Parameters<FindingsRepository['listReplaySpecsForFinding']>) { return this.findingsRepo.listReplaySpecsForFinding(...args) }
  queryFindings(...args: Parameters<FindingsRepository['queryFindings']>) { return this.findingsRepo.queryFindings(...args) }
  confirmedFindingCount(...args: Parameters<FindingsRepository['confirmedFindingCount']>) { return this.findingsRepo.confirmedFindingCount(...args) }
  confirmationConflictCount(...args: Parameters<FindingsRepository['confirmationConflictCount']>) { return this.findingsRepo.confirmationConflictCount(...args) }
  assertConfirmationEvidence(...args: Parameters<FindingsRepository['assertConfirmationEvidence']>) { return this.findingsRepo.assertConfirmationEvidence(...args) }
  enforceConfirmationEvidence(runId: string, findingId: string, cause: string): boolean {
    return this.findingsRepo.enforceConfirmationEvidence(runId, findingId, cause)
  }
  incrementReplaySpecAttempt(...args: Parameters<FindingsRepository['incrementReplaySpecAttempt']>) { return this.findingsRepo.incrementReplaySpecAttempt(...args) }
  recordReplaySpecVerification(...args: Parameters<FindingsRepository['recordReplaySpecVerification']>) { return this.findingsRepo.recordReplaySpecVerification(...args) }
  recordRetestRun(...args: Parameters<FindingsRepository['recordRetestRun']>) { return this.findingsRepo.recordRetestRun(...args) }
  recordSastRun(...args: Parameters<FindingsRepository['recordSastRun']>) { return this.findingsRepo.recordSastRun(...args) }
  listSastRuns(...args: Parameters<FindingsRepository['listSastRuns']>) { return this.findingsRepo.listSastRuns(...args) }
  recordSurfaceProbe(...args: Parameters<FindingsRepository['recordSurfaceProbe']>) { return this.findingsRepo.recordSurfaceProbe(...args) }
  listSurfaceProbes(...args: Parameters<FindingsRepository['listSurfaceProbes']>) { return this.findingsRepo.listSurfaceProbes(...args) }
  savePatchProposal(...args: Parameters<FindingsRepository['savePatchProposal']>) { return this.findingsRepo.savePatchProposal(...args) }
  listPatchProposals(...args: Parameters<FindingsRepository['listPatchProposals']>) { return this.findingsRepo.listPatchProposals(...args) }
  getPatchProposal(...args: Parameters<FindingsRepository['getPatchProposal']>) { return this.findingsRepo.getPatchProposal(...args) }
  listOpenProofGaps(...args: Parameters<FindingsRepository['listOpenProofGaps']>) { return this.findingsRepo.listOpenProofGaps(...args) }
  updateProposedFinding(...args: Parameters<FindingsRepository['updateProposedFinding']>) { return this.findingsRepo.updateProposedFinding(...args) }
  upsertCoverageEntry(...args: Parameters<FindingsRepository['upsertCoverageEntry']>) { return this.findingsRepo.upsertCoverageEntry(...args) }
  listCoverageEntries(...args: Parameters<FindingsRepository['listCoverageEntries']>) { return this.findingsRepo.listCoverageEntries(...args) }
  findDuplicateChainFinding(...args: Parameters<FindingsRepository['findDuplicateChainFinding']>) { return this.findingsRepo.findDuplicateChainFinding(...args) }
  upsertChainFinding(...args: Parameters<FindingsRepository['upsertChainFinding']>) { return this.findingsRepo.upsertChainFinding(...args) }
  upsertFindingRecord(...args: Parameters<FindingsRepository['upsertFindingRecord']>) { return this.findingsRepo.upsertFindingRecord(...args) }
  upsertEndpoint(...args: Parameters<FindingsRepository['upsertEndpoint']>) { return this.findingsRepo.upsertEndpoint(...args) }
  listEndpoints(...args: Parameters<FindingsRepository['listEndpoints']>) { return this.findingsRepo.listEndpoints(...args) }
  updateEndpointCoverage(...args: Parameters<FindingsRepository['updateEndpointCoverage']>) { return this.findingsRepo.updateEndpointCoverage(...args) }
  upsertEndpointParam(...args: Parameters<FindingsRepository['upsertEndpointParam']>) { return this.findingsRepo.upsertEndpointParam(...args) }
  listEndpointParams(...args: Parameters<FindingsRepository['listEndpointParams']>) { return this.findingsRepo.listEndpointParams(...args) }
  recordApiDependency(...args: Parameters<FindingsRepository['recordApiDependency']>) { return this.findingsRepo.recordApiDependency(...args) }
  listApiDependencies(...args: Parameters<FindingsRepository['listApiDependencies']>) { return this.findingsRepo.listApiDependencies(...args) }
  markApiDependencyTestedBola(...args: Parameters<FindingsRepository['markApiDependencyTestedBola']>) { return this.findingsRepo.markApiDependencyTestedBola(...args) }
  recordResourceSample(...args: Parameters<FindingsRepository['recordResourceSample']>) { return this.findingsRepo.recordResourceSample(...args) }
  listResourceSamples(...args: Parameters<FindingsRepository['listResourceSamples']>) { return this.findingsRepo.listResourceSamples(...args) }
  trackExchangeResources(...args: Parameters<FindingsRepository['trackExchangeResources']>) { return this.findingsRepo.trackExchangeResources(...args) }
  noteEndpointProbe(...args: Parameters<FindingsRepository['noteEndpointProbe']>) { return this.findingsRepo.noteEndpointProbe(...args) }
  insertSecondOrderCanary(...args: Parameters<FindingsRepository['insertSecondOrderCanary']>) { return this.findingsRepo.insertSecondOrderCanary(...args) }
  markSecondOrderCanarySurfaced(...args: Parameters<FindingsRepository['markSecondOrderCanarySurfaced']>) { return this.findingsRepo.markSecondOrderCanarySurfaced(...args) }
  listSecondOrderCanaries(...args: Parameters<FindingsRepository['listSecondOrderCanaries']>) { return this.findingsRepo.listSecondOrderCanaries(...args) }
  insertLabTelemetry(...args: Parameters<FindingsRepository['insertLabTelemetry']>) { return this.findingsRepo.insertLabTelemetry(...args) }
  listLabTelemetry(...args: Parameters<FindingsRepository['listLabTelemetry']>) { return this.findingsRepo.listLabTelemetry(...args) }
  insertBenchmarkRun(...args: Parameters<FindingsRepository['insertBenchmarkRun']>) { return this.findingsRepo.insertBenchmarkRun(...args) }
  listBenchmarkRuns(...args: Parameters<FindingsRepository['listBenchmarkRuns']>) { return this.findingsRepo.listBenchmarkRuns(...args) }
  getLatestBenchmarkRun(...args: Parameters<FindingsRepository['getLatestBenchmarkRun']>) { return this.findingsRepo.getLatestBenchmarkRun(...args) }

  /**
   * Return a tenant-scoped repository boundary enforcing strict tenant isolation on every
   * project, run, child-entity, and content-addressed blob read/write. Single-tenant CLI/desktop
   * callers can continue using `Store` directly (defaulting to `'default'`) or call
   * `store.forTenant('default')`.
   */
  forTenant(tenantId: string) {
    const scopedSession = new TenantScopedSession(this.session, tenantId)
    const projectsRepo = new ProjectsRepository(scopedSession)
    const findingsRepo = new FindingsRepository(scopedSession)
    const runsRepo = new RunsRepository(scopedSession, projectsRepo, findingsRepo)
    return {
      tenantId: scopedSession.tenantId,
      workspace: scopedSession.workspace,
      directory: scopedSession.directory,
      session: scopedSession as DbSession,
      projectsRepo,
      findingsRepo,
      runsRepo,
      flushNow: () => scopedSession.flushNow(),
      transaction: <T>(fn: () => T, options?: { behavior?: 'deferred' | 'immediate' | 'exclusive' }) =>
        scopedSession.transaction(fn, options),
      afterCommit: (fn: () => void) => scopedSession.afterCommit(fn),
      writeBlob: (content: string, secrets?: Parameters<DbSession['writeBlob']>[1], runId?: string, durable?: boolean) =>
        scopedSession.writeBlob(content, secrets, runId, durable, scopedSession.tenantId),
      readBlob: (blobId: string, runId?: string) =>
        scopedSession.readBlob(blobId, runId, scopedSession.tenantId),
      // Projects
      project: (...args: Parameters<ProjectsRepository['project']>) => projectsRepo.project(...args),
      listWorkspace: () => projectsRepo.listWorkspace(),
      workspaceSummary: (...args: Parameters<ProjectsRepository['workspaceSummary']>) => {
        const summary = projectsRepo.workspaceSummary(...args)
        const runIds = [
          ...summary.projects.map(p => p.latestRun?.id).filter((id): id is string => Boolean(id)),
          ...summary.recentRuns.map(r => r.id),
        ]
        if (!runIds.length) return summary
        const rollups = findingsRepo.rollupFindingCountsByRunIds(runIds)
        return {
          ...summary,
          projects: summary.projects.map(project => {
            if (!project.latestRun) return project
            const rollup = rollups.get(project.latestRun.id)
            if (!rollup) return project
            return {
              ...project,
              latestRun: {
                ...project.latestRun,
                confirmedCount: rollup.confirmedCount,
                findingCount: rollup.findingCount,
              },
            }
          }),
          recentRuns: summary.recentRuns.map(run => {
            const rollup = rollups.get(run.id)
            if (!rollup) return run
            return {
              ...run,
              confirmedCount: rollup.confirmedCount,
              findings: rollup.findingCount,
            }
          }),
        }
      },
      projectDetail: (...args: Parameters<ProjectsRepository['projectDetail']>) => {
        const detail = projectsRepo.projectDetail(...args)
        if (!detail.runs.length) return detail
        const rollups = findingsRepo.rollupFindingCountsByRunIds(detail.runs.map(r => r.id))
        return {
          ...detail,
          runs: detail.runs.map(run => {
            const rollup = rollups.get(run.id)
            if (!rollup) return run
            return {
              ...run,
              confirmedCount: rollup.confirmedCount,
              findingCount: rollup.findingCount,
            }
          }),
        }
      },
      createProject: (...args: Parameters<ProjectsRepository['createProject']>) => projectsRepo.createProject(...args),
      updateProject: (...args: Parameters<ProjectsRepository['updateProject']>) => projectsRepo.updateProject(...args),
      deleteProject: (...args: Parameters<ProjectsRepository['deleteProject']>) => projectsRepo.deleteProject(...args),
      listProjectSpecs: (...args: Parameters<ProjectsRepository['listProjectSpecs']>) => projectsRepo.listProjectSpecs(...args),
      listProjectSpecsFull: (...args: Parameters<ProjectsRepository['listProjectSpecsFull']>) => projectsRepo.listProjectSpecsFull(...args),
      getProjectSpec: (...args: Parameters<ProjectsRepository['getProjectSpec']>) => projectsRepo.getProjectSpec(...args),
      importProjectSpec: (...args: Parameters<ProjectsRepository['importProjectSpec']>) => projectsRepo.importProjectSpec(...args),
      upsertProjectSpecRaw: (...args: Parameters<ProjectsRepository['upsertProjectSpecRaw']>) => projectsRepo.upsertProjectSpecRaw(...args),
      deleteProjectSpec: (...args: Parameters<ProjectsRepository['deleteProjectSpec']>) => projectsRepo.deleteProjectSpec(...args),
      addProjectAsset: (...args: Parameters<ProjectsRepository['addProjectAsset']>) => projectsRepo.addProjectAsset(...args),
      updateProjectAsset: (...args: Parameters<ProjectsRepository['updateProjectAsset']>) => projectsRepo.updateProjectAsset(...args),
      updateProjectAssetScope: (...args: Parameters<ProjectsRepository['updateProjectAssetScope']>) => projectsRepo.updateProjectAssetScope(...args),
      deleteProjectAsset: (...args: Parameters<ProjectsRepository['deleteProjectAsset']>) => projectsRepo.deleteProjectAsset(...args),
      getProjectTenant: (...args: Parameters<ProjectsRepository['getProjectTenant']>) => projectsRepo.getProjectTenant(...args),
      listProjectsForTenant: () => projectsRepo.listProjectsForTenant(scopedSession.tenantId),
      // Runs
      run: (...args: Parameters<RunsRepository['run']>) => runsRepo.run(...args),
      runDetail: (...args: Parameters<RunsRepository['runDetail']>) => runsRepo.runDetail(...args),
      runShellSummary: (...args: Parameters<RunsRepository['runShellSummary']>) => runsRepo.runShellSummary(...args),
      createRun: (...args: Parameters<RunsRepository['createRun']>) => runsRepo.createRun(...args),
      updateRun: (...args: Parameters<RunsRepository['updateRun']>) => runsRepo.updateRun(...args),
      deleteRun: (...args: Parameters<RunsRepository['deleteRun']>) => {
        cancelOobDrainForRun(args[0])
        return runsRepo.deleteRun(...args)
      },
      command: (...args: Parameters<RunsRepository['command']>) => runsRepo.command(...args),
      listRunsForTenant: () => runsRepo.listRunsForTenant(scopedSession.tenantId),
      getRunTenant: (...args: Parameters<RunsRepository['getRunTenant']>) => runsRepo.getRunTenant(...args),
      assertRunTenantAccess: (runId: string, actor?: string) => runsRepo.assertRunTenantAccess(runId, scopedSession.tenantId, actor),
      appendTenantAuditLog: (input: Omit<Parameters<RunsRepository['appendTenantAuditLog']>[0], 'tenantId'> & { tenantId?: string }) =>
        runsRepo.appendTenantAuditLog({ ...input, tenantId: input.tenantId ?? scopedSession.tenantId }),
      listTenantAuditLog: (options?: Parameters<RunsRepository['listTenantAuditLog']>[1]) =>
        runsRepo.listTenantAuditLog(scopedSession.tenantId, options),
      verifyTenantAuditLogChain: () => runsRepo.verifyTenantAuditLogChain(scopedSession.tenantId),
      workerList: (...args: Parameters<RunsRepository['workerList']>) => runsRepo.workerList(...args),
      worker: (...args: Parameters<RunsRepository['worker']>) => runsRepo.worker(...args),
      makeWorker: (...args: Parameters<RunsRepository['makeWorker']>) => runsRepo.makeWorker(...args),
      updateWorker: (...args: Parameters<RunsRepository['updateWorker']>) => runsRepo.updateWorker(...args),
      listChainSteps: (...args: Parameters<RunsRepository['listChainSteps']>) => runsRepo.listChainSteps(...args),
      addChainStep: (...args: Parameters<RunsRepository['addChainStep']>) => runsRepo.addChainStep(...args),
      updateChainStep: (...args: Parameters<RunsRepository['updateChainStep']>) => runsRepo.updateChainStep(...args),
      suggestCandidateHost: (...args: Parameters<RunsRepository['suggestCandidateHost']>) => runsRepo.suggestCandidateHost(...args),
      admitDynamicOrigin: (...args: Parameters<RunsRepository['admitDynamicOrigin']>) => runsRepo.admitDynamicOrigin(...args),
      boardMember: (...args: Parameters<RunsRepository['boardMember']>) => runsRepo.boardMember(...args),
      listBoardMembers: (...args: Parameters<RunsRepository['listBoardMembers']>) => runsRepo.listBoardMembers(...args),
      upsertBoardMember: (...args: Parameters<RunsRepository['upsertBoardMember']>) => runsRepo.upsertBoardMember(...args),
      postBoardMessage: (...args: Parameters<RunsRepository['postBoardMessage']>) => runsRepo.postBoardMessage(...args),
      listBoardMessages: (...args: Parameters<RunsRepository['listBoardMessages']>) => runsRepo.listBoardMessages(...args),
      getApprovalRequest: (...args: Parameters<RunsRepository['getApprovalRequest']>) => runsRepo.getApprovalRequest(...args),
      listApprovalRequests: (...args: Parameters<RunsRepository['listApprovalRequests']>) => runsRepo.listApprovalRequests(...args),
      createApprovalRequest: (...args: Parameters<RunsRepository['createApprovalRequest']>) => runsRepo.createApprovalRequest(...args),
      decideApproval: (...args: Parameters<RunsRepository['decideApproval']>) => runsRepo.decideApproval(...args),
      grantApprovalLease: (...args: Parameters<RunsRepository['grantApprovalLease']>) => runsRepo.grantApprovalLease(...args),
      listApprovalLeases: (...args: Parameters<RunsRepository['listApprovalLeases']>) => runsRepo.listApprovalLeases(...args),
      leaseAuthorizes: (...args: Parameters<RunsRepository['leaseAuthorizes']>) => runsRepo.leaseAuthorizes(...args),
      writeReport: (...args: Parameters<RunsRepository['writeReport']>) => runsRepo.writeReport(...args),
      eventsAfter: (...args: Parameters<RunsRepository['eventsAfter']>) => runsRepo.eventsAfter(...args),
      isRunActive: (...args: Parameters<RunsRepository['isRunActive']>) => runsRepo.isRunActive(...args),
      hasExplicitEnvironmentMode: (...args: Parameters<RunsRepository['hasExplicitEnvironmentMode']>) => runsRepo.hasExplicitEnvironmentMode(...args),
      // Findings & Exchanges
      artifact: (...args: Parameters<FindingsRepository['artifact']>) => findingsRepo.artifact(...args),
      addArtifact: (...args: Parameters<FindingsRepository['addArtifact']>) => findingsRepo.addArtifact(...args),
      recordExchange: (...args: Parameters<FindingsRepository['recordExchange']>) => findingsRepo.recordExchange(...args),
      getExchange: (...args: Parameters<FindingsRepository['getExchange']>) => findingsRepo.getExchange(...args),
      searchExchanges: (...args: Parameters<FindingsRepository['searchExchanges']>) => findingsRepo.searchExchanges(...args),
      pruneExchanges: (...args: Parameters<FindingsRepository['pruneExchanges']>) => findingsRepo.pruneExchanges(...args),
      prune: (...args: Parameters<FindingsRepository['prune']>) => findingsRepo.prune(...args),
      addFact: (...args: Parameters<FindingsRepository['addFact']>) => findingsRepo.addFact(...args),
      listFacts: (...args: Parameters<FindingsRepository['listFacts']>) => findingsRepo.listFacts(...args),
      createReplaySpec: (...args: Parameters<FindingsRepository['createReplaySpec']>) => findingsRepo.createReplaySpec(...args),
      getReplaySpec: (...args: Parameters<FindingsRepository['getReplaySpec']>) => findingsRepo.getReplaySpec(...args),
      listReplaySpecs: (...args: Parameters<FindingsRepository['listReplaySpecs']>) => findingsRepo.listReplaySpecs(...args),
      upsertChainFinding: (...args: Parameters<FindingsRepository['upsertChainFinding']>) => findingsRepo.upsertChainFinding(...args),
      upsertFindingRecord: (...args: Parameters<FindingsRepository['upsertFindingRecord']>) => findingsRepo.upsertFindingRecord(...args),
      updateProposedFinding: (...args: Parameters<FindingsRepository['updateProposedFinding']>) => findingsRepo.updateProposedFinding(...args),
      triageFinding: (...args: Parameters<FindingsRepository['triageFinding']>) => findingsRepo.triageFinding(...args),
      queryFindings: (...args: Parameters<FindingsRepository['queryFindings']>) => findingsRepo.queryFindings(...args),
      confirmedFindingCount: (...args: Parameters<FindingsRepository['confirmedFindingCount']>) => findingsRepo.confirmedFindingCount(...args),
      enforceConfirmationEvidence: (...args: Parameters<FindingsRepository['enforceConfirmationEvidence']>) => findingsRepo.enforceConfirmationEvidence(...args),
      upsertCoverageEntry: (...args: Parameters<FindingsRepository['upsertCoverageEntry']>) => findingsRepo.upsertCoverageEntry(...args),
      listCoverageEntries: (...args: Parameters<FindingsRepository['listCoverageEntries']>) => findingsRepo.listCoverageEntries(...args),
      upsertEndpoint: (...args: Parameters<FindingsRepository['upsertEndpoint']>) => findingsRepo.upsertEndpoint(...args),
      listEndpoints: (...args: Parameters<FindingsRepository['listEndpoints']>) => findingsRepo.listEndpoints(...args),
      updateEndpointCoverage: (...args: Parameters<FindingsRepository['updateEndpointCoverage']>) => findingsRepo.updateEndpointCoverage(...args),
      listPatchProposals: (...args: Parameters<FindingsRepository['listPatchProposals']>) => findingsRepo.listPatchProposals(...args),
      getPatchProposal: (...args: Parameters<FindingsRepository['getPatchProposal']>) => findingsRepo.getPatchProposal(...args),
      updatePatchProposalReview: (...args: Parameters<FindingsRepository['updatePatchProposalReview']>) => findingsRepo.updatePatchProposalReview(...args),
    }
  }

  /** Deterministically purge expired exchanges, artifacts, and temp files according to `policy`. */
  purgeArtifactsByTtl(policy: ArtifactTtlPolicy): ArtifactTtlPurgeResult {
    return purgeExpiredArtifacts(this, policy)
  }
}

export type TenantScopedStore = ReturnType<Store['forTenant']>
export type StoreRunDetail = ReturnType<Store['runDetail']>

export class RunDeleteBusyError extends Error {
  readonly code = 'RUN_DELETE_BUSY'
  readonly status = 409
  readonly activeRunIds: string[]

  constructor(activeRunIds: readonly string[], message?: string) {
    super(
      message
      ?? `Cannot delete while in-flight tasks are still draining for run(s): ${activeRunIds.join(', ')}. Retry after active work settles.`,
    )
    this.name = 'RunDeleteBusyError'
    this.activeRunIds = [...activeRunIds]
  }
}

export interface DeleteExecutionControl {
  wake: () => void
  getLabTargetHandle: (runId: string) => unknown
  disposeRun?: (
    runId: string,
    options?: { terminalState?: 'completed' | 'failed' | 'canceled'; reason?: string; timeoutMs?: number },
  ) => Promise<{ tasksTimedOut?: number } | null>
  isRunTrackedActive?: (runId: string) => boolean
}

export interface DeleteLabControl {
  getTarget: (runId: string) => unknown
  stopLabTarget: (runId: string) => Promise<unknown>
}

function isRunActiveForDelete(
  db: Store,
  exec: DeleteExecutionControl,
  labRunner: DeleteLabControl,
  runId: string,
): boolean {
  return db.isRunActive(runId)
    || isOobDrainActive(runId)
    || Boolean(exec.isRunTrackedActive?.(runId))
    || Boolean(exec.getLabTargetHandle(runId))
    || Boolean(labRunner.getTarget(runId))
}

async function stopRunsBeforeDelete(
  db: Store,
  exec: DeleteExecutionControl,
  labRunner: DeleteLabControl,
  runIds: readonly string[],
  waitTimeoutMs = 2_500,
): Promise<void> {
  const timedOutRuns = new Set<string>()
  for (const runId of runIds) {
    cancelOobDrainForRun(runId)
    try {
      const current = db.run(runId)
      if (!['complete', 'stopped'].includes(current.status)) {
        db.command({ requestId: randomUUID(), runId, action: 'stop' })
      }
    } catch (error) {
      // Run may already be stopped, ended, or concurrently deleted; never swallow unexpected storage bugs.
      const msg = error instanceof Error ? error.message : ''
      if (!isDeletedRunRaceError(error) && !/already ended/i.test(msg)) throw error
    }
    if (exec.disposeRun) {
      const report = await exec.disposeRun(runId, {
        terminalState: 'canceled',
        reason: 'run deleted',
        timeoutMs: waitTimeoutMs,
      })
      if (report && (report.tasksTimedOut ?? 0) > 0) {
        timedOutRuns.add(runId)
      }
    }
    await labRunner.stopLabTarget(runId).catch(() => undefined)
  }
  exec.wake()

  const deadline = Date.now() + Math.max(0, waitTimeoutMs)
  while (Date.now() < deadline) {
    const stillActive = runIds.some(runId => isRunActiveForDelete(db, exec, labRunner, runId))
    if (!stillActive) break
    await new Promise(resolve => setTimeout(resolve, 100))
    exec.wake()
  }

  for (const runId of runIds) {
    if (isRunActiveForDelete(db, exec, labRunner, runId)) {
      timedOutRuns.add(runId)
    }
  }
  if (timedOutRuns.size > 0) {
    throw new RunDeleteBusyError([...timedOutRuns])
  }
}

export async function deleteRunWithActiveGuard(
  db: Store,
  exec: DeleteExecutionControl,
  labRunner: DeleteLabControl,
  input: { runId: string; stopActive?: boolean; waitTimeoutMs?: number },
): Promise<{ deleted: boolean; projectId: string; runId: string }> {
  const isActive = isRunActiveForDelete(db, exec, labRunner, input.runId)
  if (isActive && !input.stopActive) {
    throw new Error('This run is currently active. Stop the run first (or choose Stop & Delete) before deleting it.')
  }
  if (isActive && input.stopActive) {
    await stopRunsBeforeDelete(db, exec, labRunner, [input.runId], input.waitTimeoutMs)
  } else {
    cancelOobDrainForRun(input.runId)
    if (exec.disposeRun) {
      const report = await exec.disposeRun(input.runId, {
        terminalState: 'canceled',
        reason: 'run deleted',
        timeoutMs: input.waitTimeoutMs ?? 2_500,
      })
      if (report && (report.tasksTimedOut ?? 0) > 0) {
        throw new RunDeleteBusyError([input.runId])
      }
    }
    await labRunner.stopLabTarget(input.runId).catch(() => undefined)
  }
  const result = db.deleteRun(input.runId)
  if (result.deleted) exec.wake()
  return result
}

export async function deleteProjectWithActiveGuard(
  db: Store,
  exec: DeleteExecutionControl,
  labRunner: DeleteLabControl,
  input: { projectId: string; stopActive?: boolean; waitTimeoutMs?: number },
): Promise<{ deleted: boolean; projectId: string; deletedRuns: number }> {
  let detail: ReturnType<Store['projectDetail']> | null = null
  try {
    detail = db.projectDetail(input.projectId)
  } catch {
    return { deleted: false, projectId: input.projectId, deletedRuns: 0 }
  }
  const allRunIds = detail.runs.map(r => r.id)
  const activeRunIds = allRunIds.filter(runId => isRunActiveForDelete(db, exec, labRunner, runId))
  if (activeRunIds.length > 0 && !input.stopActive) {
    throw new Error(
      `This project has ${activeRunIds.length} active ${activeRunIds.length === 1 ? 'run' : 'runs'}. Stop active runs first (or choose Stop & Delete) before deleting the project.`,
    )
  }
  if (activeRunIds.length > 0 && input.stopActive) {
    await stopRunsBeforeDelete(db, exec, labRunner, activeRunIds, input.waitTimeoutMs)
  }
  const remainingRunIds = activeRunIds.length > 0 && input.stopActive
    ? allRunIds.filter(runId => !activeRunIds.includes(runId))
    : allRunIds
  for (const runId of remainingRunIds) {
    cancelOobDrainForRun(runId)
    if (exec.disposeRun) {
      const report = await exec.disposeRun(runId, {
        terminalState: 'canceled',
        reason: 'project deleted',
        timeoutMs: input.waitTimeoutMs ?? 2_500,
      })
      if (report && (report.tasksTimedOut ?? 0) > 0) {
        throw new RunDeleteBusyError([runId])
      }
    }
    await labRunner.stopLabTarget(runId).catch(() => undefined)
  }
  const result = db.deleteProject(input.projectId)
  if (result.deleted) exec.wake()
  return result
}

const STORE_SINGLETON_SYMBOL = Symbol.for('kovo.storeSingleton')

function getStoreRegistry(): Map<string, Store> {
  const g = globalThis as Record<symbol, Map<string, Store> | undefined>
  let registry = g[STORE_SINGLETON_SYMBOL]
  if (!registry) {
    registry = new Map<string, Store>()
    g[STORE_SINGLETON_SYMBOL] = registry
  }
  return registry
}

export function store() {
  const dir = resolve(dataDirectory())
  const registry = getStoreRegistry()
  let existing = registry.get(dir)
  if (!existing) {
    existing = new Store(dir)
    registry.set(dir, existing)
  }
  return existing
}
