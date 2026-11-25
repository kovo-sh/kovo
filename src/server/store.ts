import { randomUUID } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { drizzle } from 'drizzle-orm/node-sqlite'
import { purgeExpiredArtifacts } from './artifact-ttl.ts'
import type { ArtifactTtlPolicy, ArtifactTtlPurgeResult } from './artifact-ttl.ts'
import {
  CapabilityLedger,
  initCapabilityLedgerSchema,
  type CapabilityLedgerOptions,
} from './capability-ledger.ts'
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
  STORE_SCHEMA_VERSION,
  StoreSession,
  TenantIsolationError,
  assertConfirmedVerificationClass,
  assessmentAssignments,
  dataDirectory,
  ftsModes,
  replayVerdictConfirmsRuntime,
  resolvePageLimit,
  resolvePageOffset,
  safeFileSize,
  verificationClassForFinding,
  type DbSession,
  type FtsMode,
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

export class Store {
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
    const path = join(directory, 'kovo.sqlite')
    if (!existsSync(path)) {
      try {
        writeFileSync(path, '', { flag: 'wx', mode: 0o600 })
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
      }
    }
    const rawClient = new DatabaseSync(path, { timeout: 5000 })
    // v6 scale pragmas: WAL keeps readers non-blocking under the batched writer; NORMAL skips the
    // per-commit fsync (WAL still guarantees a consistent DB across process crashes), and the
    // busy timeout lets concurrent readers/snapshot copies wait instead of failing fast.
    rawClient.exec(
      'PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;',
    )
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
    this.initCoreSchema()
    this.initV3Schema()
    this.initV4Schema()
    this.initV5Schema()
    this.initV6Schema()
    this.initV7Schema()
    this.initV8Schema()
    // v6.2 full-body FTS size guard: refuse to switch on an expensive index over a database that is
    // already large unless the operator explicitly forced it. Release the process lock so a
    // subsequent correctly-configured reopen can proceed.
    if (this.ftsMode === 'full' && !options.forceFullFts) {
      const dbBytes = safeFileSize(path)
      if (dbBytes > this.maxFullFtsDbBytes) {
        try { rawClient.close() } catch { /* teardown is best-effort */ }
        try { this.processLock.exec('ROLLBACK') } catch { /* ignore */ }
        try { this.processLock.close() } catch { /* ignore */ }
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
  }

  private existingColumns(table: string): Set<string> {
    const rows = this.client.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>
    return new Set(rows.map(r => r.name))
  }

  private ensureColumn(table: string, column: string, definition: string): boolean {
    if (!this.existingColumns(table).has(column)) {
      this.client.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition};`)
      return true
    }
    return false
  }

  /**
   * Canonical SQLite DDL for all 25 core tables, matching `src/server/schema.ts` 1:1 with
   * `ON DELETE CASCADE` on every child foreign key referencing `projects(id)`, `runs(id)`,
   * `assignments(id)`, and `replay_specs(id)`. Uses `CREATE TABLE IF NOT EXISTS` so existing
   * pre-cascade databases open losslessly and are upgraded additively by `initV3..V8Schema`.
   */
  private initCoreSchema() {
    this.client.exec(`
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
        result TEXT NOT NULL
      );
    `)
  }

  private initV3Schema() {
    // model_profiles v3 columns
    this.ensureColumn('model_profiles', 'cached_input_cost_per_mtok', 'REAL NOT NULL DEFAULT 0.003')

    // projects v3 columns
    this.ensureColumn('projects', 'lab_config', 'TEXT')

    // personas v3 columns
    this.ensureColumn('personas', 'login_config', 'TEXT')

    // runs v3 Tier 3 approval policy columns
    this.ensureColumn('runs', 'approval_policy', "TEXT NOT NULL DEFAULT 'auto_review'")
    this.ensureColumn('runs', 'approved_endpoint_patterns', "TEXT NOT NULL DEFAULT '[]'")

    // approval_requests v3 audit trail columns
    this.ensureColumn('approval_requests', 'policy_note', 'TEXT')
    this.ensureColumn('approval_requests', 'risk_level', 'TEXT')

    // findings v3 columns
    this.ensureColumn('findings', 'verification_tier', 'TEXT')
    this.ensureColumn('findings', 'fingerprint_hash', 'TEXT')
    this.ensureColumn('findings', 'superseded_by_finding_id', 'TEXT')
    this.ensureColumn('findings', 'counterevidence', 'TEXT')
    this.ensureColumn('findings', 'confidence_rationale', 'TEXT')
    this.ensureColumn('findings', 'severity_change_conditions', 'TEXT')
    this.ensureColumn('findings', 'code_locations', 'TEXT')

    // coverage_entries v3 columns
    this.ensureColumn('coverage_entries', 'enforcing_control', 'TEXT')
    this.ensureColumn('coverage_entries', 'proof_gap_reason', 'TEXT')
    this.ensureColumn('coverage_entries', 'linked_finding_id', 'TEXT')

    // canaries v3 columns
    this.ensureColumn('canaries', 'protocol', `TEXT NOT NULL DEFAULT 'http'`)
    this.ensureColumn('canaries', 'dns_host', 'TEXT')
    this.ensureColumn('canaries', 'hit_count', 'INTEGER NOT NULL DEFAULT 0')

    // broker_exchanges v5 secret-disclosure metadata (redacted fingerprints; no raw values)
    this.ensureColumn('broker_exchanges', 'secret_matches', `TEXT NOT NULL DEFAULT '[]'`)

    // v3 tables & indexes
    this.client.exec(`
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
  }

  private initV4Schema() {
    // model_profiles v4 columns
    this.ensureColumn('model_profiles', 'role_affinity', "TEXT NOT NULL DEFAULT 'any'")

    // projects v4 columns
    this.ensureColumn('projects', 'sandbox_write_allowlist', "TEXT NOT NULL DEFAULT '[]'")

    // runs v4 columns
    this.ensureColumn('runs', 'dynamic_step_budget', 'INTEGER')
    this.ensureColumn('runs', 'multi_trial_enabled', 'INTEGER NOT NULL DEFAULT 1')
    this.ensureColumn('runs', 'phase0_completed_at', 'INTEGER')

    // chain_steps v4 columns
    this.ensureColumn('chain_steps', 'specialist_profile', 'TEXT')
    this.ensureColumn('chain_steps', 'trial_group_id', 'TEXT')
    this.ensureColumn('chain_steps', 'trial_index', 'INTEGER NOT NULL DEFAULT 0')

    // replay_specs v4 columns
    this.ensureColumn('replay_specs', 'attempt_count', 'INTEGER NOT NULL DEFAULT 1')
    this.ensureColumn('replay_specs', 'verified_inline', 'INTEGER NOT NULL DEFAULT 0')
    this.ensureColumn('replay_specs', 'last_verification_diff', 'TEXT')

    // v4 tables & indexes
    this.client.exec(`
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
  }

  /**
   * v5 Swarm Message Board tables. `CREATE TABLE IF NOT EXISTS` + defensive column backfill keeps
   * every v2–v4 SQLite database losslessly upgradable in place (no destructive rebuilds).
   */
  private initV5Schema() {
    this.client.exec(`
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

      -- v5 M2.1: redacted non-secret sample identifiers harvested per (run, owner persona, collection, resource key).
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
      this.ensureColumn('board_members', column, definition)
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
      this.ensureColumn('board_messages', column, definition)
    }

    // Backfill the deterministic system roster for runs created before v5 so an upgraded
    // database renders a complete Board tab without mutating any existing evidence rows.
    this.client.exec(`
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
  }

  /**
   * v6 scale/data-integrity migration. Additive only:
   * - `resource_samples.collection_path` + a wider unique key (backfilled with `''`).
   * - `lab_containers` registry for crash recovery.
   * - pagination indexes so `runDetail`/`listEndpoints`/`listFacts` do not scan whole tables.
   * `PRAGMA user_version = STORE_SCHEMA_VERSION` stamps the upgrade.
   */
  private initV6Schema() {
    this.ensureColumn('resource_samples', 'collection_path', "TEXT NOT NULL DEFAULT ''")
    this.client.exec("UPDATE resource_samples SET collection_path = '' WHERE collection_path IS NULL")

    // v6 Phase 2 Layer-1 scope + environment contract (additive).
    // The legacy approved-candidate allowlist stays the target tier; auth/asset tiers are additive.
    const hadEnvironmentMode = this.existingColumns('runs').has('environment_mode')
    this.ensureColumn('runs', 'auth_origins', "TEXT NOT NULL DEFAULT '[]'")
    this.ensureColumn('runs', 'asset_origins', "TEXT NOT NULL DEFAULT '[]'")
    this.ensureColumn('runs', 'environment_mode', "TEXT NOT NULL DEFAULT 'prod_readonly'")
    this.ensureColumn('runs', 'route_denylist', "TEXT NOT NULL DEFAULT '[]'")
    this.ensureColumn('assignments', 'approval_parked_at', 'INTEGER')

    // v6 provenance / advisory contract (additive; safe on legacy databases).
    const previousVersion = Number(
      (this.client.prepare('PRAGMA user_version').get() as { user_version?: number } | undefined)?.user_version ?? 0,
    )
    const addedProvenance = this.ensureColumn(
      'findings', 'provenance',
      "TEXT NOT NULL DEFAULT 'agent_only' CHECK (provenance IN ('floor', 'agent_only', 'chain_from_floor'))",
    )
    const addedParents = this.ensureColumn('findings', 'parent_finding_ids', 'TEXT')
    const addedVerificationClass = this.ensureColumn(
      'findings', 'verification_class',
      "TEXT NOT NULL DEFAULT 'runtime_confirmed' CHECK (verification_class IN ('runtime_confirmed', 'pending_oob', 'static_advisory', 'open_proof_gap', 'dismissed')) "
      + "CHECK (json_extract(finding, '$.status') <> 'confirmed' OR verification_class = 'runtime_confirmed') "
      + "CHECK (json_extract(finding, '$.status') <> 'confirmed' OR verification_tier IS NULL OR verification_tier <> 'static_verified')",
    )
    if (addedProvenance || addedParents || addedVerificationClass || previousVersion < STORE_SCHEMA_VERSION) {
      this.backfillFindingsProvenance()
    }
    this.client.exec(`
      CREATE INDEX IF NOT EXISTS findings_provenance ON findings (run_id, provenance);
    `)

    if (!hadEnvironmentMode) {
      // Existing local-lab runs keep autonomous testing; every other existing run starts read-only.
      this.client.exec(`
        UPDATE runs SET environment_mode = 'ephemeral_lab'
        WHERE project_id IN (SELECT id FROM projects WHERE environment = 'local-lab')
      `)
    }

    const desiredColumns = ['run_id', 'owner_persona', 'origin', 'collection_path', 'resource_key']
    const currentColumns = (this.client.prepare('PRAGMA index_info(resource_samples_key)').all() as Array<{ name: string }>)
      .map(row => row.name)
    if (currentColumns.join(',') !== desiredColumns.join(',')) {
      this.client.exec(`
        DROP INDEX IF EXISTS resource_samples_key;
        CREATE UNIQUE INDEX resource_samples_key ON resource_samples (run_id, owner_persona, origin, collection_path, resource_key);
      `)
    }

    this.client.exec(`
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
        persona_handle TEXT,
        status TEXT NOT NULL,
        source_approval_id TEXT,
        created_by TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        expires_at INTEGER,
        uses INTEGER NOT NULL DEFAULT 0,
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
    this.initConfirmationGuards()
  }

  /**
   * v7 M5 agent-script proof storage (additive, safe on legacy databases).
   *
   * A Layer-3 `kovo_verify` proof persists its oracle verdict, the receipt it was re-checked
   * with and the owner-only artifact holding script source + receipt. Declarative columns stay for
   * attribution; confirmation/retest are receipt-first. No backfill is needed: pre-migration rows
   * are simply not script proofs.
   */
  private initV7Schema() {
    this.ensureColumn('replay_specs', 'proof_kind', 'TEXT')
    this.ensureColumn('replay_specs', 'proof_verdict', 'TEXT')
    this.ensureColumn('replay_specs', 'proof_runtime', 'TEXT')
    this.ensureColumn('replay_specs', 'proof_script_sha256', 'TEXT')
    this.ensureColumn('replay_specs', 'proof_artifact_id', 'TEXT')
    this.ensureColumn('replay_specs', 'proof_receipt', 'TEXT')
    this.ensureColumn('project_assets', 'include_subdomains', 'INTEGER NOT NULL DEFAULT 0')
    // v7 M4: per-tenant isolation & append-only tenant audit log (additive, safe on legacy DBs).
    this.ensureColumn('projects', 'tenant_id', "TEXT NOT NULL DEFAULT 'default'")
    this.ensureColumn('runs', 'tenant_id', "TEXT NOT NULL DEFAULT 'default'")
    this.client.exec(`
      CREATE INDEX IF NOT EXISTS replay_specs_proof ON replay_specs (run_id, proof_kind);
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
    this.client.exec(`PRAGMA user_version = ${STORE_SCHEMA_VERSION}`)
  }

  /** v8 M0: idempotent CapabilityLedger tables, indexes, and run-delete cascade trigger. */
  private initV8Schema() {
    initCapabilityLedgerSchema(this.client)
    // CapabilityLedger can also be opened standalone without a `runs` table, so its tables do not
    // declare a FK to `runs(id)`. On a Store DB, keep them in sync on raw `DELETE FROM runs` /
    // cascaded `DELETE FROM projects` in child-before-parent order for the composite FK.
    this.client.exec(`
      CREATE TRIGGER IF NOT EXISTS runs_after_delete_capability_ledger
        AFTER DELETE ON runs
        BEGIN
          DELETE FROM capability_causal_edges WHERE run_id = OLD.id;
          DELETE FROM capability_negative_edges WHERE run_id = OLD.id;
          DELETE FROM capability_nodes WHERE run_id = OLD.id;
        END;
    `)
  }

  /**
   * Return a run-scoped v8 `CapabilityLedger` bound directly to this Store's shared WAL
   * `DatabaseSync` handle (zero extra SQLite connections; closing the returned view is a no-op).
   */
  capabilityLedger(runId: string, options: Omit<CapabilityLedgerOptions, 'runId'> = {}): CapabilityLedger {
    return new CapabilityLedger(this.client, { ...options, runId })
  }

  /**
   * Database-level confirmation guard (defence in depth for the store invariant).
   *
   * A row may only be `verification_class = 'runtime_confirmed'` + `status = 'confirmed'` while the
   * same database holds confirming evidence: the linked replay spec's persisted diff verdict is
   * `confirmed`, a verified OOB ProofReceipt, or a baseline review. Direct SQL writers (migrations,
   * ad-hoc scripts, future call sites) are aborted with `invariant.confirmation_evidence` instead of
   * persisting a confirmed claim contradicted by its own evidence.
   */
  private initConfirmationGuards() {
    if (!this.tableExists('findings') || !this.tableExists('replay_specs')) return
    const guard = (name: string, event: 'INSERT' | 'UPDATE OF verification_class, replay_spec_id, finding, verification_tier') => `
      CREATE TRIGGER IF NOT EXISTS ${name}
      BEFORE ${event} ON findings
      WHEN NEW.verification_class = 'runtime_confirmed'
        AND json_extract(NEW.finding, '$.status') = 'confirmed'
        AND coalesce(NEW.finding_kind, '') <> 'baseline_check'
        AND coalesce(NEW.verification_tier, json_extract(NEW.finding, '$.verificationTier'), '') <> 'baseline_confirmed'
        AND coalesce(json_extract(NEW.finding, '$.verification'), '') NOT LIKE 'ProofReceipt%'
        AND NOT EXISTS (
          SELECT 1 FROM replay_specs s
          WHERE s.id = NEW.replay_spec_id
            AND json_extract(s.last_verification_diff, '$.verdict') = 'confirmed'
        )
        ${this.tableExists('events') ? `AND NOT EXISTS (
          SELECT 1 FROM events e
          WHERE e.run_id = NEW.run_id
            AND e.kind = 'oob.receipt_confirmed'
            AND json_extract(e.detail, '$.findingId') = NEW.id
        )` : ''}
      BEGIN
        SELECT RAISE(ABORT, 'invariant.confirmation_evidence');
      END;
    `
    try {
      this.client.exec(guard('findings_confirmation_evidence_insert', 'INSERT'))
      this.client.exec(guard('findings_confirmation_evidence_update', 'UPDATE OF verification_class, replay_spec_id, finding, verification_tier'))
    } catch (error) {
      // Never block startup on an old SQLite build that lacks json_extract; the store-level
      // InvariantError remains authoritative.
      if (!/json_extract|syntax error/i.test((error as Error).message)) throw error
    }
  }

  /**
   * Additive backfill for pre-provenance databases:
   *  - static/open-proof-gap findings become advisories (never confirmed),
   *  - findings emitted by `deterministic_engine.confirmed` become `floor`.
   * Idempotent; the CHECK constraints guard every later write.
   */
  private backfillFindingsProvenance() {
    if (!this.tableExists('findings')) return
    this.client.exec(`
      -- A legacy "confirmed" row that was only static-verified is a static item, not a runtime
      -- confirmation. Correct the embedded status before class backfill so it can never leak
      -- into queryFindings()/report confirmed counts.
      UPDATE findings
      SET finding = json_set(finding, '$.status', 'static_verified')
      WHERE verification_tier = 'static_verified'
        AND json_extract(finding, '$.status') = 'confirmed';

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
    if (this.tableExists('events')) {
      this.client.exec(`
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
  }

  private tableExists(table: string): boolean {
    const row = this.client.prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
    ).get(table) as { name?: string } | undefined
    return Boolean(row?.name)
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
  }

  // --- Shared DbSession Facade ---

  flushNow(): void { return this.session.flushNow() }

  transaction<T>(fn: () => T, options?: { behavior?: 'deferred' | 'immediate' | 'exclusive' }): T {
    return this.session.transaction(fn, options)
  }

  operate<Result extends { id: string }>(input: { requestId: string }, apply: () => Result): Result
  operate(input: { requestId: string }, apply: () => { id: string }): { id: string } {
    return this.session.operate(input, apply)
  }

  hasCascadeSchema(): boolean { return this.session.hasCascadeSchema() }
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
  workspaceSummary(...args: Parameters<ProjectsRepository['workspaceSummary']>) { return this.projectsRepo.workspaceSummary(...args) }
  listProjectSpecs(...args: Parameters<ProjectsRepository['listProjectSpecs']>) { return this.projectsRepo.listProjectSpecs(...args) }
  listProjectSpecsFull(...args: Parameters<ProjectsRepository['listProjectSpecsFull']>) { return this.projectsRepo.listProjectSpecsFull(...args) }
  getProjectSpec(...args: Parameters<ProjectsRepository['getProjectSpec']>) { return this.projectsRepo.getProjectSpec(...args) }
  importProjectSpec(...args: Parameters<ProjectsRepository['importProjectSpec']>) { return this.projectsRepo.importProjectSpec(...args) }
  upsertProjectSpecRaw(...args: Parameters<ProjectsRepository['upsertProjectSpecRaw']>) { return this.projectsRepo.upsertProjectSpecRaw(...args) }
  deleteProjectSpec(...args: Parameters<ProjectsRepository['deleteProjectSpec']>) { return this.projectsRepo.deleteProjectSpec(...args) }
  projectDetail(...args: Parameters<ProjectsRepository['projectDetail']>) { return this.projectsRepo.projectDetail(...args) }
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

  /** Deterministically purge expired exchanges, artifacts, and temp files according to `policy`. */
  purgeArtifactsByTtl(policy: ArtifactTtlPolicy): ArtifactTtlPurgeResult {
    return purgeExpiredArtifacts(this, policy)
  }
}

export type StoreRunDetail = ReturnType<Store['runDetail']>

export interface DeleteExecutionControl {
  wake: () => void
  getLabTargetHandle: (runId: string) => unknown
}

export interface DeleteLabControl {
  getTarget: (runId: string) => unknown
  stopLabTarget: (runId: string) => Promise<unknown>
}

async function stopRunsBeforeDelete(
  db: Store,
  exec: DeleteExecutionControl,
  labRunner: DeleteLabControl,
  runIds: readonly string[],
  waitTimeoutMs = 2_500,
): Promise<void> {
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
    await labRunner.stopLabTarget(runId).catch(() => undefined)
  }
  exec.wake()

  const deadline = Date.now() + Math.max(0, waitTimeoutMs)
  while (Date.now() < deadline) {
    const stillActive = runIds.some(runId =>
      db.isRunActive(runId)
      || isOobDrainActive(runId)
      || Boolean(exec.getLabTargetHandle(runId))
      || Boolean(labRunner.getTarget(runId)),
    )
    if (!stillActive) break
    await new Promise(resolve => setTimeout(resolve, 100))
    exec.wake()
  }
}

export async function deleteRunWithActiveGuard(
  db: Store,
  exec: DeleteExecutionControl,
  labRunner: DeleteLabControl,
  input: { runId: string; stopActive?: boolean; waitTimeoutMs?: number },
): Promise<{ deleted: boolean; projectId: string; runId: string }> {
  const isActive = db.isRunActive(input.runId)
    || isOobDrainActive(input.runId)
    || Boolean(exec.getLabTargetHandle(input.runId))
    || Boolean(labRunner.getTarget(input.runId))
  if (isActive && !input.stopActive) {
    throw new Error('This run is currently active. Stop the run first (or choose Stop & Delete) before deleting it.')
  }
  if (isActive && input.stopActive) {
    await stopRunsBeforeDelete(db, exec, labRunner, [input.runId], input.waitTimeoutMs)
  } else {
    cancelOobDrainForRun(input.runId)
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
  const activeRunIds = allRunIds.filter(runId =>
    db.isRunActive(runId)
    || isOobDrainActive(runId)
    || Boolean(exec.getLabTargetHandle(runId))
    || Boolean(labRunner.getTarget(runId)),
  )
  if (activeRunIds.length > 0 && !input.stopActive) {
    throw new Error(
      `This project has ${activeRunIds.length} active ${activeRunIds.length === 1 ? 'run' : 'runs'}. Stop active runs first (or choose Stop & Delete) before deleting the project.`,
    )
  }
  if (activeRunIds.length > 0 && input.stopActive) {
    await stopRunsBeforeDelete(db, exec, labRunner, activeRunIds, input.waitTimeoutMs)
  } else {
    for (const runId of allRunIds) {
      cancelOobDrainForRun(runId)
      await labRunner.stopLabTarget(runId).catch(() => undefined)
    }
  }
  const result = db.deleteProject(input.projectId)
  if (result.deleted) exec.wake()
  return result
}

let instance: Store | undefined
export function store() {
  return instance ??= new Store(dataDirectory())
}
