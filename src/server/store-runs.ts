/**
 * Domain repository for runs, assignments/workers, chain steps, threat models, graph digests,
 * events, messages, swarm board members/messages, scope policy, Tier-3 approvals & leases,
 * crash recovery, lab containers, `runShellSummary`, `runDetail`, `writeReport`, `command`,
 * run tenant isolation + append-only `tenant_audit_log`, and cascade-aware `deleteRun` + cleanup.
 *
 * Strictly acyclic: depends only on `store-session.ts` plus type-only collaborator references to
 * `ProjectsRepository` and `FindingsRepository` (never imports `store.ts`).
 */
import { randomUUID } from 'node:crypto'
import { and, asc, desc, eq, gt, inArray, sql } from 'drizzle-orm'
import type { z } from 'zod'
import {
  assessmentCheckTitles,
  assetOriginForEnvironment,
  boardHandlePattern,
  boardSystemHandles,
  canReviewScope,
  canonicalBoardHandles,
  defaultBudgetRequests,
  defaultBudgetUsd,
  defaultLabBudgetRequests,
  defaultMaxRpsPerOrigin,
  defaultPublicBudgetRequests,
  defaultWorkerConcurrency,
  defaultWorkerMaxTurns,
  maxBoardBodyLength,
  normalizeBoardHandle,
  parseBoardMentions,
  specialistProfiles,
  workerHistory,
} from '../domain.ts'
import type {
  ApprovalPolicy,
  ApprovedEndpointPattern,
  BoardAuthorRole,
  BoardMemberRole,
  BoardMemberState,
  BoardMessageKind,
  Candidate,
  CapabilityTier,
  CheckCoverage,
  DnsSource,
  Finding,
  OwaspCategory,
  PatchProposalSummary,
  ReportBody,
  RunCommand,
  SelectedChecks,
  SpecialistProfile,
  ThreatModelSummary,
  WorkerPhase,
  newRun,
} from '../domain.ts'
import {
  buildProvenanceReport,
  collapseBaselineHeaderFindings,
  deduplicateChainFindings,
} from '../report-summary.ts'
import type {
  FindingProvenanceFields,
  ReportProvenanceSurface,
} from '../report-summary.ts'
import { matchesApprovedEndpointPattern, normalizeApprovalPathPattern } from './approval-pattern.ts'
import type { ApprovalDecidedBy, ApprovalRiskLevel } from './approval-judge.ts'
import { redact, redactZdrJsonValue } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import { restrictAccessVerification } from './report-evidence.ts'
import { availableReviewChecks } from './review-plan.ts'
import * as tables from './schema.ts'
import {
  defaultEnvironmentMode,
  environmentModes,
  isProvenanceOriginAllowed,
  normalizeScopeOrigin,
  originRoles,
  provenanceOriginsFor,
  routePatternForPath,
  tenantTagForRun,
} from './scope-policy.ts'
import type { EnvironmentMode, OriginRole, ScopePolicy } from './scope-policy.ts'
import type { FindingsRepository } from './store-findings.ts'
import type { ProjectsRepository } from './store-projects.ts'
import {
  TenantIsolationError,
  assessmentAssignments,
  computeTenantAuditHash,
  evidenceTitle,
  inconclusiveReasons,
  inventoryTitle,
  normalizeTenantId,
  reportAccessOperation,
  resolvePageLimit,
  resolvePageOffset,
  untestedCoverage,
  untestedReason,
  type AppendTenantAuditLogInput,
  type ApprovalLeaseRow,
  type ApprovalRequest,
  type Assignment,
  type BoardMemberRow,
  type BoardMessageRow,
  type ChainStep,
  type DbSession,
  type Evidence,
  type ExchangeSummary,
  type GraphDigest,
  type LabContainerRow,
  type PaginationOptions,
  type RawTenantAuditRow,
  type RecoveryReport,
  type Run,
  type RunDetailOptions,
  type RunShellIndexEntry,
  type RunShellSummary,
  type SerializableFact,
  type SerializableReplaySpecRow,
  type TenantAuditLogEntry,
  type TenantAuditOutcome,
  type ThreatModel,
} from './store-session.ts'

function deriveDefaultEnvironmentMode(
  projectEnvironment: 'public' | 'local-lab' | string,
  capabilityTier: CapabilityTier,
  approvalPolicy?: ApprovalPolicy,
): EnvironmentMode {
  if (projectEnvironment === 'local-lab') return 'ephemeral_lab'
  if (capabilityTier >= 3 || approvalPolicy === 'yolo') return 'staging_isolated'
  return defaultEnvironmentMode(projectEnvironment)
}

export class RunsRepository {
  private readonly session: DbSession
  private readonly projects: ProjectsRepository
  private readonly findings: FindingsRepository

  constructor(session: DbSession, projects: ProjectsRepository, findings: FindingsRepository) {
    this.session = session
    this.projects = projects
    this.findings = findings
  }

  run(runId: string): Run {
    return this.session.requireRun(runId)
  }

  /**
   * Crash recovery (idempotent). Resets interrupted runs, stuck board members and stale
   * assignments, expires pending approval leases, and reclaims persisted LabRunner container rows.
   * Permanently `failed` assignments are never re-queued.
   */
  recover(now = Date.now()): RecoveryReport {
    if (this.session.txDepth > 0) throw new Error('recover() cannot run inside an open transaction.')
    this.session.flushNow()
    const report: RecoveryReport = {
      pausedRuns: 0,
      requeuedAssignments: 0,
      resetBoardMembers: 0,
      expiredApprovals: 0,
      reclaimedContainers: [],
      changed: false,
    }
    this.session.transaction(() => {
      const runRows = this.session.db.select({ id: tables.runs.id, status: tables.runs.status }).from(tables.runs)
        .where(and(
          eq(tables.runs.workspaceId, this.session.workspace.id),
          inArray(tables.runs.status, ['running', 'paused']),
        )).all()
      const runIds = runRows.map(row => row.id)
      const interrupted = runRows.filter(row => row.status === 'running')

      for (const row of interrupted) {
        const run = this.run(row.id)
        this.setStatus(run, 'paused')
        this.session.db.update(tables.chainSteps).set({ status: 'ready', assignedWorkerId: null, updatedAt: now })
          .where(and(eq(tables.chainSteps.runId, run.id), eq(tables.chainSteps.status, 'running'))).run()
        report.pausedRuns += 1
      }

      if (runIds.length) {
        const placeholders = runIds.map(() => '?').join(', ')
        const requeued = this.session.client.prepare(
          `UPDATE assignments SET status = 'queued', lease = NULL, lease_expires_at = NULL
           WHERE run_id IN (${placeholders}) AND (
             status IN ('running', 'paused')
             OR (status = 'waiting_approval' AND approval_parked_at IS NULL)
           )`,
        ).run(...runIds) as { changes?: number }
        report.requeuedAssignments = Number(requeued.changes ?? 0)

        const resetMembers = this.session.client.prepare(
          `UPDATE board_members SET state = 'waiting', active_assignment_id = NULL, updated_at = ?
           WHERE run_id IN (${placeholders}) AND state = 'working'`,
        ).run(now, ...runIds) as { changes?: number }
        report.resetBoardMembers = Number(resetMembers.changes ?? 0)
      }

      const expired = this.session.client.prepare(
        `UPDATE approval_requests SET status = 'expired', decided_at = ?,
           policy_note = coalesce(policy_note, 'Expired approval lease cleared during crash recovery.')
         WHERE status = 'pending' AND expires_at < ?
           AND run_id IN (SELECT id FROM runs WHERE workspace_id = ?)`,
      ).run(now, now, this.session.workspace.id) as { changes?: number }
      report.expiredApprovals = Number(expired.changes ?? 0)

      const orphanedRows = this.session.db.select().from(tables.labContainers)
        .where(eq(tables.labContainers.status, 'orphaned')).all()
      const liveRows = runIds.length
        ? this.session.db.select().from(tables.labContainers).where(and(
            eq(tables.labContainers.status, 'running'),
            inArray(tables.labContainers.runId, runIds),
          )).all()
        : []
      const containerRows = [...orphanedRows, ...liveRows]
      const uniqueContainers = new Map(containerRows.map(row => [row.id, row]))
      if (uniqueContainers.size) {
        const ids = [...uniqueContainers.keys()]
        const deleteStmt = this.session.client.prepare(`DELETE FROM lab_containers WHERE id IN (${ids.map(() => '?').join(', ')})`)
        deleteStmt.run(...ids)
        report.reclaimedContainers = [...uniqueContainers.values()]
          .map(row => ({ runId: row.runId, containerName: row.containerName }))
      }

      for (const row of interrupted) {
        this.session.event(row.id, 'interrupted', 'The application restarted. Resume to continue from saved evidence.')
      }

      report.changed = report.pausedRuns > 0 || report.requeuedAssignments > 0
        || report.resetBoardMembers > 0 || report.expiredApprovals > 0 || report.reclaimedContainers.length > 0

      if (report.reclaimedContainers.length || report.expiredApprovals) {
        this.session.event(null, 'recovery.completed', 'Crash recovery reclaimed runtime state.', {
          pausedRuns: report.pausedRuns,
          requeuedAssignments: report.requeuedAssignments,
          resetBoardMembers: report.resetBoardMembers,
          expiredApprovals: report.expiredApprovals,
          reclaimedContainers: report.reclaimedContainers.map(row => row.containerName).slice(0, 50),
        })
      }
    }, { behavior: 'immediate' })
    return report
  }

  // --- LabRunner container registry (v6 crash recovery) ---

  recordLabContainer(input: {
    runId: string
    assignmentId?: string | null
    containerName: string
    imageName?: string | null
    status?: LabContainerRow['status']
  }): LabContainerRow {
    const now = Date.now()
    const existing = this.session.db.select().from(tables.labContainers).where(and(
      eq(tables.labContainers.runId, input.runId),
      eq(tables.labContainers.containerName, input.containerName),
    )).get()
    if (existing) {
      return this.session.db.update(tables.labContainers).set({
        assignmentId: input.assignmentId !== undefined ? input.assignmentId : existing.assignmentId,
        imageName: input.imageName !== undefined ? input.imageName : existing.imageName,
        status: input.status ?? existing.status,
        updatedAt: now,
      }).where(eq(tables.labContainers.id, existing.id)).returning().get()!
    }
    return this.session.db.insert(tables.labContainers).values({
      id: randomUUID(),
      runId: input.runId,
      assignmentId: input.assignmentId ?? null,
      containerName: input.containerName,
      imageName: input.imageName ?? null,
      status: input.status ?? 'running',
      createdAt: now,
      updatedAt: now,
    }).returning().get()
  }

  markLabContainerOrphaned(runId: string, containerName: string) {
    this.session.db.update(tables.labContainers).set({ status: 'orphaned', updatedAt: Date.now() }).where(and(
      eq(tables.labContainers.runId, runId),
      eq(tables.labContainers.containerName, containerName),
    )).run()
  }

  listLabContainers(runId: string): LabContainerRow[] {
    return this.session.db.select().from(tables.labContainers).where(eq(tables.labContainers.runId, runId))
      .orderBy(asc(tables.labContainers.createdAt), asc(tables.labContainers.containerName)).all()
  }

  // --- Scope policy & v5 Swarm Message Board ---

  private approvedOriginsFor(run: Run): Set<string> {
    const approved = new Set(run.approved)
    return new Set(run.candidates.filter(candidate => approved.has(candidate.id)).map(candidate => candidate.origin))
  }

  /** True when the operator explicitly locked `environmentMode` via `setEnvironmentMode()`. */
  private hasExplicitEnvironmentMode(runId: string): boolean {
    const row = this.session.db.select({ id: tables.events.id }).from(tables.events).where(and(
      eq(tables.events.workspaceId, this.session.workspace.id),
      eq(tables.events.runId, runId),
      eq(tables.events.kind, 'scope.environment_mode'),
    )).limit(1).get()
    return Boolean(row)
  }

  /**
   * v6 three-tier scope for a run. `targetOrigins` remains the legacy approved-candidate allowlist
   * (so every pre-v6 database upgrades without data loss); `authOrigins`/`assetOrigins` are
   * additive benign-infrastructure tiers.
   */
  scopePolicy(runOrId: Run | string): ScopePolicy {
    const run = typeof runOrId === 'string' ? this.run(runOrId) : runOrId
    return {
      mode: run.environmentMode ?? deriveDefaultEnvironmentMode(
        this.projects.project(run.projectId).environment,
        run.capabilityTier,
        run.approvalPolicy,
      ),
      targetOrigins: [...this.approvedOriginsFor(run)],
      authOrigins: [...(run.authOrigins ?? [])],
      assetOrigins: [...(run.assetOrigins ?? [])],
      routeDenylist: [...(run.routeDenylist ?? [])],
      tenantTag: tenantTagForRun(run.id),
      runId: run.id,
    }
  }

  /** Target + benign auth/asset origins, used for provenance and revocation decisions. */
  private provenanceOriginsFor(run: Run): Set<string> {
    return provenanceOriginsFor(this.scopePolicy(run))
  }

  setEnvironmentMode(run: Run, mode: EnvironmentMode): Run {
    if (!environmentModes.includes(mode)) throw new Error('Unknown environment mode.')
    if (['complete', 'stopped', 'failed'].includes(run.status)) {
      throw new Error('Cannot change the environment mode after a run has ended.')
    }
    const updated = this.updateRun(run.id, { environmentMode: mode })
    this.session.event(run.id, 'scope.environment_mode', `Environment contract set to ${mode}.`, {
      environmentMode: mode,
    })
    return updated
  }

  setRouteDenylist(run: Run, routes: readonly string[]): Run {
    const normalized: string[] = []
    for (const entry of routes) {
      const path = (entry ?? '').trim()
      if (!path) continue
      if (!path.startsWith('/')) throw new Error('Route denylist entries must start with "/".')
      if (/[\r\n\0]/.test(path)) throw new Error('Invalid route denylist entry.')
      normalized.push(path)
    }
    const updated = this.updateRun(run.id, { routeDenylist: [...new Set(normalized)] })
    this.session.event(run.id, 'scope.route_denylist', `Staging route denylist updated (${normalized.length} entries).`, {
      routeDenylist: updated.routeDenylist,
    })
    return updated
  }

  /**
   * Assign an origin to one of the three tiers. The legacy approved-candidate allowlist is the
   * target tier, so promoting/demoting is expressed as an edit to `approved` plus the role lists.
   */
  setOriginRole(run: Run, origin: string, role: OriginRole): Run {
    if (!originRoles.includes(role)) throw new Error('Unknown origin role.')
    const project = this.projects.project(run.projectId)
    const validated = assetOriginForEnvironment(project.environment).parse(origin)
    const normalized = normalizeScopeOrigin(validated) ?? validated
    const candidate = run.candidates.find(item => normalizeScopeOrigin(item.origin) === normalized)
    const approved = new Set(run.approved)
    if (role === 'target') {
      if (!candidate) {
        throw new Error('Add the host to the run inventory before approving it as a target origin.')
      }
      approved.add(candidate.id)
    } else if (candidate) {
      approved.delete(candidate.id)
    }
    const without = (list: readonly string[] | undefined) =>
      [...(list ?? [])].filter(item => normalizeScopeOrigin(item) !== normalized)
    const updated = this.updateRun(run.id, {
      approved: [...approved],
      authOrigins: role === 'auth' ? [...new Set([...without(run.authOrigins), normalized])] : without(run.authOrigins),
      assetOrigins: role === 'asset' ? [...new Set([...without(run.assetOrigins), normalized])] : without(run.assetOrigins),
    })
    this.session.event(run.id, 'scope.origin_role', `Origin ${normalized} assigned the ${role} role.`, {
      origin: normalized, role,
    })
    return updated
  }

  boardMember(runId: string, handle: string): BoardMemberRow | undefined {
    const normalized = normalizeBoardHandle(handle)
    if (!normalized) return undefined
    return this.session.db.select().from(tables.boardMembers).where(and(
      eq(tables.boardMembers.runId, runId), eq(tables.boardMembers.handle, normalized),
    )).get()
  }

  listBoardMembers(runId: string): BoardMemberRow[] {
    return this.session.db.select().from(tables.boardMembers).where(eq(tables.boardMembers.runId, runId))
      .orderBy(asc(tables.boardMembers.createdAt), asc(tables.boardMembers.handle)).all()
  }

  upsertBoardMember(runOrId: Run | string, input: {
    handle: string
    role: BoardMemberRole
    specialistProfile?: SpecialistProfile | null
    sessionId?: string
    activeAssignmentId?: string | null
    state?: BoardMemberState
    roleAffinity?: BoardMemberRow['roleAffinity']
    lastReadSeq?: number
    turnsUsed?: number
    postsCount?: number
    peerHopsUsed?: number
    scopeRevision?: number
    goalRevision?: number
    sourceOrigins?: readonly string[]
  }): BoardMemberRow {
    const run = typeof runOrId === 'string' ? this.run(runOrId) : runOrId
    const handle = normalizeBoardHandle(input.handle)
    if (!handle || !boardHandlePattern.test(handle)) {
      throw new Error('Board handle must match ^[a-z][a-z0-9_-]{1,23}$.')
    }
    if (input.specialistProfile && !specialistProfiles.includes(input.specialistProfile)) {
      throw new Error('Unknown specialist profile.')
    }
    const now = Date.now()
    const existing = this.boardMember(run.id, handle)
    const values = {
      handle,
      role: input.role,
      specialistProfile: input.specialistProfile ?? existing?.specialistProfile ?? null,
      sessionId: input.sessionId ?? existing?.sessionId ?? randomUUID(),
      activeAssignmentId: input.activeAssignmentId !== undefined ? input.activeAssignmentId : existing?.activeAssignmentId ?? null,
      state: input.state ?? existing?.state ?? 'waiting',
      roleAffinity: input.roleAffinity !== undefined ? input.roleAffinity : existing?.roleAffinity ?? null,
      lastReadSeq: Math.max(0, Math.round(input.lastReadSeq ?? existing?.lastReadSeq ?? 0)),
      turnsUsed: Math.max(0, Math.round(input.turnsUsed ?? existing?.turnsUsed ?? 0)),
      postsCount: Math.max(0, Math.round(input.postsCount ?? existing?.postsCount ?? 0)),
      peerHopsUsed: Math.max(0, Math.round(input.peerHopsUsed ?? existing?.peerHopsUsed ?? 0)),
      scopeRevision: Math.max(0, Math.round(input.scopeRevision ?? existing?.scopeRevision ?? run.scopeRevision)),
      goalRevision: Math.max(0, Math.round(input.goalRevision ?? existing?.goalRevision ?? run.goalRevision)),
      sourceOrigins: [...new Set(input.sourceOrigins ?? existing?.sourceOrigins ?? [])],
    }
    if (existing) {
      return this.session.db.update(tables.boardMembers).set({ ...values, updatedAt: now })
        .where(eq(tables.boardMembers.id, existing.id)).returning().get()!
    }
    return this.session.db.insert(tables.boardMembers).values({
      id: randomUUID(), runId: run.id, ...values, createdAt: now, updatedAt: now,
    }).returning().get()
  }

  updateBoardMemberState(runId: string, handle: string, patch: {
    state?: BoardMemberState
    activeAssignmentId?: string | null
    lastReadSeq?: number
    turnsUsed?: number
    postsCount?: number
    peerHopsUsed?: number
    scopeRevision?: number
    goalRevision?: number
    roleAffinity?: BoardMemberRow['roleAffinity']
    sourceOrigins?: readonly string[]
    sessionId?: string
  }): BoardMemberRow {
    const existing = this.boardMember(runId, handle)
    if (!existing) throw new Error('Board member not found.')
    return this.upsertBoardMember(runId, {
      handle: existing.handle,
      role: existing.role,
      specialistProfile: existing.specialistProfile,
      sessionId: patch.sessionId ?? existing.sessionId,
      activeAssignmentId: patch.activeAssignmentId !== undefined ? patch.activeAssignmentId : existing.activeAssignmentId,
      state: patch.state ?? existing.state,
      roleAffinity: patch.roleAffinity !== undefined ? patch.roleAffinity : existing.roleAffinity,
      lastReadSeq: patch.lastReadSeq ?? existing.lastReadSeq,
      turnsUsed: patch.turnsUsed ?? existing.turnsUsed,
      postsCount: patch.postsCount ?? existing.postsCount,
      peerHopsUsed: patch.peerHopsUsed ?? existing.peerHopsUsed,
      scopeRevision: patch.scopeRevision ?? existing.scopeRevision,
      goalRevision: patch.goalRevision ?? existing.goalRevision,
      sourceOrigins: patch.sourceOrigins ?? existing.sourceOrigins,
    })
  }

  retireBoardMember(run: Run | string, handle: string, reason: string): BoardMemberRow {
    const resolved = typeof run === 'string' ? this.run(run) : run
    const member = this.updateBoardMemberState(resolved.id, handle, { state: 'retired' })
    this.session.event(resolved.id, 'board.member.retired', `@${member.handle} retired.`, {
      handle: member.handle, reason, assignmentId: member.activeAssignmentId, scopeRevision: resolved.scopeRevision,
    })
    return member
  }

  private boardHandleAllowList(runId: string): Set<string> {
    const handles = new Set<string>([...canonicalBoardHandles, ...boardSystemHandles])
    for (const member of this.listBoardMembers(runId)) {
      if (member.state === 'retired') handles.delete(member.handle)
      else handles.add(member.handle)
    }
    return handles
  }

  /** Redact + cap + reject prompt-injection carriers before a board body reaches SQLite or SSE. */
  private cleanBoardBody(body: string, secrets: readonly NamedSecret[]): string {
    const trimmed = body.trim()
    if (!trimmed) throw new Error('Board message body is required.')
    if (/<\s*\/?\s*(?:script|iframe|object|embed|style|img|svg|a|div|span|table|form|input|link|meta|html|body|br|p|h[1-6])\b[^>]*>/i.test(trimmed)) {
      throw new Error('Board messages cannot contain raw HTML or markup.')
    }
    const headerLines = trimmed.split('\n').filter(line =>
      /^(?:host|user-agent|authorization|cookie|set-cookie|content-type|content-length|accept|referer|origin|x-[a-z0-9-]+):\s*\S/i.test(line.trim()))
    if (headerLines.length >= 2) {
      throw new Error('Board messages cannot contain multi-line HTTP header dumps. Reference an exchange instead.')
    }
    const cleaned = redact(trimmed, secrets).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '')
    if (cleaned.length <= maxBoardBodyLength) return cleaned
    return cleaned.slice(0, maxBoardBodyLength - 1) + '…'
  }

  postBoardMessage(runOrId: Run | string, input: {
    authorHandle: string
    authorRole: BoardAuthorRole
    kind: BoardMessageKind
    body: string
    mentions?: readonly string[]
    refFactIds?: readonly string[]
    refExchangeIds?: readonly string[]
    refFindingIds?: readonly string[]
    refStepId?: string | null
    refApprovalId?: string | null
    replyToSeq?: number | null
    sourceOrigins?: readonly string[]
  }, secrets: readonly NamedSecret[] = []): BoardMessageRow {
    const run = typeof runOrId === 'string' ? this.run(runOrId) : runOrId
    const authorHandle = normalizeBoardHandle(input.authorHandle)
    if (!authorHandle) throw new Error('Invalid board author handle.')
    const roleHandles: Record<Exclude<BoardAuthorRole, 'specialist'>, readonly string[]> = {
      operator: ['operator'],
      coordinator: ['coordinator'],
      verifier: ['verifier'],
      system: ['broker', 'canary', 'system'],
    }
    if (input.authorRole === 'specialist') {
      if (['operator', 'coordinator', 'verifier', 'broker', 'canary', 'system', 'all'].includes(authorHandle)) {
        throw new Error('A specialist cannot post under a system actor handle.')
      }
    } else if (!roleHandles[input.authorRole].includes(authorHandle)) {
      throw new Error(`@${authorHandle} cannot post with the ${input.authorRole} author role.`)
    }
    const allowed = this.boardHandleAllowList(run.id)
    if (input.authorRole === 'specialist' && !allowed.has(authorHandle)) {
      throw new Error(`Specialist @${authorHandle} is not on the active board roster.`)
    }
    const mentions = [...new Set((input.mentions ?? parseBoardMentions(input.body))
      .map(mention => normalizeBoardHandle(mention))
      .filter((h): h is string => Boolean(h)))]
    for (const mention of mentions) {
      if (mention === 'all') {
        if (!['operator', 'coordinator', 'system'].includes(input.authorRole)) {
          throw new Error('Only the operator, coordinator, or system actors may use @all.')
        }
        continue
      }
      if (!allowed.has(mention)) throw new Error(`Cannot mention unknown or retired board handle @${mention}.`)
    }
    const scopePolicy = this.scopePolicy(run)
    const approvedOrigins = this.approvedOriginsFor(run)
    // A board post may cite a benign IdP/CDN hop without being out of scope.
    // Operator posts default empty/omitted sourceOrigins to the run's approved origins
    // so cold @specialist mentions can wake specialists against the active scope.
    const sourceOrigins = [...new Set(
      input.sourceOrigins !== undefined
        ? (input.authorRole === 'operator' && input.sourceOrigins.length === 0 ? approvedOrigins : input.sourceOrigins)
        : approvedOrigins,
    )]
    if (sourceOrigins.some(origin => !isProvenanceOriginAllowed(scopePolicy, origin))) {
      throw new Error('Board message references an origin outside approved scope.')
    }
    const body = this.cleanBoardBody(input.body, secrets)
    if (input.replyToSeq !== undefined && input.replyToSeq !== null) {
      const exists = this.session.db.select({ id: tables.boardMessages.id }).from(tables.boardMessages).where(and(
        eq(tables.boardMessages.runId, run.id), eq(tables.boardMessages.seq, input.replyToSeq),
      )).get()
      if (!exists) throw new Error('Cannot reply to a board sequence that does not exist.')
    }
    const message = this.session.transaction(() => {
      const maxSeq = this.session.db.select({ value: sql<number>`COALESCE(MAX(${tables.boardMessages.seq}), 0)` })
        .from(tables.boardMessages).where(eq(tables.boardMessages.runId, run.id)).get()
      const seq = Number(maxSeq?.value ?? 0) + 1
      return this.session.db.insert(tables.boardMessages).values({
        id: randomUUID(),
        runId: run.id,
        seq,
        authorHandle,
        authorRole: input.authorRole,
        kind: input.kind,
        mentions,
        body,
        refFactIds: [...new Set(input.refFactIds ?? [])].slice(0, 50),
        refExchangeIds: [...new Set(input.refExchangeIds ?? [])].slice(0, 50),
        refFindingIds: [...new Set(input.refFindingIds ?? [])].slice(0, 50),
        refStepId: input.refStepId ?? null,
        refApprovalId: input.refApprovalId ?? null,
        replyToSeq: input.replyToSeq ?? null,
        scopeRevision: run.scopeRevision,
        goalRevision: run.goalRevision,
        sourceOrigins,
        tainted: false,
        createdAt: Date.now(),
      }).returning().get()
    }, { behavior: 'immediate' })
    const member = this.boardMember(run.id, authorHandle)
    if (member) {
      this.session.db.update(tables.boardMembers).set({ postsCount: member.postsCount + 1, updatedAt: Date.now() })
        .where(eq(tables.boardMembers.id, member.id)).run()
    }
    this.session.event(run.id, 'board.message', `@${authorHandle} posted a ${input.kind}.`, {
      boardMessageId: message.id, seq: message.seq, authorHandle, authorRole: input.authorRole,
      kind: input.kind, mentions, refApprovalId: message.refApprovalId, tainted: false,
    })
    return message
  }

  listBoardMessages(runId: string, opts: {
    sinceSeq?: number
    limit?: number
    includeTainted?: boolean
    authorHandle?: string
    kind?: BoardMessageKind
    mentionHandle?: string
    approvalId?: string
  } = {}): BoardMessageRow[] {
    const sinceSeq = Math.max(0, Math.round(opts.sinceSeq ?? 0))
    const limit = Math.min(Math.max(1, opts.limit ?? 200), 500)
    const authorHandle = opts.authorHandle ? normalizeBoardHandle(opts.authorHandle) : null
    const mentionHandle = opts.mentionHandle ? normalizeBoardHandle(opts.mentionHandle) : null
    return this.session.db.select().from(tables.boardMessages).where(and(
      eq(tables.boardMessages.runId, runId),
      gt(tables.boardMessages.seq, sinceSeq),
      ...(opts.includeTainted ? [] : [eq(tables.boardMessages.tainted, false)]),
      ...(opts.kind ? [eq(tables.boardMessages.kind, opts.kind)] : []),
      ...(authorHandle ? [eq(tables.boardMessages.authorHandle, authorHandle)] : []),
      ...(opts.approvalId ? [eq(tables.boardMessages.refApprovalId, opts.approvalId)] : []),
    )).orderBy(asc(tables.boardMessages.seq)).all()
      .filter(message => !mentionHandle || message.mentions.includes(mentionHandle))
      .slice(0, limit)
  }

  /**
   * Scope revocation: immediately taint board posts touching unapproved origins and retire the
   * affected roster members so revoked-origin text can never reach a later specialist wake.
   */
  taintBoardMessagesForRevokedOrigins(runId: string, approvedOrigins: ReadonlySet<string>): {
    taintedMessageIds: string[]
    retiredHandles: string[]
  } {
    // IdP/CDN hops are benign infrastructure: they must never taint a valid target finding.
    const policy = this.scopePolicy(runId)
    const allowed = (origin: string) =>
      approvedOrigins.has(origin) || isProvenanceOriginAllowed(policy, origin)
    const taintedMessageIds: string[] = []
    for (const message of this.session.db.select().from(tables.boardMessages).where(and(
      eq(tables.boardMessages.runId, runId), eq(tables.boardMessages.tainted, false),
    )).all()) {
      if (message.sourceOrigins.some(origin => !allowed(origin))) {
        taintedMessageIds.push(message.id)
      }
    }
    if (taintedMessageIds.length) {
      this.session.db.update(tables.boardMessages).set({ tainted: true }).where(and(
        eq(tables.boardMessages.runId, runId), inArray(tables.boardMessages.id, taintedMessageIds),
      )).run()
    }
    const retiredHandles: string[] = []
    for (const member of this.listBoardMembers(runId)) {
      if (member.state === 'retired') continue
      if (member.sourceOrigins.some(origin => !allowed(origin))) {
        this.updateBoardMemberState(runId, member.handle, { state: 'retired', activeAssignmentId: null })
        retiredHandles.push(member.handle)
      }
    }
    if (taintedMessageIds.length || retiredHandles.length) {
      this.session.event(runId, 'board.tainted', 'Scope revocation tainted board messages and retired affected members.', {
        taintedMessageIds, retiredHandles,
      })
    }
    return { taintedMessageIds, retiredHandles }
  }

  eventsAfter(runId: string, after: number, limit = 1000) {
    return this.session.db.select({
      id: tables.events.id, kind: tables.events.kind, message: tables.events.message,
      detail: tables.events.detail, createdAt: tables.events.createdAt,
    }).from(tables.events).where(and(
      eq(tables.events.workspaceId, this.session.workspace.id), eq(tables.events.runId, runId), gt(tables.events.id, after),
    )).orderBy(asc(tables.events.id)).limit(limit).all()
  }

  /** Run workspace shell summary: workspace run index (newest first) and exact totals for one run. */
  runShellSummary(runId: string, limit = 200): RunShellSummary {
    const run = this.run(runId)
    const safeLimit = resolvePageLimit(limit, 200)
    const runs = this.session.client.prepare(`
      select r.id as id, r.goal as goal, r.status as status, r.phase as phase,
        r.created_at as createdAt, r.project_id as projectId, p.name as projectName,
        (select count(*) from findings f where f.run_id = r.id and f.superseded_by_finding_id is null) as findings
      from runs r
      join projects p on p.id = r.project_id
      where r.workspace_id = ?
      order by r.created_at desc, r.rowid desc
      limit ?
    `).all(run.workspaceId, safeLimit) as unknown as RunShellIndexEntry[]
    const counts = this.session.client.prepare(`
      select
        (select count(*) from broker_exchanges where run_id = ?) as exchanges,
        (select count(*) from events where run_id = ?) as events
    `).get(run.id, run.id) as { exchanges: number; events: number }
    return {
      runs: runs.map(r => ({ ...r, createdAt: Number(r.createdAt), findings: Number(r.findings) })),
      counts: { exchanges: Number(counts.exchanges), events: Number(counts.events) },
    }
  }

  /** True when the run itself is in `running` status or still owns running workers/lab containers. */
  isRunActive(runId: string): boolean {
    const run = this.session.db.select({ id: tables.runs.id, status: tables.runs.status })
      .from(tables.runs)
      .where(and(eq(tables.runs.id, runId), eq(tables.runs.workspaceId, this.session.workspace.id)))
      .get()
    if (!run) return false
    if (run.status === 'running') return true
    const activeAssignments = this.session.client.prepare(
      `SELECT count(*) AS c FROM assignments WHERE run_id = ? AND status IN ('running', 'waiting_approval')`,
    ).get(runId) as { c?: number } | undefined
    if (Number(activeAssignments?.c ?? 0) > 0) return true
    const activeContainers = this.session.client.prepare(
      `SELECT count(*) AS c FROM lab_containers WHERE run_id = ? AND status = 'running'`,
    ).get(runId) as { c?: number } | undefined
    return Number(activeContainers?.c ?? 0) > 0
  }

  /** Return all run IDs belonging to a project that are currently active. */
  listActiveRunIdsForProject(projectId: string): string[] {
    const rows = this.session.db.select({ id: tables.runs.id })
      .from(tables.runs)
      .where(and(eq(tables.runs.projectId, projectId), eq(tables.runs.workspaceId, this.session.workspace.id)))
      .all()
    return rows.map(r => r.id).filter(runId => this.isRunActive(runId))
  }

  /**
   * Delete a single run and all of its child rows atomically in one SQLite transaction,
   * then remove on-disk run artifacts and worker session files.
   */
  deleteRun(runId: string): { deleted: boolean; projectId: string; runId: string } {
    this.session.flushNow()
    const committed = this.session.transaction(() => {
      const existing = this.session.db.select({ id: tables.runs.id, projectId: tables.runs.projectId })
        .from(tables.runs)
        .where(and(eq(tables.runs.id, runId), eq(tables.runs.workspaceId, this.session.workspace.id)))
        .get()
      if (!existing) return null
      const files = this.session.deleteRunRowsInTx(runId)
      this.session.event(null, 'run.deleted', `Deleted run ${runId}.`, {
        projectId: existing.projectId,
        runId,
      })
      return { projectId: existing.projectId, ...files }
    }, { behavior: 'immediate' })
    if (!committed) return { deleted: false, projectId: '', runId }
    this.session.cleanupRunFilesOnDisk(runId, committed.sessionIds, committed.flatArtifactIds)
    return { deleted: true, projectId: committed.projectId, runId }
  }

  runDetail(runId: string, options?: RunDetailOptions) {
    // A caller that just recorded an exchange must see it in the detail view.
    this.session.flushNow()
    const run = this.run(runId)
    const pageFor = (specific?: PaginationOptions): PaginationOptions => ({
      limit: specific?.limit ?? options?.limit,
      offset: specific?.offset ?? options?.offset,
    })
    const isPaged = (page: PaginationOptions) => page.limit !== undefined || page.offset !== undefined
    const evidencePage = pageFor(options?.evidence)
    const factsPage = pageFor(options?.facts)
    const exchangePage = pageFor(options?.exchanges)
    const endpointPage = pageFor(options?.endpoints)
    const messagePage = pageFor(options?.messages)
    const boardPage = pageFor(options?.boardMessages)

    const streamHead = this.session.db.select({ id: tables.events.id }).from(tables.events)
      .where(eq(tables.events.runId, run.id)).orderBy(desc(tables.events.id)).limit(1).get()

    const evidenceBase = this.session.db.select().from(tables.evidence).where(eq(tables.evidence.runId, runId))
      .orderBy(asc(tables.evidence.createdAt), asc(tables.evidence.id))
    const evidenceRows = isPaged(evidencePage)
      ? evidenceBase.limit(resolvePageLimit(evidencePage.limit, 1000)).offset(resolvePageOffset(evidencePage.offset)).all()
      : evidenceBase.all()

    const threatModel = this.latestThreatModel(runId, run.goalRevision)
    const chainSteps = this.listChainSteps(runId)

    const factsBase = this.session.db.select().from(tables.facts).where(eq(tables.facts.runId, runId))
      .orderBy(asc(tables.facts.createdAt), asc(tables.facts.id))
    const facts = isPaged(factsPage)
      ? factsBase.limit(resolvePageLimit(factsPage.limit, 100)).offset(resolvePageOffset(factsPage.offset)).all()
      : factsBase.all()

    const graphEdges = this.findings.listGraphEdges(runId)
    const digests = this.listDigests(runId, false)
    const assignments = this.workerList(runId)
    const approvals = this.listApprovalRequests(runId)

    const exchangeColumns = {
      id: tables.brokerExchanges.id,
      assignmentId: tables.brokerExchanges.assignmentId,
      scopeRevision: tables.brokerExchanges.scopeRevision,
      origin: tables.brokerExchanges.origin,
      finalOrigin: tables.brokerExchanges.finalOrigin,
      redirectOrigins: tables.brokerExchanges.redirectOrigins,
      method: tables.brokerExchanges.method,
      pathAndQuery: tables.brokerExchanges.pathAndQuery,
      personaHandle: tables.brokerExchanges.personaHandle,
      status: tables.brokerExchanges.status,
      mediaType: tables.brokerExchanges.mediaType,
      bodyPreview: tables.brokerExchanges.bodyPreview,
      bodyArtifactId: tables.brokerExchanges.bodyArtifactId,
      bodySha256: tables.brokerExchanges.bodySha256,
      durationMs: tables.brokerExchanges.durationMs,
      createdAt: tables.brokerExchanges.createdAt,
    }
    const exchangeBase = this.session.db.select(exchangeColumns).from(tables.brokerExchanges)
      .where(eq(tables.brokerExchanges.runId, runId))
      .orderBy(desc(tables.brokerExchanges.createdAt), asc(tables.brokerExchanges.id))
    const exchangesSummary: ExchangeSummary[] = (isPaged(exchangePage)
      ? exchangeBase.limit(resolvePageLimit(exchangePage.limit, 500)).offset(resolvePageOffset(exchangePage.offset)).all()
      : exchangeBase.limit(500).all())
      .map(ex => ({ ...ex, bodyPreview: ex.bodyPreview.slice(0, 320) }))

    const coverageEntries = this.findings.listCoverageEntries(runId)
    const endpoints = this.findings.listEndpoints(runId, isPaged(endpointPage)
      ? { limit: resolvePageLimit(endpointPage.limit, 500), offset: resolvePageOffset(endpointPage.offset) }
      : undefined)
    const endpointParams = isPaged(endpointPage)
      ? (endpoints.length
          ? this.session.db.select().from(tables.endpointParams).where(and(
              eq(tables.endpointParams.runId, runId),
              inArray(tables.endpointParams.endpointId, endpoints.map(endpoint => endpoint.id)),
            )).orderBy(asc(tables.endpointParams.createdAt), asc(tables.endpointParams.id)).all()
          : [])
      : this.findings.listEndpointParams(runId)
    const apiDependencies = this.findings.listApiDependencies(runId)
    const labTelemetry = this.findings.listLabTelemetry(runId)
    const openProofGaps = this.findings.listOpenProofGaps(runId, run.goalRevision)
    const sastRuns = this.findings.listSastRuns(runId)
    const surfaceProbes = this.findings.listSurfaceProbes(runId)
    const patchProposals = this.findings.listPatchProposals(runId)
    const replaySpecs = this.findings.listReplaySpecs(runId)
    const retestRuns = this.session.db.select().from(tables.retestRuns).where(eq(tables.retestRuns.runId, runId))
      .orderBy(desc(tables.retestRuns.createdAt)).all()
    const findingsRows = this.session.db.select().from(tables.findings).where(eq(tables.findings.runId, runId)).all()
    const findings: Finding[] = findingsRows.map(row => ({
      ...row.finding,
      findingKind: row.findingKind,
      replaySpecId: row.replaySpecId ?? row.finding.replaySpecId,
      verificationTier: row.verificationTier ?? row.finding.verificationTier,
      fingerprintHash: row.fingerprintHash ?? row.finding.fingerprintHash,
      supersededByFindingId: row.supersededByFindingId ?? row.finding.supersededByFindingId,
      counterevidence: row.counterevidence ?? row.finding.counterevidence,
      confidenceRationale: row.confidenceRationale ?? row.finding.confidenceRationale,
      severityChangeConditions: row.severityChangeConditions ?? row.finding.severityChangeConditions,
      ...(row.codeLocations?.length ? { codeLocations: row.codeLocations } : row.finding.codeLocations?.length ? { codeLocations: row.finding.codeLocations } : {}),
      // The DB row is authoritative for the v6 provenance/verification contract.
      provenance: row.provenance,
      ...(row.parentFindingIds?.length ? { parentFindingIds: row.parentFindingIds } : {}),
      verificationStatus: row.verificationClass,
    } as Finding & FindingProvenanceFields))
    const provenanceCounts = buildProvenanceReport(findings as (Finding & FindingProvenanceFields)[]).provenanceCounts

    const messageBase = this.session.db.select().from(tables.messages).where(eq(tables.messages.runId, runId))
      .orderBy(asc(tables.messages.createdAt), sql`${tables.messages}.rowid`)
    const messages = isPaged(messagePage)
      ? messageBase.limit(resolvePageLimit(messagePage.limit, 1000)).offset(resolvePageOffset(messagePage.offset)).all()
      : messageBase.all()
    const boardMessages = isPaged(boardPage)
      ? this.session.db.select().from(tables.boardMessages).where(eq(tables.boardMessages.runId, runId))
          .orderBy(asc(tables.boardMessages.seq))
          .limit(resolvePageLimit(boardPage.limit, 500)).offset(resolvePageOffset(boardPage.offset)).all()
      : this.listBoardMessages(runId, { includeTainted: true, limit: 500 })

    const paging = options
      ? {
          ...(options.includeTotals === false ? {} : {
            totals: {
              evidence: this.session.countRunRows('evidence', runId),
              facts: this.session.countRunRows('facts', runId),
              exchanges: this.session.countRunRows('broker_exchanges', runId),
              endpoints: this.session.countRunRows('endpoints', runId),
              endpointParams: this.session.countRunRows('endpoint_params', runId),
              messages: this.session.countRunRows('messages', runId),
              boardMessages: this.session.countRunRows('board_messages', runId),
            },
          }),
          limit: options.limit,
          offset: resolvePageOffset(options.offset),
        }
      : undefined

    return {
      run,
      project: this.projects.project(run.projectId),
      personas: this.session.listProjectPersonas(run.projectId),
      specs: this.projects.listProjectSpecs(run.projectId),
      threatModel,
      chainSteps,
      facts: facts as SerializableFact[],
      graphEdges,
      digests,
      assignments,
      approvals,
      exchangesSummary,
      coverageEntries,
      endpoints,
      endpointParams,
      apiDependencies,
      labTelemetry,
      openProofGaps,
      sastRuns,
      surfaceProbes,
      patchProposals,
      replaySpecs: replaySpecs as unknown as SerializableReplaySpecRow[],
      retestRuns,
      findings,
      provenanceCounts,
      messages,
      boardMembers: this.listBoardMembers(runId),
      boardMessages,
      evidence: evidenceRows.map(item => ({ ...item, title: evidenceTitle(run, item.kind, item.title) })),
      reports: this.session.db.select().from(tables.reports).where(eq(tables.reports.runId, runId))
        .orderBy(desc(tables.reports.version)).all(),
      cursor: streamHead?.id ?? 0,
      ...(paging ? { paging } : {}),
    }
  }

  workerList(runId: string) {
    return this.session.db.select().from(tables.assignments).where(eq(tables.assignments.runId, runId))
      .orderBy(asc(tables.assignments.createdAt), asc(tables.assignments.title)).all()
  }

  runnable() {
    return this.session.db.select().from(tables.runs).where(and(
      eq(tables.runs.workspaceId, this.session.workspace.id), eq(tables.runs.status, 'running'),
    )).orderBy(asc(tables.runs.createdAt)).all()
  }

  runsWithPendingRetests() {
    const queuedRetests = this.session.db.select({ runId: tables.assignments.runId }).from(tables.assignments).where(and(
      eq(tables.assignments.phase, 'retest'), eq(tables.assignments.status, 'queued'),
    )).all()
    const ids = [...new Set(queuedRetests.map(r => r.runId))]
    if (!ids.length) return []
    return this.session.db.select().from(tables.runs).where(and(
      eq(tables.runs.workspaceId, this.session.workspace.id), inArray(tables.runs.id, ids),
    )).all()
  }

  worker(workerId: string) {
    const assignment = this.session.db.select().from(tables.assignments).where(eq(tables.assignments.id, workerId)).get()
    if (!assignment) throw new Error('Assignment not found.')
    this.run(assignment.runId)
    return assignment
  }

  // --- Threat Models, Chain Steps, Digests ---

  saveThreatModel(run: Run, entries: ThreatModelSummary[], summary: string): ThreatModel {
    const row = this.session.db.insert(tables.threatModels).values({
      id: randomUUID(),
      runId: run.id,
      scopeRevision: run.scopeRevision,
      goalRevision: run.goalRevision,
      entries,
      summary: redact(summary),
      createdAt: Date.now(),
    }).returning().get()
    this.session.event(run.id, 'threat_model.saved', `Threat model ranked ${entries.length} approved hosts.`, {
      threatModelId: row.id, scopeRevision: run.scopeRevision, hosts: entries.length,
    })
    return row
  }

  latestThreatModel(runId: string, goalRevision?: number): ThreatModel | null {
    const where = goalRevision !== undefined
      ? and(eq(tables.threatModels.runId, runId), eq(tables.threatModels.goalRevision, goalRevision))
      : eq(tables.threatModels.runId, runId)
    return this.session.db.select().from(tables.threatModels).where(where)
      .orderBy(desc(tables.threatModels.createdAt)).limit(1).get() ?? null
  }

  listChainSteps(runId: string, goalRevision?: number): ChainStep[] {
    const where = goalRevision !== undefined
      ? and(eq(tables.chainSteps.runId, runId), eq(tables.chainSteps.goalRevision, goalRevision))
      : eq(tables.chainSteps.runId, runId)
    return this.session.db.select().from(tables.chainSteps).where(where)
      .orderBy(asc(tables.chainSteps.seq), desc(tables.chainSteps.priority)).all()
  }

  addChainStep(run: Run, input: {
    title: string
    hypothesis: string
    category?: OwaspCategory | string
    priority?: number
    targetAssetIds: string[]
    skills?: string[]
    dependsOnFactIds?: string[]
    dependsOnStepIds?: string[]
    sourceOrigins?: string[]
    specialistProfile?: SpecialistProfile | null
    trialGroupId?: string | null
    trialIndex?: number
  }): ChainStep {
    if (
      input.specialistProfile !== undefined &&
      input.specialistProfile !== null &&
      !(specialistProfiles as readonly string[]).includes(input.specialistProfile)
    ) {
      throw new Error(`Invalid specialistProfile "${String(input.specialistProfile)}": expected one of ${specialistProfiles.join(', ')}.`)
    }
    const existingSteps = this.listChainSteps(run.id)
    const nextSeq = (existingSteps.at(-1)?.seq ?? 0) + 1
    const depFactIds = [...new Set(input.dependsOnFactIds ?? [])]
    const depStepIds = [...new Set(input.dependsOnStepIds ?? [])]
    const origins = new Set<string>(input.sourceOrigins ?? [])
    for (const assetId of input.targetAssetIds) {
      const asset = run.candidates.find(c => c.id === assetId)
      if (asset) origins.add(asset.origin)
    }
    if (depFactIds.length) {
      const depFacts = this.session.db.select().from(tables.facts).where(and(
        eq(tables.facts.runId, run.id), inArray(tables.facts.id, depFactIds),
      )).all()
      for (const f of depFacts) {
        origins.add(f.origin)
        for (const o of f.sourceOrigins) origins.add(o)
      }
    }
    const allDepStepsComplete = depStepIds.every(sid => existingSteps.find(s => s.id === sid)?.status === 'complete')
    const now = Date.now()
    const step = this.session.transaction(() => {
      const created = this.session.db.insert(tables.chainSteps).values({
        id: randomUUID(),
        runId: run.id,
        goalRevision: run.goalRevision,
        scopeRevision: run.scopeRevision,
        seq: nextSeq,
        title: redact(input.title.slice(0, 200)),
        hypothesis: redact(input.hypothesis.slice(0, 1200)),
        category: input.category ?? 'misconfig-exposure',
        priority: Math.max(0, Math.min(100, Math.round(input.priority ?? 50))),
        targetAssetIds: [...new Set(input.targetAssetIds)],
        skills: [...new Set(input.skills ?? [])],
        dependsOnFactIds: depFactIds,
        dependsOnStepIds: depStepIds,
        status: allDepStepsComplete ? 'ready' : 'pending',
        assignedWorkerId: null,
        specialistProfile: input.specialistProfile ?? null,
        trialGroupId: input.trialGroupId ?? null,
        trialIndex: Math.max(0, Math.round(input.trialIndex ?? 0)),
        sourceOrigins: [...origins],
        createdAt: now,
        updatedAt: now,
      }).returning().get()
      for (const fId of depFactIds) {
        this.findings.addGraphEdge(run.id, { fromKind: 'step', fromId: created.id, toKind: 'fact', toId: fId, edgeKind: 'depends_on' })
      }
      for (const sId of depStepIds) {
        this.findings.addGraphEdge(run.id, { fromKind: 'step', fromId: created.id, toKind: 'step', toId: sId, edgeKind: 'depends_on' })
      }
      return created
    }, { behavior: 'immediate' })
    this.session.event(run.id, 'chain_step.created', `Planned step #${step.seq}: ${step.title}`, {
      stepId: step.id, seq: step.seq, priority: step.priority, category: step.category,
    })
    return step
  }

  updateChainStep(stepId: string, patch: Partial<ChainStep>): ChainStep {
    const existing = this.session.db.select().from(tables.chainSteps).where(eq(tables.chainSteps.id, stepId)).get()
    if (!existing) throw new Error('Chain step not found.')
    // `canceled` is terminal: a sibling trial's worker can finish after early-stop and must not
    // resurrect its step as complete/running.
    if (existing.status === 'canceled' && patch.status && patch.status !== 'canceled') {
      return existing as unknown as ChainStep
    }
    const updated = this.session.db.update(tables.chainSteps).set({ ...patch, updatedAt: Date.now() })
      .where(eq(tables.chainSteps.id, stepId)).returning().get()
    if (!updated) throw new Error('Chain step not found.')
    return updated
  }

  refreshReadyChainSteps(runId: string, goalRevision: number) {
    const steps = this.listChainSteps(runId, goalRevision)
    const stepById = new Map(steps.map(s => [s.id, { ...s }]))
    const runFacts = new Map(
      this.session.db.select({ id: tables.facts.id, tainted: tables.facts.tainted }).from(tables.facts)
        .where(eq(tables.facts.runId, runId)).all().map(f => [f.id, f]),
    )
    // Fixed-point propagation so transitive chains (A blocked/canceled/tainted -> B -> C)
    // resolve in one pass and circuit-open steps (M-12) can never wedge driveInvestigation.
    let changed = true
    while (changed) {
      changed = false
      for (const step of stepById.values()) {
        if (step.status !== 'pending') continue
        const taintedDep = step.dependsOnStepIds.some(sid => {
          const s = stepById.get(sid)
          return s && (s.status === 'tainted' || s.status === 'canceled' || s.status === 'blocked')
        }) || step.dependsOnFactIds.some(fid => runFacts.get(fid)?.tainted)
        if (taintedDep) {
          this.updateChainStep(step.id, { status: 'tainted' })
          step.status = 'tainted'
          changed = true
          continue
        }
        const ready = step.dependsOnStepIds.every(sid => stepById.get(sid)?.status === 'complete') &&
          step.dependsOnFactIds.every(fid => {
            const f = runFacts.get(fid)
            return f && !f.tainted
          })
        if (ready) {
          this.updateChainStep(step.id, { status: 'ready' })
          step.status = 'ready'
          changed = true
        }
      }
    }
  }

  listDigests(runId: string, activeOnly = true): GraphDigest[] {
    const where = activeOnly
      ? and(eq(tables.graphDigests.runId, runId), eq(tables.graphDigests.active, true))
      : eq(tables.graphDigests.runId, runId)
    return this.session.db.select().from(tables.graphDigests).where(where)
      .orderBy(desc(tables.graphDigests.createdAt)).all()
  }

  getDigest(runId: string, digestId: string) {
    this.run(runId)
    const digest = this.session.db.select().from(tables.graphDigests).where(and(
      eq(tables.graphDigests.runId, runId), eq(tables.graphDigests.id, digestId),
    )).get()
    if (!digest) throw new Error('Graph digest not found.')
    const coveredFacts = digest.coveredFactIds.length
      ? this.session.db.select().from(tables.facts).where(and(
          eq(tables.facts.runId, runId),
          eq(tables.facts.tainted, false),
          inArray(tables.facts.id, digest.coveredFactIds),
        )).all()
      : []
    return { digest, facts: coveredFacts as SerializableFact[] }
  }

  saveDigest(runId: string, input: {
    roundNo: number
    level: 'minor' | 'major'
    signatureHash: string
    summary: string
    coveredFactIds: string[]
    coveredAssignmentIds: string[]
    supersedeDigestIds?: string[]
  }): GraphDigest {
    const digest = this.session.transaction(() => {
      const created = this.session.db.insert(tables.graphDigests).values({
        id: randomUUID(),
        runId,
        roundNo: input.roundNo,
        level: input.level,
        signatureHash: input.signatureHash,
        summary: redact(input.summary),
        coveredFactIds: [...new Set(input.coveredFactIds)],
        coveredAssignmentIds: [...new Set(input.coveredAssignmentIds)],
        active: true,
        createdAt: Date.now(),
      }).returning().get()
      if (created.coveredFactIds.length) {
        this.session.db.update(tables.facts).set({ digestId: created.id }).where(and(
          eq(tables.facts.runId, runId), inArray(tables.facts.id, created.coveredFactIds),
        )).run()
        for (const fId of created.coveredFactIds) {
          this.findings.addGraphEdge(runId, { fromKind: 'digest', fromId: created.id, toKind: 'fact', toId: fId, edgeKind: 'covers' })
        }
      }
      if (input.supersedeDigestIds?.length) {
        this.session.db.update(tables.graphDigests).set({ active: false }).where(and(
          eq(tables.graphDigests.runId, runId), inArray(tables.graphDigests.id, input.supersedeDigestIds),
        )).run()
      }
      return created
    }, { behavior: 'immediate' })
    this.session.event(runId, 'graph.compacted', `Created ${digest.level} digest covering ${digest.coveredFactIds.length} facts.`, {
      digestId: digest.id, level: digest.level, roundNo: digest.roundNo,
    })
    return digest
  }

  // --- Tier 3 Approval Requests & Durable Route Leases ---

  createApprovalRequest(run: Run, assignment: Assignment, input: {
    origin: string
    method: string
    pathAndQuery: string
    personaHandle?: string | null
    rationale: string
    requestPreview: string
    policyNote?: string | null
    riskLevel?: ApprovalRiskLevel | null
    expiresInMs?: number
    secrets?: readonly NamedSecret[]
  }): ApprovalRequest {
    const secrets = input.secrets ?? []
    const now = Date.now()
    const row = this.session.db.insert(tables.approvalRequests).values({
      id: randomUUID(),
      runId: run.id,
      assignmentId: assignment.id,
      scopeRevision: run.scopeRevision,
      origin: input.origin,
      method: input.method.toUpperCase(),
      pathAndQuery: redact(input.pathAndQuery, secrets),
      personaHandle: input.personaHandle ?? null,
      rationale: redact(input.rationale, secrets),
      requestPreview: redact(input.requestPreview, secrets),
      status: 'pending',
      decidedBy: null,
      decidedAt: null,
      policyNote: input.policyNote ? redact(input.policyNote, secrets) : null,
      riskLevel: input.riskLevel ?? null,
      expiresAt: now + (input.expiresInMs ?? 15 * 60_000),
      createdAt: now,
    }).returning().get()
    this.updateWorker(assignment.id, { status: 'waiting_approval' })
    this.session.event(run.id, 'approval.requested', `Tier 3 approval requested for ${row.method} ${row.origin}${row.pathAndQuery.slice(0, 80)}.`, {
      approvalId: row.id, assignmentId: assignment.id, origin: row.origin, method: row.method,
      riskLevel: row.riskLevel, policyNote: row.policyNote,
    })
    this.session.message(run.id, run.coordinatorId, 'kovo',
      `Tier 3 approval required: ${row.method} ${row.origin}${row.pathAndQuery}\nRationale: ${row.rationale}`)
    return row
  }

  /**
   * Append an audit row for an automatic Tier-3 decision. These rows are deliberately NOT an
   * authorization source: the broker fast path only accepts an exact, single-use fingerprint from
   * the Execution ledger (see approval-judge.authorizeStateChange). `expiresAt` here only bounds
   * how long the audit row is considered recent for operator review; it never grants a later probe.
   */
  recordAutoApprovalDecision(run: Run, assignment: Assignment, input: {
    origin: string
    method: string
    pathAndQuery: string
    personaHandle?: string | null
    rationale: string
    requestPreview: string
    decision: 'approved' | 'denied'
    decidedBy: Exclude<ApprovalDecidedBy, 'operator'>
    riskLevel: ApprovalRiskLevel
    policyNote: string
    expiresInMs?: number
    secrets?: readonly NamedSecret[]
  }): ApprovalRequest {
    const secrets = input.secrets ?? []
    const now = Date.now()
    const row = this.session.db.insert(tables.approvalRequests).values({
      id: randomUUID(),
      runId: run.id,
      assignmentId: assignment.id,
      scopeRevision: run.scopeRevision,
      origin: input.origin,
      method: input.method.toUpperCase(),
      pathAndQuery: redact(input.pathAndQuery, secrets),
      personaHandle: input.personaHandle ?? null,
      rationale: redact(input.rationale, secrets),
      requestPreview: redact(input.requestPreview, secrets),
      status: input.decision,
      decidedBy: input.decidedBy,
      decidedAt: now,
      policyNote: redact(input.policyNote, secrets),
      riskLevel: input.riskLevel,
      expiresAt: now + (input.expiresInMs ?? 15 * 60_000),
      createdAt: now,
    }).returning().get()
    const kind = input.decision === 'approved' ? 'approval.auto_approved' : 'approval.auto_denied'
    const verb = input.decision === 'approved' ? 'auto-approved' : 'auto-denied'
    this.session.event(run.id, kind, `Tier 3 probe ${verb} (${input.decidedBy}) for ${row.method} ${row.origin}${row.pathAndQuery.slice(0, 80)}.`, {
      approvalId: row.id,
      assignmentId: assignment.id,
      origin: row.origin,
      method: row.method,
      decidedBy: row.decidedBy,
      riskLevel: row.riskLevel,
      policyNote: row.policyNote,
    })
    return row
  }

  getApprovalRequest(runId: string, approvalId: string): ApprovalRequest {
    const row = this.session.db.select().from(tables.approvalRequests).where(and(
      eq(tables.approvalRequests.runId, runId), eq(tables.approvalRequests.id, approvalId),
    )).get()
    if (!row) throw new Error('Approval request not found.')
    return row
  }

  listApprovalRequests(runId: string, status?: ApprovalRequest['status']): ApprovalRequest[] {
    const where = status
      ? and(eq(tables.approvalRequests.runId, runId), eq(tables.approvalRequests.status, status))
      : eq(tables.approvalRequests.runId, runId)
    return this.session.db.select().from(tables.approvalRequests).where(where)
      .orderBy(desc(tables.approvalRequests.createdAt)).all()
  }

  /**
   * Grant (or refresh) a durable, route-scoped lease. Unlike the single-use 60 s body-hash
   * fingerprint, a lease authorizes every probe iteration and independent replay on the normalized
   * route, until the run's scope revision changes or the origin leaves scope.
   */
  grantApprovalLease(run: Run, input: {
    origin: string
    method: string
    pathAndQuery: string
    personaHandle?: string | null
    sourceApprovalId?: string | null
    createdBy?: string
    expiresInMs?: number | null
  }): ApprovalLeaseRow {
    const origin = normalizeScopeOrigin(input.origin)
    if (!origin) throw new Error('Approval lease origin is malformed.')
    const method = input.method.trim().toUpperCase()
    if (!method) throw new Error('Approval lease method is required.')
    const routePattern = normalizeApprovalPathPattern(input.pathAndQuery)
    const now = Date.now()
    const row = this.session.db.insert(tables.approvalLeases).values({
      id: randomUUID(),
      runId: run.id,
      scopeRevision: run.scopeRevision,
      origin,
      method,
      routePattern,
      personaHandle: input.personaHandle ?? null,
      status: 'active',
      sourceApprovalId: input.sourceApprovalId ?? null,
      createdBy: input.createdBy ?? 'operator',
      createdAt: now,
      updatedAt: now,
      expiresAt: input.expiresInMs === null || input.expiresInMs === undefined ? null : now + input.expiresInMs,
      uses: 0,
      lastUsedAt: null,
    }).onConflictDoUpdate({
      target: [
        tables.approvalLeases.runId, tables.approvalLeases.origin, tables.approvalLeases.method,
        tables.approvalLeases.routePattern, tables.approvalLeases.scopeRevision,
      ],
      set: {
        status: 'active',
        updatedAt: now,
        personaHandle: input.personaHandle ?? null,
        sourceApprovalId: input.sourceApprovalId ?? null,
        expiresAt: input.expiresInMs == null ? null : now + input.expiresInMs,
      },
    }).returning().get()
    this.session.event(run.id, 'approval.lease_granted', `Durable route lease for ${method} ${origin}${routePattern}.`, {
      leaseId: row.id, origin, method, routePattern, sourceApprovalId: row.sourceApprovalId,
    })
    return row
  }

  listApprovalLeases(runId: string, status?: ApprovalLeaseRow['status']): ApprovalLeaseRow[] {
    const where = status
      ? and(eq(tables.approvalLeases.runId, runId), eq(tables.approvalLeases.status, status))
      : eq(tables.approvalLeases.runId, runId)
    return this.session.db.select().from(tables.approvalLeases).where(where)
      .orderBy(desc(tables.approvalLeases.createdAt)).all()
  }

  revokeApprovalLease(run: Run, leaseId: string, reason = 'Revoked by operator.'): ApprovalLeaseRow {
    const updated = this.session.db.update(tables.approvalLeases).set({ status: 'revoked', updatedAt: Date.now() })
      .where(and(eq(tables.approvalLeases.runId, run.id), eq(tables.approvalLeases.id, leaseId)))
      .returning().get()
    if (!updated) throw new Error('Approval lease not found.')
    this.session.event(run.id, 'approval.lease_revoked', `Durable route lease revoked: ${updated.method} ${updated.origin}${updated.routePattern}.`, {
      leaseId: updated.id, origin: updated.origin, method: updated.method, reason,
    })
    return updated
  }

  revokeApprovalLeasesForOrigin(run: Run, origin: string): number {
    const normalized = normalizeScopeOrigin(origin)
    if (!normalized) return 0
    const revoked = this.session.db.update(tables.approvalLeases).set({ status: 'revoked', updatedAt: Date.now() })
      .where(and(
        eq(tables.approvalLeases.runId, run.id),
        eq(tables.approvalLeases.status, 'active'),
        eq(tables.approvalLeases.origin, normalized),
      )).returning({ id: tables.approvalLeases.id }).all()
    if (revoked.length) {
      this.session.event(run.id, 'approval.lease_revoked', `${revoked.length} durable lease(s) revoked for ${normalized}.`, {
        origin: normalized, leases: revoked.map(row => row.id),
      })
    }
    return revoked.length
  }

  /**
   * Broker-side lease check. A match authorizes the normalized route without a per-request
   * approval; the lease must belong to the run's current scope revision and be unexpired.
   */
  leaseAuthorizes(runId: string, origin: string, method: string, pathAndQuery: string): boolean {
    const normalized = normalizeScopeOrigin(origin)
    if (!normalized) return false
    let run: Run
    try {
      run = this.run(runId)
    } catch {
      return false
    }
    const normalizedPattern = normalizeApprovalPathPattern(pathAndQuery)
    const legacyRoutePattern = routePatternForPath(pathAndQuery)
    const routePatterns = normalizedPattern === legacyRoutePattern
      ? [normalizedPattern]
      : [normalizedPattern, legacyRoutePattern]
    const row = this.session.db.select().from(tables.approvalLeases).where(and(
      eq(tables.approvalLeases.runId, runId),
      eq(tables.approvalLeases.origin, normalized),
      eq(tables.approvalLeases.method, method.trim().toUpperCase()),
      inArray(tables.approvalLeases.routePattern, routePatterns),
      eq(tables.approvalLeases.status, 'active'),
      eq(tables.approvalLeases.scopeRevision, run.scopeRevision),
    )).get()
    if (!row) return false
    if (row.expiresAt !== null && row.expiresAt <= Date.now()) {
      this.session.db.update(tables.approvalLeases).set({ status: 'expired', updatedAt: Date.now() })
        .where(eq(tables.approvalLeases.id, row.id)).run()
      return false
    }
    this.session.db.update(tables.approvalLeases).set({
      uses: row.uses + 1, lastUsedAt: Date.now(), updatedAt: Date.now(),
    }).where(eq(tables.approvalLeases.id, row.id)).run()
    return true
  }

  /** Ready-to-wire broker grant hook: `approvalLeases: storage.approvalLeaseAuthorizer(runId)`. */
  approvalLeaseAuthorizer(runId: string): (origin: string, method: string, pathAndQuery: string) => boolean {
    return (origin, method, pathAndQuery) => this.leaseAuthorizes(runId, origin, method, pathAndQuery)
  }

  /**
   * Park an assignment in `awaiting_approval` with its worker slot released. The caller persists
   * the approval request separately; this is the non-blocking half of the operator opt-in flow.
   */
  parkWorkerForApproval(run: Run, assignmentId: string): Assignment {
    const existing = this.worker(assignmentId)
    if (existing.runId !== run.id) throw new Error('Assignment does not belong to this run.')
    if (!['queued', 'running', 'waiting_approval'].includes(existing.status)) {
      throw new Error(`Cannot park an assignment in state ${existing.status}.`)
    }
    const updated = this.updateWorker(assignmentId, {
      status: 'waiting_approval',
      approvalParkedAt: Date.now(),
      lease: null,
      leaseExpiresAt: null,
    })!
    this.session.event(run.id, 'approval.worker_parked', `Worker parked awaiting approval; slot released.`, {
      assignmentId,
    })
    return updated
  }

  /** Resume a parked assignment with a fresh worker lease (caller re-enters the scheduler). */
  resumeParkedWorker(run: Run, assignmentId: string): Assignment {
    const existing = this.worker(assignmentId)
    if (existing.runId !== run.id) throw new Error('Assignment does not belong to this run.')
    if (existing.status !== 'waiting_approval') {
      throw new Error(`Assignment is not awaiting approval (state ${existing.status}).`)
    }
    const updated = this.updateWorker(assignmentId, {
      status: 'running',
      approvalParkedAt: null,
      lease: randomUUID(),
      leaseExpiresAt: Date.now() + 10 * 60_000,
    })!
    this.session.event(run.id, 'approval.worker_resumed', `Worker resumed with a fresh slot lease.`, {
      assignmentId, leaseExpiresAt: updated.leaseExpiresAt,
    })
    return updated
  }

  parkedWorkerCount(runId: string): number {
    const row = this.session.client.prepare(
      `SELECT count(*) AS c FROM assignments WHERE run_id = ? AND status = 'waiting_approval' AND approval_parked_at IS NOT NULL AND lease IS NULL`,
    ).get(runId) as { c?: number } | undefined
    return Number(row?.c ?? 0)
  }

  decideApproval(run: Run, approvalId: string, decision: 'approved' | 'denied'): ApprovalRequest {
    const existing = this.getApprovalRequest(run.id, approvalId)
    if (existing.status !== 'pending') throw new Error(`Approval request is already ${existing.status}.`)
    if (existing.scopeRevision !== run.scopeRevision) {
      this.session.db.update(tables.approvalRequests).set({ status: 'canceled', decidedAt: Date.now() })
        .where(eq(tables.approvalRequests.id, approvalId)).run()
      throw new Error('Scope changed before this approval could be decided.')
    }
    const updated = this.session.db.update(tables.approvalRequests).set({
      status: decision,
      decidedBy: 'operator',
      decidedAt: Date.now(),
    }).where(eq(tables.approvalRequests.id, approvalId)).returning().get()!
    this.session.event(run.id, 'approval.decided', `Tier 3 request ${decision} for ${updated.method} ${updated.origin}.`, {
      approvalId: updated.id, assignmentId: updated.assignmentId, decision, decidedBy: 'operator',
    })
    if (decision === 'approved') {
      // Operator opt-in grants a durable route-scoped lease, not a 60 s single-use body-hash token.
      this.grantApprovalLease(run, {
        origin: updated.origin,
        method: updated.method,
        pathAndQuery: updated.pathAndQuery,
        personaHandle: updated.personaHandle,
        sourceApprovalId: updated.id,
        createdBy: 'operator',
      })
    }
    this.session.message(run.id, run.coordinatorId, 'kovo',
      `Tier 3 request ${decision}: ${updated.method} ${updated.origin}${updated.pathAndQuery}`)
    return updated
  }

  setApprovalPolicy(run: Run, approvalPolicy: ApprovalPolicy) {
    if (['complete', 'stopped', 'failed'].includes(run.status)) {
      throw new Error('Cannot change approval policy after a run has ended.')
    }
    const previous = run.approvalPolicy ?? 'auto_review'
    const project = this.projects.project(run.projectId)
    const derivedEnvironmentMode = !this.hasExplicitEnvironmentMode(run.id)
      ? deriveDefaultEnvironmentMode(project.environment, run.capabilityTier, approvalPolicy)
      : undefined
    this.updateRun(run.id, {
      approvalPolicy,
      ...(derivedEnvironmentMode !== undefined && derivedEnvironmentMode !== run.environmentMode
        ? { environmentMode: derivedEnvironmentMode }
        : {}),
    })
    let autoApprovedCount = 0
    if (approvalPolicy === 'yolo') {
      const now = Date.now()
      const pending = this.listApprovalRequests(run.id, 'pending')
      for (const req of pending) {
        if (req.scopeRevision !== run.scopeRevision) {
          this.session.db.update(tables.approvalRequests).set({ status: 'canceled', decidedAt: now })
            .where(eq(tables.approvalRequests.id, req.id)).run()
          continue
        }
        this.session.db.update(tables.approvalRequests).set({
          status: 'approved',
          decidedBy: 'auto-yolo',
          decidedAt: now,
          riskLevel: 'low',
          policyNote: 'Auto-approved when operator switched Tier 3 policy to YOLO autonomous mode.',
        }).where(eq(tables.approvalRequests.id, req.id)).run()
        autoApprovedCount += 1
        this.session.event(run.id, 'approval.auto_approved', `Auto-approved ${req.method} ${req.origin}${req.pathAndQuery.slice(0, 80)} via YOLO policy switch.`, {
          approvalId: req.id, assignmentId: req.assignmentId, decidedBy: 'auto-yolo',
        })
      }
    }
    this.session.event(run.id, 'approval.policy_changed', `Tier 3 approval policy switched from ${previous} to ${approvalPolicy}.`, {
      previous, approvalPolicy, autoApprovedCount,
    })
    this.session.message(run.id, run.coordinatorId, 'kovo',
      `Tier 3 approval policy updated to ${approvalPolicy}${autoApprovedCount > 0 ? ` (${autoApprovedCount} pending ${autoApprovedCount === 1 ? 'request' : 'requests'} auto-approved)` : ''}.`)
  }

  approveSimilarEndpoint(run: Run, approvalId: string) {
    const existing = this.getApprovalRequest(run.id, approvalId)
    const now = Date.now()
    if (existing.status === 'pending') {
      if (existing.scopeRevision !== run.scopeRevision) {
        this.session.db.update(tables.approvalRequests).set({ status: 'canceled', decidedAt: now })
          .where(eq(tables.approvalRequests.id, approvalId)).run()
        throw new Error('Scope changed before this approval could be decided.')
      }
      this.session.db.update(tables.approvalRequests).set({
        status: 'approved',
        decidedBy: 'operator',
        decidedAt: now,
        policyNote: 'Approved by operator with similar endpoint pattern.',
      }).where(eq(tables.approvalRequests.id, approvalId)).run()
    } else if (existing.status !== 'approved') {
      throw new Error(`Approval request is already ${existing.status}.`)
    }

    const pathPattern = normalizeApprovalPathPattern(existing.pathAndQuery)
    const newPattern: ApprovedEndpointPattern = {
      origin: existing.origin,
      method: existing.method.toUpperCase(),
      pathPattern,
      scopeRevision: run.scopeRevision,
      createdAt: now,
    }
    const currentPatterns = run.approvedEndpointPatterns ?? []
    const alreadyStored = currentPatterns.some(p =>
      p.origin === newPattern.origin &&
      p.method.toUpperCase() === newPattern.method &&
      p.pathPattern === newPattern.pathPattern &&
      p.scopeRevision === newPattern.scopeRevision,
    )
    const nextPatterns = alreadyStored ? currentPatterns : [...currentPatterns, newPattern]
    if (!alreadyStored) {
      this.updateRun(run.id, { approvedEndpointPatterns: nextPatterns })
    }

    // Also approve any other pending requests matching this exact newly approved pattern
    let matchedPendingCount = 0
    for (const req of this.listApprovalRequests(run.id, 'pending')) {
      if (req.id === approvalId || req.scopeRevision !== run.scopeRevision) continue
      if (matchesApprovedEndpointPattern({ origin: req.origin, method: req.method, pathAndQuery: req.pathAndQuery }, [newPattern])) {
        this.session.db.update(tables.approvalRequests).set({
          status: 'approved',
          decidedBy: 'auto-review:rule',
          decidedAt: now,
          riskLevel: 'low',
          policyNote: `Auto-approved via operator-approved pattern ${newPattern.method} ${newPattern.pathPattern}.`,
        }).where(eq(tables.approvalRequests.id, req.id)).run()
        matchedPendingCount += 1
      }
    }

    this.session.event(run.id, 'approval.pattern_approved', `Approved similar probes matching ${newPattern.method} ${newPattern.origin}${newPattern.pathPattern}.`, {
      approvalId: existing.id,
      origin: newPattern.origin,
      method: newPattern.method,
      pathPattern: newPattern.pathPattern,
      matchedPendingCount,
    })
    this.grantApprovalLease(run, {
      origin: newPattern.origin,
      method: newPattern.method,
      pathAndQuery: newPattern.pathPattern,
      personaHandle: existing.personaHandle,
      sourceApprovalId: existing.id,
      createdBy: 'operator',
    })
    this.session.message(run.id, run.coordinatorId, 'kovo',
      `Approved ${existing.method} ${existing.origin}${existing.pathAndQuery} and future probes matching ${newPattern.method} ${newPattern.pathPattern}.`)
  }

  approveAllPending(run: Run): number {
    const now = Date.now()
    const pending = this.listApprovalRequests(run.id, 'pending')
    let approvedCount = 0
    for (const req of pending) {
      if (req.scopeRevision !== run.scopeRevision) {
        this.session.db.update(tables.approvalRequests).set({ status: 'canceled', decidedAt: now })
          .where(eq(tables.approvalRequests.id, req.id)).run()
        continue
      }
      this.session.db.update(tables.approvalRequests).set({
        status: 'approved',
        decidedBy: 'operator',
        decidedAt: now,
        policyNote: 'Batch-approved by operator (Approve all pending).',
      }).where(eq(tables.approvalRequests.id, req.id)).run()
      this.grantApprovalLease(run, {
        origin: req.origin,
        method: req.method,
        pathAndQuery: req.pathAndQuery,
        personaHandle: req.personaHandle,
        sourceApprovalId: req.id,
        createdBy: 'operator',
      })
      approvedCount += 1
    }
    this.session.event(run.id, 'approval.batch_approved', `Operator batch-approved ${approvedCount} pending Tier 3 ${approvedCount === 1 ? 'request' : 'requests'}.`, {
      approvedCount,
    })
    if (approvedCount > 0) {
      this.session.message(run.id, run.coordinatorId, 'kovo',
        `Batch-approved ${approvedCount} pending Tier 3 ${approvedCount === 1 ? 'probe' : 'probes'}.`)
    }
    return approvedCount
  }

  // --- Budget & Spend Tracking ---

  recordLlmSpend(runId: string, delta: { usd?: number; tokens?: number; turns?: number }) {
    const usd = Math.max(0, delta.usd ?? 0)
    const tokens = Math.max(0, Math.round(delta.tokens ?? 0))
    const turns = Math.max(0, Math.round(delta.turns ?? 0))
    return this.session.db.update(tables.runs).set({
      spentUsd: sql`${tables.runs.spentUsd} + ${usd}`,
      spentTokens: sql`${tables.runs.spentTokens} + ${tokens}`,
      turnsUsed: sql`${tables.runs.turnsUsed} + ${turns}`,
    }).where(eq(tables.runs.id, runId)).returning().get()
  }

  checkBudgetExceeded(runId: string): boolean {
    const run = this.run(runId)
    const usdExceeded = run.spentUsd >= run.budgetUsd
    const reqExceeded = run.budgetRequests > 0 && run.spentRequests >= run.budgetRequests
    if (!usdExceeded && !reqExceeded) return false
    if (run.status === 'running') {
      this.session.transaction(() => {
        const current = this.run(runId)
        if (current.status !== 'running') return
        this.setStatus(current, 'budget_paused')
        const reason = usdExceeded
          ? `USD spend budget reached ($${current.spentUsd.toFixed(2)} / $${current.budgetUsd.toFixed(2)}).`
          : `Broker request budget reached (${current.spentRequests} / ${current.budgetRequests}).`
        this.session.event(runId, 'run.budget_paused', `${reason} Raise the budget and click Resume to continue.`, {
          spentUsd: current.spentUsd, budgetUsd: current.budgetUsd,
          spentRequests: current.spentRequests, budgetRequests: current.budgetRequests,
        })
        this.session.message(runId, current.coordinatorId, 'kovo',
          `Run paused: ${reason} A partial report has been saved. Raise the budget to resume.`)
        this.writeReport(this.run(runId), true)
      }, { behavior: 'immediate' })
    }
    return true
  }

  // --- Run Creation, Workers, Scope Revocation, Reports & Commands ---

  createRun(input: Omit<z.output<typeof newRun>, 'approvalPolicy' | 'multiTrialEnabled'> & {
    approvalPolicy?: ApprovalPolicy
    multiTrialEnabled?: boolean
  }) {
    return this.session.operate(input, () => {
      const project = this.projects.project(input.projectId)
      const goal = redact(input.goal)
      const capabilityTier: CapabilityTier = input.sourceMode === 'prepared' ? 0 : (input.capabilityTier ?? 1)
      const validPersonaIds = new Set(this.session.listProjectPersonas(project.id).map(p => p.id))
      const approvedPersonaIds = capabilityTier >= 2
        ? [...new Set((input.approvedPersonaIds ?? []).filter(pid => validPersonaIds.has(pid)))]
        : []
      const approvalPolicy: ApprovalPolicy = input.approvalPolicy ?? 'auto_review'
      const defaultReqs = project.environment === 'local-lab' ? defaultLabBudgetRequests : defaultPublicBudgetRequests
      const run = this.session.db.insert(tables.runs).values({
        id: randomUUID(),
        projectId: project.id,
        workspaceId: this.session.workspace.id,
        coordinatorId: randomUUID(),
        originalGoal: goal,
        goal,
        goalRevision: 0,
        scopeRevision: 0,
        phase: 'consent',
        status: 'waiting',
        sourceMode: input.sourceMode,
        capabilityTier,
        approvalPolicy,
        approvedEndpointPatterns: [],
        approvedPersonaIds,
        roundNo: 0,
        budgetUsd: input.budgetUsd ?? defaultBudgetUsd,
        budgetRequests: input.budgetRequests ?? defaultReqs ?? defaultBudgetRequests,
        spentUsd: 0,
        spentTokens: 0,
        spentRequests: 0,
        turnsUsed: 0,
        maxRpsPerOrigin: input.maxRpsPerOrigin ?? defaultMaxRpsPerOrigin,
        workerConcurrency: input.workerConcurrency ?? defaultWorkerConcurrency,
        workerMaxTurns: input.workerMaxTurns ?? defaultWorkerMaxTurns,
        dynamicStepBudget: null,
        multiTrialEnabled: input.multiTrialEnabled ?? true,
        phase0CompletedAt: null,
        candidates: [],
        approved: [],
        authOrigins: [],
        assetOrigins: [],
        environmentMode: deriveDefaultEnvironmentMode(project.environment, capabilityTier, approvalPolicy),
        routeDenylist: [],
        createdAt: Date.now(),
      }).returning().get()
      for (const [handle, role] of [
        ['coordinator', 'coordinator'],
        ['verifier', 'verifier'],
        ['broker', 'system'],
        ['canary', 'system'],
      ] as const) {
        this.upsertBoardMember(run, {
          handle,
          role,
          sessionId: handle === 'coordinator' ? run.coordinatorId : `system:${handle}`,
          state: 'waiting',
          sourceOrigins: [],
        })
      }
      this.session.event(run.id, 'run.created', 'Run created.', {
        capabilityTier,
        approvalPolicy: run.approvalPolicy,
        sourceMode: input.sourceMode,
      })
      const goalMessageId = this.session.message(run.id, run.coordinatorId, 'operator', goal)
      this.updateRun(run.id, { reviewPlan: { status: 'pending', goalMessageId } })
      return { id: run.id }
    })
  }

  suggestCandidateHost(run: Run, origin: string, source: string, thirdParty = false, dnsSource?: DnsSource | null) {
    if (run.candidates.some(candidate => candidate.origin === origin)) {
      return { added: false, origin }
    }
    const asset = this.projects.saveCandidate(
      run.projectId,
      { origin, source: redact(source), thirdParty, ...(dnsSource !== undefined ? { dnsSource } : {}) },
      false,
    )
    const discovery = this.workerList(run.id).find(worker => worker.phase === 'discovery' && worker.assetId === null)
    const sourceEv = discovery && this.recordInventory(run, discovery, 'Candidate source', [asset])
    const candidate = sourceEv ? { ...asset, sourceEvidenceId: sourceEv.id } : asset
    this.updateRun(run.id, { candidates: [...run.candidates, candidate] })
    this.session.event(run.id, 'asset.candidate', `Worker suggested candidate host ${origin} (unapproved until scope approval).`, {
      id: asset.id, origin: asset.origin, source: redact(source), thirdParty, sourceEvidenceId: sourceEv?.id,
    })
    return { added: true, id: asset.id, origin: asset.origin }
  }

  makeWorker(
    run: Run,
    phase: WorkerPhase,
    candidate: Candidate | undefined,
    title: string,
    objective: string,
    opts: {
      input?: Assignment
      stepId?: string | null
      maxTurns?: number
      parentFactIds?: string[]
      sourceOrigins?: string[]
    } = {},
  ): Assignment {
    const sourceOrigins = [...new Set([
      ...(candidate ? [candidate.origin] : []),
      ...(opts.sourceOrigins ?? []),
    ])]
    const assignment = this.session.db.insert(tables.assignments).values({
      id: randomUUID(),
      runId: run.id,
      assetId: candidate?.id ?? null,
      stepId: opts.stepId ?? null,
      inputAssignmentId: opts.input?.id ?? null,
      phase,
      status: 'queued',
      scopeRevision: run.scopeRevision,
      goalRevision: run.goalRevision,
      sessionId: randomUUID(),
      lease: null,
      leaseExpiresAt: null,
      attempt: 0,
      maxTurns: opts.maxTurns ?? run.workerMaxTurns ?? defaultWorkerMaxTurns,
      turnsUsed: 0,
      requestsUsed: 0,
      parentFactIds: [...new Set(opts.parentFactIds ?? [])],
      sourceOrigins,
      title: redact(title),
      objective: redact(objective),
      outcome: null,
      checks: null,
      createdAt: Date.now(),
    }).returning().get()
    const target = candidate?.origin ?? (sourceOrigins.join(', ') || 'Supplied project records')
    this.findings.addArtifact(run, assignment, 'handoff', 'assignment.md',
      [
        '# Assignment', '', objective, '',
        'Phase: ' + phase,
        'Target: ' + target,
        ...(opts.stepId ? ['Chain step: ' + opts.stepId] : []),
        ...(opts.input ? ['Input assignment: ' + opts.input.id] : []),
        'Goal: ' + run.goal,
        'Goal revision: ' + run.goalRevision,
        'Scope revision: ' + run.scopeRevision,
      ].join('\n'), 'assignment')
    return assignment
  }

  commitReviewPlan(expected: Pick<Run, 'id' | 'goalRevision' | 'scopeRevision'>, selection: SelectedChecks) {
    this.session.transaction(() => {
      const run = this.run(expected.id)
      const plan = run.reviewPlan
      if (run.status !== 'running' || plan?.status !== 'pending' ||
        run.goalRevision !== expected.goalRevision || run.scopeRevision !== expected.scopeRevision) return
      this.updateRun(run.id, { reviewPlan: { status: 'ready', goalMessageId: plan.goalMessageId, ...selection } })
      const titles = selection.checks.map(id => assessmentCheckTitles[id]).join(', ')
      const planned = selection.source === 'coordinator'
      this.session.message(run.id, run.coordinatorId, planned ? 'coordinator' : 'kovo',
        (planned ? 'Baseline checks selected: ' : 'Standard baseline checks selected: ') + titles + '.', plan.goalMessageId)
      this.session.event(run.id, 'review.planned', 'Baseline check plan saved.', {
        goalRevision: run.goalRevision, scopeRevision: run.scopeRevision, ...selection,
      })
    }, { behavior: 'immediate' })
  }

  updateRun(runId: string, state: Partial<Run>) {
    const updated = this.session.db.update(tables.runs).set(state).where(eq(tables.runs.id, runId)).returning().get()
    if (!updated) throw new Error('Run not found.')
    return updated
  }

  updateWorker(assignmentId: string, state: Partial<Assignment>) {
    return this.session.db.update(tables.assignments).set(state).where(eq(tables.assignments.id, assignmentId)).returning().get()
  }

  setStatus(run: Run, status: Run['status']) {
    this.updateRun(run.id, { status })
    if (status === 'paused' || status === 'budget_paused' || status === 'stopped' || status === 'failed') {
      this.session.db.update(tables.assignments).set({ status: 'paused', lease: null, leaseExpiresAt: null }).where(and(
        eq(tables.assignments.runId, run.id),
        inArray(tables.assignments.status, ['queued', 'running', 'waiting_approval']),
        // Operator opt-in approvals that released their slot survive pause/recovery.
        sql`NOT (${tables.assignments.status} = 'waiting_approval' AND ${tables.assignments.approvalParkedAt} IS NOT NULL)`,
      )).run()
    }
    if (status === 'running') {
      this.session.db.update(tables.assignments).set({ status: 'queued', lease: null, leaseExpiresAt: null }).where(and(
        eq(tables.assignments.runId, run.id),
        eq(tables.assignments.goalRevision, run.goalRevision),
        eq(tables.assignments.status, 'paused'),
      )).run()
    }
  }

  private discover(run: Run) {
    if (run.phase !== 'consent' || run.status !== 'waiting') throw new Error('Discovery has already started.')
    const project = this.projects.project(run.projectId)
    this.session.event(run.id, 'discovery.consented', 'Discovery consent recorded.', {
      actorId: this.session.workspace.actorId, seeds: project.seeds,
    })
    const inventory = this.session.db.select().from(tables.projectAssets).where(eq(tables.projectAssets.projectId, run.projectId)).all()
    this.updateRun(run.id, { phase: 'discovery', status: 'running' })
    const worker = this.makeWorker(run, 'discovery', undefined, 'Asset inventory', 'Review supplied project records and attribute the candidate origins.')
    const initial = this.recordInventory(run, worker, inventoryTitle, inventory)
    this.updateWorker(worker.id, { status: 'complete', outcome: 'Reviewed supplied project records.' })
    this.session.message(run.id, worker.id, 'worker', `Recorded ${inventory.length} candidates from supplied project records.`,
      undefined, [initial.id])
    this.updateRun(run.id, {
      phase: 'review', status: 'waiting',
      candidates: inventory.map(asset => ({ ...asset, sourceEvidenceId: initial.id })),
    })
    this.session.event(run.id, 'discovery.complete', 'Discovery complete. Review scope and capability tier to continue.')
    this.session.message(run.id, run.coordinatorId, 'kovo', 'Review the candidate hosts, capability tier, and personas before approving assessment.')
  }

  private recordInventory(run: Run, worker: Assignment, title: string, assets: readonly Candidate[]) {
    const records = assets.map(({ origin, thirdParty, source, dnsSource }) =>
      ({ origin, thirdParty, source, ...(dnsSource ? { dnsSource } : {}) }))
    return this.findings.addArtifact(run, worker, 'inventory', title, JSON.stringify(records, null, 2))
  }

  // --- Transitive Scope Revocation ---

  private applyTransitiveRevocation(run: Run, approvedIds: readonly string[], approvedOrigins: ReadonlySet<string>, scopeRevision: number) {
    const approvedIdSet = new Set(approvedIds)
    // Benign auth/asset hops remain valid provenance after a target origin is revoked.
    const provenanceOrigins = this.provenanceOriginsFor(run)
    const provenanceAllowed = (origin: string) =>
      approvedOrigins.has(origin) || provenanceOrigins.has(normalizeScopeOrigin(origin) ?? origin)
    const allFacts = this.session.db.select().from(tables.facts).where(eq(tables.facts.runId, run.id)).all()
    const allSteps = this.session.db.select().from(tables.chainSteps).where(eq(tables.chainSteps.runId, run.id)).all()
    const allAssignments = this.workerList(run.id)
    const allEdges = this.findings.listGraphEdges(run.id)

    // Build downstream propagation graph: upstream node key -> downstream node keys
    const downstream = new Map<string, Set<string>>()
    const addLink = (fromKey: string, toKey: string) => {
      let set = downstream.get(fromKey)
      if (!set) {
        set = new Set()
        downstream.set(fromKey, set)
      }
      set.add(toKey)
    }

    for (const edge of allEdges) {
      const fromKey = `${edge.fromKind}:${edge.fromId}`
      const toKey = `${edge.toKind}:${edge.toId}`
      if (edge.edgeKind === 'depends_on' || edge.edgeKind === 'derived_from') {
        // from depends on to -> taint flows from `to` to `from`
        addLink(toKey, fromKey)
      } else if (edge.edgeKind === 'yields' || edge.edgeKind === 'spawns' || edge.edgeKind === 'proves') {
        // from produces/spawns/proves to -> taint flows from `from` to `to`
        addLink(fromKey, toKey)
      }
    }

    // Also incorporate explicit foreign-key dependency links
    for (const step of allSteps) {
      const stepKey = `step:${step.id}`
      for (const fId of step.dependsOnFactIds) addLink(`fact:${fId}`, stepKey)
      for (const sId of step.dependsOnStepIds) addLink(`step:${sId}`, stepKey)
      if (step.assignedWorkerId) addLink(stepKey, `assignment:${step.assignedWorkerId}`)
    }
    for (const worker of allAssignments) {
      const wKey = `assignment:${worker.id}`
      for (const fId of worker.parentFactIds) addLink(`fact:${fId}`, wKey)
      if (worker.stepId) addLink(`step:${worker.stepId}`, wKey)
    }
    for (const fact of allFacts) {
      addLink(`assignment:${fact.assignmentId}`, `fact:${fact.id}`)
    }

    const taintedNodes = new Set<string>()
    const queue: string[] = []
    const enqueue = (key: string) => {
      if (taintedNodes.has(key)) return
      taintedNodes.add(key)
      queue.push(key)
    }

    // Seed with directly affected facts, steps, assignments
    for (const fact of allFacts) {
      if (!approvedOrigins.has(fact.origin) || fact.sourceOrigins.some(o => !provenanceAllowed(o))) {
        enqueue(`fact:${fact.id}`)
      }
    }
    for (const step of allSteps) {
      if (step.sourceOrigins.some(o => !provenanceAllowed(o)) ||
          step.targetAssetIds.some(aid => !approvedIdSet.has(aid))) {
        enqueue(`step:${step.id}`)
      }
    }
    for (const worker of allAssignments) {
      if (worker.phase === 'discovery') continue
      const touchesUnapproved =
        (worker.assetId !== null && !approvedIdSet.has(worker.assetId)) ||
        worker.sourceOrigins.some(o => !provenanceAllowed(o)) ||
        this.findings.brokerOrigins(worker).some(o => !provenanceAllowed(o))
      if (touchesUnapproved) enqueue(`assignment:${worker.id}`)
    }

    // BFS transitive propagation
    while (queue.length) {
      const current = queue.shift()!
      const neighbors = downstream.get(current)
      if (!neighbors) continue
      for (const next of neighbors) enqueue(next)
    }

    const taintedFactIds: string[] = []
    const taintedStepIds: string[] = []
    const canceledAssignmentIds: string[] = []

    for (const key of taintedNodes) {
      const [kind, itemId] = key.split(':')
      if (kind === 'fact') taintedFactIds.push(itemId)
      else if (kind === 'step') taintedStepIds.push(itemId)
      else if (kind === 'assignment') canceledAssignmentIds.push(itemId)
    }

    if (taintedFactIds.length) {
      this.session.db.update(tables.facts).set({ tainted: true }).where(and(
        eq(tables.facts.runId, run.id), inArray(tables.facts.id, taintedFactIds),
      )).run()
      // Deactivate any digest covering a tainted fact
      const taintedSet = new Set(taintedFactIds)
      for (const digest of this.listDigests(run.id, true)) {
        if (digest.coveredFactIds.some(fid => taintedSet.has(fid))) {
          this.session.db.update(tables.graphDigests).set({ active: false }).where(eq(tables.graphDigests.id, digest.id)).run()
        }
      }
    }

    if (taintedStepIds.length) {
      this.session.db.update(tables.chainSteps).set({ status: 'tainted', assignedWorkerId: null, updatedAt: Date.now() }).where(and(
        eq(tables.chainSteps.runId, run.id),
        inArray(tables.chainSteps.id, taintedStepIds),
        sql`${tables.chainSteps.status} != 'canceled'`,
      )).run()
    }

    if (canceledAssignmentIds.length) {
      for (const worker of allAssignments) {
        if (canceledAssignmentIds.includes(worker.id) && !['complete', 'canceled'].includes(worker.status)) {
          this.updateWorker(worker.id, { status: 'canceled', outcome: 'Scope revoked.', lease: null, leaseExpiresAt: null })
        }
      }
    }

    // Cancel pending approvals referencing unapproved origins or canceled assignments
    const pendingApprovals = this.listApprovalRequests(run.id, 'pending')
    for (const req of pendingApprovals) {
      if (!approvedOrigins.has(req.origin) || canceledAssignmentIds.includes(req.assignmentId)) {
        this.session.db.update(tables.approvalRequests).set({ status: 'canceled', decidedAt: Date.now() })
          .where(eq(tables.approvalRequests.id, req.id)).run()
      }
    }

    // Durable leases are scoped to the current scope revision; revoke any lease on a revoked origin.
    this.session.db.update(tables.approvalLeases).set({ status: 'revoked', updatedAt: Date.now() }).where(and(
      eq(tables.approvalLeases.runId, run.id),
      eq(tables.approvalLeases.status, 'active'),
      sql`${tables.approvalLeases.scopeRevision} != ${scopeRevision}`,
    )).run()
    for (const lease of this.listApprovalLeases(run.id, 'active')) {
      if (!approvedOrigins.has(lease.origin)) {
        this.session.db.update(tables.approvalLeases).set({ status: 'revoked', updatedAt: Date.now() })
          .where(eq(tables.approvalLeases.id, lease.id)).run()
      }
    }

    const boardTaint = this.taintBoardMessagesForRevokedOrigins(run.id, approvedOrigins)

    if (taintedFactIds.length || taintedStepIds.length || canceledAssignmentIds.length) {
      this.session.event(run.id, 'scope.revoked',
        `Scope revision ${scopeRevision} tainted ${taintedFactIds.length} facts, ${taintedStepIds.length} steps, ${boardTaint.taintedMessageIds.length} board posts, and canceled ${canceledAssignmentIds.length} assignments.`,
        { scopeRevision, taintedFactIds, taintedStepIds, canceledAssignmentIds, ...boardTaint })
    }
  }

  private setScope(run: Run, cmd: Extract<RunCommand, { action: 'scope' }>) {
    const { assetIds, expectedScopeRevision, saveProject } = cmd
    if (run.scopeRevision !== expectedScopeRevision) {
      throw new Error('Scope changed since you opened this review.')
    }
    if (!canReviewScope(run.phase, run.status)) {
      throw new Error('Scope changes are unavailable in this phase.')
    }
    const approved = [...new Set(assetIds)]
    if (approved.some(id => !run.candidates.some(asset => asset.id === id))) {
      throw new Error('Select assets from this run’s inventory.')
    }
    const project = this.projects.project(run.projectId)
    const originValidator = assetOriginForEnvironment(project.environment)
    for (const id of approved) {
      const asset = run.candidates.find(c => c.id === id)
      if (asset) originValidator.parse(asset.origin)
    }
    if (run.phase === 'review' && approved.length === 0) {
      throw new Error('Approve at least one host to start assessment.')
    }

    const capabilityTier: CapabilityTier = cmd.capabilityTier ?? run.capabilityTier
    if (run.sourceMode === 'prepared' && capabilityTier > 0) {
      throw new Error('Prepared runs are restricted to Tier 0 (offline prepared).')
    }

    // Validate approved persona IDs belong to this project
    const approvedPersonaIds = cmd.approvedPersonaIds !== undefined
      ? [...new Set(cmd.approvedPersonaIds)]
      : run.approvedPersonaIds
    if (approvedPersonaIds.length) {
      if (capabilityTier < 2) {
        throw new Error('Persona credentials require Capability Tier 2 or Tier 3.')
      }
      const validIds = new Set(this.session.listProjectPersonas(run.projectId).map(p => p.id))
      if (approvedPersonaIds.some(pid => !validIds.has(pid))) {
        throw new Error('Select personas registered in this project.')
      }
    }

    const scopeRevision = run.scopeRevision + 1
    const removed = run.approved.filter(id => !approved.includes(id))
    const added = approved.filter(id => !run.approved.includes(id))
    const approvedOrigins = new Set(run.candidates.filter(a => approved.includes(a.id)).map(a => a.origin))
    const loweredTier = capabilityTier < run.capabilityTier

    const phase = run.phase === 'review'
      ? 'threat_model'
      : added.length && run.phase === 'verification'
        ? 'investigation'
        : run.phase
    const status = run.phase === 'review' ? 'running' : run.status

    const plan = run.reviewPlan
    let reviewPlan = plan
    if (plan?.status === 'ready' && added.length) {
      const priorAssets = run.candidates.filter(asset => run.approved.includes(asset.id))
      const priorChecks = priorAssets.length ? availableReviewChecks(priorAssets, run.sourceMode) : []
      const currentChecks = availableReviewChecks(run.candidates.filter(asset => approved.includes(asset.id)), run.sourceMode)
      if (currentChecks.some(check => !priorChecks.includes(check))) {
        reviewPlan = { status: 'pending', goalMessageId: plan.goalMessageId, previous: { checks: plan.checks, source: plan.source } }
      }
    }

    const nextApprovalPolicy = cmd.approvalPolicy ?? run.approvalPolicy ?? 'auto_review'
    const derivedEnvironmentMode = !this.hasExplicitEnvironmentMode(run.id) &&
      (cmd.capabilityTier !== undefined || cmd.approvalPolicy !== undefined)
      ? deriveDefaultEnvironmentMode(project.environment, capabilityTier, nextApprovalPolicy)
      : undefined

    const updated = this.updateRun(run.id, {
      approved,
      scopeRevision,
      phase,
      status,
      reviewPlan,
      capabilityTier,
      approvedPersonaIds,
      ...(cmd.approvalPolicy !== undefined ? { approvalPolicy: cmd.approvalPolicy } : {}),
      ...(derivedEnvironmentMode !== undefined ? { environmentMode: derivedEnvironmentMode } : {}),
      ...(cmd.budgetUsd !== undefined ? { budgetUsd: cmd.budgetUsd } : {}),
      ...(cmd.budgetRequests !== undefined ? { budgetRequests: cmd.budgetRequests } : {}),
      ...(cmd.maxRpsPerOrigin !== undefined ? { maxRpsPerOrigin: cmd.maxRpsPerOrigin } : {}),
    })

    if (saveProject) {
      this.session.db.update(tables.projects).set({
        defaultScope: run.candidates.filter(asset => approved.includes(asset.id)).map(asset => asset.origin),
      }).where(eq(tables.projects.id, run.projectId)).run()
    }

    if (removed.length) {
      this.applyTransitiveRevocation(updated, approved, approvedOrigins, scopeRevision)
    }

    if (loweredTier && capabilityTier < 3) {
      this.session.db.update(tables.approvalRequests).set({ status: 'canceled', decidedAt: Date.now() }).where(and(
        eq(tables.approvalRequests.runId, run.id), eq(tables.approvalRequests.status, 'pending'),
      )).run()
    }

    this.session.event(run.id, 'scope.approved', `Recorded scope revision ${scopeRevision} (Tier ${capabilityTier}).`, {
      actorId: this.session.workspace.actorId,
      scopeRevision,
      capabilityTier,
      approvedPersonaIds,
      approved: updated.candidates.filter(asset => approved.includes(asset.id)).map(asset => asset.origin),
      excluded: updated.candidates.filter(asset => !approved.includes(asset.id)).map(asset => asset.origin),
      removed,
      added,
    })
    this.session.message(run.id, run.coordinatorId, 'kovo',
      `Scope revision ${scopeRevision} approved for ${approved.length} ${approved.length === 1 ? 'host' : 'hosts'} at Tier ${capabilityTier}.`)
  }

  private revise(run: Run, input: string) {
    if (run.phase === 'complete') throw new Error('Create a new run to change a completed goal.')
    const goal = redact(input)
    const revision = run.goalRevision + 1
    const phase = ['investigation', 'verification'].includes(run.phase) ? 'threat_model' : run.phase
    if (run.reviewPlan?.status === 'pending') {
      this.session.message(run.id, run.coordinatorId, 'kovo', 'This goal was superseded by a revision.', run.reviewPlan.goalMessageId)
    }
    const goalMessageId = this.session.message(run.id, run.coordinatorId, 'operator', `Revised goal: ${goal}`)
    this.updateRun(run.id, { goal, goalRevision: revision, phase, reviewPlan: { status: 'pending', goalMessageId } })
    for (const assignment of this.workerList(run.id)) {
      if (assignment.goalRevision === run.goalRevision && assignment.phase !== 'discovery' &&
          !['complete', 'canceled'].includes(assignment.status)) {
        this.updateWorker(assignment.id, { status: 'canceled', outcome: 'Superseded by a goal revision.', lease: null, leaseExpiresAt: null })
      }
    }
    this.session.db.update(tables.chainSteps).set({ status: 'canceled', assignedWorkerId: null, updatedAt: Date.now() }).where(and(
      eq(tables.chainSteps.runId, run.id), eq(tables.chainSteps.goalRevision, run.goalRevision),
      inArray(tables.chainSteps.status, ['pending', 'ready', 'running', 'blocked']),
    )).run()
    this.session.event(run.id, 'goal.revised', `Goal revision ${revision} recorded.`, { actorId: this.session.workspace.actorId, revision, goal })
  }

  private retainAccessVerification(run: Run, origin: string, worker: Assignment, source: Evidence, receipt: Evidence) {
    if (source.goalRevision !== run.goalRevision || receipt.goalRevision !== run.goalRevision ||
      source.scopeRevision > receipt.scopeRevision || receipt.scopeRevision > run.scopeRevision ||
      source.createdAt > receipt.createdAt) return
    const restricted = (() => {
      try {
        return restrictAccessVerification(this.findings.artifact(run.id, receipt.id).content, this.findings.artifact(run.id, source.id), origin)
      } catch {
        return undefined
      }
    })()
    if (!restricted) return

    const operation = reportAccessOperation + run.scopeRevision
    const existing = this.findings.assignmentEvidence(worker.id, operation)
    const evidence = existing ?? this.findings.addArtifact(run, worker, 'verification', 'Access policy verification',
      JSON.stringify({ ...restricted.receipt, verifiedAt: new Date(receipt.createdAt).toISOString() }, null, 2), operation)
    if (!existing) this.session.event(run.id, 'evidence.restricted', 'Preserved the independent access verification for the current scope.', {
      assignmentId: worker.id, artifactId: evidence.id, sourceArtifactId: receipt.id, scopeRevision: run.scopeRevision,
    })
    return {
      sourceId: source.id, receiptId: receipt.id, evidenceId: evidence.id, origin,
      checks: restricted.receipt.checks, recordedAt: restricted.recordedAt,
    }
  }

  writeReport(run: Run, partial: boolean) {
    const snapshot = this.runDetail(run.id)
    const scope = run.candidates.filter(candidate => run.approved.includes(candidate.id))
    const approvedOrigins = new Set(scope.map(asset => asset.origin))
    // Provenance rule: IdP/auth and CDN/asset hops are benign infrastructure. They may appear in a
    // recorded redirect chain or source set without invalidating a valid targetOrigins finding.
    const provenancePolicy = this.scopePolicy(run)
    const provenanceOrigins = provenanceOriginsFor(provenancePolicy)
    const provenanceAllowed = (origin: string) =>
      approvedOrigins.has(origin) || provenanceOrigins.has(normalizeScopeOrigin(origin) ?? origin)
    const currentEvidence = new Set<string>()
    const retainedAccess = new Map<string, NonNullable<ReturnType<RunsRepository['retainAccessVerification']>>>()
    const gaps: string[] = []
    const plan = run.reviewPlan
    const selection = plan?.status === 'ready' ? { checks: plan.checks, source: plan.source } : plan?.previous
    if (plan?.status === 'pending' && plan.previous) gaps.push('A revised check plan was pending for this approval.')

    // Non-tainted facts set for transitive chain validation
    const taintedFactIds = new Set(snapshot.facts.filter(f => f.tainted).map(f => f.id))
    const validFactCount = snapshot.facts.filter(f => !f.tainted && approvedOrigins.has(f.origin)).length

    // Collect valid evidence from non-revoked assignments
    for (const item of snapshot.evidence) {
      if (item.goalRevision === run.goalRevision && item.scopeRevision <= run.scopeRevision) {
        currentEvidence.add(item.id)
      }
    }

    const coverage = scope.map(asset => {
      const { analysis, verification } = assessmentAssignments(snapshot.assignments, asset.id, run.goalRevision)
      const analyzed = analysis?.status === 'complete' ? analysis : undefined
      const verified = verification?.status === 'complete' ? verification : undefined
      const done = verified ?? analyzed
      const evList = snapshot.evidence.filter(item =>
        (item.assignmentId === analyzed?.id || item.assignmentId === verified?.id) &&
        !item.operationId?.startsWith(reportAccessOperation))
      const artifact = evList.findLast(item => item.assignmentId === done?.id &&
        (verified ? item.kind === 'verification' : ['observation', 'access-policy'].includes(item.kind)))
      const access = evList.findLast(item => item.assignmentId === analyzed?.id && item.kind === 'access-policy')

      if (analyzed && this.findings.brokerOrigins(analyzed).some(origin => !provenanceAllowed(origin))) {
        const reason = 'A source in the recorded redirect chain is no longer approved.'
        const retained = verified?.inputAssignmentId === analyzed.id && access && artifact
          ? this.retainAccessVerification(run, asset.origin, verified, access, artifact) : undefined
        if (retained) retainedAccess.set(asset.id, retained)
        const checks: CheckCoverage[] = (verified?.checks ?? []).filter(check => check.id !== 'access-policy' || !retained).map(check => ({
          ...check, observed: null,
          status: check.status === 'untested' ? 'untested' : 'inconclusive',
          reason: check.status === 'untested' ? untestedReason : check.id === 'access-policy'
            ? 'The saved verification does not support a separate access policy result.' : reason,
        }))
        if (retained) checks.push(...retained.checks)
        if (selection) {
          for (const check of untestedCoverage(asset, selection)) {
            if (!checks.some(saved => saved.id === check.id && saved.caseId === check.caseId)) checks.push(check)
          }
        }
        const status = 'Inconclusive. ' + reason
        gaps.push(asset.origin + ' · ' + status)
        for (const r of inconclusiveReasons(retained?.checks ?? [])) gaps.push(asset.origin + ' · ' + r)
        return {
          origin: asset.origin,
          status: retained?.checks.some(check => check.status === 'met' || check.status === 'gap')
            ? 'Access policy reviewed. Response checks inconclusive.' : status,
          evidenceId: retained?.evidenceId ?? null,
          ...(retained ? { accessEvidence: { id: retained.sourceId, recordedAt: retained.recordedAt } } : {}),
          ...(checks.length ? { checks } : {}),
        }
      }

      const derived = evList.findLast(item => item.assignmentId === analyzed?.id && item.kind === 'analysis')
      const status = verified?.outcome ?? (analyzed ? 'Analysis complete. Verification pending.' : 'Pending review')
      const checks = verified ? verified.checks : selection && untestedCoverage(asset, selection)
      if (!verified || !artifact) {
        gaps.push(asset.origin + ' · ' + status)
      } else if (verified.checks) {
        for (const r of inconclusiveReasons(verified.checks)) gaps.push(asset.origin + ' · ' + r)
      } else if (status.startsWith('Inconclusive')) {
        gaps.push(asset.origin + ' · ' + status)
      }
      return {
        origin: asset.origin,
        status,
        evidenceId: artifact?.id ?? null,
        analysisEvidenceId: derived?.id,
        ...(access ? { accessEvidence: { id: access.id, recordedAt: asset.accessPolicy?.recordedAt } } : {}),
        ...(checks ? { checks } : {}),
      }
    })

    // Filter findings strictly by current approved scope & non-tainted provenance
    const results = this.session.db.select().from(tables.findings).where(and(
      eq(tables.findings.runId, run.id), eq(tables.findings.goalRevision, run.goalRevision),
    )).all().flatMap(row => {
      const { assetId, checkId, caseId, findingKind, sourceOrigins, replaySpecId } = row
      const finding: Finding & FindingProvenanceFields = {
        ...row.finding,
        verificationTier: row.verificationTier ?? row.finding.verificationTier,
        fingerprintHash: row.fingerprintHash ?? row.finding.fingerprintHash,
        supersededByFindingId: row.supersededByFindingId ?? row.finding.supersededByFindingId,
        counterevidence: row.counterevidence ?? row.finding.counterevidence,
        confidenceRationale: row.confidenceRationale ?? row.finding.confidenceRationale,
        severityChangeConditions: row.severityChangeConditions ?? row.finding.severityChangeConditions,
        ...(row.codeLocations?.length ? { codeLocations: row.codeLocations } : row.finding.codeLocations?.length ? { codeLocations: row.finding.codeLocations } : {}),
        provenance: row.provenance,
        ...(row.parentFindingIds?.length ? { parentFindingIds: row.parentFindingIds } : {}),
        verificationStatus: row.verificationClass,
      }
      const isStaticVerified = finding.status === 'static_verified' || finding.verificationTier === 'static_verified'
      if (!isStaticVerified) {
        if (!run.approved.includes(assetId) || !approvedOrigins.has(finding.origin)) return []
        if (sourceOrigins.some(o => !provenanceAllowed(o))) return []
      } else {
        // Static-verified findings may reference approved origins or synthetic 'https://static-analysis.invalid'
        const nonSynthetic = sourceOrigins.filter(o => o !== 'https://static-analysis.invalid')
        if (nonSynthetic.some(o => !provenanceAllowed(o))) return []
      }
      if (finding.chainFactIds?.some(fid => taintedFactIds.has(fid))) return []
      if (!finding.evidenceIds.length && !(finding.exchangeIds?.length)) return []
      if (findingKind === 'multi_step_chain') {
        return [{ ...finding, findingKind, replaySpecId: replaySpecId ?? finding.replaySpecId }]
      }
      if (finding.evidenceIds.every(eid => currentEvidence.has(eid))) return [finding]
      const retained = retainedAccess.get(assetId)
      const check = finding.check
      if (!retained || checkId !== 'access-policy' || finding.status !== 'confirmed' || finding.origin !== retained.origin ||
        check?.id !== 'access-policy' || check.caseId !== caseId || finding.evidenceIds.length !== 2 ||
        !finding.evidenceIds.includes(retained.sourceId) || !finding.evidenceIds.includes(retained.receiptId)) return []
      const verified = retained.checks.find(item => item.caseId === caseId && item.status === 'gap')
      if (!verified || verified.observed !== check.observed || verified.expected !== check.expected) return []
      return [{ ...finding, evidenceIds: [retained.sourceId, retained.evidenceId] }]
    })

    const deduplicated = deduplicateChainFindings(results)
    const { findings: finalFindings } = collapseBaselineHeaderFindings(deduplicated)
    // v6 report contract: only runtime-confirmed items count; static/open-proof-gap items are
    // surfaced separately as advisories and can never become recall/precision TPs.
    const reportProvenance = buildProvenanceReport(finalFindings as (Finding & FindingProvenanceFields)[])

    const currentSteps = snapshot.chainSteps.filter(s => s.goalRevision === run.goalRevision)
    const chainStepsCompleted = currentSteps.filter(s => s.status === 'complete').length
    const chainStepsUntested = currentSteps.filter(s => ['pending', 'ready', 'running', 'blocked'].includes(s.status)).length
    const taintedSteps = currentSteps.filter(s => s.status === 'tainted')
    if (chainStepsUntested > 0) {
      gaps.push(`${chainStepsUntested} planned investigation ${chainStepsUntested === 1 ? 'step remained' : 'steps remained'} untested when this report was saved.`)
    }
    if (taintedSteps.length > 0) {
      gaps.push(`${taintedSteps.length} chain ${taintedSteps.length === 1 ? 'step was' : 'steps were'} omitted due to mid-run scope revocation.`)
    }
    if (!scope.length) gaps.push('No approved hosts in this report.')

    const threatModelEntries = snapshot.threatModel?.entries.filter(e => approvedOrigins.has(e.origin))
    const owaspCoverage = snapshot.coverageEntries
      .filter(c => c.goalRevision === run.goalRevision && approvedOrigins.has(c.origin))
      .map(c => ({
        origin: c.origin,
        category: c.category,
        status: c.status,
        summary: c.summary,
        ...(c.enforcingControl ? { enforcingControl: c.enforcingControl } : {}),
        ...(c.proofGapReason ? { proofGapReason: c.proofGapReason } : {}),
        ...(c.linkedFindingId ? { linkedFindingId: c.linkedFindingId } : {}),
      }))
    const openProofGaps = snapshot.openProofGaps
      .filter(c => approvedOrigins.has(c.origin))
      .map(c => ({
        origin: c.origin,
        category: c.category,
        summary: c.summary,
        proofGapReason: c.proofGapReason || c.summary,
      }))
    const includedFindingIds = new Set(finalFindings.map(f => f.id))
    const patchProposals: PatchProposalSummary[] = snapshot.patchProposals
      .filter(p => includedFindingIds.has(p.findingId))
      .map(p => ({
        id: p.id,
        findingId: p.findingId,
        repo: p.repo,
        status: p.status,
        callerCompatibility: p.callerCompatibility,
        diff: p.diff,
        codeLocations: p.codeLocations,
        reviewNotes: p.reviewNotes,
        dynamicRetestVerdict: p.dynamicRetestVerdict,
        createdAt: p.createdAt,
        updatedAt: p.updatedAt,
      }))

    const body: ReportBody & ReportProvenanceSurface = {
      goal: run.goal,
      capabilityTier: run.capabilityTier,
      scope: scope.map(({ accessPolicy: _ap, ...asset }) => asset),
      scopeRevision: run.scopeRevision,
      goalRevision: run.goalRevision,
      ...(selection ? { selectedChecks: selection } : {}),
      ...(threatModelEntries?.length ? { threatModel: threatModelEntries } : {}),
      ...(owaspCoverage.length ? { owaspCoverage } : {}),
      ...(openProofGaps.length ? { openProofGaps } : {}),
      ...(patchProposals.length ? { patchProposals } : {}),
      metrics: {
        turnsUsed: run.turnsUsed,
        requestsUsed: run.spentRequests,
        factsRecorded: validFactCount,
        chainStepsCompleted,
        chainStepsUntested,
        spentUsd: Number(run.spentUsd.toFixed(4)),
        spentTokens: run.spentTokens,
      },
      coverage,
      findings: finalFindings,
      provenanceCounts: reportProvenance.provenanceCounts,
      confirmedFindings: reportProvenance.confirmedFindings,
      advisories: reportProvenance.advisories,
      gaps,
    }

    const reportId = randomUUID()
    const version = (snapshot.reports[0]?.version ?? 0) + 1
    this.session.db.insert(tables.reports).values({ id: reportId, runId: run.id, partial, body, version, createdAt: Date.now() }).run()
    this.session.event(run.id, partial ? 'report.partial' : 'report.complete',
      partial ? 'Partial report created.' : 'Complete report created.',
      { reportId, version, phase: run.phase, status: run.status })
    return reportId
  }

  command(input: RunCommand, canUseModel = true) {
    return this.session.operate(input, () => {
      const run = this.run(input.runId)
      switch (input.action) {
        case 'discover':
          this.discover(run)
          break
        case 'scope':
          this.setScope(run, input)
          break
        case 'candidate': {
          if (run.phase === 'complete') throw new Error('Add the host to the project for the next run.')
          if (run.candidates.some(candidate => candidate.origin === input.candidate.origin)) {
            throw new Error('This host is already in the inventory.')
          }
          const asset = this.projects.saveCandidate(run.projectId, input.candidate, false)
          const discovery = this.workerList(run.id).find(worker => worker.phase === 'discovery' && worker.assetId === null)
          const source = discovery && this.recordInventory(run, discovery, 'Candidate source', [asset])
          const candidate = source ? { ...asset, sourceEvidenceId: source.id } : asset
          this.updateRun(run.id, { candidates: [...run.candidates, candidate] })
          this.session.event(run.id, 'asset.candidate', 'Added a candidate host awaiting scope review.', {
            id: asset.id, origin: asset.origin, actorId: this.session.workspace.actorId, sourceEvidenceId: source?.id,
          })
          break
        }
        case 'revise':
          this.revise(run, input.goal)
          break
        case 'message': {
          // Mirror operator text onto the board (defaulting plain text to @coordinator) while
          // keeping the legacy coordinator thread fully functional for v2–v4 compatibility.
          try {
            const allowed = this.boardHandleAllowList(run.id)
            const parsed = parseBoardMentions(input.message).filter(handle => allowed.has(handle) || handle === 'all')
            const targets = parsed.length ? parsed : ['coordinator']
            this.postBoardMessage(run, {
              authorHandle: 'operator',
              authorRole: 'operator',
              kind: targets.length === 1 && targets[0] === 'coordinator' ? 'note' : 'handoff',
              body: input.message,
              mentions: targets,
              sourceOrigins: [...this.approvedOriginsFor(run)],
            })
          } catch {
            // Board mirroring is advisory; legacy operator messaging must never regress.
          }
          const questionId = this.session.message(run.id, run.coordinatorId, 'operator', input.message)
          this.session.event(run.id, 'coordinator.message', 'Coordinator message received.')
          if (run.status !== 'running') {
            const workers = this.workerList(run.id)
            const history = workerHistory(run, workers)
            const count = workers.filter(worker => worker.status === 'complete' && !history.has(worker.id)).length
            const complete = count === 1 ? '1 assignment is complete.' : `${count} assignments are complete.`
            this.session.message(run.id, run.coordinatorId, 'kovo',
              `The run is ${run.status}. ${complete} See Workflow for the next available action.`, questionId)
          } else if (!canUseModel) {
            this.session.message(run.id, run.coordinatorId, 'kovo',
              'This run needs a configured model profile. Open Settings to add a model profile.', questionId)
          }
          break
        }
        case 'board_post': {
          const allowed = this.boardHandleAllowList(run.id)
          const parsed = [...new Set((input.mentions ?? parseBoardMentions(input.body))
            .map(handle => normalizeBoardHandle(handle))
            .filter((handle): handle is string => Boolean(handle)))]
          const mentions = parsed.filter(handle => allowed.has(handle) || handle === 'all')
          const rejected = parsed.filter(handle => !allowed.has(handle) && handle !== 'all')
          if (rejected.length) throw new Error(`Cannot mention unknown board handle @${rejected[0]}.`)
          this.postBoardMessage(run, {
            authorHandle: 'operator',
            authorRole: 'operator',
            kind: input.kind ?? (mentions.some(handle => handle !== 'coordinator') ? 'handoff' : 'note'),
            body: input.body,
            mentions,
            replyToSeq: input.replyToSeq ?? null,
            sourceOrigins: [...this.approvedOriginsFor(run)],
          })
          break
        }
        case 'retire_member': {
          const member = this.boardMember(run.id, input.handle)
          if (!member) throw new Error('Board member not found.')
          if (member.role === 'coordinator') throw new Error('The coordinator cannot be retired.')
          this.retireBoardMember(run, member.handle, 'Retired by operator.')
          break
        }
        case 'inject_hint': {
          if (run.phase === 'complete') throw new Error('Cannot inject a hint into a completed run.')
          const cleanHint = redact(input.hint)
          const targetAsset = input.targetAssetId
            ? run.candidates.find(c => c.id === input.targetAssetId && run.approved.includes(c.id))
            : run.candidates.find(c => run.approved.includes(c.id))
          this.session.message(run.id, run.coordinatorId, 'operator', `Steering hint: ${cleanHint}`)
          if (targetAsset) {
            this.addChainStep(run, {
              title: `Operator hint · ${new URL(targetAsset.origin).hostname}`,
              hypothesis: cleanHint,
              category: 'misconfig-exposure',
              priority: 95,
              targetAssetIds: [targetAsset.id],
              sourceOrigins: [targetAsset.origin],
            })
          }
          this.session.event(run.id, 'hint.injected', 'Operator steering hint queued for the planner.', {
            hint: cleanHint, targetAssetId: targetAsset?.id ?? null,
          })
          break
        }
        case 'decide_approval':
          this.decideApproval(run, input.approvalId, input.decision)
          break
        case 'set_approval_policy':
          this.setApprovalPolicy(run, input.approvalPolicy)
          break
        case 'approve_similar_endpoint':
          this.approveSimilarEndpoint(run, input.approvalId)
          break
        case 'approve_all_pending':
          this.approveAllPending(run)
          break
        case 'cancel_step': {
          const step = this.session.db.select().from(tables.chainSteps).where(and(
            eq(tables.chainSteps.runId, run.id), eq(tables.chainSteps.id, input.stepId),
          )).get()
          if (!step) throw new Error('Chain step not found.')
          this.updateChainStep(step.id, { status: 'canceled', assignedWorkerId: null })
          if (step.assignedWorkerId) {
            this.updateWorker(step.assignedWorkerId, { status: 'canceled', outcome: 'Canceled by operator.', lease: null, leaseExpiresAt: null })
          }
          this.session.event(run.id, 'chain_step.canceled', `Canceled step #${step.seq}: ${step.title}`, { stepId: step.id })
          break
        }
        case 'raise_budget': {
          if (['complete', 'stopped', 'failed'].includes(run.status)) {
            throw new Error('Cannot revise budget after a run has ended.')
          }
          const patch: Partial<Run> = {}
          if (input.budgetUsd !== undefined) {
            if (input.budgetUsd <= run.spentUsd) throw new Error('New USD budget must exceed current spend.')
            patch.budgetUsd = input.budgetUsd
          }
          if (input.budgetRequests !== undefined) {
            if (input.budgetRequests !== 0 && input.budgetRequests <= run.spentRequests) {
              throw new Error('New request cap must be 0 (unlimited) or exceed current requests used.')
            }
            patch.budgetRequests = input.budgetRequests
          }
          if (input.maxRpsPerOrigin !== undefined) {
            patch.maxRpsPerOrigin = input.maxRpsPerOrigin
          }
          if (Object.keys(patch).length > 0) {
            this.updateRun(run.id, patch)
          }
          const updated = this.run(run.id)
          const stillExceeded = updated.spentUsd >= updated.budgetUsd ||
            (updated.budgetRequests > 0 && updated.spentRequests >= updated.budgetRequests)
          const resumed = Boolean(
            input.resume &&
            !stillExceeded &&
            (run.status === 'budget_paused' || run.status === 'paused'),
          )
          if (resumed) {
            this.setStatus(updated, 'running')
          }
          this.session.event(run.id, 'budget.raised', 'Run budget updated.', { ...patch, resumed })
          break
        }
        case 'retest_finding': {
          const row = this.session.db.select().from(tables.findings).where(and(
            eq(tables.findings.runId, run.id), eq(tables.findings.id, input.findingId),
          )).get()
          if (!row) throw new Error('Finding not found.')
          if (!row.replaySpecId) throw new Error('Only findings with a Declarative Replay Spec support one-click Verify Fix retest.')
          const specRow = this.findings.getReplaySpec(run.id, row.replaySpecId)
          const approvedOrigins = new Set(run.candidates.filter(c => run.approved.includes(c.id)).map(c => c.origin))
          const retestPolicy = this.scopePolicy(run)
          if (specRow.sourceOrigins.some(o =>
            !approvedOrigins.has(o) && !isProvenanceOriginAllowed(retestPolicy, o))) {
            throw new Error('Cannot retest because one or more origins in this replay spec are no longer in approved scope.')
          }
          const asset = run.candidates.find(c => c.id === row.assetId)
          const worker = this.makeWorker(run, 'retest', asset, `Verify Fix · ${row.finding.title.slice(0, 80)}`,
            `Re-run declarative replay spec ${specRow.id} to verify whether "${row.finding.title}" is fixed.`, {
              stepId: row.id,
              sourceOrigins: specRow.sourceOrigins,
            })
          this.session.event(run.id, 'retest.queued', `Queued Verify Fix retest for "${row.finding.title}".`, {
            findingId: row.id, replaySpecId: specRow.id, assignmentId: worker.id,
          })
          break
        }
        case 'pause':
          if (run.status !== 'running') throw new Error('Only running work can be paused.')
          this.setStatus(run, 'paused')
          this.session.event(run.id, 'run.paused', 'Run paused.')
          break
        case 'stop':
          if (['complete', 'stopped'].includes(run.status)) throw new Error('This run has already ended.')
          this.setStatus(run, 'stopped')
          this.writeReport(this.run(run.id), true)
          break
        case 'resume':
          if (run.phase === 'complete') {
            throw new Error('Completed runs cannot be resumed.')
          }
          if (!['paused', 'budget_paused', 'stopped', 'failed'].includes(run.status)) {
            throw new Error('This run is not paused or stopped.')
          }
          if (run.status === 'budget_paused' && (run.spentUsd >= run.budgetUsd || (run.budgetRequests > 0 && run.spentRequests >= run.budgetRequests))) {
            throw new Error('Raise the run budget before resuming a budget-paused run.')
          }
          this.setStatus(run, ['consent', 'review'].includes(run.phase) ? 'waiting' : 'running')
          this.session.event(run.id, 'run.resumed', 'Run resumed.')
          break
      }
      return { id: run.id }
    })
  }

  updateRunPhase0Completed(runId: string, ts = Date.now()): Run {
    const updated = this.updateRun(runId, { phase0CompletedAt: ts })
    this.session.event(runId, 'phase0.completed', 'Phase-0 deterministic surface mapping completed.', {
      phase0CompletedAt: ts,
    })
    return updated
  }

  updateRunDynamicStepBudget(runId: string, budget: number | null): Run {
    if (budget === null) return this.updateRun(runId, { dynamicStepBudget: null })
    if (!Number.isFinite(budget)) {
      if (budget === Infinity) return this.updateRun(runId, { dynamicStepBudget: 300 })
      if (budget === -Infinity) return this.updateRun(runId, { dynamicStepBudget: 1 })
      return this.run(runId)
    }
    const clamped = Math.max(1, Math.min(300, Math.round(budget)))
    return this.updateRun(runId, { dynamicStepBudget: clamped })
  }

  // --- v7 M4: Per-tenant isolation and append-only audit log ---

  /** Assign a specific run to a tenant namespace. */
  setRunTenant(runId: string, tenantId: string): void {
    const normalized = normalizeTenantId(tenantId)
    this.run(runId)
    this.session.client.prepare('UPDATE runs SET tenant_id = ? WHERE id = ?').run(normalized, runId)
  }

  /** Resolve a run's effective tenant (inheriting its parent project tenant if unset). */
  getRunTenant(runId: string): string {
    const row = this.session.client.prepare(
      'SELECT r.tenant_id AS run_tenant, p.tenant_id AS project_tenant FROM runs r LEFT JOIN projects p ON p.id = r.project_id WHERE r.id = ?',
    ).get(runId) as { run_tenant: string | null; project_tenant: string | null } | undefined
    if (!row) throw new Error(`Unknown run ${runId}`)
    if (row.run_tenant && row.run_tenant !== 'default') return row.run_tenant
    if (row.project_tenant && row.project_tenant !== 'default') return row.project_tenant
    return row.run_tenant || 'default'
  }

  /** Fail closed if `tenantId` does not own `runId`, recording a denied audit entry. */
  assertRunTenantAccess(runId: string, tenantId: string, actor = 'operator'): void {
    const requested = normalizeTenantId(tenantId)
    const owner = this.getRunTenant(runId)
    if (owner !== requested) {
      this.appendTenantAuditLog({
        tenantId: requested,
        runId,
        actor,
        action: 'tenant.access_denied',
        resourceKind: 'run',
        resourceId: runId,
        outcome: 'denied',
        detail: { reason: 'Cross-tenant run access rejected.' },
      })
      throw new TenantIsolationError(requested, owner, runId)
    }
  }

  /** List runs strictly belonging to `tenantId` (zero cross-tenant visibility). */
  listRunsForTenant(tenantId: string): Run[] {
    const normalized = normalizeTenantId(tenantId)
    const rows = this.session.client.prepare(
      `SELECT r.id FROM runs r
       LEFT JOIN projects p ON p.id = r.project_id
       WHERE r.tenant_id = ?
          OR (r.tenant_id = 'default' AND p.tenant_id = ?)
       ORDER BY r.created_at DESC`,
    ).all(normalized, normalized) as Array<{ id: string }>
    return rows.map(r => this.run(r.id))
  }

  /** Append a hash-chained, PII/secret-scrubbed entry to the immutable `tenant_audit_log`. */
  appendTenantAuditLog(input: AppendTenantAuditLogInput): TenantAuditLogEntry {
    const tenantId = normalizeTenantId(input.tenantId)
    const now = input.now ?? Date.now()
    const id = randomUUID()
    const actor = (input.actor || 'system').trim().slice(0, 128)
    const action = (input.action || 'unknown').trim().slice(0, 128)
    const resourceKind = (input.resourceKind || 'system').trim().slice(0, 64)
    const resourceId = input.resourceId ?? null
    const runId = input.runId ?? null
    const scrubbedDetail = redactZdrJsonValue(input.detail ?? {}) as Record<string, unknown>
    const detailJson = JSON.stringify(scrubbedDetail)

    const prevRow = this.session.client.prepare(
      'SELECT entry_hash FROM tenant_audit_log WHERE tenant_id = ? ORDER BY seq DESC LIMIT 1',
    ).get(tenantId) as { entry_hash: string } | undefined
    const prevHash = prevRow?.entry_hash ?? 'GENESIS'
    const entryHash = computeTenantAuditHash({
      id,
      tenantId,
      runId,
      actor,
      action,
      resourceKind,
      resourceId,
      outcome: input.outcome,
      detailJson,
      prevHash,
      createdAt: now,
    })

    const inserted = this.session.client.prepare(
      `INSERT INTO tenant_audit_log
       (id, tenant_id, run_id, actor, action, resource_kind, resource_id, outcome, detail, prev_hash, entry_hash, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, tenantId, runId, actor, action, resourceKind, resourceId, input.outcome, detailJson, prevHash, entryHash, now)

    return {
      seq: Number(inserted.lastInsertRowid),
      id,
      tenantId,
      runId,
      actor,
      action,
      resourceKind,
      resourceId,
      outcome: input.outcome,
      detail: scrubbedDetail,
      prevHash,
      entryHash,
      createdAt: now,
    }
  }

  /** Query append-only audit log entries strictly scoped to `tenantId`. */
  listTenantAuditLog(
    tenantId: string,
    options: { runId?: string; limit?: number } = {},
  ): TenantAuditLogEntry[] {
    const normalized = normalizeTenantId(tenantId)
    const limit = Math.max(1, Math.min(1000, Math.trunc(options.limit ?? 200)))
    const rows = options.runId
      ? (this.session.client.prepare(
          'SELECT seq, id, tenant_id, run_id, actor, action, resource_kind, resource_id, outcome, detail, prev_hash, entry_hash, created_at FROM tenant_audit_log WHERE tenant_id = ? AND run_id = ? ORDER BY seq ASC LIMIT ?',
        ).all(normalized, options.runId, limit) as unknown as RawTenantAuditRow[])
      : (this.session.client.prepare(
          'SELECT seq, id, tenant_id, run_id, actor, action, resource_kind, resource_id, outcome, detail, prev_hash, entry_hash, created_at FROM tenant_audit_log WHERE tenant_id = ? ORDER BY seq ASC LIMIT ?',
        ).all(normalized, limit) as unknown as RawTenantAuditRow[])
    return rows.map(row => ({
      seq: row.seq,
      id: row.id,
      tenantId: row.tenant_id,
      runId: row.run_id,
      actor: row.actor,
      action: row.action,
      resourceKind: row.resource_kind,
      resourceId: row.resource_id,
      outcome: row.outcome as TenantAuditOutcome,
      detail: JSON.parse(row.detail) as Record<string, unknown>,
      prevHash: row.prev_hash,
      entryHash: row.entry_hash,
      createdAt: row.created_at,
    }))
  }

  /** Verify the cryptographic hash chain of all audit log entries for `tenantId`. */
  verifyTenantAuditLogChain(tenantId: string): { valid: boolean; count: number; brokenAtSeq?: number } {
    const normalized = normalizeTenantId(tenantId)
    const rows = this.session.client.prepare(
      'SELECT seq, id, tenant_id, run_id, actor, action, resource_kind, resource_id, outcome, detail, prev_hash, entry_hash, created_at FROM tenant_audit_log WHERE tenant_id = ? ORDER BY seq ASC',
    ).all(normalized) as unknown as RawTenantAuditRow[]
    let expectedPrev = 'GENESIS'
    for (const row of rows) {
      if (row.prev_hash !== expectedPrev) {
        return { valid: false, count: rows.length, brokenAtSeq: row.seq }
      }
      const recomputed = computeTenantAuditHash({
        id: row.id,
        tenantId: row.tenant_id,
        runId: row.run_id,
        actor: row.actor,
        action: row.action,
        resourceKind: row.resource_kind,
        resourceId: row.resource_id,
        outcome: row.outcome,
        detailJson: row.detail,
        prevHash: row.prev_hash,
        createdAt: row.created_at,
      })
      if (recomputed !== row.entry_hash) {
        return { valid: false, count: rows.length, brokenAtSeq: row.seq }
      }
      expectedPrev = row.entry_hash
    }
    return { valid: true, count: rows.length }
  }
}
