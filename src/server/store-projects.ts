/**
 * Domain repository for projects, project assets, API specs, personas summary rollups,
 * `workspaceSummary`, project tenant scoping, and cascade-aware `deleteProject` + disk cleanup.
 *
 * Strictly depends only on `store-session.ts` (never imports `store.ts`, `store-runs.ts`, or
 * `store-findings.ts`).
 */
import { randomUUID } from 'node:crypto'
import { rmSync } from 'node:fs'
import { join } from 'node:path'
import { and, desc, eq, inArray } from 'drizzle-orm'
import type { z } from 'zod'
import type { importAccessPolicy } from '../access-policy.ts'
import { assetOriginForEnvironment, isLocalLabEnvEnabled, maxProjectSeeds, shortText } from '../domain.ts'
import type {
  ApprovedEndpointPattern,
  Candidate,
  LabConfig,
  importDnsInventory,
  importProjectSpec,
  newProject,
  projectAsset,
} from '../domain.ts'
import { parseDnsInventory } from '../passive-dns.ts'
import { deletePersonaCredentialFiles } from './persona-vault.ts'
import { redact } from './redact.ts'
import * as tables from './schema.ts'
import {
  TenantIsolationError,
  isSafePathSegment,
  normalizeTenantId,
  resolvePageLimit,
  toSpecSummary,
  type DbSession,
  type Project,
  type ProjectSpec,
  type ProjectSpecSummary,
  type WorkspaceProjectLatestRun,
  type WorkspaceRecentRunSummary,
  type WorkspaceSummary,
} from './store-session.ts'

export class ProjectsRepository {
  private readonly session: DbSession

  constructor(session: DbSession) {
    this.session = session
  }

  project(projectId: string): Project {
    return this.session.requireProject(projectId)
  }

  listWorkspace() {
    const where = this.session.tenantId
      ? and(eq(tables.projects.workspaceId, this.session.workspace.id), eq(tables.projects.tenantId, this.session.tenantId))
      : eq(tables.projects.workspaceId, this.session.workspace.id)
    return {
      workspace: { id: this.session.workspace.id, name: this.session.workspace.name },
      projects: this.session.db.select().from(tables.projects)
        .where(where)
        .orderBy(desc(tables.projects.createdAt)).all(),
    }
  }

  updateWorkspaceName(input: { requestId: string; workspaceId?: string; name: string }) {
    return this.session.operate(input, () => {
      if (input.workspaceId && input.workspaceId !== this.session.workspace.id) {
        throw new Error('Workspace not found.')
      }
      const cleanName = redact(shortText.parse(input.name))
      this.session.db.update(tables.workspaces)
        .set({ name: cleanName })
        .where(eq(tables.workspaces.id, this.session.workspace.id))
        .run()
      this.session.workspace.name = cleanName
      this.session.event(null, 'workspace.renamed', `Renamed workspace to ${cleanName}.`, {
        workspaceId: this.session.workspace.id,
        name: cleanName,
      })
      return { id: this.session.workspace.id, name: cleanName }
    })
  }

  /** Typed workspace dashboard summary (projects with run/host/latest-run rollups + recent runs). */
  workspaceSummary(recentLimit = 15): WorkspaceSummary {
    const workspaceList = this.listWorkspace()
    const workspaceId = workspaceList.workspace.id
    const safeRecentLimit = resolvePageLimit(recentLimit, 15)
    const tenantId = this.session.tenantId

    const runCountRows = tenantId
      ? (this.session.client.prepare(`
          select r.project_id as projectId, count(*) as runCount
          from runs r
          join projects p on p.id = r.project_id
          where r.workspace_id = ?
            and COALESCE(NULLIF(r.tenant_id, 'default'), p.tenant_id, 'default') = ?
          group by r.project_id
        `).all(workspaceId, tenantId) as { projectId: string; runCount: number }[])
      : (this.session.client.prepare(`
          select project_id as projectId, count(*) as runCount
          from runs
          where workspace_id = ?
          group by project_id
        `).all(workspaceId) as { projectId: string; runCount: number }[])
    const runCounts = new Map(runCountRows.map(r => [r.projectId, Number(r.runCount)]))

    const hostCountRows = tenantId
      ? (this.session.client.prepare(`
          select a.project_id as projectId, count(*) as hostCount
          from project_assets a
          join projects p on p.id = a.project_id
          where p.workspace_id = ? and p.tenant_id = ?
          group by a.project_id
        `).all(workspaceId, tenantId) as { projectId: string; hostCount: number }[])
      : (this.session.client.prepare(`
          select a.project_id as projectId, count(*) as hostCount
          from project_assets a
          join projects p on p.id = a.project_id
          where p.workspace_id = ?
          group by a.project_id
        `).all(workspaceId) as { projectId: string; hostCount: number }[])
    const hostCounts = new Map(hostCountRows.map(r => [r.projectId, Number(r.hostCount)]))

    const latestRunRows = tenantId
      ? (this.session.client.prepare(`
          select r.id as id, r.project_id as projectId, r.goal as goal, r.status as status, r.phase as phase,
            r.created_at as startedAt,
            (select count(*) from findings f where f.run_id = r.id and f.superseded_by_finding_id is null
              and json_extract(f.finding, '$.status') in ('confirmed', 'verified', 'static_verified')) as confirmedCount,
            (select count(*) from findings f where f.run_id = r.id and f.superseded_by_finding_id is null) as findingCount
          from runs r
          join projects p on p.id = r.project_id
          where r.workspace_id = ?
            and COALESCE(NULLIF(r.tenant_id, 'default'), p.tenant_id, 'default') = ?
            and r.id = (
              select r2.id from runs r2
              where r2.project_id = r.project_id and r2.workspace_id = r.workspace_id
                and COALESCE(NULLIF(r2.tenant_id, 'default'), p.tenant_id, 'default') = ?
              order by r2.created_at desc, r2.rowid desc
              limit 1
            )
        `).all(workspaceId, tenantId, tenantId) as unknown as (WorkspaceProjectLatestRun & { projectId: string })[])
      : (this.session.client.prepare(`
          select r.id as id, r.project_id as projectId, r.goal as goal, r.status as status, r.phase as phase,
            r.created_at as startedAt,
            (select count(*) from findings f where f.run_id = r.id and f.superseded_by_finding_id is null
              and json_extract(f.finding, '$.status') in ('confirmed', 'verified', 'static_verified')) as confirmedCount,
            (select count(*) from findings f where f.run_id = r.id and f.superseded_by_finding_id is null) as findingCount
          from runs r
          where r.workspace_id = ?
            and r.id = (
              select r2.id from runs r2
              where r2.project_id = r.project_id and r2.workspace_id = r.workspace_id
              order by r2.created_at desc, r2.rowid desc
              limit 1
            )
        `).all(workspaceId) as unknown as (WorkspaceProjectLatestRun & { projectId: string })[])
    const latestRuns = new Map<string, WorkspaceProjectLatestRun>(latestRunRows.map(r => [r.projectId, {
      id: r.id,
      goal: r.goal,
      status: r.status,
      phase: r.phase,
      startedAt: Number(r.startedAt),
      confirmedCount: Number(r.confirmedCount),
      findingCount: Number(r.findingCount),
    }]))

    const recentRunRows = tenantId
      ? (this.session.client.prepare(`
          select r.id as id, r.project_id as projectId, p.name as projectName, r.goal as goal,
            r.status as status, r.phase as phase, r.created_at as startedAt,
            (select count(*) from findings f where f.run_id = r.id and f.superseded_by_finding_id is null
              and json_extract(f.finding, '$.status') in ('confirmed', 'verified', 'static_verified')) as confirmedCount,
            (select count(*) from findings f where f.run_id = r.id and f.superseded_by_finding_id is null) as findings
          from runs r
          join projects p on p.id = r.project_id
          where r.workspace_id = ?
            and COALESCE(NULLIF(r.tenant_id, 'default'), p.tenant_id, 'default') = ?
          order by r.created_at desc, r.rowid desc
          limit ?
        `).all(workspaceId, tenantId, safeRecentLimit) as unknown as WorkspaceRecentRunSummary[])
      : (this.session.client.prepare(`
          select r.id as id, r.project_id as projectId, p.name as projectName, r.goal as goal,
            r.status as status, r.phase as phase, r.created_at as startedAt,
            (select count(*) from findings f where f.run_id = r.id and f.superseded_by_finding_id is null
              and json_extract(f.finding, '$.status') in ('confirmed', 'verified', 'static_verified')) as confirmedCount,
            (select count(*) from findings f where f.run_id = r.id and f.superseded_by_finding_id is null) as findings
          from runs r
          join projects p on p.id = r.project_id
          where r.workspace_id = ?
          order by r.created_at desc, r.rowid desc
          limit ?
        `).all(workspaceId, safeRecentLimit) as unknown as WorkspaceRecentRunSummary[])

    return {
      workspace: workspaceList.workspace,
      projects: workspaceList.projects.map(project => ({
        ...project,
        runCount: runCounts.get(project.id) ?? 0,
        hostCount: hostCounts.get(project.id) ?? project.seeds.length,
        latestRun: latestRuns.get(project.id) ?? null,
      })),
      recentRuns: recentRunRows.map(r => ({
        ...r,
        startedAt: Number(r.startedAt),
        confirmedCount: Number(r.confirmedCount),
        findings: Number(r.findings),
      })),
    }
  }

  listProjectSpecs(projectId: string): ProjectSpecSummary[] {
    this.project(projectId)
    return this.session.db.select().from(tables.projectSpecs).where(eq(tables.projectSpecs.projectId, projectId))
      .orderBy(desc(tables.projectSpecs.createdAt)).all().map(toSpecSummary)
  }

  listProjectSpecsFull(projectId: string): ProjectSpec[] {
    this.project(projectId)
    return this.session.db.select().from(tables.projectSpecs).where(eq(tables.projectSpecs.projectId, projectId))
      .orderBy(desc(tables.projectSpecs.createdAt)).all()
  }

  getProjectSpec(projectId: string, specId: string): ProjectSpec {
    this.project(projectId)
    const spec = this.session.db.select().from(tables.projectSpecs).where(and(
      eq(tables.projectSpecs.projectId, projectId), eq(tables.projectSpecs.id, specId),
    )).get()
    if (!spec) throw new Error('Project spec not found.')
    return spec
  }

  importProjectSpec(input: z.output<typeof importProjectSpec>) {
    return this.session.operate(input, () => {
      const project = this.project(input.projectId)
      const spec = this.upsertProjectSpecRaw(project.id, {
        name: input.name,
        kind: input.kind,
        origin: input.origin ?? null,
        content: input.content,
      })
      return { id: spec.id, name: spec.name, kind: spec.kind }
    })
  }

  upsertProjectSpecRaw(projectId: string, input: {
    name: string
    kind: ProjectSpec['kind']
    origin?: string | null
    content: string
  }): ProjectSpec {
    this.project(projectId)
    const cleanName = redact(input.name)
    const cleanContent = redact(input.content)
    const existing = this.session.db.select().from(tables.projectSpecs).where(and(
      eq(tables.projectSpecs.projectId, projectId), eq(tables.projectSpecs.name, cleanName),
    )).get()
    if (existing) {
      const updated = this.session.db.update(tables.projectSpecs).set({
        kind: input.kind,
        origin: input.origin ?? null,
        content: cleanContent,
        createdAt: Date.now(),
      }).where(eq(tables.projectSpecs.id, existing.id)).returning().get()!
      this.session.event(null, 'spec.updated', `Updated project spec ${cleanName}.`, { projectId, specId: updated.id, kind: updated.kind })
      return updated
    }
    const created = this.session.db.insert(tables.projectSpecs).values({
      id: randomUUID(),
      projectId,
      name: cleanName,
      kind: input.kind,
      origin: input.origin ?? null,
      content: cleanContent,
      createdAt: Date.now(),
    }).returning().get()
    this.session.event(null, 'spec.imported', `Imported project spec ${cleanName}.`, { projectId, specId: created.id, kind: created.kind })
    return created
  }

  deleteProjectSpec(input: { requestId: string; projectId: string; specId: string }) {
    return this.session.operate(input, () => {
      this.project(input.projectId)
      const existing = this.getProjectSpec(input.projectId, input.specId)
      this.session.db.delete(tables.projectSpecs).where(eq(tables.projectSpecs.id, existing.id)).run()
      this.session.event(null, 'spec.deleted', `Removed project spec ${existing.name}.`, { projectId: input.projectId, specId: existing.id })
      return { id: existing.id }
    })
  }

  projectDetail(projectId: string) {
    const project = this.project(projectId)
    const runRows = this.session.db.select({
      id: tables.runs.id,
      goal: tables.runs.goal,
      status: tables.runs.status,
      phase: tables.runs.phase,
      capabilityTier: tables.runs.capabilityTier,
      approvalPolicy: tables.runs.approvalPolicy,
      spentUsd: tables.runs.spentUsd,
      spentRequests: tables.runs.spentRequests,
      turnsUsed: tables.runs.turnsUsed,
      createdAt: tables.runs.createdAt,
    }).from(tables.runs).where(eq(tables.runs.projectId, projectId)).orderBy(desc(tables.runs.createdAt)).all()
    const findingCountRows = this.session.client.prepare(`
      SELECT r.id AS runId,
        (SELECT count(*) FROM findings f WHERE f.run_id = r.id AND f.superseded_by_finding_id IS NULL) AS findingCount,
        (SELECT count(*) FROM findings f WHERE f.run_id = r.id AND f.superseded_by_finding_id IS NULL
          AND json_extract(f.finding, '$.status') IN ('confirmed', 'verified', 'static_verified')) AS confirmedCount,
        (SELECT count(*) FROM assignments a WHERE a.run_id = r.id AND a.status IN ('running', 'waiting_approval')) AS activeAssignments,
        (SELECT count(*) FROM lab_containers lc WHERE lc.run_id = r.id AND lc.status = 'running') AS activeLabContainers
      FROM runs r
      WHERE r.project_id = ? AND r.workspace_id = ?
    `).all(projectId, this.session.workspace.id) as {
      runId: string
      findingCount: number
      confirmedCount: number
      activeAssignments: number
      activeLabContainers: number
    }[]
    const findingCounts = new Map(findingCountRows.map(r => [r.runId, {
      findingCount: Number(r.findingCount),
      confirmedCount: Number(r.confirmedCount),
      activeAssignments: Number(r.activeAssignments),
      activeLabContainers: Number(r.activeLabContainers),
    }]))
    return {
      project,
      assets: this.session.db.select().from(tables.projectAssets).where(eq(tables.projectAssets.projectId, projectId)).all(),
      personas: this.session.listProjectPersonas(projectId),
      specs: this.listProjectSpecs(projectId),
      runs: runRows.map(r => {
        const counts = findingCounts.get(r.id)
        return {
          ...r,
          findingCount: counts?.findingCount ?? 0,
          confirmedCount: counts?.confirmedCount ?? 0,
          isActive: r.status === 'running' || (counts?.activeAssignments ?? 0) > 0 || (counts?.activeLabContainers ?? 0) > 0,
        }
      }),
    }
  }

  /**
   * Delete a project, cascading all runs (and their child rows), specs, personas, assets,
   * on-disk run artifacts/sessions, local 0600 persona credentials, and synced repo cache dir.
   */
  deleteProject(projectId: string): { deleted: boolean; projectId: string; deletedRuns: number } {
    this.session.flushNow()
    const committed = this.session.transaction(() => {
      const existing = this.session.db.select({
        id: tables.projects.id,
        name: tables.projects.name,
        tenantId: tables.projects.tenantId,
      })
        .from(tables.projects)
        .where(and(eq(tables.projects.id, projectId), eq(tables.projects.workspaceId, this.session.workspace.id)))
        .get()
      if (!existing) return null
      const projectTenant = existing.tenantId || 'default'
      if (this.session.tenantId && projectTenant !== this.session.tenantId) {
        throw new TenantIsolationError(this.session.tenantId, projectTenant, projectId)
      }
      const runRows = this.session.db.select({ id: tables.runs.id })
        .from(tables.runs)
        .where(and(eq(tables.runs.projectId, projectId), eq(tables.runs.workspaceId, this.session.workspace.id)))
        .all()
      const personaRows = this.session.db.select({ credentialId: tables.personas.credentialId })
        .from(tables.personas)
        .where(and(eq(tables.personas.projectId, projectId), eq(tables.personas.workspaceId, this.session.workspace.id)))
        .all()

      let runCleanups: Array<{ runId: string; sessionIds: string[]; flatArtifactIds: string[]; tenantBlobFiles: string[] }>
      if (this.session.hasCascadeSchema()) {
        const pending = runRows.map(row => ({
          runId: row.id,
          runTenant: this.session.effectiveRunTenant(row.id) ?? projectTenant,
          ...this.session.collectRunCleanupFiles(row.id),
        }))
        this.session.client.prepare(`DELETE FROM projects WHERE id = ? AND workspace_id = ?`).run(projectId, this.session.workspace.id)
        runCleanups = pending.map(item => ({
          runId: item.runId,
          sessionIds: item.sessionIds,
          flatArtifactIds: this.session.filterUnreferencedFlatArtifacts(item.artifactIds),
          tenantBlobFiles: this.session.filterUnreferencedTenantBlobs(item.runTenant, item.artifactIds),
        }))
      } else {
        runCleanups = []
        for (const row of runRows) {
          const files = this.session.deleteRunRowsInTx(row.id, false)
          runCleanups.push({ runId: row.id, ...files })
        }
        this.session.client.prepare(`DELETE FROM retest_runs WHERE project_id = ?`).run(projectId)
        this.session.client.prepare(`DELETE FROM personas WHERE project_id = ? AND workspace_id = ?`).run(projectId, this.session.workspace.id)
        this.session.client.prepare(`DELETE FROM project_specs WHERE project_id = ?`).run(projectId)
        this.session.client.prepare(`DELETE FROM project_assets WHERE project_id = ?`).run(projectId)
        this.session.client.prepare(`DELETE FROM projects WHERE id = ? AND workspace_id = ?`).run(projectId, this.session.workspace.id)
      }
      this.session.event(null, 'project.deleted', `Deleted project ${existing.name}.`, {
        projectId,
        projectName: existing.name,
        deletedRuns: runRows.length,
      })
      return {
        runCleanups,
        credentialIds: personaRows.map(p => p.credentialId),
        deletedRuns: runRows.length,
      }
    }, { behavior: 'immediate' })
    if (!committed) return { deleted: false, projectId, deletedRuns: 0 }

    for (const cleanup of committed.runCleanups) {
      this.session.cleanupRunFilesOnDisk(cleanup.runId, cleanup.sessionIds, cleanup.flatArtifactIds, cleanup.tenantBlobFiles)
    }
    deletePersonaCredentialFiles(this.session.directory, committed.credentialIds)
    if (isSafePathSegment(projectId)) {
      try {
        rmSync(join(this.session.directory, 'repos', projectId), { recursive: true, force: true })
      } catch {
        // Best-effort repo cache cleanup.
      }
    }
    return { deleted: true, projectId, deletedRuns: committed.deletedRuns }
  }

  createProject(input: z.output<typeof newProject>) {
    return this.session.operate(input, () => {
      const environment = input.environment ?? 'public'
      const originValidator = assetOriginForEnvironment(environment)
      const validatedSeeds = [...new Set(input.seeds.map(seed => originValidator.parse(seed)))]
      const labConfig = environment === 'local-lab' && input.labConfig
        ? ((input.labConfig.enabled || input.labConfig.iastEnabled) && !isLocalLabEnvEnabled()
            ? (() => { throw new Error('Enabling local-lab execution requires KOVO_ALLOW_LOCAL_LAB=1.') })()
            : input.labConfig)
        : (input.labConfig?.enabled || input.labConfig?.iastEnabled
            ? (() => { throw new Error('Local-lab execution and IAST telemetry are forbidden on public projects.') })()
            : null)
      const project = this.session.db.insert(tables.projects).values({
        id: randomUUID(),
        workspaceId: this.session.workspace.id,
        tenantId: this.session.tenantId ?? 'default',
        name: redact(input.name),
        environment,
        seeds: validatedSeeds,
        defaultScope: validatedSeeds,
        labConfig,
        sandboxWriteAllowlist: input.sandboxWriteAllowlist ?? [],
        createdAt: Date.now(),
      }).returning().get()
      const includeSubdomains = environment === 'public' && Boolean(input.includeSubdomains)
      this.session.db.insert(tables.projectAssets).values(project.seeds.map(origin => ({
        id: randomUUID(), projectId: project.id, origin, source: 'Project seed', thirdParty: false, includeSubdomains,
      }))).run()
      this.session.event(null, 'project.created', 'Project created.', { projectId: project.id, environment: project.environment })
      return { id: project.id }
    })
  }

  updateProject(input: {
    requestId: string
    projectId: string
    name?: string
    environment?: 'public' | 'local-lab'
    seeds?: string[]
  }) {
    return this.session.operate(input, () => {
      const project = this.project(input.projectId)
      const nextName = input.name !== undefined ? redact(shortText.parse(input.name)) : project.name
      const nextEnvironment = input.environment ?? project.environment
      const rawSeeds = input.seeds ?? project.seeds
      if (rawSeeds.length === 0 || rawSeeds.length > maxProjectSeeds) {
        throw new Error(`Project must have between 1 and ${maxProjectSeeds} seed origins.`)
      }
      const originValidator = assetOriginForEnvironment(nextEnvironment)
      const nextSeeds = [...new Set(rawSeeds.map(seed => originValidator.parse(seed)))]
      const prevSeeds = new Set(project.seeds)
      const nextSeedSet = new Set(nextSeeds)
      const removedSeeds = new Set(project.seeds.filter(seed => !nextSeedSet.has(seed)))
      const addedSeeds = nextSeeds.filter(seed => !prevSeeds.has(seed))

      const nextDefaultScope = [
        ...project.defaultScope.filter(origin => !removedSeeds.has(origin)),
        ...addedSeeds.filter(origin => !project.defaultScope.includes(origin)),
      ]
      const nextLabConfig = nextEnvironment === 'local-lab' ? project.labConfig : null

      this.session.db.update(tables.projects)
        .set({
          name: nextName,
          environment: nextEnvironment,
          seeds: nextSeeds,
          defaultScope: nextDefaultScope,
          labConfig: nextLabConfig,
        })
        .where(eq(tables.projects.id, project.id))
        .run()

      if (addedSeeds.length > 0) {
        this.session.db.insert(tables.projectAssets)
          .values(addedSeeds.map(origin => ({
            id: randomUUID(),
            projectId: project.id,
            origin,
            source: 'Project seed',
            thirdParty: false,
            includeSubdomains: false,
          })))
          .onConflictDoNothing()
          .run()
      }

      this.session.event(null, 'project.updated', `Updated project ${nextName}.`, {
        projectId: project.id,
        name: nextName,
        environment: nextEnvironment,
        seedsCount: nextSeeds.length,
      })
      return {
        id: project.id,
        name: nextName,
        environment: nextEnvironment,
        seeds: nextSeeds,
        defaultScope: nextDefaultScope,
      }
    })
  }

  updateProjectLabConfig(input: { requestId: string; projectId: string; labConfig: LabConfig | null }) {
    return this.session.operate(input, () => {
      const project = this.project(input.projectId)
      if (input.labConfig?.enabled || input.labConfig?.iastEnabled) {
        if (project.environment !== 'local-lab') {
          throw new Error('Local-lab app execution and IAST telemetry are forbidden on public projects.')
        }
        if (!isLocalLabEnvEnabled()) {
          throw new Error('Local-lab app execution and IAST telemetry require KOVO_ALLOW_LOCAL_LAB=1 on the server.')
        }
      }
      const nextConfig = project.environment === 'local-lab' ? input.labConfig : null
      this.session.db.update(tables.projects).set({ labConfig: nextConfig }).where(eq(tables.projects.id, project.id)).run()
      this.session.event(null, 'project.lab_config_updated', 'Project lab configuration updated.', {
        projectId: project.id,
        enabled: Boolean(nextConfig?.enabled),
      })
      return { id: project.id, labConfig: nextConfig }
    })
  }

  updateProjectSandboxWriteAllowlist(input: {
    requestId: string
    projectId: string
    sandboxWriteAllowlist: ApprovedEndpointPattern[]
  }) {
    return this.session.operate(input, () => {
      const project = this.project(input.projectId)
      const originValidator = assetOriginForEnvironment(project.environment)
      const validated: ApprovedEndpointPattern[] = []
      for (const entry of input.sandboxWriteAllowlist) {
        const origin = originValidator.parse(entry.origin)
        const method = entry.method.trim().toUpperCase()
        const pathPattern = entry.pathPattern.trim()
        if (!pathPattern.startsWith('/')) {
          throw new Error('Allowlist path pattern must start with "/".')
        }
        validated.push({
          origin,
          method,
          pathPattern,
          ...(entry.scopeRevision !== undefined ? { scopeRevision: entry.scopeRevision } : {}),
          createdAt: entry.createdAt ?? Date.now(),
        })
      }
      this.session.db.update(tables.projects)
        .set({ sandboxWriteAllowlist: validated })
        .where(eq(tables.projects.id, project.id))
        .run()
      this.session.event(null, 'project.sandbox_allowlist_updated', 'Project sandbox write allowlist updated.', {
        projectId: project.id,
        count: validated.length,
      })
      return { id: project.id, sandboxWriteAllowlist: validated }
    })
  }

  addProjectAsset(input: z.output<typeof projectAsset>) {
    return this.session.operate(input, () => {
      const project = this.project(input.projectId)
      const origin = assetOriginForEnvironment(project.environment).parse(input.origin)
      const includeSubdomains = project.environment === 'public' && !input.thirdParty && Boolean(input.includeSubdomains)
      const candidate = this.saveCandidate(project.id, { ...input, origin, includeSubdomains })
      return { id: candidate.id }
    })
  }

  updateProjectAssetScope(input: {
    requestId: string
    projectId: string
    assetId: string
    includeSubdomains?: boolean
    approveInDefaultScope?: boolean
  }) {
    return this.session.operate(input, () => {
      const project = this.project(input.projectId)
      const asset = this.session.db.select().from(tables.projectAssets)
        .where(and(eq(tables.projectAssets.projectId, project.id), eq(tables.projectAssets.id, input.assetId)))
        .get()
      if (!asset) throw new Error('Project asset not found.')

      let nextIncludeSubdomains = Boolean(asset.includeSubdomains)
      if (input.includeSubdomains !== undefined) {
        nextIncludeSubdomains = project.environment === 'public' && !asset.thirdParty && Boolean(input.includeSubdomains)
        this.session.db.update(tables.projectAssets)
          .set({ includeSubdomains: nextIncludeSubdomains })
          .where(eq(tables.projectAssets.id, asset.id))
          .run()
      }

      let nextDefaultScope = [...project.defaultScope]
      if (input.approveInDefaultScope !== undefined) {
        if (input.approveInDefaultScope) {
          if (!nextDefaultScope.includes(asset.origin)) nextDefaultScope.push(asset.origin)
        } else {
          nextDefaultScope = nextDefaultScope.filter(origin => origin !== asset.origin)
        }
        this.session.db.update(tables.projects)
          .set({ defaultScope: nextDefaultScope })
          .where(eq(tables.projects.id, project.id))
          .run()
      }

      this.session.event(null, 'inventory.asset_scope_updated', `Updated scope settings for ${asset.origin}.`, {
        projectId: project.id,
        assetId: asset.id,
        origin: asset.origin,
        thirdParty: asset.thirdParty,
        includeSubdomains: nextIncludeSubdomains,
        approvedInDefaultScope: nextDefaultScope.includes(asset.origin),
      })
      return {
        id: asset.id,
        includeSubdomains: nextIncludeSubdomains,
        approvedInDefaultScope: nextDefaultScope.includes(asset.origin),
      }
    })
  }

  updateProjectAsset(input: {
    requestId: string
    projectId: string
    assetId: string
    origin?: string
    source?: string
    thirdParty?: boolean
  }) {
    return this.session.operate(input, () => {
      const project = this.project(input.projectId)
      const asset = this.session.db.select().from(tables.projectAssets)
        .where(and(eq(tables.projectAssets.projectId, project.id), eq(tables.projectAssets.id, input.assetId)))
        .get()
      if (!asset) throw new Error('Project asset not found.')

      const nextOrigin = input.origin !== undefined && input.origin.trim() !== asset.origin
        ? assetOriginForEnvironment(project.environment).parse(input.origin)
        : asset.origin
      if (nextOrigin !== asset.origin) {
        const collision = this.session.db.select({ id: tables.projectAssets.id })
          .from(tables.projectAssets)
          .where(and(eq(tables.projectAssets.projectId, project.id), eq(tables.projectAssets.origin, nextOrigin)))
          .get()
        if (collision && collision.id !== asset.id) {
          throw new Error('A host with that origin already exists in this project.')
        }
      }

      const nextSource = input.source !== undefined ? redact(shortText.parse(input.source)) : asset.source
      const nextThirdParty = input.thirdParty !== undefined ? Boolean(input.thirdParty) : asset.thirdParty
      const nextIncludeSubdomains = project.environment === 'public' && !nextThirdParty && Boolean(asset.includeSubdomains)
      const nextAccessPolicy = asset.accessPolicy && nextOrigin !== asset.origin
        ? { ...asset.accessPolicy, origin: nextOrigin }
        : asset.accessPolicy

      this.session.db.update(tables.projectAssets)
        .set({
          origin: nextOrigin,
          source: nextSource,
          thirdParty: nextThirdParty,
          includeSubdomains: nextIncludeSubdomains,
          ...(nextAccessPolicy !== undefined ? { accessPolicy: nextAccessPolicy } : {}),
        })
        .where(eq(tables.projectAssets.id, asset.id))
        .run()

      if (nextOrigin !== asset.origin) {
        const nextDefaultScope = [...new Set(project.defaultScope.map(o => (o === asset.origin ? nextOrigin : o)))]
        const nextSeeds = [...new Set(project.seeds.map(o => (o === asset.origin ? nextOrigin : o)))]
        if (
          nextDefaultScope.length !== project.defaultScope.length ||
          nextSeeds.length !== project.seeds.length ||
          nextDefaultScope.some((o, i) => o !== project.defaultScope[i]) ||
          nextSeeds.some((o, i) => o !== project.seeds[i])
        ) {
          this.session.db.update(tables.projects)
            .set({ defaultScope: nextDefaultScope, seeds: nextSeeds })
            .where(eq(tables.projects.id, project.id))
            .run()
        }
      }

      this.session.event(null, 'inventory.asset_updated', `Updated host ${nextOrigin}.`, {
        projectId: project.id,
        assetId: asset.id,
        origin: nextOrigin,
        source: nextSource,
        thirdParty: nextThirdParty,
        includeSubdomains: nextIncludeSubdomains,
      })
      return {
        id: asset.id,
        origin: nextOrigin,
        source: nextSource,
        thirdParty: nextThirdParty,
        includeSubdomains: nextIncludeSubdomains,
      }
    })
  }

  clearProjectAssetAccessPolicy(input: { requestId: string; projectId: string; assetId: string }) {
    return this.session.operate(input, () => {
      const project = this.project(input.projectId)
      const asset = this.session.db.select().from(tables.projectAssets)
        .where(and(eq(tables.projectAssets.projectId, project.id), eq(tables.projectAssets.id, input.assetId)))
        .get()
      if (!asset) throw new Error('Project asset not found.')

      this.session.db.update(tables.projectAssets)
        .set({ accessPolicy: null })
        .where(eq(tables.projectAssets.id, asset.id))
        .run()
      this.session.event(null, 'inventory.access_policy_cleared', `Cleared access policy for ${asset.origin}.`, {
        projectId: project.id,
        assetId: asset.id,
        origin: asset.origin,
      })
      return { id: asset.id, origin: asset.origin, cleared: asset.accessPolicy !== null }
    })
  }

  deleteProjectAsset(input: { requestId: string; projectId: string; assetId: string }) {
    return this.session.operate(input, () => {
      const project = this.project(input.projectId)
      const asset = this.session.db.select().from(tables.projectAssets)
        .where(and(eq(tables.projectAssets.projectId, project.id), eq(tables.projectAssets.id, input.assetId)))
        .get()
      if (!asset) throw new Error('Project asset not found.')

      this.session.db.delete(tables.projectAssets).where(eq(tables.projectAssets.id, asset.id)).run()
      const nextDefaultScope = project.defaultScope.filter(origin => origin !== asset.origin)
      const nextSeeds = project.seeds.filter(origin => origin !== asset.origin)
      if (nextDefaultScope.length !== project.defaultScope.length || nextSeeds.length !== project.seeds.length) {
        this.session.db.update(tables.projects)
          .set({ defaultScope: nextDefaultScope, seeds: nextSeeds })
          .where(eq(tables.projects.id, project.id))
          .run()
      }
      this.session.event(null, 'inventory.asset_deleted', `Removed host ${asset.origin} from project inventory.`, {
        projectId: project.id,
        assetId: asset.id,
        origin: asset.origin,
      })
      return { id: asset.id, origin: asset.origin }
    })
  }

  bulkUpdateProjectAssetScope(input: {
    requestId: string
    projectId: string
    assetIds: string[]
    includeSubdomains?: boolean
    approveInDefaultScope?: boolean
  }) {
    return this.session.operate(input, () => {
      const project = this.project(input.projectId)
      const uniqueIds = [...new Set(input.assetIds.filter(Boolean))]
      if (uniqueIds.length === 0) {
        return {
          id: project.id,
          updatedCount: 0,
          updatedIds: [] as string[],
          ignoredIds: [] as string[],
          defaultScope: [...project.defaultScope],
        }
      }
      const matched: (typeof tables.projectAssets.$inferSelect)[] = []
      for (let offset = 0; offset < uniqueIds.length; offset += 500) {
        matched.push(
          ...this.session.db.select().from(tables.projectAssets)
            .where(and(
              eq(tables.projectAssets.projectId, project.id),
              inArray(tables.projectAssets.id, uniqueIds.slice(offset, offset + 500)),
            ))
            .all(),
        )
      }
      const matchedIds = new Set(matched.map(a => a.id))
      const ignoredIds = uniqueIds.filter(assetId => !matchedIds.has(assetId))
      if (matched.length === 0) {
        return {
          id: project.id,
          updatedCount: 0,
          updatedIds: [] as string[],
          ignoredIds,
          defaultScope: [...project.defaultScope],
        }
      }

      if (input.includeSubdomains !== undefined) {
        const nextFlag = Boolean(input.includeSubdomains)
        const idsToEnable = nextFlag && project.environment === 'public'
          ? matched.filter(a => !a.thirdParty).map(a => a.id)
          : []
        const idsToDisable = nextFlag
          ? matched.filter(a => a.thirdParty || project.environment !== 'public').map(a => a.id)
          : matched.map(a => a.id)
        for (let offset = 0; offset < idsToEnable.length; offset += 500) {
          this.session.db.update(tables.projectAssets)
            .set({ includeSubdomains: true })
            .where(and(
              eq(tables.projectAssets.projectId, project.id),
              inArray(tables.projectAssets.id, idsToEnable.slice(offset, offset + 500)),
            ))
            .run()
        }
        for (let offset = 0; offset < idsToDisable.length; offset += 500) {
          this.session.db.update(tables.projectAssets)
            .set({ includeSubdomains: false })
            .where(and(
              eq(tables.projectAssets.projectId, project.id),
              inArray(tables.projectAssets.id, idsToDisable.slice(offset, offset + 500)),
            ))
            .run()
        }
      }

      let nextDefaultScope = [...project.defaultScope]
      if (input.approveInDefaultScope !== undefined) {
        const matchedOrigins = new Set(matched.map(a => a.origin))
        if (input.approveInDefaultScope) {
          const existingSet = new Set(nextDefaultScope)
          for (const asset of matched) {
            if (!existingSet.has(asset.origin)) {
              existingSet.add(asset.origin)
              nextDefaultScope.push(asset.origin)
            }
          }
        } else {
          nextDefaultScope = nextDefaultScope.filter(origin => !matchedOrigins.has(origin))
        }
        this.session.db.update(tables.projects)
          .set({ defaultScope: nextDefaultScope })
          .where(eq(tables.projects.id, project.id))
          .run()
      }

      const updatedIds = matched.map(a => a.id)
      const actionVerb = input.approveInDefaultScope === true
        ? 'Approved'
        : input.approveInDefaultScope === false
          ? 'Unapproved'
          : 'Updated scope settings for'
      this.session.event(null, 'inventory.assets_scope_bulk_updated', `${actionVerb} ${updatedIds.length} ${updatedIds.length === 1 ? 'host' : 'hosts'} in project scope.`, {
        projectId: project.id,
        updatedCount: updatedIds.length,
        ignoredCount: ignoredIds.length,
        ...(input.approveInDefaultScope !== undefined ? { approveInDefaultScope: input.approveInDefaultScope } : {}),
        ...(input.includeSubdomains !== undefined ? { includeSubdomains: input.includeSubdomains } : {}),
      })
      return {
        id: project.id,
        updatedCount: updatedIds.length,
        updatedIds,
        ignoredIds,
        defaultScope: nextDefaultScope,
      }
    })
  }

  bulkRemoveProjectAssets(input: {
    requestId: string
    projectId: string
    assetIds: string[]
  }) {
    return this.session.operate(input, () => {
      const project = this.project(input.projectId)
      const uniqueIds = [...new Set(input.assetIds.filter(Boolean))]
      if (uniqueIds.length === 0) {
        return {
          id: project.id,
          removedCount: 0,
          removedIds: [] as string[],
          ignoredIds: [] as string[],
          defaultScope: [...project.defaultScope],
        }
      }
      const matched: (typeof tables.projectAssets.$inferSelect)[] = []
      for (let offset = 0; offset < uniqueIds.length; offset += 500) {
        matched.push(
          ...this.session.db.select().from(tables.projectAssets)
            .where(and(
              eq(tables.projectAssets.projectId, project.id),
              inArray(tables.projectAssets.id, uniqueIds.slice(offset, offset + 500)),
            ))
            .all(),
        )
      }
      const matchedIds = new Set(matched.map(a => a.id))
      const ignoredIds = uniqueIds.filter(assetId => !matchedIds.has(assetId))
      if (matched.length === 0) {
        return {
          id: project.id,
          removedCount: 0,
          removedIds: [] as string[],
          ignoredIds,
          defaultScope: [...project.defaultScope],
        }
      }

      const removedIds = matched.map(a => a.id)
      const removedOrigins = new Set(matched.map(a => a.origin))
      for (let offset = 0; offset < removedIds.length; offset += 500) {
        this.session.db.delete(tables.projectAssets)
          .where(and(
            eq(tables.projectAssets.projectId, project.id),
            inArray(tables.projectAssets.id, removedIds.slice(offset, offset + 500)),
          ))
          .run()
      }

      const nextDefaultScope = project.defaultScope.filter(origin => !removedOrigins.has(origin))
      const nextSeeds = project.seeds.filter(origin => !removedOrigins.has(origin))
      if (nextDefaultScope.length !== project.defaultScope.length || nextSeeds.length !== project.seeds.length) {
        this.session.db.update(tables.projects)
          .set({ defaultScope: nextDefaultScope, seeds: nextSeeds })
          .where(eq(tables.projects.id, project.id))
          .run()
      }

      this.session.event(null, 'inventory.assets_bulk_deleted', `Removed ${removedIds.length} ${removedIds.length === 1 ? 'host' : 'hosts'} from project inventory.`, {
        projectId: project.id,
        removedCount: removedIds.length,
        ignoredCount: ignoredIds.length,
      })
      return {
        id: project.id,
        removedCount: removedIds.length,
        removedIds,
        ignoredIds,
        defaultScope: nextDefaultScope,
      }
    })
  }

  importProjectDns(input: z.output<typeof importDnsInventory>) {
    return this.session.operate(input, () => {
      const project = this.project(input.projectId)
      const { zone, candidates } = parseDnsInventory(input.zone, input.document)
      let added = 0
      for (let offset = 0; offset < candidates.length; offset += 100) {
        const rows = candidates.slice(offset, offset + 100).map(candidate => ({
          ...candidate, id: randomUUID(), projectId: project.id,
        }))
        added += this.session.db.insert(tables.projectAssets).values(rows).onConflictDoNothing()
          .returning({ id: tables.projectAssets.id }).all().length
      }
      const existing = candidates.length - added
      this.session.event(null, 'inventory.dns_imported', 'Passive DNS inventory imported.', {
        projectId: project.id, actorId: this.session.workspace.actorId, zone, added, existing,
      })
      return { id: project.id, added, existing }
    })
  }

  importProjectAccessPolicy(input: z.output<typeof importAccessPolicy>) {
    return this.session.operate(input, () => {
      const project = this.project(input.projectId)
      const snapshot = input.snapshot
      const json = JSON.stringify(snapshot)
      if (redact(json) !== json) throw new Error('Use case, role, and capability labels without credentials.')
      const target = and(eq(tables.projectAssets.projectId, project.id), eq(tables.projectAssets.origin, snapshot.origin))
      const asset = this.session.db.update(tables.projectAssets).set({ accessPolicy: snapshot }).where(target)
        .returning({ id: tables.projectAssets.id }).get()
      if (!asset) throw new Error('Select a file for an existing project host.')
      this.session.event(null, 'inventory.access_policy_imported', 'Access policy records imported.', {
        projectId: project.id, assetId: asset.id, actorId: this.session.workspace.actorId,
        recordedAt: snapshot.recordedAt, expected: snapshot.expected.length, observed: snapshot.observed.length,
      })
      return { id: asset.id, origin: snapshot.origin, cases: snapshot.expected.length }
    })
  }

  saveCandidate(projectId: string, input: Omit<Candidate, 'id'>, replace = true) {
    const candidate = {
      id: randomUUID(), projectId, origin: input.origin, source: redact(input.source),
      thirdParty: input.thirdParty,
      includeSubdomains: !input.thirdParty && Boolean(input.includeSubdomains),
      prepared: input.prepared ?? null,
      dnsSource: input.dnsSource ?? null,
    }
    const insert = this.session.db.insert(tables.projectAssets).values(candidate)
    if (replace) return insert.onConflictDoUpdate({
      target: [tables.projectAssets.projectId, tables.projectAssets.origin],
      set: {
        source: candidate.source,
        thirdParty: candidate.thirdParty,
        ...(input.includeSubdomains === undefined ? {} : { includeSubdomains: candidate.includeSubdomains }),
        ...(input.prepared === undefined ? {} : { prepared: input.prepared }),
        ...(input.dnsSource === undefined ? {} : { dnsSource: input.dnsSource }),
      },
    }).returning().get()
    insert.onConflictDoNothing().run()
    return this.session.db.select().from(tables.projectAssets).where(and(
      eq(tables.projectAssets.projectId, projectId), eq(tables.projectAssets.origin, input.origin),
    )).get()!
  }

  /** Assign a project (and its existing runs) to a tenant namespace atomically. */
  setProjectTenant(projectId: string, tenantId: string): void {
    const normalized = normalizeTenantId(tenantId)
    if (this.session.tenantId && normalized !== this.session.tenantId) {
      throw new TenantIsolationError(this.session.tenantId, normalized, projectId)
    }
    this.session.transaction(() => {
      this.project(projectId)
      this.session.client.prepare(
        'UPDATE projects SET tenant_id = ? WHERE id = ? AND workspace_id = ?',
      ).run(normalized, projectId, this.session.workspace.id)
      this.session.client.prepare(
        'UPDATE runs SET tenant_id = ? WHERE project_id = ? AND workspace_id = ?',
      ).run(normalized, projectId, this.session.workspace.id)
    }, { behavior: 'immediate' })
  }

  getProjectTenant(projectId: string): string {
    const row = this.session.client.prepare(
      'SELECT tenant_id FROM projects WHERE id = ? AND workspace_id = ?',
    ).get(projectId, this.session.workspace.id) as
      | { tenant_id: string }
      | undefined
    if (!row) throw new Error(`Unknown project ${projectId}`)
    const owner = row.tenant_id || 'default'
    if (this.session.tenantId && owner !== this.session.tenantId) {
      throw new TenantIsolationError(this.session.tenantId, owner, projectId)
    }
    return owner
  }

  /** List projects strictly belonging to `tenantId` (zero cross-tenant visibility). */
  listProjectsForTenant(tenantId: string): Project[] {
    const normalized = normalizeTenantId(tenantId)
    if (this.session.tenantId && normalized !== this.session.tenantId) {
      throw new TenantIsolationError(this.session.tenantId, normalized, 'projects')
    }
    const rows = this.session.client.prepare(
      'SELECT id FROM projects WHERE workspace_id = ? AND tenant_id = ? ORDER BY created_at DESC',
    ).all(this.session.workspace.id, normalized) as Array<{ id: string }>
    return rows.map(r => this.project(r.id))
  }
}
