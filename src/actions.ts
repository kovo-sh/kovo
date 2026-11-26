import { randomUUID } from 'node:crypto'
import { join } from 'node:path'
import { createServerFn } from '@tanstack/react-start'
import { z } from 'zod'
import { importAccessPolicy } from './access-policy.ts'
import {
  approvedEndpointPatternSchema,
  assetOriginForEnvironment,
  createPersona,
  deletePersona,
  id,
  importDnsInventory,
  importProjectSpec,
  isLocalLabEnvEnabled,
  labConfigSchema,
  newProject,
  newRun,
  projectAsset,
  providerSettings,
  runCommand,
} from './domain.ts'
import { execution } from './server/execution.ts'
import {
  cancelGithubDeviceFlow,
  clearGithubPat,
  defaultSelectedRepoNames,
  getGithubAuthStatus,
  listAccessibleGithubRepos,
  pollGithubDeviceFlow,
  projectReposDir,
  saveGithubPat,
  startGithubDeviceFlow,
  syncGithubRepos,
} from './server/github-connector.ts'
import { assertLocalLabAllowed } from './server/lab-runner.ts'
import type { LabTargetHandle } from './server/lab-runner.ts'
import {
  checkModelConnection,
  deleteModelProfile,
  listModelProfiles,
  modelReady,
  publicModelSettings,
  saveModelProfile,
  setModelProfileEnabled,
} from './server/model-settings.ts'
import {
  createProjectPersona,
  deleteProjectPersona,
  listProjectPersonas,
} from './server/persona-vault.ts'
import { exportReportMarkdown } from './server/report-export.ts'
import { exportReportSarif } from './server/sarif-export.ts'
import {
  deleteProjectWithActiveGuard,
  deleteRunWithActiveGuard,
  store,
} from './server/store.ts'
import type { Store } from './server/store.ts'
import { runDiscoverySubdomainsForRun } from './server/subdomain-discovery.ts'
import type { RunDiscoverySubdomainsResult } from './server/subdomain-discovery.ts'
import { readWorkerSession, resolvePrimaryLabRepoDir, testPersonaAuth } from './server/worker-session-reader.ts'

export const workspaceData = createServerFn({ method: 'GET' }).handler(() => {
  const db = store()
  const githubPatStatus = getGithubAuthStatus(db.directory)
  const summary = db.workspaceSummary()

  const profiles = listModelProfiles(db)
  const hasModel = modelReady(db)
  const enabledProfiles = profiles.filter(p => p.enabled)
  const poolHealth: 'healthy' | 'degraded' | 'unconfigured' = !hasModel
    ? 'unconfigured'
    : enabledProfiles.length > 0 && enabledProfiles.every(p => p.healthState === 'closed')
      ? 'healthy'
      : 'degraded'

  return {
    ...summary,
    hasModel,
    poolHealth,
    hasGithubPat: githubPatStatus.configured,
    githubPatStatus,
  }
})

// --- Model Profiles (Multi-Profile Failover Pool) ---

export const modelData = createServerFn({ method: 'GET' }).handler(() => publicModelSettings())

export const listModels = createServerFn({ method: 'GET' }).handler(() => listModelProfiles())

export const testModel = createServerFn({ method: 'POST' }).validator(providerSettings)
  .handler(async ({ data }) => {
    const result = await checkModelConnection(data)
    if (data.id) execution().wake()
    return result
  })

export const saveModel = createServerFn({ method: 'POST' }).validator(providerSettings)
  .handler(async ({ data }) => {
    const result = await saveModelProfile(data)
    execution().wake()
    return result
  })

export const toggleModelProfile = createServerFn({ method: 'POST' })
  .validator(z.object({ profileId: id, enabled: z.boolean() }))
  .handler(({ data }) => {
    const result = setModelProfileEnabled(data.profileId, data.enabled)
    execution().wake()
    return result
  })

export const removeModelProfile = createServerFn({ method: 'POST' })
  .validator(z.object({ profileId: id }))
  .handler(({ data }) => deleteModelProfile(data.profileId))

// --- Projects, Assets, Specs, GitHub Sync & Personas ---

function serializeLabTarget(handle: LabTargetHandle | undefined) {
  if (!handle) return null
  return {
    targetId: handle.targetId,
    runId: handle.runId,
    networkName: handle.networkName,
    containerName: handle.containerName,
    containerNames: handle.containerNames,
    origin: handle.origin,
    baseUrls: handle.baseUrls,
    hostPort: handle.hostPort,
    internalPort: handle.internalPort,
    healthPath: handle.healthPath,
    seededPersonas: handle.seededPersonas,
    startedAt: handle.startedAt,
  }
}

export const projectData = createServerFn({ method: 'GET' })
  .validator(z.object({ projectId: id }))
  .handler(({ data }) => {
    const db = store()
    const githubPatStatus = getGithubAuthStatus(db.directory)
    return {
      ...db.projectDetail(data.projectId),
      hasGithubPat: githubPatStatus.configured,
      githubPatStatus,
      localLabEnvEnabled: isLocalLabEnvEnabled(),
    }
  })

export const createProject = createServerFn({ method: 'POST' }).validator(newProject)
  .handler(({ data }) => store().createProject(data))

export const removeProject = createServerFn({ method: 'POST' })
  .validator(z.object({
    projectId: id,
    stopActive: z.boolean().optional(),
  }))
  .handler(({ data }) => {
    const exec = execution()
    return deleteProjectWithActiveGuard(store(), exec, exec.labRunner, data)
  })

export const addProjectAsset = createServerFn({ method: 'POST' }).validator(projectAsset)
  .handler(({ data }) => store().addProjectAsset(data))

export const updateProjectAssetScope = createServerFn({ method: 'POST' })
  .validator(z.object({
    requestId: id,
    projectId: id,
    assetId: id,
    includeSubdomains: z.boolean().optional(),
    approveInDefaultScope: z.boolean().optional(),
  }))
  .handler(({ data }) => store().updateProjectAssetScope(data))

export const importProjectDns = createServerFn({ method: 'POST' }).validator(importDnsInventory)
  .handler(({ data }) => store().importProjectDns(data))

export const importProjectAccessPolicy = createServerFn({ method: 'POST' }).validator(importAccessPolicy)
  .handler(({ data }) => store().importProjectAccessPolicy(data))

export const importSpec = createServerFn({ method: 'POST' }).validator(importProjectSpec)
  .handler(({ data }) => {
    const db = store()
    if (data.origin) {
      const project = db.project(data.projectId)
      const origin = assetOriginForEnvironment(project.environment).parse(data.origin)
      return db.importProjectSpec({ ...data, origin })
    }
    return db.importProjectSpec(data)
  })

export const readProjectSpec = createServerFn({ method: 'GET' })
  .validator(z.object({ projectId: id, specId: id }))
  .handler(({ data }) => store().getProjectSpec(data.projectId, data.specId))

export const removeProjectSpec = createServerFn({ method: 'POST' })
  .validator(z.object({ requestId: id, projectId: id, specId: id }))
  .handler(({ data }) => store().deleteProjectSpec(data))

export const getGithubStatus = createServerFn({ method: 'GET' })
  .handler(() => getGithubAuthStatus(store().directory))

export const startGithubDeviceFlowAction = createServerFn({ method: 'POST' })
  .validator(z.object({
    clientId: z.string().trim().min(6, 'Enter a valid GitHub App Client ID.').max(128).optional(),
  }).optional())
  .handler(async ({ data }) => {
    const db = store()
    return startGithubDeviceFlow({
      dataDir: db.directory,
      ...(data?.clientId ? { clientId: data.clientId } : {}),
    })
  })

export const pollGithubDeviceFlowAction = createServerFn({ method: 'POST' })
  .validator(z.object({
    flowId: z.string().trim().min(1).max(128),
  }))
  .handler(async ({ data }) => {
    const db = store()
    return pollGithubDeviceFlow(data.flowId, { dataDir: db.directory })
  })

export const cancelGithubDeviceFlowAction = createServerFn({ method: 'POST' })
  .validator(z.object({
    flowId: z.string().trim().min(1).max(128),
  }))
  .handler(({ data }) => cancelGithubDeviceFlow(data.flowId))

export const saveGithubToken = createServerFn({ method: 'POST' })
  .validator(z.object({
    token: z.string().trim().min(10, 'Enter a valid GitHub personal access token.').max(512),
  }))
  .handler(async ({ data }) => {
    const db = store()
    saveGithubPat(db.directory, data.token)
    try {
      const listed = await listAccessibleGithubRepos({ dataDir: db.directory })
      return {
        status: getGithubAuthStatus(db.directory),
        repos: listed.repos,
        defaultSelected: defaultSelectedRepoNames(listed.repos),
        truncated: listed.truncated,
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to verify GitHub token.'
      if (msg.includes('HTTP 401')) {
        clearGithubPat(db.directory)
      }
      throw new Error(msg)
    }
  })

export const clearGithubToken = createServerFn({ method: 'POST' })
  .handler(() => {
    const db = store()
    const res = clearGithubPat(db.directory)
    return {
      cleared: res.cleared,
      status: getGithubAuthStatus(db.directory),
    }
  })

export const listGithubRepositories = createServerFn({ method: 'GET' })
  .handler(async () => {
    const db = store()
    const status = getGithubAuthStatus(db.directory)
    if (!status.configured) {
      return { status, repos: [], defaultSelected: [], truncated: false }
    }
    const listed = await listAccessibleGithubRepos({ dataDir: db.directory })
    return {
      status: getGithubAuthStatus(db.directory),
      repos: listed.repos,
      defaultSelected: defaultSelectedRepoNames(listed.repos),
      truncated: listed.truncated,
    }
  })

export const syncGithubRepositories = createServerFn({ method: 'POST' })
  .validator(z.object({
    projectId: id,
    repos: z.array(z.string().trim().regex(/^[a-zA-Z0-9_.-]{1,100}\/[a-zA-Z0-9_.-]{1,100}$/)).min(1).max(20),
  }))
  .handler(async ({ data }) => {
    const db = store()
    db.project(data.projectId)
    const synced = await syncGithubRepos(data.repos, undefined, {
      dataDir: db.directory,
      cloneDir: projectReposDir(db.directory, data.projectId),
    })
    let specsImported = 0
    let dependenciesExtracted = 0
    const warnings: string[] = []
    for (const repo of synced) {
      dependenciesExtracted += repo.dependencies.length
      warnings.push(...repo.warnings)
      for (const spec of repo.specs) {
        db.upsertProjectSpecRaw(data.projectId, {
          name: spec.name,
          kind: spec.kind,
          content: spec.content,
        })
        specsImported += 1
      }
    }
    return {
      repos: synced.map(r => ({
        fullName: r.fullName,
        defaultBranch: r.defaultBranch,
        filesCount: r.files.length,
        dependenciesCount: r.dependencies.length,
        specsCount: r.specs.length,
      })),
      specsImported,
      dependenciesExtracted,
      warnings,
    }
  })

export const listPersonas = createServerFn({ method: 'GET' })
  .validator(z.object({ projectId: id }))
  .handler(({ data }) => listProjectPersonas(store(), data.projectId))

export const registerPersona = createServerFn({ method: 'POST' }).validator(createPersona)
  .handler(({ data }) => createProjectPersona(store(), data))

export const removePersona = createServerFn({ method: 'POST' }).validator(deletePersona)
  .handler(({ data }) => deleteProjectPersona(store(), data))

export const testPersonaAuthAction = createServerFn({ method: 'POST' })
  .validator(z.object({
    projectId: id,
    personaId: id,
    origin: z.string().trim().min(1).max(253).optional(),
    path: z.string().trim().startsWith('/').max(256).optional(),
  }))
  .handler(({ data }) => testPersonaAuth(store(), execution().broker, data, execution().personaAuth))

export const readWorkerSessionAction = createServerFn({ method: 'GET' })
  .validator(z.object({ runId: id, workerId: id }))
  .handler(({ data }) => readWorkerSession(store(), data.runId, data.workerId))

// --- Runs, Commands, Exchanges, Artifacts & Reports ---

export const SUBDOMAIN_DISCOVERY_TIMEOUT_MS = 30_000

/** True when a `discovery.subdomains_started` event has no subsequent `discovery.subdomains_discovered`. */
export function isSubdomainDiscoveryPendingFromEvents(
  events: readonly { id: number; kind: string }[],
): boolean {
  let lastStartedId = -1
  let lastDiscoveredId = -1
  for (const ev of events) {
    if (ev.kind === 'discovery.subdomains_started' && ev.id > lastStartedId) lastStartedId = ev.id
    if (ev.kind === 'discovery.subdomains_discovered' && ev.id > lastDiscoveredId) lastDiscoveredId = ev.id
  }
  return lastStartedId > lastDiscoveredId
}

/**
 * Emit `discovery.subdomains_started` and execute subdomain discovery asynchronously in the
 * background so navigation returns immediately. Always guarantees a matching
 * `discovery.subdomains_discovered` event on completion, skip, or error.
 */
export function launchSubdomainDiscoveryInBackground(
  db: Store,
  runId: string,
  runDiscovery: (signal?: AbortSignal) => Promise<RunDiscoverySubdomainsResult>,
  timeoutMs = SUBDOMAIN_DISCOVERY_TIMEOUT_MS,
  options: { signal?: AbortSignal } = {},
): Promise<void> {
  const signal = options.signal
  if (signal?.aborted) return Promise.resolve()
  let startedEventId = 0
  try {
    db.event(
      runId,
      'discovery.subdomains_started',
      'Discovering subdomains in the background (CT logs + DNS)…',
      { timeoutMs },
    )
    const recent = db.eventsAfter(runId, 0, 1000)
    startedEventId = recent.at(-1)?.id ?? 0
  } catch {
    // Store may be unavailable; still return a resolved promise so callers never reject.
    return Promise.resolve()
  }

  return Promise.resolve()
    .then(() => runDiscovery(signal))
    .then(result => {
      if (signal?.aborted) return
      try {
        db.run(runId)
        const after = db.eventsAfter(runId, startedEventId, 100)
        if (!after.some(ev => ev.kind === 'discovery.subdomains_discovered')) {
          db.event(
            runId,
            'discovery.subdomains_discovered',
            result.skipped
              ? `Subdomain discovery skipped (${result.reason ?? 'ineligible'}).`
              : `Subdomain discovery finished (${result.addedOrigins.length} newly added).`,
            {
              skipped: result.skipped,
              reason: result.reason ?? null,
              discoveredCount: result.discovery.discovered.length,
              addedCount: result.addedOrigins.length,
              thirdPartyCount: result.thirdPartyOrigins.length,
              addedOrigins: result.addedOrigins,
              thirdPartyOrigins: result.thirdPartyOrigins,
              warnings: result.discovery.warnings,
            },
          )
        }
      } catch {
        // Store may have closed or run may have been deleted before background discovery settled.
      }
    })
    .catch(err => {
      if (signal?.aborted) return
      try {
        db.run(runId)
        db.event(
          runId,
          'discovery.subdomains_discovered',
          `Subdomain discovery finished with warning: ${err instanceof Error ? err.message : String(err)}`,
          {
            error: err instanceof Error ? err.message : String(err),
            discoveredCount: 0,
            addedCount: 0,
            thirdPartyCount: 0,
            addedOrigins: [],
            thirdPartyOrigins: [],
          },
        )
      } catch {
        // Store may have closed or run may have been deleted before background discovery rejected.
      }
    })
}

export const runData = createServerFn({ method: 'GET' })
  .validator(z.object({ runId: id }))
  .handler(({ data }) => {
    const db = store()
    const detail = db.runDetail(data.runId)
    const subdomainDiscoveryPending = detail.run.phase === 'review'
      ? isSubdomainDiscoveryPendingFromEvents(db.eventsAfter(data.runId, 0, 1000))
      : false
    const includeSubdomainOrigins = db.projectDetail(detail.run.projectId).assets
      .filter(a => a.includeSubdomains && !a.thirdParty)
      .map(a => a.origin)
    return {
      ...detail,
      subdomainDiscoveryPending,
      includeSubdomainOrigins,
      labTarget: serializeLabTarget(execution().labRunner.getTarget(data.runId)),
      localLabEnvEnabled: isLocalLabEnvEnabled(),
      hasModel: modelReady(db),
    }
  })

// Run workspace shell: the run switcher (every run in the workspace, newest first, with
// project names) and true totals for lists the run detail caps (exchanges, events).
export const runShellData = createServerFn({ method: 'GET' })
  .validator(z.object({ runId: id }))
  .handler(({ data }) => store().runShellSummary(data.runId))

export const createRun = createServerFn({ method: 'POST' }).validator(newRun)
  .handler(async ({ data }) => {
    const db = store()
    const created = db.createRun(data)
    try {
      const run = db.run(created.id)
      if (run.phase === 'consent' && run.status === 'waiting') {
        db.command({
          requestId: randomUUID(),
          runId: created.id,
          action: 'discover',
          consent: true,
        })
        void execution().runSupervisedBackgroundTask(
          created.id,
          'subdomain-discovery',
          signal => launchSubdomainDiscoveryInBackground(
            db,
            created.id,
            sig => runDiscoverySubdomainsForRun(db, created.id, {
              timeoutMs: SUBDOMAIN_DISCOVERY_TIMEOUT_MS,
              ...(sig ? { signal: sig } : {}),
            }),
            SUBDOMAIN_DISCOVERY_TIMEOUT_MS,
            { signal },
          ),
        )
      }
    } catch {
      // Auto-discovery must never fail run creation; the run still exists and can be reviewed/discovered.
    }
    return created
  })

/** Testable core for `createRun` instant navigation + non-blocking async subdomain discovery. */
export function createRunWithAsyncDiscovery(
  db: Store,
  data: z.infer<typeof newRun>,
  options: {
    discover: typeof runDiscoverySubdomainsForRun
    timeoutMs?: number
  },
): { created: ReturnType<Store['createRun']>; discoveryPromise: Promise<void> | null } {
  const created = db.createRun(data)
  let discoveryPromise: Promise<void> | null = null
  try {
    const run = db.run(created.id)
    if (run.phase === 'consent' && run.status === 'waiting') {
      db.command({
        requestId: globalThis.crypto.randomUUID(),
        runId: created.id,
        action: 'discover',
        consent: true,
      })
      const timeoutMs = options.timeoutMs ?? SUBDOMAIN_DISCOVERY_TIMEOUT_MS
      discoveryPromise = launchSubdomainDiscoveryInBackground(
        db,
        created.id,
        () => options.discover(db, created.id, { timeoutMs }),
        timeoutMs,
      )
    }
  } catch {
    // Auto-discovery must never fail run creation; the run still exists and can be reviewed/discovered.
  }
  return { created, discoveryPromise }
}

export const removeRun = createServerFn({ method: 'POST' })
  .validator(z.object({
    runId: id,
    stopActive: z.boolean().optional(),
  }))
  .handler(({ data }) => {
    const exec = execution()
    return deleteRunWithActiveGuard(store(), exec, exec.labRunner, data)
  })

export const commandRun = createServerFn({ method: 'POST' }).validator(runCommand)
  .handler(async ({ data }) => {
    const db = store()
    const shouldDiscoverSubdomains = data.action === 'discover' && data.consent && (() => {
      try {
        return db.run(data.runId).phase === 'consent'
      } catch {
        return false
      }
    })()
    const result = db.command(data, data.action !== 'message' || modelReady())
    if (shouldDiscoverSubdomains) {
      void execution().runSupervisedBackgroundTask(
        data.runId,
        'subdomain-discovery',
        signal => launchSubdomainDiscoveryInBackground(
          db,
          data.runId,
          sig => runDiscoverySubdomainsForRun(db, data.runId, {
            timeoutMs: SUBDOMAIN_DISCOVERY_TIMEOUT_MS,
            ...(sig ? { signal: sig } : {}),
          }),
          SUBDOMAIN_DISCOVERY_TIMEOUT_MS,
          { signal },
        ),
      )
    }
    execution().wake()
    return result
  })

export const readArtifact = createServerFn({ method: 'GET' })
  .validator(z.object({ runId: id, artifactId: id }))
  .handler(({ data }) => store().artifact(data.runId, data.artifactId))

export const readExchange = createServerFn({ method: 'GET' })
  .validator(z.object({ runId: id, exchangeId: id }))
  .handler(({ data }) => store().getExchange(data.runId, data.exchangeId))

export const searchRunExchanges = createServerFn({ method: 'GET' })
  .validator(z.object({
    runId: id,
    query: z.string().max(300),
    origin: z.string().max(256).optional(),
    limit: z.number().int().min(1).max(100).optional(),
  }))
  .handler(({ data }) => {
    const db = store()
    const run = db.run(data.runId)
    const approvedOrigins = new Set(run.candidates.filter(c => run.approved.includes(c.id)).map(c => c.origin))
    return db.searchExchanges(data.runId, data.query, {
      approvedOrigins,
      origin: data.origin,
      limit: data.limit,
    })
  })

export const readGraphDigest = createServerFn({ method: 'GET' })
  .validator(z.object({ runId: id, digestId: id }))
  .handler(({ data }) => store().getDigest(data.runId, data.digestId))

export const downloadReportMarkdown = createServerFn({ method: 'GET' })
  .validator(z.object({ runId: id, reportId: id }))
  .handler(({ data }) => exportReportMarkdown(store(), data.runId, data.reportId))

export const exportSarifAction = createServerFn({ method: 'GET' })
  .validator(z.object({ runId: id, reportId: id.optional() }))
  .handler(({ data }) => {
    const res = exportReportSarif(store(), data.runId, data.reportId)
    return { filename: res.filename, content: res.content }
  })

export const generatePatchAction = createServerFn({ method: 'POST' })
  .validator(z.object({
    runId: id,
    findingId: id,
    repo: z.string().trim().min(1).max(200).optional(),
  }))
  .handler(async ({ data }) => execution().runPatchWorkflow(data.runId, data.findingId, data.repo))

export const updateProjectLabConfigAction = createServerFn({ method: 'POST' })
  .validator(z.object({
    requestId: id,
    projectId: id,
    labConfig: labConfigSchema.nullable(),
  }))
  .handler(({ data }) => store().updateProjectLabConfig(data))

export const updateProjectSandboxAllowlistAction = createServerFn({ method: 'POST' })
  .validator(z.object({
    requestId: id,
    projectId: id,
    sandboxWriteAllowlist: z.array(approvedEndpointPatternSchema).max(100),
  }))
  .handler(({ data }) => store().updateProjectSandboxWriteAllowlist(data))

export const startRunLabAction = createServerFn({ method: 'POST' })
  .validator(z.object({ runId: id }))
  .handler(async ({ data }) => {
    const db = store()
    const run = db.run(data.runId)
    const project = db.project(run.projectId)
    assertLocalLabAllowed(project.environment)
    if (!project.labConfig?.enabled) {
      throw new Error('Enable local lab in Project settings before starting LabRunner.')
    }
    const repoDir = resolvePrimaryLabRepoDir(db.directory, project.id, project.labConfig.repo)
    const handle = await execution().labRunner.startLabTarget({
      runId: run.id,
      environment: project.environment,
      repoDir,
      labConfig: project.labConfig,
      storage: db,
      projectId: project.id,
      ...(project.labConfig.iastEnabled
        ? { telemetryDir: join(db.directory, 'evidence', 'lab-telemetry') }
        : {}),
      signal: AbortSignal.timeout(120_000),
    })
    return { target: serializeLabTarget(handle) }
  })

export const stopRunLabAction = createServerFn({ method: 'POST' })
  .validator(z.object({ runId: id }))
  .handler(async ({ data }) => {
    await execution().labRunner.stopLabTarget(data.runId)
    return { stopped: true }
  })

export const checkRunLabHealthAction = createServerFn({ method: 'GET' })
  .validator(z.object({ runId: id }))
  .handler(async ({ data }) => {
    const handle = execution().labRunner.getTarget(data.runId)
    if (!handle) {
      return { running: false, healthy: false, message: 'Lab stack is not running.' }
    }
    try {
      const path = handle.healthPath.startsWith('/') ? handle.healthPath : '/' + handle.healthPath
      const res = await fetch(`${handle.origin}${path}`, {
        method: 'GET',
        redirect: 'manual',
        signal: AbortSignal.timeout(3_000),
      })
      await res.body?.cancel().catch(() => undefined)
      return {
        running: true,
        healthy: res.status < 500,
        statusCode: res.status,
        origin: handle.origin,
        message: `HTTP ${res.status} at ${handle.origin}${path}`,
      }
    } catch (err) {
      return {
        running: true,
        healthy: false,
        origin: handle.origin,
        message: err instanceof Error ? err.message : 'Health check failed.',
      }
    }
  })
