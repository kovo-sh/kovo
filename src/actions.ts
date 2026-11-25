import { createServerFn } from '@tanstack/react-start'
import { z } from 'zod'
import { importAccessPolicy } from './access-policy.ts'
import {
  approvedEndpointPatternSchema,
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
  clearGithubPat,
  defaultSelectedRepoNames,
  getGithubPatStatus,
  listAccessibleGithubRepos,
  projectReposDir,
  saveGithubPat,
  syncGithubRepos,
} from './server/github-connector.ts'
import { assertLocalLabAllowed, LabRunner } from './server/lab-runner.ts'
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
import { store } from './server/store.ts'
import { readWorkerSession, testPersonaAuth } from './server/worker-session-reader.ts'

export const workspaceData = createServerFn({ method: 'GET' }).handler(() => {
  const db = store()
  const githubPatStatus = getGithubPatStatus(db.directory)
  return {
    ...db.listWorkspace(),
    hasModel: modelReady(),
    hasGithubPat: githubPatStatus.configured,
    githubPatStatus,
  }
})

// --- Model Profiles (Multi-Profile Failover Pool) ---

export const modelData = createServerFn({ method: 'GET' }).handler(() => publicModelSettings())

export const listModels = createServerFn({ method: 'GET' }).handler(() => listModelProfiles())

export const testModel = createServerFn({ method: 'POST' }).validator(providerSettings)
  .handler(({ data }) => checkModelConnection(data))

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

let sharedLabRunner: LabRunner | undefined
function getLabRunner(): LabRunner {
  sharedLabRunner ??= new LabRunner()
  return sharedLabRunner
}

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
    const githubPatStatus = getGithubPatStatus(db.directory)
    return {
      ...db.projectDetail(data.projectId),
      hasGithubPat: githubPatStatus.configured,
      githubPatStatus,
      localLabEnvEnabled: isLocalLabEnvEnabled(),
    }
  })

export const createProject = createServerFn({ method: 'POST' }).validator(newProject)
  .handler(({ data }) => store().createProject(data))

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
  .handler(({ data }) => store().importProjectSpec(data))

export const readProjectSpec = createServerFn({ method: 'GET' })
  .validator(z.object({ projectId: id, specId: id }))
  .handler(({ data }) => store().getProjectSpec(data.projectId, data.specId))

export const removeProjectSpec = createServerFn({ method: 'POST' })
  .validator(z.object({ requestId: id, projectId: id, specId: id }))
  .handler(({ data }) => store().deleteProjectSpec(data))

export const saveGithubToken = createServerFn({ method: 'POST' })
  .validator(z.object({
    token: z.string().trim().min(10, 'Enter a valid GitHub personal access token.').max(512),
  }))
  .handler(async ({ data }) => {
    const db = store()
    const status = saveGithubPat(db.directory, data.token)
    try {
      const listed = await listAccessibleGithubRepos({ dataDir: db.directory })
      return {
        status,
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
  .handler(() => clearGithubPat(store().directory))

export const listGithubRepositories = createServerFn({ method: 'GET' })
  .handler(async () => {
    const db = store()
    const status = getGithubPatStatus(db.directory)
    if (!status.configured) {
      return { status, repos: [], defaultSelected: [], truncated: false }
    }
    const listed = await listAccessibleGithubRepos({ dataDir: db.directory })
    return {
      status,
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

export const runData = createServerFn({ method: 'GET' })
  .validator(z.object({ runId: id }))
  .handler(({ data }) => {
    const db = store()
    const detail = db.runDetail(data.runId)
    return {
      ...detail,
      endpoints: db.listEndpoints(data.runId),
      endpointParams: db.listEndpointParams(data.runId),
      apiDependencies: db.listApiDependencies(data.runId),
      labTelemetry: db.listLabTelemetry(data.runId),
      labTarget: serializeLabTarget(getLabRunner().getTarget(data.runId)),
      localLabEnvEnabled: isLocalLabEnvEnabled(),
      hasModel: modelReady(),
    }
  })

// Run workspace shell: the run switcher (every run in the workspace, newest first, with
// project names) and true totals for lists the run detail caps (exchanges, events).
export const runShellData = createServerFn({ method: 'GET' })
  .validator(z.object({ runId: id }))
  .handler(({ data }) => {
    const db = store()
    const run = db.run(data.runId)
    const runs = db.client.prepare(`select r.id as id, r.goal as goal, r.status as status, r.phase as phase,
        r.created_at as createdAt, r.project_id as projectId, p.name as projectName,
        (select count(*) from findings f where f.run_id = r.id and f.superseded_by_finding_id is null) as findings
      from runs r join projects p on p.id = r.project_id
      where r.workspace_id = ? order by r.created_at desc limit 200`).all(run.workspaceId) as {
      id: string; goal: string; status: string; phase: string; createdAt: number; projectId: string; projectName: string; findings: number
    }[]
    const counts = db.client.prepare(`select
        (select count(*) from broker_exchanges where run_id = ?) as exchanges,
        (select count(*) from events where run_id = ?) as events`).get(run.id, run.id) as { exchanges: number; events: number }
    return { runs: runs.map(r => ({ ...r, findings: Number(r.findings) })), counts: { exchanges: Number(counts.exchanges), events: Number(counts.events) } }
  })

export const createRun = createServerFn({ method: 'POST' }).validator(newRun)
  .handler(({ data }) => store().createRun(data))

export const commandRun = createServerFn({ method: 'POST' }).validator(runCommand)
  .handler(({ data }) => {
    const result = store().command(data, data.action !== 'message' || modelReady())
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
    const repoDir = projectReposDir(db.directory, project.id)
    const handle = await getLabRunner().startLabTarget({
      runId: run.id,
      environment: project.environment,
      repoDir,
      labConfig: project.labConfig,
      storage: db,
      projectId: project.id,
      signal: AbortSignal.timeout(120_000),
    })
    return { target: serializeLabTarget(handle) }
  })

export const stopRunLabAction = createServerFn({ method: 'POST' })
  .validator(z.object({ runId: id }))
  .handler(async ({ data }) => {
    await getLabRunner().stopLabTarget(data.runId)
    return { stopped: true }
  })

export const checkRunLabHealthAction = createServerFn({ method: 'GET' })
  .validator(z.object({ runId: id }))
  .handler(async ({ data }) => {
    const handle = getLabRunner().getTarget(data.runId)
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
