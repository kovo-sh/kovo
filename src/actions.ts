import { createServerFn } from '@tanstack/react-start'
import { z } from 'zod'
import { importAccessPolicy } from './access-policy.ts'
import {
  createPersona,
  deletePersona,
  id,
  importDnsInventory,
  importProjectSpec,
  newProject,
  newRun,
  projectAsset,
  providerSettings,
  runCommand,
} from './domain.ts'
import { execution } from './server/execution.ts'
import { hasGithubPat, projectReposDir, syncGithubRepos } from './server/github-connector.ts'
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
import { store } from './server/store.ts'

export const workspaceData = createServerFn({ method: 'GET' }).handler(() => ({
  ...store().listWorkspace(),
  hasModel: modelReady(),
  hasGithubPat: hasGithubPat(),
}))

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

export const projectData = createServerFn({ method: 'GET' })
  .validator(z.object({ projectId: id }))
  .handler(({ data }) => ({
    ...store().projectDetail(data.projectId),
    hasGithubPat: hasGithubPat(),
  }))

export const createProject = createServerFn({ method: 'POST' }).validator(newProject)
  .handler(({ data }) => store().createProject(data))

export const addProjectAsset = createServerFn({ method: 'POST' }).validator(projectAsset)
  .handler(({ data }) => store().addProjectAsset(data))

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

export const syncGithubRepositories = createServerFn({ method: 'POST' })
  .validator(z.object({
    projectId: id,
    repos: z.array(z.string().trim().regex(/^[a-zA-Z0-9_.-]{1,100}\/[a-zA-Z0-9_.-]{1,100}$/)).min(1).max(20),
  }))
  .handler(async ({ data }) => {
    const db = store()
    db.project(data.projectId)
    const synced = await syncGithubRepos(data.repos, undefined, {
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

// --- Runs, Commands, Exchanges, Artifacts & Reports ---

export const runData = createServerFn({ method: 'GET' })
  .validator(z.object({ runId: id }))
  .handler(({ data }) => ({ ...store().runDetail(data.runId), hasModel: modelReady() }))

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
