import { createServerFn } from '@tanstack/react-start'
import { z } from 'zod'
import { importAccessPolicy } from './access-policy.ts'
import { id, importDnsInventory, newProject, newRun, projectAsset, providerSettings, runCommand } from './domain.ts'
import { execution } from './server/execution.ts'
import { checkModelConnection, modelReady, publicModelSettings, saveModelSettings } from './server/model-settings.ts'
import { exportReportMarkdown } from './server/report-export.ts'
import { store } from './server/store.ts'

export const workspaceData = createServerFn({ method: 'GET' }).handler(() => ({
  ...store().listWorkspace(),
  hasModel: modelReady(),
}))

export const modelData = createServerFn({ method: 'GET' }).handler(() => publicModelSettings())

export const testModel = createServerFn({ method: 'POST' }).validator(providerSettings)
  .handler(({ data }) => checkModelConnection(data))

export const saveModel = createServerFn({ method: 'POST' }).validator(providerSettings)
  .handler(async ({ data }) => {
    const result = await saveModelSettings(data)
    execution().wake()
    return result
  })

export const projectData = createServerFn({ method: 'GET' })
  .validator(z.object({ projectId: id }))
  .handler(({ data }) => store().projectDetail(data.projectId))

export const runData = createServerFn({ method: 'GET' })
  .validator(z.object({ runId: id }))
  .handler(({ data }) => ({ ...store().runDetail(data.runId), hasModel: modelReady() }))

export const createProject = createServerFn({ method: 'POST' }).validator(newProject)
  .handler(({ data }) => store().createProject(data))

export const createRun = createServerFn({ method: 'POST' }).validator(newRun)
  .handler(({ data }) => store().createRun(data))

export const addProjectAsset = createServerFn({ method: 'POST' }).validator(projectAsset)
  .handler(({ data }) => store().addProjectAsset(data))

export const importProjectDns = createServerFn({ method: 'POST' }).validator(importDnsInventory)
  .handler(({ data }) => store().importProjectDns(data))

export const importProjectAccessPolicy = createServerFn({ method: 'POST' }).validator(importAccessPolicy)
  .handler(({ data }) => store().importProjectAccessPolicy(data))

export const commandRun = createServerFn({ method: 'POST' }).validator(runCommand)
  .handler(({ data }) => {
    const result = store().command(data, data.action !== 'message' || modelReady())
    execution().wake()
    return result
  })

export const readArtifact = createServerFn({ method: 'GET' })
  .validator(z.object({ runId: id, artifactId: id }))
  .handler(({ data }) => store().artifact(data.runId, data.artifactId))

export const downloadReportMarkdown = createServerFn({ method: 'GET' })
  .validator(z.object({ runId: id, reportId: id }))
  .handler(({ data }) => exportReportMarkdown(store(), data.runId, data.reportId))
