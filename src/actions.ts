import { createServerFn } from '@tanstack/react-start'
import { z } from 'zod'
import { id, newProject, newRun, projectAsset, runCommand } from './domain.ts'
import { store } from './server/store.ts'

export const workspaceData = createServerFn({ method: 'GET' }).handler(() => store().listWorkspace())

export const projectData = createServerFn({ method: 'GET' })
  .validator(z.object({ projectId: id }))
  .handler(({ data }) => store().projectDetail(data.projectId))

export const runData = createServerFn({ method: 'GET' })
  .validator(z.object({ runId: id }))
  .handler(({ data }) => store().runDetail(data.runId))

export const createProject = createServerFn({ method: 'POST' }).validator(newProject)
  .handler(({ data }) => store().createProject(data))

export const createRun = createServerFn({ method: 'POST' }).validator(newRun)
  .handler(({ data }) => store().createRun(data))

export const addProjectAsset = createServerFn({ method: 'POST' }).validator(projectAsset)
  .handler(({ data }) => store().addProjectAsset(data))

export const commandRun = createServerFn({ method: 'POST' }).validator(runCommand)
  .handler(({ data }) => store().command(data))

export const readArtifact = createServerFn({ method: 'GET' })
  .validator(z.object({ runId: id, artifactId: id }))
  .handler(({ data }) => store().artifact(data.runId, data.artifactId))
