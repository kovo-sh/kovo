import { createServerFn } from '@tanstack/react-start'
import { and, eq, ne } from 'drizzle-orm'
import { z } from 'zod'
import { assetOriginForEnvironment, id, maxSpecBytes, shortText } from './domain.ts'
import {
  listProjectMountedRepos,
  projectReposDir,
  syncGithubRepos,
  unlinkProjectMountedRepo,
} from './server/github-repo-sync.ts'
import { redact } from './server/redact.ts'
import * as tables from './server/schema.ts'
import { store } from './server/store.ts'
import type { Store } from './server/store.ts'

const repoSlugSchema = z
  .string()
  .trim()
  .regex(/^[a-zA-Z0-9_.-]{1,100}\/[a-zA-Z0-9_.-]{1,100}$/, 'Enter a repository name in owner/repo format.')
  .refine(value => {
    if (value.includes('..')) return false
    const [owner, repo] = value.split('/')
    return Boolean(owner && repo && owner !== '.' && repo !== '.' && !owner.startsWith('-') && !repo.startsWith('-'))
  }, 'Invalid repository name.')

export const updateProjectSpecSchema = z.object({
  requestId: id,
  projectId: id,
  specId: id,
  name: shortText,
  kind: z.enum(['openapi', 'graphql', 'routes', 'notes']),
  origin: z.string().trim().max(253).optional().nullable(),
  content: z.string().min(1).max(maxSpecBytes),
})

export function unlinkProjectRepoInStore(db: Store, projectId: string, repoSlug: string) {
  db.project(projectId)
  const result = unlinkProjectMountedRepo(db.directory, projectId, repoSlug)
  if (result.unlinked) {
    db.event(null, 'repo.unlinked', `Unlinked repository ${result.fullName}.`, {
      projectId,
      repoSlug: result.fullName,
    })
  }
  return result
}

export function updateProjectSpecInStore(
  db: Store,
  input: z.output<typeof updateProjectSpecSchema>,
) {
  return db.operate(input, () => {
    const project = db.project(input.projectId)
    const existing = db.getProjectSpec(project.id, input.specId)
    const rawOrigin = input.origin?.trim() ?? ''
    const normalizedOrigin = rawOrigin
      ? assetOriginForEnvironment(project.environment).parse(rawOrigin)
      : null
    const cleanName = redact(input.name.trim())
    if (!cleanName) {
      throw new Error('Spec name is required.')
    }
    const cleanContent = redact(input.content)

    const collision = db.db
      .select({ id: tables.projectSpecs.id })
      .from(tables.projectSpecs)
      .where(and(
        eq(tables.projectSpecs.projectId, project.id),
        eq(tables.projectSpecs.name, cleanName),
        ne(tables.projectSpecs.id, existing.id),
      ))
      .get()
    if (collision) {
      throw new Error(`Another spec named "${cleanName}" already exists in this project.`)
    }

    const updated = db.db
      .update(tables.projectSpecs)
      .set({
        name: cleanName,
        kind: input.kind,
        origin: normalizedOrigin,
        content: cleanContent,
      })
      .where(and(
        eq(tables.projectSpecs.id, existing.id),
        eq(tables.projectSpecs.projectId, project.id),
      ))
      .returning()
      .get()
    if (!updated) {
      throw new Error('Project spec not found.')
    }

    db.event(null, 'spec.updated', `Updated project spec ${updated.name}.`, {
      projectId: project.id,
      specId: updated.id,
      kind: updated.kind,
    })

    return {
      id: updated.id,
      projectId: updated.projectId,
      name: updated.name,
      kind: updated.kind,
      origin: updated.origin,
      bytes: Buffer.byteLength(updated.content, 'utf8'),
      createdAt: updated.createdAt,
    }
  })
}

export const listProjectReposAction = createServerFn({ method: 'GET' })
  .validator(z.object({ projectId: id }))
  .handler(({ data }) => {
    const db = store()
    db.project(data.projectId)
    return listProjectMountedRepos(db.directory, data.projectId)
  })

export const unlinkProjectRepoAction = createServerFn({ method: 'POST' })
  .validator(z.object({ projectId: id, repoSlug: repoSlugSchema }))
  .handler(({ data }) => unlinkProjectRepoInStore(store(), data.projectId, data.repoSlug))

export const resyncProjectRepoAction = createServerFn({ method: 'POST' })
  .validator(z.object({ projectId: id, repoSlug: repoSlugSchema }))
  .handler(async ({ data }) => {
    const db = store()
    db.project(data.projectId)
    const synced = await syncGithubRepos([data.repoSlug], undefined, {
      dataDir: db.directory,
      cloneDir: projectReposDir(db.directory, data.projectId),
    })
    const repo = synced[0]
    if (!repo) {
      throw new Error(`Repository "${data.repoSlug}" could not be synced.`)
    }
    let specsImported = 0
    for (const spec of repo.specs) {
      db.upsertProjectSpecRaw(data.projectId, {
        name: spec.name,
        kind: spec.kind,
        content: spec.content,
      })
      specsImported += 1
    }
    db.event(null, 'repo.resynced', `Re-synced repository ${repo.fullName}.`, {
      projectId: data.projectId,
      repoSlug: repo.fullName,
      specsImported,
      dependenciesExtracted: repo.dependencies.length,
    })
    return {
      fullName: repo.fullName,
      defaultBranch: repo.defaultBranch,
      commitSha: repo.commitSha ?? null,
      filesCount: repo.files.length,
      dependenciesCount: repo.dependencies.length,
      specsImported,
      warnings: repo.warnings,
    }
  })

export const readProjectSpecContentAction = createServerFn({ method: 'GET' })
  .validator(z.object({ projectId: id, specId: id }))
  .handler(({ data }) => store().getProjectSpec(data.projectId, data.specId))

export const updateProjectSpecAction = createServerFn({ method: 'POST' })
  .validator(updateProjectSpecSchema)
  .handler(({ data }) => updateProjectSpecInStore(store(), data))
