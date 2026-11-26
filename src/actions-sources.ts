import { createRequire } from 'node:module'
import { createServerFn } from '@tanstack/react-start'
import { z } from 'zod'
import { assetOriginForEnvironment, id, maxSpecBytes, shortText } from './domain.ts'
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

function findActiveProjectRunIds(db: Store, projectId: string): string[] {
  if (typeof db.listActiveRunIdsForProject === 'function') {
    return db.listActiveRunIdsForProject(projectId)
  }
  const detail = db.projectDetail(projectId)
  return detail.runs
    .filter(run => run.isActive || db.isRunActive(run.id))
    .map(run => run.id)
}

function assertProjectHasNoActiveRuns(
  db: Store,
  projectId: string,
  action: 're-sync' | 'unlink',
  repoSlug: string,
): void {
  const activeRunIds = findActiveProjectRunIds(db, projectId)
  if (activeRunIds.length > 0) {
    throw new Error(
      `Cannot ${action} repository "${repoSlug}" while project has ${activeRunIds.length} active ${activeRunIds.length === 1 ? 'run' : 'runs'} (${activeRunIds.join(', ')}). Stop active runs first so live worker bind mounts are not corrupted.`,
    )
  }
}

function purgeRepoDerivedSpecs(
  db: Store,
  projectId: string,
  fullName: string,
  drizzle: typeof import('drizzle-orm'),
  tables: typeof import('./server/schema.ts'),
  keepNames?: ReadonlySet<string>,
): number {
  const prefix = `${fullName}:`
  const specs = db.listProjectSpecs(projectId)
  let removed = 0
  for (const spec of specs) {
    if (!spec.name.startsWith(prefix)) continue
    if (keepNames && keepNames.has(spec.name)) continue
    db.db
      .delete(tables.projectSpecs)
      .where(drizzle.and(
        drizzle.eq(tables.projectSpecs.projectId, projectId),
        drizzle.eq(tables.projectSpecs.id, spec.id),
      ))
      .run()
    removed += 1
  }
  return removed
}

export function unlinkProjectRepoInStore(db: Store, projectId: string, repoSlug: string) {
  const req = createRequire(import.meta.url)
  const { unlinkProjectMountedRepo } = req(
    './server/github-repo-sync.ts',
  ) as typeof import('./server/github-repo-sync.ts')
  const drizzle = req('drizzle-orm') as typeof import('drizzle-orm')
  const tables = req('./server/schema.ts') as typeof import('./server/schema.ts')
  db.project(projectId)
  assertProjectHasNoActiveRuns(db, projectId, 'unlink', repoSlug)
  const result = unlinkProjectMountedRepo(db.directory, projectId, repoSlug)
  const removedSpecsCount = purgeRepoDerivedSpecs(db, projectId, result.fullName, drizzle, tables)
  if (result.unlinked || removedSpecsCount > 0) {
    db.event(null, 'repo.unlinked', `Unlinked repository ${result.fullName}.`, {
      projectId,
      repoSlug: result.fullName,
      removedSpecsCount,
    })
  }
  return result
}

export async function resyncProjectRepoInStore(
  db: Store,
  projectId: string,
  repoSlug: string,
  options: import('./server/github-repo-sync.ts').GithubSyncOptions = {},
) {
  const req = createRequire(import.meta.url)
  const { projectReposDir, syncGithubRepos } = req(
    './server/github-repo-sync.ts',
  ) as typeof import('./server/github-repo-sync.ts')
  const drizzle = req('drizzle-orm') as typeof import('drizzle-orm')
  const tables = req('./server/schema.ts') as typeof import('./server/schema.ts')
  db.project(projectId)
  assertProjectHasNoActiveRuns(db, projectId, 're-sync', repoSlug)
  const synced = await syncGithubRepos([repoSlug], undefined, {
    dataDir: db.directory,
    cloneDir: projectReposDir(db.directory, projectId),
    historyDepth: 1,
    ...options,
    assertNoActiveRuns: fullName => {
      assertProjectHasNoActiveRuns(db, projectId, 're-sync', fullName)
    },
  })
  const repo = synced[0]
  if (!repo) {
    throw new Error(`Repository "${repoSlug}" could not be synced.`)
  }
  let specsImported = 0
  const importedNames = new Set<string>()
  for (const spec of repo.specs) {
    db.upsertProjectSpecRaw(projectId, {
      name: spec.name,
      kind: spec.kind,
      content: spec.content,
    })
    importedNames.add(spec.name)
    specsImported += 1
  }
  const staleSpecsRemoved = purgeRepoDerivedSpecs(db, projectId, repo.fullName, drizzle, tables, importedNames)
  db.event(null, 'repo.resynced', `Re-synced repository ${repo.fullName}.`, {
    projectId,
    repoSlug: repo.fullName,
    specsImported,
    staleSpecsRemoved,
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
}

export function updateProjectSpecInStore(
  db: Store,
  input: z.output<typeof updateProjectSpecSchema>,
) {
  const req = createRequire(import.meta.url)
  const { and, eq, ne } = req('drizzle-orm') as typeof import('drizzle-orm')
  const { redact } = req('./server/redact.ts') as typeof import('./server/redact.ts')
  const tables = req('./server/schema.ts') as typeof import('./server/schema.ts')
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
  .handler(async ({ data }) => {
    const [{ store }, { listProjectMountedRepos }] = await Promise.all([
      import('./server/store.ts'),
      import('./server/github-repo-sync.ts'),
    ])
    const db = store()
    db.project(data.projectId)
    return listProjectMountedRepos(db.directory, data.projectId)
  })

export const unlinkProjectRepoAction = createServerFn({ method: 'POST' })
  .validator(z.object({ projectId: id, repoSlug: repoSlugSchema }))
  .handler(async ({ data }) => {
    const [{ store }, { unlinkProjectMountedRepoLocked }, drizzle, tables] = await Promise.all([
      import('./server/store.ts'),
      import('./server/github-repo-sync.ts'),
      import('drizzle-orm'),
      import('./server/schema.ts'),
    ])
    const db = store()
    db.project(data.projectId)
    assertProjectHasNoActiveRuns(db, data.projectId, 'unlink', data.repoSlug)
    const result = await unlinkProjectMountedRepoLocked(db.directory, data.projectId, data.repoSlug, {
      assertNoActiveRuns: () => {
        assertProjectHasNoActiveRuns(db, data.projectId, 'unlink', data.repoSlug)
      },
    })
    const removedSpecsCount = purgeRepoDerivedSpecs(db, data.projectId, result.fullName, drizzle, tables)
    if (result.unlinked || removedSpecsCount > 0) {
      db.event(null, 'repo.unlinked', `Unlinked repository ${result.fullName}.`, {
        projectId: data.projectId,
        repoSlug: result.fullName,
        removedSpecsCount,
      })
    }
    return result
  })

export const resyncProjectRepoAction = createServerFn({ method: 'POST' })
  .validator(z.object({ projectId: id, repoSlug: repoSlugSchema }))
  .handler(async ({ data }) => {
    const [{ store }, { projectReposDir, syncGithubRepos }, drizzle, tables] = await Promise.all([
      import('./server/store.ts'),
      import('./server/github-repo-sync.ts'),
      import('drizzle-orm'),
      import('./server/schema.ts'),
    ])
    const db = store()
    db.project(data.projectId)
    assertProjectHasNoActiveRuns(db, data.projectId, 're-sync', data.repoSlug)
    const synced = await syncGithubRepos([data.repoSlug], undefined, {
      dataDir: db.directory,
      cloneDir: projectReposDir(db.directory, data.projectId),
      historyDepth: 1,
      assertNoActiveRuns: fullName => {
        assertProjectHasNoActiveRuns(db, data.projectId, 're-sync', fullName)
      },
    })
    const repo = synced[0]
    if (!repo) {
      throw new Error(`Repository "${data.repoSlug}" could not be synced.`)
    }
    let specsImported = 0
    const importedNames = new Set<string>()
    for (const spec of repo.specs) {
      db.upsertProjectSpecRaw(data.projectId, {
        name: spec.name,
        kind: spec.kind,
        content: spec.content,
      })
      importedNames.add(spec.name)
      specsImported += 1
    }
    const staleSpecsRemoved = purgeRepoDerivedSpecs(db, data.projectId, repo.fullName, drizzle, tables, importedNames)
    db.event(null, 'repo.resynced', `Re-synced repository ${repo.fullName}.`, {
      projectId: data.projectId,
      repoSlug: repo.fullName,
      specsImported,
      staleSpecsRemoved,
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
  .handler(async ({ data }) => {
    const { store } = await import('./server/store.ts')
    return store().getProjectSpec(data.projectId, data.specId)
  })

export const updateProjectSpecAction = createServerFn({ method: 'POST' })
  .validator(updateProjectSpecSchema)
  .handler(async ({ data }) => {
    const [{ store }, { and, eq, ne }, { redact }, tables] = await Promise.all([
      import('./server/store.ts'),
      import('drizzle-orm'),
      import('./server/redact.ts'),
      import('./server/schema.ts'),
    ])
    const db = store()
    return db.operate(data, () => {
      const project = db.project(data.projectId)
      const existing = db.getProjectSpec(project.id, data.specId)
      const rawOrigin = data.origin?.trim() ?? ''
      const normalizedOrigin = rawOrigin
        ? assetOriginForEnvironment(project.environment).parse(rawOrigin)
        : null
      const cleanName = redact(data.name.trim())
      if (!cleanName) {
        throw new Error('Spec name is required.')
      }
      const cleanContent = redact(data.content)

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
          kind: data.kind,
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
  })
