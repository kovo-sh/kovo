import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'
import {
  listProjectReposAction,
  readProjectSpecContentAction,
  resyncProjectRepoAction,
  unlinkProjectRepoAction,
  unlinkProjectRepoInStore,
  updateProjectSpecAction,
  updateProjectSpecInStore,
} from '../src/actions-sources.ts'
import { newProject } from '../src/domain.ts'
import {
  listProjectMountedRepos,
  projectReposDir,
  unlinkProjectMountedRepo,
} from '../src/server/github-repo-sync.ts'
import * as tables from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')

function withTempDir(fn: (dir: string) => Promise<void> | void) {
  return async () => {
    const dir = mkdtempSync(join(tmpdir(), 'kovo-ux-sources-'))
    try {
      await fn(dir)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  }
}

function withTempStore(fn: (ctx: { dir: string; store: Store }) => Promise<void> | void) {
  return async () => {
    const dir = mkdtempSync(join(tmpdir(), 'kovo-ux-sources-store-'))
    const store = new Store(dir, { ftsMode: 'preview' })
    try {
      await fn({ dir, store })
    } finally {
      store.close()
      rmSync(dir, { recursive: true, force: true })
    }
  }
}

test('listProjectMountedRepos returns empty list when unset and inspects git + non-git repos', withTempDir(dir => {
  const projectId = randomUUID()
  assert.deepEqual(listProjectMountedRepos(dir, projectId), [])

  const reposDir = projectReposDir(dir, projectId)
  const gitRepoDir = join(reposDir, 'acme', 'api-service')
  mkdirSync(gitRepoDir, { recursive: true })
  writeFileSync(join(gitRepoDir, 'openapi.yaml'), 'openapi: 3.1.0\ninfo:\n  title: API\n  version: 1.0.0\n')
  execFileSync('git', ['-C', gitRepoDir, 'init', '-b', 'main'], { stdio: 'ignore' })
  execFileSync('git', ['-C', gitRepoDir, 'config', 'user.email', 'qa@example.test'], { stdio: 'ignore' })
  execFileSync('git', ['-C', gitRepoDir, 'config', 'user.name', 'QA'], { stdio: 'ignore' })
  execFileSync('git', ['-C', gitRepoDir, 'add', '.'], { stdio: 'ignore' })
  execFileSync('git', ['-C', gitRepoDir, 'commit', '-m', 'init'], { stdio: 'ignore' })
  const expectedSha = execFileSync('git', ['-C', gitRepoDir, 'rev-parse', '--short', 'HEAD'], { encoding: 'utf8' }).trim()

  const plainRepoDir = join(reposDir, 'beta', 'web-app')
  mkdirSync(plainRepoDir, { recursive: true })
  writeFileSync(join(plainRepoDir, 'package.json'), '{"name":"web-app"}\n')

  const listed = listProjectMountedRepos(dir, projectId)
  assert.equal(listed.length, 2)
  assert.equal(listed[0].fullName, 'acme/api-service')
  assert.equal(listed[0].mountPath, '/repos/acme/api-service')
  assert.equal(listed[0].branch, 'main')
  assert.equal(listed[0].commitSha, expectedSha)
  assert.ok(listed[0].sizeBytes > 0)
  assert.ok(listed[0].updatedAt > 0)

  assert.equal(listed[1].fullName, 'beta/web-app')
  assert.equal(listed[1].mountPath, '/repos/beta/web-app')
  assert.equal(listed[1].branch, null)
  assert.equal(listed[1].commitSha, null)
  assert.ok(listed[1].sizeBytes >= 19)
}))

test('unlinkProjectMountedRepo removes target repo cleanly and strictly rejects path traversal & symlink escapes', withTempDir(dir => {
  const projectId = randomUUID()
  const siblingProjectId = randomUUID()
  const reposDir = projectReposDir(dir, projectId)
  const siblingRepo = join(projectReposDir(dir, siblingProjectId), 'acme', 'keep-me')
  const sameOwnerSibling = join(reposDir, 'acme', 'stay-mounted')
  const targetRepo = join(reposDir, 'acme', 'remove-me')
  const outsideDir = join(dir, 'outside-secret')

  mkdirSync(siblingRepo, { recursive: true })
  mkdirSync(sameOwnerSibling, { recursive: true })
  mkdirSync(targetRepo, { recursive: true })
  mkdirSync(outsideDir, { recursive: true })
  writeFileSync(join(siblingRepo, 'marker.txt'), 'keep')
  writeFileSync(join(sameOwnerSibling, 'marker.txt'), 'keep')
  writeFileSync(join(targetRepo, 'README.md'), 'bye')
  writeFileSync(join(outsideDir, 'sensitive.txt'), 'do-not-delete')

  const badSlugs = [
    '../other/repo',
    'acme/../../outside-secret',
    'acme/..',
    '../..',
    '..',
    '/etc/passwd',
    'acme/remove-me/sub',
    '-acme/repo',
    'acme/-repo',
    'acme\\remove-me',
  ]
  for (const badSlug of badSlugs) {
    assert.throws(
      () => unlinkProjectMountedRepo(dir, projectId, badSlug),
      /Invalid|escapes/i,
      `Expected traversal/invalid repo slug to throw: ${badSlug}`,
    )
  }

  assert.throws(
    () => unlinkProjectMountedRepo(dir, '../escape', 'acme/remove-me'),
    /Invalid project ID/i,
  )

  // Symlinked owner or target escaping repos/<projectId>/ must be rejected without touching outsideDir.
  symlinkSync(outsideDir, join(reposDir, 'evil-owner'))
  assert.throws(
    () => unlinkProjectMountedRepo(dir, projectId, 'evil-owner/sensitive'),
    /symlink|invalid owner/i,
  )
  mkdirSync(join(reposDir, 'evil-link-owner'), { recursive: true })
  symlinkSync(outsideDir, join(reposDir, 'evil-link-owner', 'escape-repo'))
  assert.throws(
    () => unlinkProjectMountedRepo(dir, projectId, 'evil-link-owner/escape-repo'),
    /symlink/i,
  )
  assert.equal(existsSync(join(outsideDir, 'sensitive.txt')), true)

  // Unlink valid repo
  const res = unlinkProjectMountedRepo(dir, projectId, 'acme/remove-me')
  assert.deepEqual(res, { unlinked: true, fullName: 'acme/remove-me' })
  assert.equal(existsSync(targetRepo), false)
  assert.equal(existsSync(join(sameOwnerSibling, 'marker.txt')), true)
  assert.equal(existsSync(join(siblingRepo, 'marker.txt')), true)

  // Unlinking missing repo is idempotent and returns unlinked: false
  const again = unlinkProjectMountedRepo(dir, projectId, 'acme/remove-me')
  assert.deepEqual(again, { unlinked: false, fullName: 'acme/remove-me' })

  // Unlinking last repo under an owner cleans up the empty owner directory
  const lastOwnerDir = join(reposDir, 'solo')
  mkdirSync(join(lastOwnerDir, 'only-repo'), { recursive: true })
  assert.deepEqual(unlinkProjectMountedRepo(dir, projectId, 'solo/only-repo'), {
    unlinked: true,
    fullName: 'solo/only-repo',
  })
  assert.equal(existsSync(lastOwnerDir), false)
}))

test('updateProjectSpecInStore updates name, kind, origin, content in place without leaving orphan rows', withTempStore(({ dir, store }) => {
  const project = store.createProject(newProject.parse({
    requestId: randomUUID(),
    name: 'Spec Edit Project',
    seeds: ['https://api.example.com'],
  }))

  const imported = store.importProjectSpec({
    requestId: randomUUID(),
    projectId: project.id,
    name: 'initial-spec.yaml',
    kind: 'openapi',
    origin: 'https://api.example.com',
    content: 'openapi: 3.0.0\npaths: {}\n',
  })

  const second = store.importProjectSpec({
    requestId: randomUUID(),
    projectId: project.id,
    name: 'schema.graphql',
    kind: 'graphql',
    content: 'type Query { ping: String }\n',
  })

  // Rename and update every editable field on the first spec
  const updated = updateProjectSpecInStore(store, {
    requestId: randomUUID(),
    projectId: project.id,
    specId: imported.id,
    name: 'renamed-routes.md',
    kind: 'routes',
    origin: null,
    content: '# Updated routes\nGET /v2/health\n',
  })

  assert.equal(updated.id, imported.id)
  assert.equal(updated.name, 'renamed-routes.md')
  assert.equal(updated.kind, 'routes')
  assert.equal(updated.origin, null)

  // Verify no orphan rows were left behind
  const allSpecs = store.listProjectSpecs(project.id)
  assert.equal(allSpecs.length, 2)
  const fetched = store.getProjectSpec(project.id, imported.id)
  assert.equal(fetched.name, 'renamed-routes.md')
  assert.equal(fetched.kind, 'routes')
  assert.equal(fetched.origin, null)
  assert.equal(fetched.content, '# Updated routes\nGET /v2/health\n')

  // Reject colliding rename against another spec in the same project
  assert.throws(
    () => updateProjectSpecInStore(store, {
      requestId: randomUUID(),
      projectId: project.id,
      specId: imported.id,
      name: second.name,
      kind: 'routes',
      origin: 'https://api.example.com',
      content: 'changed',
    }),
    /already exists/i,
  )

  // Reject invalid origin for public project
  assert.throws(
    () => updateProjectSpecInStore(store, {
      requestId: randomUUID(),
      projectId: project.id,
      specId: imported.id,
      name: 'renamed-routes.md',
      kind: 'routes',
      origin: 'http://localhost:3000',
      content: 'changed',
    }),
  )

  // unlinkProjectRepoInStore emits repo.unlinked event when removing mounted repo
  const mountedRepoDir = join(projectReposDir(dir, project.id), 'acme', 'demo-app')
  mkdirSync(mountedRepoDir, { recursive: true })
  writeFileSync(join(mountedRepoDir, 'index.ts'), 'export const ok = true\n')
  const unlinked = unlinkProjectRepoInStore(store, project.id, 'acme/demo-app')
  assert.deepEqual(unlinked, { unlinked: true, fullName: 'acme/demo-app' })
  assert.equal(existsSync(mountedRepoDir), false)

  const events = store.db.select().from(tables.events).all()
  assert.ok(events.some(e => e.kind === 'spec.updated'))
  assert.ok(events.some(e => e.kind === 'repo.unlinked'))
}))

test('actions-sources exports TanStack server functions and ProjectSourcesTab wires Linked repos + View/Edit modal', () => {
  assert.equal(typeof listProjectReposAction, 'function')
  assert.equal(typeof unlinkProjectRepoAction, 'function')
  assert.equal(typeof resyncProjectRepoAction, 'function')
  assert.equal(typeof readProjectSpecContentAction, 'function')
  assert.equal(typeof updateProjectSpecAction, 'function')

  const sourcesTab = readFileSync(join(REPO_ROOT, 'src/components/project/ProjectSourcesTab.tsx'), 'utf8')
  assert.match(sourcesTab, /Linked repositories/)
  assert.match(sourcesTab, /Re-sync/)
  assert.match(sourcesTab, /Unlink repository/)
  assert.match(sourcesTab, /role="alertdialog"/)
  assert.match(sourcesTab, /View \/ Edit/)
  assert.match(sourcesTab, /readProjectSpecContentAction/)
  assert.match(sourcesTab, /updateProjectSpecAction/)
  assert.match(sourcesTab, /listProjectReposAction/)
  assert.match(sourcesTab, /resyncProjectRepoAction/)
  assert.match(sourcesTab, /unlinkProjectRepoAction/)
  assert.doesNotMatch(sourcesTab, /\bgithubPatStatus\./)
})
