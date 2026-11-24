import assert from 'node:assert/strict'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import {
  clearGithubPat,
  DEFAULT_GITHUB_PAT_PATH,
  defaultSelectedRepoNames,
  getGithubPatStatus,
  hasGithubPat,
  listAccessibleGithubRepos,
  resolveGithubPatPath,
  saveGithubPat,
  syncGithubRepos,
} from '../src/server/github-connector.ts'

function tempDataDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix))
}

test('vault GitHub PAT lifecycle: 0700 dir, 0600 file, status, clear, and fallback only when absent', () => {
  const dataDir = tempDataDir('guardian-gh-pat-')
  const rawToken = 'github_pat_11EXAMPLE_VAULT_TOKEN_SECRET_9876543210'
  try {
    // Before save: resolve falls back to DEFAULT_GITHUB_PAT_PATH
    assert.equal(resolveGithubPatPath(dataDir), DEFAULT_GITHUB_PAT_PATH)

    // Save writes <dataDir>/credentials/github.pat with 0700 dir and 0600 file
    const saved = saveGithubPat(dataDir, `  ${rawToken}\n`)
    assert.deepEqual(saved, {
      configured: true,
      source: 'vault',
      tokenKind: 'fine_grained',
    })
    assert.equal(JSON.stringify(saved).includes(rawToken), false)

    const credDir = join(dataDir, 'credentials')
    const patPath = join(credDir, 'github.pat')
    assert.equal(existsSync(patPath), true)
    assert.equal(statSync(credDir).mode & 0o777, 0o700)
    assert.equal(statSync(patPath).mode & 0o777, 0o600)

    // Resolution & status prefer vault over fixture
    assert.equal(resolveGithubPatPath(dataDir), patPath)
    assert.deepEqual(getGithubPatStatus(dataDir), {
      configured: true,
      source: 'vault',
      tokenKind: 'fine_grained',
    })
    assert.equal(hasGithubPat({ dataDir }), true)
    assert.equal(hasGithubPat(dataDir), true)
    assert.equal(hasGithubPat(patPath), true)

    // If vault file exists with bad permissions, do NOT silently fall back to fixture
    chmodSync(patPath, 0o644)
    assert.equal(resolveGithubPatPath(dataDir), patPath)
    assert.deepEqual(getGithubPatStatus(dataDir), {
      configured: false,
      source: null,
      tokenKind: null,
    })
    assert.equal(hasGithubPat({ dataDir }), false)

    // Overwriting with a classic PAT restores 0600 and classifies as classic
    const classicToken = 'ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD'
    const updated = saveGithubPat(dataDir, classicToken)
    assert.deepEqual(updated, {
      configured: true,
      source: 'vault',
      tokenKind: 'classic',
    })
    assert.equal(statSync(patPath).mode & 0o777, 0o600)
    assert.equal(JSON.stringify(updated).includes(classicToken), false)

    // Clearing removes the vault file and falls back to fixture only when absent
    const cleared = clearGithubPat(dataDir)
    assert.equal(cleared.cleared, true)
    assert.equal(existsSync(patPath), false)
    assert.equal(resolveGithubPatPath(dataDir), DEFAULT_GITHUB_PAT_PATH)
    assert.equal(JSON.stringify(cleared).includes(classicToken), false)
    assert.equal(cleared.status.source === 'vault', false)

    // Second clear is a safe no-op
    const clearedAgain = clearGithubPat(dataDir)
    assert.equal(clearedAgain.cleared, false)
  } finally {
    rmSync(dataDir, { recursive: true, force: true })
  }
})

test('saveGithubPat rejects malformed tokens without echoing raw input', () => {
  const dataDir = tempDataDir('guardian-gh-invalid-')
  const badToken = 'github_pat_with space_SECRET_DO_NOT_ECHO'
  try {
    assert.throws(
      () => saveGithubPat(dataDir, badToken),
      err => {
        assert.ok(err instanceof Error)
        assert.equal(err.message.includes(badToken), false)
        assert.equal(err.message.includes('SECRET_DO_NOT_ECHO'), false)
        return true
      },
    )
    assert.throws(() => saveGithubPat(dataDir, 'short'))
  } finally {
    rmSync(dataDir, { recursive: true, force: true })
  }
})

test('listAccessibleGithubRepos paginates up to maxRepos, classifies tokenKind, and redacts secrets', async () => {
  const dataDir = tempDataDir('guardian-gh-list-')
  const rawToken = 'github_pat_11LIST_TOKEN_SECRET_XYZ987654321'
  try {
    saveGithubPat(dataDir, rawToken)

    const seenUrls: string[] = []
    const seenAuth: string[] = []
    const page1 = Array.from({ length: 100 }, (_, i) => ({
      full_name: `acme/repo-${String(i + 1).padStart(3, '0')}`,
      private: i % 2 === 0,
      default_branch: i === 0 ? 'develop' : 'main',
      updated_at: '2026-11-24T12:00:00Z',
      description: i === 0 ? `Contains accidental ${rawToken} text` : `Service ${i + 1}`,
    }))
    const page2 = Array.from({ length: 60 }, (_, i) => ({
      full_name: `acme/repo-${String(i + 101).padStart(3, '0')}`,
      private: true,
      default_branch: 'main',
      updated_at: '2026-11-20T12:00:00Z',
      description: null,
    }))

    const stubFetch: typeof fetch = async (input, init) => {
      const url = String(input)
      seenUrls.push(url)
      const hdrs = init?.headers as Record<string, string> | undefined
      seenAuth.push(hdrs?.Authorization ?? '')
      const isPage2 = url.includes('page=2')
      const body = isPage2 ? page2 : page1
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: {
          'content-type': 'application/json',
          ...(isPage2 ? {} : { link: '<https://api.github.com/user/repos?page=2>; rel="next"' }),
        },
      })
    }

    const res = await listAccessibleGithubRepos({ dataDir, fetchImpl: stubFetch, maxRepos: 150 })
    assert.equal(res.tokenKind, 'fine_grained')
    assert.equal(res.repos.length, 150)
    assert.equal(res.truncated, true)
    assert.equal(seenUrls.length, 2)
    assert.ok(seenUrls[0]!.includes('/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member'))
    assert.ok(seenUrls[1]!.includes('&page=2'))
    assert.deepEqual(seenAuth, [`Bearer ${rawToken}`, `Bearer ${rawToken}`])

    // Raw token never leaks into returned repo metadata
    assert.equal(res.repos[0]!.fullName, 'acme/repo-001')
    assert.equal(res.repos[0]!.defaultBranch, 'develop')
    assert.equal(res.repos[0]!.private, true)
    assert.equal(res.repos[0]!.description?.includes(rawToken), false)
    assert.ok(res.repos[0]!.description?.includes('[redacted]'))

    // 401 error redacts any echoed token in error response
    const badFetch: typeof fetch = async () => new Response(`Invalid token: ${rawToken}`, { status: 401 })
    await assert.rejects(
      () => listAccessibleGithubRepos({ dataDir, fetchImpl: badFetch }),
      err => {
        assert.ok(err instanceof Error)
        assert.ok(err.message.includes('HTTP 401'))
        assert.equal(err.message.includes(rawToken), false)
        return true
      },
    )
  } finally {
    rmSync(dataDir, { recursive: true, force: true })
  }
})

test('listAccessibleGithubRepos classifies unknown and classic token kinds via explicit patPath', async () => {
  const dir = tempDataDir('guardian-gh-kind-')
  const patPath = join(dir, 'custom.pat')
  try {
    writeFileSync(patPath, 'custom_token_without_prefix_123456\n', { mode: 0o600 })
    chmodSync(patPath, 0o600)
    const stubFetch: typeof fetch = async () => new Response(JSON.stringify([
      { full_name: 'org/app', private: false, default_branch: 'main', updated_at: null, description: 'App' },
    ]), { status: 200, headers: { 'content-type': 'application/json' } })

    const res = await listAccessibleGithubRepos({ patPath, fetchImpl: stubFetch })
    assert.equal(res.tokenKind, 'unknown')
    assert.equal(res.truncated, false)
    assert.deepEqual(res.repos, [{
      fullName: 'org/app',
      private: false,
      defaultBranch: 'main',
      updatedAt: null,
      description: 'App',
    }])
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('defaultSelectedRepoNames selects all when <= maxAutoSelect and none when > maxAutoSelect', () => {
  const makeRepos = (n: number) => Array.from({ length: n }, (_, i) => ({ fullName: `org/repo-${i + 1}` }))

  assert.deepEqual(defaultSelectedRepoNames([]), [])
  assert.deepEqual(defaultSelectedRepoNames(makeRepos(1)), ['org/repo-1'])
  assert.equal(defaultSelectedRepoNames(makeRepos(10)).length, 10)
  assert.deepEqual(defaultSelectedRepoNames(makeRepos(11)), [])
  assert.equal(defaultSelectedRepoNames(makeRepos(5), 5).length, 5)
  assert.deepEqual(defaultSelectedRepoNames(makeRepos(6), 5), [])
})

test('syncGithubRepos uses vault PAT via dataDir option', async () => {
  const dataDir = tempDataDir('guardian-gh-sync-')
  const rawToken = 'github_pat_11SYNC_VAULT_TOKEN_999888777666'
  try {
    mkdirSync(dataDir, { recursive: true })
    saveGithubPat(dataDir, rawToken)

    let sawBearer = false
    const stubFetch: typeof fetch = async (input, init) => {
      const url = String(input)
      const auth = (init?.headers as Record<string, string> | undefined)?.Authorization
      if (auth === `Bearer ${rawToken}`) sawBearer = true
      if (url.endsWith('/repos/acme/demo')) {
        return new Response(JSON.stringify({ default_branch: 'main', private: true, description: 'Demo', language: 'TypeScript' }), { status: 200 })
      }
      if (url.includes('/git/trees/')) {
        return new Response(JSON.stringify({ truncated: false, tree: [] }), { status: 200 })
      }
      return new Response('Not Found', { status: 404 })
    }

    const synced = await syncGithubRepos(['acme/demo'], undefined, { dataDir, fetchImpl: stubFetch })
    assert.equal(sawBearer, true)
    assert.equal(synced.length, 1)
    assert.equal(synced[0]!.fullName, 'acme/demo')
  } finally {
    rmSync(dataDir, { recursive: true, force: true })
  }
})
