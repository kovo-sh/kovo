import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import {
  clearGithubPat,
  getGithubAuthStatus,
  githubAppInstallUrl,
  listAccessibleGithubRepos,
  resolveGithubAppSlug,
  saveGithubClientId,
  saveGithubPat,
  saveGithubVaultCredential,
} from '../src/server/github-connector.ts'

function tempDataDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix))
}

async function startMockGithubServer(handler: (
  req: IncomingMessage,
  res: ServerResponse,
) => void | Promise<void>): Promise<{ baseUrl: string; close: () => Promise<void> }> {
  const server = createServer((req, res) => {
    void handler(req, res)
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', () => resolve()))
  const port = (server.address() as AddressInfo).port
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve, reject) => server.close(err => (err ? reject(err) : resolve()))),
  }
}

test('resolveGithubAppSlug & githubAppInstallUrl: env precedence, validation, github-app.json fallback, and custom base URL', () => {
  const dataDir = tempDataDir('kovo-gh-slug-')
  const prevSlug = process.env.KOVO_GITHUB_APP_SLUG
  delete process.env.KOVO_GITHUB_APP_SLUG

  try {
    // Default null when neither env nor github-app.json is set
    assert.equal(resolveGithubAppSlug(dataDir), null)
    assert.equal(githubAppInstallUrl(null), null)
    assert.equal(githubAppInstallUrl(undefined), null)
    assert.equal(githubAppInstallUrl('INVALID_SLUG'), null)
    assert.equal(githubAppInstallUrl('../escape'), null)

    // Fallback to github-app.json (0600)
    const credDir = join(dataDir, 'credentials')
    mkdirSync(credDir, { recursive: true, mode: 0o700 })
    writeFileSync(
      join(credDir, 'github-app.json'),
      `${JSON.stringify({ appSlug: 'kovo' }, null, 2)}\n`,
      { mode: 0o600 },
    )
    assert.equal(resolveGithubAppSlug(dataDir), 'kovo')
    assert.equal(
      githubAppInstallUrl('kovo'),
      'https://github.com/apps/kovo/installations/new',
    )
    assert.equal(
      githubAppInstallUrl('kovo', 'https://github.enterprise.local///'),
      'https://github.enterprise.local/apps/kovo/installations/new',
    )

    // saveGithubClientId preserves existing appSlug in github-app.json
    saveGithubClientId(dataDir, 'Iv23liKEEPAPPSLUG99')
    const persisted = JSON.parse(readFileSync(join(credDir, 'github-app.json'), 'utf8')) as Record<string, unknown>
    assert.equal(persisted.clientId, 'Iv23liKEEPAPPSLUG99')
    assert.equal(persisted.appSlug, 'kovo')
    assert.equal(resolveGithubAppSlug(dataDir), 'kovo')

    // Env var takes precedence over github-app.json and trims whitespace
    process.env.KOVO_GITHUB_APP_SLUG = '  kovo-staging  '
    assert.equal(resolveGithubAppSlug(dataDir), 'kovo-staging')

    // Invalid env slug is rejected (returns null)
    process.env.KOVO_GITHUB_APP_SLUG = 'Bad Slug/Path'
    assert.equal(resolveGithubAppSlug(dataDir), null)

    // getGithubAuthStatus exposes appSlug and installUrl
    process.env.KOVO_GITHUB_APP_SLUG = 'kovo'
    const status = getGithubAuthStatus(dataDir)
    assert.equal(status.appSlug, 'kovo')
    assert.equal(status.installUrl, 'https://github.com/apps/kovo/installations/new')
  } finally {
    if (prevSlug === undefined) delete process.env.KOVO_GITHUB_APP_SLUG
    else process.env.KOVO_GITHUB_APP_SLUG = prevSlug
    rmSync(dataDir, { recursive: true, force: true })
  }
})

test('listAccessibleGithubRepos queries /user/installations FIRST, puts installed private/org repos ahead of public repos, and deduplicates keeping richer/private entry', async () => {
  const dataDir = tempDataDir('kovo-gh-inst-first-')
  const prevSlug = process.env.KOVO_GITHUB_APP_SLUG
  process.env.KOVO_GITHUB_APP_SLUG = 'kovo'

  const accessToken = 'ghu_11INSTALLATIONS_FIRST_TEST_TOKEN_12345'
  const callOrder: string[] = []

  const server = await startMockGithubServer((req, res) => {
    const url = req.url ?? '/'
    callOrder.push(url)
    res.setHeader('content-type', 'application/json')

    if (req.method === 'GET' && url.startsWith('/user/installations?')) {
      res.end(JSON.stringify({
        total_count: 2,
        installations: [
          {
            id: 101,
            account: { login: 'acme-corp', type: 'Organization' },
            repository_selection: 'selected',
            html_url: 'https://github.com/organizations/acme-corp/settings/installations/101',
          },
          {
            id: 202,
            account: { login: 'octo-dev', type: 'User' },
            repository_selection: 'all',
            html_url: 'https://github.com/settings/installations/202',
          },
        ],
      }))
      return
    }

    if (req.method === 'GET' && url.startsWith('/user/installations/101/repositories')) {
      res.end(JSON.stringify({
        total_count: 2,
        repositories: [
          {
            full_name: 'acme-corp/payments-private',
            private: true,
            default_branch: 'main',
            updated_at: '2026-11-24T10:00:00Z',
            description: null,
          },
          {
            full_name: 'acme-corp/shared-lib',
            private: false,
            default_branch: 'main',
            updated_at: '2026-11-20T10:00:00Z',
            description: null,
          },
        ],
      }))
      return
    }

    if (req.method === 'GET' && url.startsWith('/user/installations/202/repositories')) {
      res.end(JSON.stringify({
        total_count: 1,
        repositories: [
          {
            full_name: 'octo-dev/secret-sandbox',
            private: true,
            default_branch: 'main',
            updated_at: '2026-11-22T10:00:00Z',
            description: 'Personal private sandbox',
          },
        ],
      }))
      return
    }

    if (req.method === 'GET' && url.startsWith('/user/repos')) {
      res.end(JSON.stringify([
        // Duplicate of installed repo with richer description (should enrich in place without moving order)
        {
          full_name: 'acme-corp/payments-private',
          private: true,
          default_branch: 'main',
          updated_at: '2026-11-24T10:00:00Z',
          description: 'Core payments API',
        },
        // Duplicate where /user/repos reports private=true (should upgrade private flag & description)
        {
          full_name: 'acme-corp/shared-lib',
          private: true,
          default_branch: 'develop',
          updated_at: '2026-11-25T00:00:00Z',
          description: 'Internal shared library',
        },
        // Older public repos that would otherwise push private repos past maxRepos
        {
          full_name: 'octo-dev/public-old-1',
          private: false,
          default_branch: 'main',
          updated_at: '2025-01-01T00:00:00Z',
          description: 'Old public repo 1',
        },
        {
          full_name: 'octo-dev/public-old-2',
          private: false,
          default_branch: 'main',
          updated_at: '2024-01-01T00:00:00Z',
          description: 'Old public repo 2',
        },
      ]))
      return
    }

    res.statusCode = 404
    res.end(JSON.stringify({ message: 'Not Found' }))
  })

  try {
    saveGithubVaultCredential(dataDir, {
      accessToken,
      clientId: 'Iv23liINSTFIRST001',
      login: 'octo-dev',
      authKind: 'github_app_device',
    })

    // Cap maxRepos at 4: all 3 installed repos + 1 public repo, with 2nd public repo truncated
    const listed = await listAccessibleGithubRepos({
      dataDir,
      apiBaseUrl: server.baseUrl,
      githubBaseUrl: server.baseUrl,
      maxRepos: 4,
    })

    // Installations endpoint MUST be called before /user/repos
    const firstInstallIdx = callOrder.findIndex(u => u.startsWith('/user/installations?'))
    const firstUserReposIdx = callOrder.findIndex(u => u.startsWith('/user/repos'))
    assert.ok(firstInstallIdx >= 0)
    assert.ok(firstUserReposIdx > firstInstallIdx, `expected /user/installations before /user/repos, got: ${callOrder.join(', ')}`)

    // Installed repos appear FIRST, followed by non-duplicate public repo
    assert.deepEqual(
      listed.repos.map(r => r.fullName),
      [
        'acme-corp/payments-private',
        'acme-corp/shared-lib',
        'octo-dev/secret-sandbox',
        'octo-dev/public-old-1',
      ],
    )
    assert.equal(listed.truncated, true)

    // Deduplication kept richer metadata & upgraded private=true
    assert.equal(listed.repos[0]!.description, 'Core payments API')
    assert.equal(listed.repos[1]!.private, true)
    assert.equal(listed.repos[1]!.description, 'Internal shared library')
    assert.equal(listed.repos[1]!.defaultBranch, 'develop')

    // Structured installation metadata
    assert.equal(listed.needsAppInstall, false)
    assert.equal(listed.privateRepoCount, 3)
    assert.equal(listed.installUrl, `${server.baseUrl}/apps/kovo/installations/new`)
    assert.deepEqual(listed.installations, [
      {
        id: 101,
        accountLogin: 'acme-corp',
        accountType: 'Organization',
        repositorySelection: 'selected',
        htmlUrl: 'https://github.com/organizations/acme-corp/settings/installations/101',
      },
      {
        id: 202,
        accountLogin: 'octo-dev',
        accountType: 'User',
        repositorySelection: 'all',
        htmlUrl: 'https://github.com/settings/installations/202',
      },
    ])

    // getGithubAuthStatus surfaces observed installation metadata too (for server actions)
    const statusAfter = getGithubAuthStatus(dataDir, undefined, server.baseUrl)
    assert.equal(statusAfter.needsAppInstall, false)
    assert.equal(statusAfter.privateRepoCount, 3)
    assert.equal(statusAfter.installations?.length, 2)
    assert.equal(statusAfter.installUrl, `${server.baseUrl}/apps/kovo/installations/new`)
  } finally {
    await server.close()
    if (prevSlug === undefined) delete process.env.KOVO_GITHUB_APP_SLUG
    else process.env.KOVO_GITHUB_APP_SLUG = prevSlug
    rmSync(dataDir, { recursive: true, force: true })
  }
})

test('listAccessibleGithubRepos sets needsAppInstall=true when GitHub App token has 0 installations, and false for PATs', async () => {
  const dataDir = tempDataDir('kovo-gh-needs-inst-')
  const prevSlug = process.env.KOVO_GITHUB_APP_SLUG
  process.env.KOVO_GITHUB_APP_SLUG = 'kovo'

  const server = await startMockGithubServer((req, res) => {
    const url = req.url ?? '/'
    res.setHeader('content-type', 'application/json')

    if (req.method === 'GET' && url.startsWith('/user/installations')) {
      res.end(JSON.stringify({ total_count: 0, installations: [] }))
      return
    }
    if (req.method === 'GET' && url.startsWith('/user/repos')) {
      res.end(JSON.stringify([
        {
          full_name: 'octo-dev/public-demo',
          private: false,
          default_branch: 'main',
          updated_at: '2026-11-24T12:00:00Z',
          description: 'Public demo repo',
        },
      ]))
      return
    }
    res.statusCode = 404
    res.end(JSON.stringify({}))
  })

  try {
    // 1. GitHub App Device Flow token with 0 installations -> needsAppInstall=true
    saveGithubVaultCredential(dataDir, {
      accessToken: 'ghu_11NO_INSTALLATIONS_TOKEN_999888777',
      clientId: 'Iv23liNOINST00001',
      login: 'octo-dev',
      authKind: 'github_app_device',
    })

    const appListed = await listAccessibleGithubRepos({
      dataDir,
      apiBaseUrl: server.baseUrl,
      githubBaseUrl: server.baseUrl,
    })
    assert.equal(appListed.tokenKind, 'github_app')
    assert.equal(appListed.installations.length, 0)
    assert.equal(appListed.needsAppInstall, true)
    assert.equal(appListed.privateRepoCount, 0)
    assert.equal(appListed.installUrl, `${server.baseUrl}/apps/kovo/installations/new`)
    assert.deepEqual(appListed.repos.map(r => r.fullName), ['octo-dev/public-demo'])

    const appStatus = getGithubAuthStatus(dataDir, undefined, server.baseUrl)
    assert.equal(appStatus.needsAppInstall, true)
    assert.deepEqual(appStatus.installations, [])
    assert.equal(appStatus.privateRepoCount, 0)

    // Clearing credential invalidates cached installation observation
    clearGithubPat(dataDir)
    const clearedStatus = getGithubAuthStatus(dataDir)
    assert.equal(clearedStatus.needsAppInstall, undefined)

    // 2. Fine-grained PAT -> needsAppInstall=false even with 0 installations
    saveGithubPat(dataDir, 'github_pat_11BACKWARD_COMPAT_PAT_555666777')
    const patListed = await listAccessibleGithubRepos({
      dataDir,
      apiBaseUrl: server.baseUrl,
      githubBaseUrl: server.baseUrl,
    })
    assert.equal(patListed.tokenKind, 'fine_grained')
    assert.equal(patListed.installations.length, 0)
    assert.equal(patListed.needsAppInstall, false)
    assert.equal(patListed.privateRepoCount, 0)
    assert.deepEqual(patListed.repos.map(r => r.fullName), ['octo-dev/public-demo'])
  } finally {
    await server.close()
    if (prevSlug === undefined) delete process.env.KOVO_GITHUB_APP_SLUG
    else process.env.KOVO_GITHUB_APP_SLUG = prevSlug
    rmSync(dataDir, { recursive: true, force: true })
  }
})
