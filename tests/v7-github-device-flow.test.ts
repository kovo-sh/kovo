import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import {
  cancelGithubDeviceFlow,
  clearGithubPat,
  getGithubAuthStatus,
  listAccessibleGithubRepos,
  pollGithubDeviceFlow,
  readGithubVaultCredential,
  saveGithubPat,
  saveGithubVaultCredential,
  startGithubDeviceFlow,
  syncGithubRepos,
} from '../src/server/github-connector.ts'

function tempDataDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix))
}

async function readRequestBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))
  }
  return Buffer.concat(chunks).toString('utf8')
}

async function startMockGithubServer(handler: (
  req: IncomingMessage,
  body: string,
  res: ServerResponse,
) => void | Promise<void>): Promise<{ baseUrl: string; close: () => Promise<void> }> {
  const server = createServer((req, res) => {
    void readRequestBody(req).then(body => handler(req, body, res))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', () => resolve()))
  const port = (server.address() as AddressInfo).port
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve, reject) => server.close(err => (err ? reject(err) : resolve()))),
  }
}

test('GitHub App Device Flow end-to-end: start -> pending -> slow_down -> authorized -> 0600 vault -> repo discovery', async () => {
  const dataDir = tempDataDir('kovo-gh-device-')
  const prevEnvClientId = process.env.KOVO_GITHUB_CLIENT_ID
  delete process.env.KOVO_GITHUB_CLIENT_ID

  const testClientId = 'Iv23liTESTCLIENTID001'
  const secretDeviceCode = 'dc_super_secret_device_code_never_expose_998877'
  const userCode = 'WDJB-MJHT'
  const accessToken = 'ghu_11DEVICE_FLOW_ACCESS_TOKEN_SECRET_11223344'
  const refreshToken = 'ghr_11DEVICE_FLOW_REFRESH_TOKEN_SECRET_55667788'

  let pollAttempts = 0
  const seenDeviceStartParams: URLSearchParams[] = []
  const seenPollParams: URLSearchParams[] = []
  const seenApiPaths: string[] = []

  const server = await startMockGithubServer((req, body, res) => {
    const url = req.url ?? '/'
    res.setHeader('content-type', 'application/json')

    if (req.method === 'POST' && url === '/login/device/code') {
      const params = new URLSearchParams(body)
      seenDeviceStartParams.push(params)
      res.end(JSON.stringify({
        device_code: secretDeviceCode,
        user_code: userCode,
        verification_uri: 'https://github.com/login/device',
        expires_in: 900,
        interval: 5,
      }))
      return
    }

    if (req.method === 'POST' && url === '/login/oauth/access_token') {
      const params = new URLSearchParams(body)
      seenPollParams.push(params)
      assert.equal(params.get('grant_type'), 'urn:ietf:params:oauth:grant-type:device_code')
      assert.equal(params.get('client_id'), testClientId)
      assert.equal(params.get('device_code'), secretDeviceCode)

      pollAttempts += 1
      if (pollAttempts === 1) {
        res.end(JSON.stringify({ error: 'authorization_pending' }))
        return
      }
      if (pollAttempts === 2) {
        res.end(JSON.stringify({ error: 'slow_down', interval: 10 }))
        return
      }
      res.end(JSON.stringify({
        access_token: accessToken,
        token_type: 'bearer',
        expires_in: 28800,
        refresh_token: refreshToken,
        refresh_token_expires_in: 15897600,
      }))
      return
    }

    if (req.method === 'GET' && url === '/user') {
      seenApiPaths.push(url)
      assert.equal(req.headers.authorization, `Bearer ${accessToken}`)
      res.end(JSON.stringify({ login: 'octo-researcher' }))
      return
    }

    if (req.method === 'GET' && url.startsWith('/user/repos')) {
      seenApiPaths.push(url)
      assert.equal(req.headers.authorization, `Bearer ${accessToken}`)
      // Empty /user/repos to exercise /user/installations merge for GitHub App tokens
      res.end(JSON.stringify([]))
      return
    }

    if (req.method === 'GET' && url.startsWith('/user/installations/4242/repositories')) {
      seenApiPaths.push(url)
      assert.equal(req.headers.authorization, `Bearer ${accessToken}`)
      res.end(JSON.stringify({
        total_count: 2,
        repositories: [
          {
            full_name: 'acme/api-gateway',
            private: true,
            default_branch: 'main',
            updated_at: '2026-11-24T12:00:00Z',
            description: 'Gateway service',
          },
          {
            full_name: 'acme/web-portal',
            private: false,
            default_branch: 'develop',
            updated_at: '2026-11-23T12:00:00Z',
            description: null,
          },
        ],
      }))
      return
    }

    if (req.method === 'GET' && url.startsWith('/user/installations')) {
      seenApiPaths.push(url)
      assert.equal(req.headers.authorization, `Bearer ${accessToken}`)
      res.end(JSON.stringify({
        total_count: 1,
        installations: [{ id: 4242 }],
      }))
      return
    }

    res.statusCode = 404
    res.end(JSON.stringify({ message: 'Not Found' }))
  })

  try {
    // Initially env is unset and vault has no clientId
    const before = getGithubAuthStatus(dataDir)
    assert.equal(before.githubDeviceFlowConfigured, false)
    assert.equal(before.clientIdSource, null)

    // Start device flow with explicit clientId (persisted to 0600 vault config)
    const started = await startGithubDeviceFlow({
      dataDir,
      clientId: testClientId,
      githubBaseUrl: server.baseUrl,
      apiBaseUrl: server.baseUrl,
    })

    assert.ok(started.flowId.length >= 16)
    assert.equal(started.userCode, userCode)
    assert.equal(started.verificationUri, 'https://github.com/login/device')
    assert.equal(started.expiresIn, 900)
    assert.equal(started.intervalSec, 5)

    // CRITICAL: device_code must NEVER appear in client-facing response
    const serializedStart = JSON.stringify(started)
    assert.equal(serializedStart.includes(secretDeviceCode), false)
    assert.equal('device_code' in started, false)
    assert.equal('deviceCode' in started, false)

    // Verify no scope was sent to /login/device/code for GitHub App
    assert.equal(seenDeviceStartParams.length, 1)
    assert.equal(seenDeviceStartParams[0]!.get('client_id'), testClientId)
    assert.equal(seenDeviceStartParams[0]!.get('scope'), null)

    // Poll 1: authorization_pending
    const poll1 = await pollGithubDeviceFlow(started.flowId, {
      dataDir,
      githubBaseUrl: server.baseUrl,
      apiBaseUrl: server.baseUrl,
    })
    assert.deepEqual(poll1, { status: 'pending', intervalSec: 5 })

    // Poll 2: slow_down increments intervalSec
    const poll2 = await pollGithubDeviceFlow(started.flowId, {
      dataDir,
      githubBaseUrl: server.baseUrl,
      apiBaseUrl: server.baseUrl,
    })
    assert.deepEqual(poll2, { status: 'slow_down', intervalSec: 10 })

    // Poll 3: authorized -> stores 0600 vault JSON, deletes flowId, discovers installed repos
    const poll3 = await pollGithubDeviceFlow(started.flowId, {
      dataDir,
      githubBaseUrl: server.baseUrl,
      apiBaseUrl: server.baseUrl,
    })
    assert.equal(poll3.status, 'authorized')
    assert.equal(poll3.login, 'octo-researcher')
    assert.equal(poll3.authKind, 'github_app_device')
    assert.equal(poll3.repoCount, 2)
    assert.ok(poll3.expiresAt)
    assert.equal(poll3.accountStatus.configured, true)
    assert.equal(poll3.accountStatus.authKind, 'github_app_device')
    assert.equal(poll3.accountStatus.login, 'octo-researcher')
    assert.equal(poll3.accountStatus.tokenKind, 'github_app')
    assert.equal(poll3.accountStatus.githubDeviceFlowConfigured, true)

    // Neither accessToken nor refreshToken nor deviceCode leaks in poll result
    const serializedPoll3 = JSON.stringify(poll3)
    assert.equal(serializedPoll3.includes(accessToken), false)
    assert.equal(serializedPoll3.includes(refreshToken), false)
    assert.equal(serializedPoll3.includes(secretDeviceCode), false)

    // Verify vault files exist with strict 0700 dir and 0600 file permissions
    const credDir = join(dataDir, 'credentials')
    const patPath = join(credDir, 'github.pat')
    const appCfgPath = join(credDir, 'github-app.json')
    assert.equal(existsSync(patPath), true)
    assert.equal(existsSync(appCfgPath), true)
    assert.equal(statSync(credDir).mode & 0o777, 0o700)
    assert.equal(statSync(patPath).mode & 0o777, 0o600)
    assert.equal(statSync(appCfgPath).mode & 0o777, 0o600)

    const stored = readGithubVaultCredential(patPath)
    assert.equal(stored.accessToken, accessToken)
    assert.equal(stored.refreshToken, refreshToken)
    assert.equal(stored.clientId, testClientId)
    assert.equal(stored.login, 'octo-researcher')
    assert.equal(stored.authKind, 'github_app_device')
    assert.ok(stored.expiresAt)
    assert.ok(stored.refreshTokenExpiresAt)

    // flowId must be removed from memory after completion
    const pollAfterComplete = await pollGithubDeviceFlow(started.flowId, {
      dataDir,
      githubBaseUrl: server.baseUrl,
      apiBaseUrl: server.baseUrl,
    })
    assert.equal(pollAfterComplete.status, 'expired')

    // Repo discovery via listAccessibleGithubRepos merges /user/installations repos
    const listed = await listAccessibleGithubRepos({
      dataDir,
      apiBaseUrl: server.baseUrl,
      githubBaseUrl: server.baseUrl,
    })
    assert.equal(listed.tokenKind, 'github_app')
    assert.deepEqual(listed.repos.map(r => r.fullName), ['acme/api-gateway', 'acme/web-portal'])
    assert.ok(seenApiPaths.some(p => p.startsWith('/user/installations')))
    assert.ok(seenApiPaths.some(p => p.includes('/user/installations/4242/repositories')))

    // Disconnecting clears github.pat while retaining vault clientId for 1-click reconnect
    clearGithubPat(dataDir)
    const afterClear = getGithubAuthStatus(dataDir)
    assert.equal(afterClear.githubDeviceFlowConfigured, true)
    assert.equal(afterClear.clientIdSource, 'vault')
  } finally {
    await server.close()
    if (prevEnvClientId === undefined) delete process.env.KOVO_GITHUB_CLIENT_ID
    else process.env.KOVO_GITHUB_CLIENT_ID = prevEnvClientId
    rmSync(dataDir, { recursive: true, force: true })
  }
})

test('automatic silent refresh rotates near-expiry token via grant_type=refresh_token and persists 0600 vault', async () => {
  const dataDir = tempDataDir('kovo-gh-refresh-')
  const testClientId = 'Iv23liREFRESHCLIENT02'
  const oldAccess = 'ghu_11OLD_EXPIRING_ACCESS_TOKEN_AAAAAA'
  const oldRefresh = 'ghr_11OLD_REFRESH_TOKEN_BBBBBBBBBBBB'
  const newAccess = 'ghu_11ROTATED_FRESH_ACCESS_TOKEN_CCCCC'
  const newRefresh = 'ghr_11ROTATED_FRESH_REFRESH_TOKEN_DDDD'

  let refreshCalls = 0
  const seenApiTokens: string[] = []

  const server = await startMockGithubServer((req, body, res) => {
    const url = req.url ?? '/'
    res.setHeader('content-type', 'application/json')

    if (req.method === 'POST' && url === '/login/oauth/access_token') {
      refreshCalls += 1
      const params = new URLSearchParams(body)
      assert.equal(params.get('grant_type'), 'refresh_token')
      assert.equal(params.get('client_id'), testClientId)
      assert.equal(params.get('refresh_token'), oldRefresh)
      res.end(JSON.stringify({
        access_token: newAccess,
        refresh_token: newRefresh,
        expires_in: 28800,
        refresh_token_expires_in: 15897600,
      }))
      return
    }

    if (req.method === 'GET' && url.startsWith('/user/repos')) {
      seenApiTokens.push(String(req.headers.authorization ?? ''))
      res.end(JSON.stringify([
        {
          full_name: 'acme/refreshed-app',
          private: true,
          default_branch: 'main',
          updated_at: '2026-11-24T12:00:00Z',
          description: 'Synced after silent refresh',
        },
      ]))
      return
    }

    if (req.method === 'GET' && url.startsWith('/user/installations')) {
      res.end(JSON.stringify({ installations: [] }))
      return
    }

    if (req.method === 'GET' && url === '/repos/acme/refreshed-app') {
      seenApiTokens.push(String(req.headers.authorization ?? ''))
      res.end(JSON.stringify({ default_branch: 'main', private: true, description: 'App', language: 'TypeScript' }))
      return
    }

    if (req.method === 'GET' && url.includes('/git/trees/')) {
      seenApiTokens.push(String(req.headers.authorization ?? ''))
      res.end(JSON.stringify({ truncated: false, tree: [] }))
      return
    }

    res.statusCode = 404
    res.end(JSON.stringify({ message: 'Not Found' }))
  })

  try {
    // Store token expiring in 2 minutes (inside the 5-minute silent refresh leeway)
    saveGithubVaultCredential(dataDir, {
      accessToken: oldAccess,
      refreshToken: oldRefresh,
      expiresAt: new Date(Date.now() + 2 * 60 * 1000).toISOString(),
      refreshTokenExpiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
      clientId: testClientId,
      login: 'octo-refresh',
      authKind: 'github_app_device',
    })

    const listed = await listAccessibleGithubRepos({
      dataDir,
      apiBaseUrl: server.baseUrl,
      githubBaseUrl: server.baseUrl,
    })

    assert.equal(refreshCalls, 1)
    assert.equal(listed.repos.length, 1)
    assert.equal(listed.repos[0]!.fullName, 'acme/refreshed-app')
    assert.equal(seenApiTokens[0], `Bearer ${newAccess}`)

    // Vault file must contain rotated tokens with 0600 permissions
    const patPath = join(dataDir, 'credentials', 'github.pat')
    assert.equal(statSync(patPath).mode & 0o777, 0o600)
    const rotated = readGithubVaultCredential(patPath)
    assert.equal(rotated.accessToken, newAccess)
    assert.equal(rotated.refreshToken, newRefresh)
    assert.equal(rotated.login, 'octo-refresh')
    assert.equal(rotated.authKind, 'github_app_device')
    assert.ok(Date.parse(rotated.expiresAt!) > Date.now() + 60 * 60 * 1000)

    // Subsequent syncGithubRepos uses the rotated token WITHOUT refreshing again
    const synced = await syncGithubRepos(['acme/refreshed-app'], undefined, {
      dataDir,
      apiBaseUrl: server.baseUrl,
      githubBaseUrl: server.baseUrl,
    })
    assert.equal(refreshCalls, 1)
    assert.equal(synced.length, 1)
    assert.equal(seenApiTokens.every(auth => auth === `Bearer ${newAccess}`), true)
  } finally {
    await server.close()
    rmSync(dataDir, { recursive: true, force: true })
  }
})

test('device flow handles expired_token, access_denied, cancellation, and KOVO_GITHUB_CLIENT_ID env var', async () => {
  const dataDir = tempDataDir('kovo-gh-edge-')
  const prevEnvClientId = process.env.KOVO_GITHUB_CLIENT_ID
  process.env.KOVO_GITHUB_CLIENT_ID = 'Iv23liENVCLIENTID99'

  let mode: 'expired' | 'denied' = 'expired'
  const server = await startMockGithubServer((req, body, res) => {
    const url = req.url ?? '/'
    res.setHeader('content-type', 'application/json')
    if (req.method === 'POST' && url === '/login/device/code') {
      const params = new URLSearchParams(body)
      assert.equal(params.get('client_id'), 'Iv23liENVCLIENTID99')
      res.end(JSON.stringify({
        device_code: `dc_${mode}_secret_value`,
        user_code: 'ABCD-EFGH',
        verification_uri: 'https://github.com/login/device',
        expires_in: 600,
        interval: 5,
      }))
      return
    }
    if (req.method === 'POST' && url === '/login/oauth/access_token') {
      res.end(JSON.stringify(
        mode === 'expired'
          ? { error: 'expired_token', error_description: 'The device code has expired.' }
          : { error: 'access_denied', error_description: 'The user denied authorization.' },
      ))
      return
    }
    res.statusCode = 404
    res.end(JSON.stringify({}))
  })

  try {
    const status = getGithubAuthStatus(dataDir)
    assert.equal(status.githubDeviceFlowConfigured, true)
    assert.equal(status.clientIdSource, 'env')

    // Expired token
    mode = 'expired'
    const flow1 = await startGithubDeviceFlow({ dataDir, githubBaseUrl: server.baseUrl, apiBaseUrl: server.baseUrl })
    const res1 = await pollGithubDeviceFlow(flow1.flowId, { dataDir, githubBaseUrl: server.baseUrl, apiBaseUrl: server.baseUrl })
    assert.equal(res1.status, 'expired')

    // Access denied
    mode = 'denied'
    const flow2 = await startGithubDeviceFlow({ dataDir, githubBaseUrl: server.baseUrl, apiBaseUrl: server.baseUrl })
    const res2 = await pollGithubDeviceFlow(flow2.flowId, { dataDir, githubBaseUrl: server.baseUrl, apiBaseUrl: server.baseUrl })
    assert.equal(res2.status, 'denied')

    // Explicit cancel
    const flow3 = await startGithubDeviceFlow({ dataDir, githubBaseUrl: server.baseUrl, apiBaseUrl: server.baseUrl })
    assert.deepEqual(cancelGithubDeviceFlow(flow3.flowId), { cancelled: true })
    assert.deepEqual(cancelGithubDeviceFlow(flow3.flowId), { cancelled: false })
    const res3 = await pollGithubDeviceFlow(flow3.flowId, { dataDir, githubBaseUrl: server.baseUrl, apiBaseUrl: server.baseUrl })
    assert.equal(res3.status, 'expired')
  } finally {
    await server.close()
    if (prevEnvClientId === undefined) delete process.env.KOVO_GITHUB_CLIENT_ID
    else process.env.KOVO_GITHUB_CLIENT_ID = prevEnvClientId
    rmSync(dataDir, { recursive: true, force: true })
  }
})

test('plain Fine-Grained PAT vault files remain 100% backward compatible alongside Device Flow', async () => {
  const dataDir = tempDataDir('kovo-gh-pat-compat-')
  const plainPat = 'github_pat_11PLAIN_COMPAT_TOKEN_9876543210'

  const server = await startMockGithubServer((req, _body, res) => {
    const url = req.url ?? '/'
    res.setHeader('content-type', 'application/json')
    if (req.method === 'GET' && url.startsWith('/user/repos')) {
      assert.equal(req.headers.authorization, `Bearer ${plainPat}`)
      res.end(JSON.stringify([
        {
          full_name: 'acme/legacy-pat-repo',
          private: true,
          default_branch: 'main',
          updated_at: '2026-11-24T12:00:00Z',
          description: 'Plain PAT repo',
        },
      ]))
      return
    }
    res.statusCode = 404
    res.end(JSON.stringify({}))
  })

  try {
    saveGithubPat(dataDir, plainPat)
    const patPath = join(dataDir, 'credentials', 'github.pat')
    assert.equal(statSync(patPath).mode & 0o777, 0o600)
    assert.equal(readFileSync(patPath, 'utf8').trim(), plainPat)

    const authStatus = getGithubAuthStatus(dataDir)
    assert.equal(authStatus.configured, true)
    assert.equal(authStatus.source, 'vault')
    assert.equal(authStatus.tokenKind, 'fine_grained')
    assert.equal(authStatus.authKind, 'pat')
    assert.equal(authStatus.login, null)

    const listed = await listAccessibleGithubRepos({
      dataDir,
      apiBaseUrl: server.baseUrl,
      githubBaseUrl: server.baseUrl,
    })
    assert.equal(listed.tokenKind, 'fine_grained')
    assert.deepEqual(listed.repos.map(r => r.fullName), ['acme/legacy-pat-repo'])
  } finally {
    await server.close()
    rmSync(dataDir, { recursive: true, force: true })
  }
})
