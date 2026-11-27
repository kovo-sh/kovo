import assert from 'node:assert/strict'
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import {
  DEFAULT_KOVO_GITHUB_APP_SLUG,
  DEFAULT_KOVO_GITHUB_CLIENT_ID,
  getGithubAuthStatus,
  githubAppInstallUrl,
  pollGithubDeviceFlow,
  resolveGithubAppSlug,
  resolveGithubClientId,
  saveGithubClientId,
  startGithubDeviceFlow,
} from '../src/server/github-auth.ts'

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

test('default Kovo Security GitHub App constants, resolution, and auth status work out of the box', () => {
  const dataDir = tempDataDir('kovo-gh-default-app-')
  const prevClientId = process.env.KOVO_GITHUB_CLIENT_ID
  const prevSlug = process.env.KOVO_GITHUB_APP_SLUG
  delete process.env.KOVO_GITHUB_CLIENT_ID
  delete process.env.KOVO_GITHUB_APP_SLUG

  try {
    assert.equal(DEFAULT_KOVO_GITHUB_CLIENT_ID, 'Iv23liqXkHdhMBUVcldr')
    assert.equal(DEFAULT_KOVO_GITHUB_APP_SLUG, 'kovo-security')

    assert.deepEqual(resolveGithubClientId(dataDir), {
      clientId: 'Iv23liqXkHdhMBUVcldr',
      source: 'default',
    })
    assert.equal(resolveGithubAppSlug(dataDir), 'kovo-security')
    assert.equal(
      githubAppInstallUrl(resolveGithubAppSlug(dataDir)),
      'https://github.com/apps/kovo-security/installations/new',
    )

    const status = getGithubAuthStatus(dataDir)
    assert.equal(status.configured, false)
    assert.equal(status.githubDeviceFlowConfigured, true)
    assert.equal(status.clientIdSource, null)
    assert.equal(status.appSlug, 'kovo-security')
    assert.equal(status.installUrl, 'https://github.com/apps/kovo-security/installations/new')
  } finally {
    if (prevClientId === undefined) delete process.env.KOVO_GITHUB_CLIENT_ID
    else process.env.KOVO_GITHUB_CLIENT_ID = prevClientId
    if (prevSlug === undefined) delete process.env.KOVO_GITHUB_APP_SLUG
    else process.env.KOVO_GITHUB_APP_SLUG = prevSlug
    rmSync(dataDir, { recursive: true, force: true })
  }
})

test('explicit input, env vars, and saved github-app.json cleanly override the built-in Kovo defaults', () => {
  const dataDir = tempDataDir('kovo-gh-override-')
  const prevClientId = process.env.KOVO_GITHUB_CLIENT_ID
  const prevSlug = process.env.KOVO_GITHUB_APP_SLUG
  delete process.env.KOVO_GITHUB_CLIENT_ID
  delete process.env.KOVO_GITHUB_APP_SLUG

  try {
    // Saved vault config overrides built-in default
    const credDir = join(dataDir, 'credentials')
    mkdirSync(credDir, { recursive: true, mode: 0o700 })
    writeFileSync(
      join(credDir, 'github-app.json'),
      `${JSON.stringify({ appSlug: 'acme-enterprise-app' }, null, 2)}\n`,
      { mode: 0o600 },
    )
    saveGithubClientId(dataDir, 'Iv23liVAULTCUSTOM01')

    assert.deepEqual(resolveGithubClientId(dataDir), {
      clientId: 'Iv23liVAULTCUSTOM01',
      source: 'vault',
    })
    assert.equal(resolveGithubAppSlug(dataDir), 'acme-enterprise-app')
    const vaultStatus = getGithubAuthStatus(dataDir)
    assert.equal(vaultStatus.githubDeviceFlowConfigured, true)
    assert.equal(vaultStatus.clientIdSource, 'vault')
    assert.equal(vaultStatus.appSlug, 'acme-enterprise-app')
    assert.equal(vaultStatus.installUrl, 'https://github.com/apps/acme-enterprise-app/installations/new')

    // Env vars override saved vault config
    process.env.KOVO_GITHUB_CLIENT_ID = 'Iv23liENVCUSTOM0002'
    process.env.KOVO_GITHUB_APP_SLUG = 'acme-env-app'

    assert.deepEqual(resolveGithubClientId(dataDir), {
      clientId: 'Iv23liENVCUSTOM0002',
      source: 'env',
    })
    assert.equal(resolveGithubAppSlug(dataDir), 'acme-env-app')
    const envStatus = getGithubAuthStatus(dataDir)
    assert.equal(envStatus.githubDeviceFlowConfigured, true)
    assert.equal(envStatus.clientIdSource, 'env')
    assert.equal(envStatus.appSlug, 'acme-env-app')
    assert.equal(envStatus.installUrl, 'https://github.com/apps/acme-env-app/installations/new')

    // Explicit input argument overrides env and vault
    assert.deepEqual(resolveGithubClientId(dataDir, 'Iv23liINPUTCUSTOM03'), {
      clientId: 'Iv23liINPUTCUSTOM03',
      source: 'input',
    })
  } finally {
    if (prevClientId === undefined) delete process.env.KOVO_GITHUB_CLIENT_ID
    else process.env.KOVO_GITHUB_CLIENT_ID = prevClientId
    if (prevSlug === undefined) delete process.env.KOVO_GITHUB_APP_SLUG
    else process.env.KOVO_GITHUB_APP_SLUG = prevSlug
    rmSync(dataDir, { recursive: true, force: true })
  }
})

test('startGithubDeviceFlow uses DEFAULT_KOVO_GITHUB_CLIENT_ID out of the box without persisting a custom override', async () => {
  const dataDir = tempDataDir('kovo-gh-default-flow-')
  const prevClientId = process.env.KOVO_GITHUB_CLIENT_ID
  const prevSlug = process.env.KOVO_GITHUB_APP_SLUG
  delete process.env.KOVO_GITHUB_CLIENT_ID
  delete process.env.KOVO_GITHUB_APP_SLUG

  const seenClientIds: string[] = []
  const server = await startMockGithubServer((req, body, res) => {
    const url = req.url ?? '/'
    res.setHeader('content-type', 'application/json')

    if (req.method === 'POST' && url === '/login/device/code') {
      const params = new URLSearchParams(body)
      seenClientIds.push(params.get('client_id') ?? '')
      res.end(JSON.stringify({
        device_code: 'dc_default_app_test_code_123456',
        user_code: 'KOVO-2026',
        verification_uri: 'https://github.com/login/device',
        expires_in: 900,
        interval: 5,
      }))
      return
    }

    if (req.method === 'POST' && url === '/login/oauth/access_token') {
      const params = new URLSearchParams(body)
      seenClientIds.push(params.get('client_id') ?? '')
      res.end(JSON.stringify({
        access_token: 'ghu_11DEFAULT_APP_ACCESS_TOKEN_12345678',
        token_type: 'bearer',
        expires_in: 28800,
        refresh_token: 'ghr_11DEFAULT_APP_REFRESH_TOKEN_12345678',
        refresh_token_expires_in: 15897600,
      }))
      return
    }

    if (req.method === 'GET' && url === '/user') {
      res.end(JSON.stringify({ login: 'default-app-user' }))
      return
    }

    if (req.method === 'GET' && url.startsWith('/user/installations')) {
      res.end(JSON.stringify({ total_count: 0, installations: [] }))
      return
    }

    if (req.method === 'GET' && url.startsWith('/user/repos')) {
      res.end(JSON.stringify([]))
      return
    }

    res.statusCode = 404
    res.end(JSON.stringify({ message: 'Not Found' }))
  })

  try {
    const started = await startGithubDeviceFlow({
      dataDir,
      githubBaseUrl: server.baseUrl,
      apiBaseUrl: server.baseUrl,
    })
    assert.equal(started.userCode, 'KOVO-2026')

    const polled = await pollGithubDeviceFlow(started.flowId, {
      dataDir,
      githubBaseUrl: server.baseUrl,
      apiBaseUrl: server.baseUrl,
    })
    assert.equal(polled.status, 'authorized')
    assert.equal(polled.login, 'default-app-user')
    assert.equal(polled.accountStatus.githubDeviceFlowConfigured, true)
    assert.equal(polled.accountStatus.clientIdSource, null)
    assert.equal(polled.accountStatus.appSlug, 'kovo-security')
    assert.equal(polled.accountStatus.installUrl, `${server.baseUrl}/apps/kovo-security/installations/new`)

    assert.deepEqual(seenClientIds, [DEFAULT_KOVO_GITHUB_CLIENT_ID, DEFAULT_KOVO_GITHUB_CLIENT_ID])
    assert.equal(existsSync(join(dataDir, 'credentials', 'github-app.json')), false)
  } finally {
    await server.close()
    if (prevClientId === undefined) delete process.env.KOVO_GITHUB_CLIENT_ID
    else process.env.KOVO_GITHUB_CLIENT_ID = prevClientId
    if (prevSlug === undefined) delete process.env.KOVO_GITHUB_APP_SLUG
    else process.env.KOVO_GITHUB_APP_SLUG = prevSlug
    rmSync(dataDir, { recursive: true, force: true })
  }
})
