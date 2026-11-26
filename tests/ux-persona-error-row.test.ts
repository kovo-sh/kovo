import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'
import ts from 'typescript'
import type { PersonaTestState } from '../src/components/project/types.ts'
import { PersonaAuthManager } from '../src/server/persona-auth.ts'
import {
  createProjectPersona,
  listProjectPersonas,
  resolveRunPersonas,
  updateProjectPersona,
} from '../src/server/persona-vault.ts'
import { Store } from '../src/server/store.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')

function readSrc(relPath: string): string {
  return readFileSync(join(REPO_ROOT, relPath), 'utf8')
}

function evalExportedFunctions<T extends Record<string, unknown>>(relPath: string, fnNames: string[]): T {
  const src = readSrc(relPath)
  const sf = ts.createSourceFile(relPath, src, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TSX)
  const snippets: string[] = []
  for (const fnName of fnNames) {
    const decl = sf.statements.find(
      (stmt): stmt is ts.FunctionDeclaration => ts.isFunctionDeclaration(stmt) && stmt.name?.text === fnName,
    )
    assert.ok(decl, `Expected export function ${fnName} in ${relPath}`)
    snippets.push(src.slice(decl.getStart(sf), decl.end).replace(/^export\s+/, ''))
  }
  const js = ts.transpileModule(snippets.join('\n\n'), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
  }).outputText
  return new Function(`${js}\nreturn { ${fnNames.join(', ')} };`)() as T
}

test('classifyPersonaTestError & formatPersonaTestStatusLabel produce crisp 2-word pills for failures', () => {
  const { classifyPersonaTestError, formatPersonaTestStatusLabel } = evalExportedFunctions<{
    classifyPersonaTestError: (message: string) => string
    formatPersonaTestStatusLabel: (t: PersonaTestState) => string
  }>('src/components/project/ProjectPersonasTab.tsx', [
    'classifyPersonaTestError',
    'formatPersonaTestStatusLabel',
  ])

  assert.equal(
    classifyPersonaTestError('Authentication aborted: Multi-factor authentication (MFA / second factor) is required for user@example.com.'),
    'MFA required',
  )
  assert.equal(
    classifyPersonaTestError('Authentication aborted: CAPTCHA / Cloudflare Turnstile challenge detected on https://app.example.com.'),
    'CAPTCHA blocked',
  )
  assert.equal(classifyPersonaTestError('Request timed out after 15000ms'), 'Timed out')
  assert.equal(classifyPersonaTestError('HTTP 403 Forbidden from target'), 'Blocked')
  assert.equal(classifyPersonaTestError('HTTP 401 (95ms) · Invalid email or password'), 'Invalid login')
  assert.equal(classifyPersonaTestError('fetch failed: ECONNREFUSED 127.0.0.1:3000'), 'Network error')
  assert.equal(classifyPersonaTestError('HTTP 502 Bad Gateway'), 'Server error')
  assert.equal(classifyPersonaTestError('Unexpected sign-in failure'), 'Auth failed')

  assert.equal(
    formatPersonaTestStatusLabel({
      status: 'error',
      message: 'Authentication aborted: Multi-factor authentication (MFA / second factor) is required for a@b.com.',
    }),
    'MFA required',
  )
  assert.equal(
    formatPersonaTestStatusLabel({ status: 'warn', message: 'HTTP 401 (42ms) · Unauthorized' }),
    'Invalid login',
  )
  assert.equal(
    formatPersonaTestStatusLabel({ status: 'ok', message: 'HTTP 200 (88ms) · Clerk (auto-refresh 35s)' }),
    'HTTP 200 (88ms) · Clerk (auto-refresh 35s)',
  )
})

test('ProjectPersonasTab renders full-width inline error callout with Edit account, Retry, Copy, and dismiss controls', () => {
  const tabSrc = readSrc('src/components/project/ProjectPersonasTab.tsx')
  const modalSrc = readSrc('src/components/project/PersonaFormModal.tsx')

  assert.match(tabSrc, /data-slot="persona-error-callout"/)
  assert.match(tabSrc, /role="alert"/)
  assert.match(tabSrc, /whitespace-normal break-words/)
  assert.match(tabSrc, /Edit account/)
  assert.match(tabSrc, /Retry/)
  assert.match(tabSrc, /isCopied \? 'Copied' : 'Copy'/)
  assert.match(tabSrc, /Dismiss error for/)
  assert.match(tabSrc, /formatPersonaTestStatusLabel\(test\)/)
  assert.match(tabSrc, /openEditModal\(persona\)/)
  assert.match(tabSrc, />[\s\n]*Edit[\s\n]*<\/Button>/)

  // Modal supports pre-filling for edit mode
  assert.match(modalSrc, /editingPersona\?: PublicPersona \| null/)
  assert.match(modalSrc, /Edit test account/)
  assert.match(modalSrc, /Save changes/)
  assert.match(modalSrc, /Leave blank to keep existing secret/)
})

test('updateProjectPersona updates in-place, preserves secret when omitted, and rotates + cleans up old credential file on change', () => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-ux-persona-edit-'))
  const store = new Store(dir, { ftsMode: 'preview' })
  try {
    const project = store.createProject({
      requestId: randomUUID(),
      name: 'Persona Edit App',
      seeds: ['https://app.persona-edit.example'],
      environment: 'public',
      includeSubdomains: false,
    })

    const created = createProjectPersona(store, {
      requestId: randomUUID(),
      projectId: project.id,
      handle: 'user-a',
      roleLabel: 'User A',
      originAllowlist: ['https://app.persona-edit.example'],
      authKind: 'login',
      loginConfig: { adapter: 'auto', email: 'a@persona-edit.example' },
      secret: 'initial-password-123',
      canaryMarkers: [],
    })

    const initialResolved = resolveRunPersonas(store, project.id, [created.id]).get(created.handle)!
    assert.ok(initialResolved.credentialId)
    const initialCredPath = join(dir, 'credentials', initialResolved.credentialId)
    assert.equal(existsSync(initialCredPath), true)
    assert.equal(statSync(initialCredPath).mode & 0o777, 0o600)

    // 1. Update roleLabel + email while omitting secret -> preserves id, handle, and existing password
    const updated1 = updateProjectPersona(store, {
      requestId: randomUUID(),
      projectId: project.id,
      personaId: created.id,
      roleLabel: 'Member A',
      originAllowlist: ['https://app.persona-edit.example', 'https://api.persona-edit.example'],
      authKind: 'login',
      loginConfig: { adapter: 'clerk', email: 'a-new@persona-edit.example' },
    })
    assert.deepEqual(updated1, { id: created.id, handle: 'user-a' })

    const after1 = listProjectPersonas(store, project.id).find(p => p.id === created.id)!
    assert.equal(after1.roleLabel, 'Member A')
    assert.equal(after1.handle, 'user-a')
    assert.equal(after1.loginConfig?.adapter, 'clerk')
    assert.equal(after1.loginConfig?.email, 'a-new@persona-edit.example')
    assert.deepEqual(after1.originAllowlist, ['https://app.persona-edit.example', 'https://api.persona-edit.example'])

    const resolved1 = resolveRunPersonas(store, project.id, [created.id]).get(created.handle)!
    assert.equal(resolved1.secret, 'initial-password-123')
    const credFile1 = JSON.parse(readFileSync(join(dir, 'credentials', resolved1.credentialId!), 'utf8'))
    assert.equal(credFile1.email, 'a-new@persona-edit.example')
    assert.equal(credFile1.password, 'initial-password-123')
    assert.equal(statSync(join(dir, 'credentials', resolved1.credentialId!)).mode & 0o777, 0o600)

    // 2. Switching authKind without secret fails cleanly
    assert.throws(() => updateProjectPersona(store, {
      requestId: randomUUID(),
      projectId: project.id,
      personaId: created.id,
      roleLabel: 'Member A',
      originAllowlist: ['https://app.persona-edit.example'],
      authKind: 'bearer',
    }), /required when switching sign-in method/i)

    // 3. Switching authKind to bearer with new secret rotates credential file with 0600 perms and removes old file
    const oldCredPath = join(dir, 'credentials', resolved1.credentialId!)
    const updated2 = updateProjectPersona(store, {
      requestId: randomUUID(),
      projectId: project.id,
      personaId: created.id,
      roleLabel: 'Member A Bearer',
      originAllowlist: ['https://app.persona-edit.example'],
      authKind: 'bearer',
      secret: 'tok_live_rotated_999',
    })
    assert.deepEqual(updated2, { id: created.id, handle: 'user-a' })

    const resolved2 = resolveRunPersonas(store, project.id, [created.id]).get(created.handle)!
    assert.equal(resolved2.authKind, 'bearer')
    assert.equal(resolved2.secret, 'tok_live_rotated_999')
    assert.notEqual(resolved2.credentialId, resolved1.credentialId)
    assert.equal(existsSync(oldCredPath), false, 'Old credential file must be deleted after rotation')
    const rotatedPath = join(dir, 'credentials', resolved2.credentialId!)
    assert.equal(existsSync(rotatedPath), true)
    assert.equal(statSync(rotatedPath).mode & 0o777, 0o600)
  } finally {
    store.close()
    rmSync(dir, { recursive: true, force: true })
  }
})

test('persona-auth MFA error message includes Clerk __client cookie (auto-refresh) remediation guidance', () => {
  const authSrc = readSrc('src/server/persona-auth.ts')
  const match = authSrc.match(/function mfaAbortMessage[\s\S]*?return `([^`]+)`/)
  assert.ok(match, 'Expected mfaAbortMessage in src/server/persona-auth.ts')
  const template = match[1]
  assert.ok(
    template.includes('Multi-factor authentication (MFA / second factor) is required'),
    'MFA message must preserve core MFA explanation',
  )
  assert.ok(
    template.includes('Clerk __client cookie (auto-refresh)'),
    'MFA message must mention Clerk __client cookie (auto-refresh)',
  )
  assert.ok(
    template.includes('Session Cookie / Bearer'),
    'MFA message must still mention Session Cookie / Bearer',
  )
})

test('clerk_client succeeds on real-world Clerk /v1/client JSON containing two_factor_enabled:false and second_factor_verification:null', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-clerk-mfa-schema-'))
  const store = new Store(dir, { ftsMode: 'preview' })
  const headerB64 = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url')
  const nowSec = Math.floor(Date.now() / 1000)
  const payloadB64 = Buffer.from(JSON.stringify({ sub: 'user_123', sid: 'sess_abc', iat: nowSec, exp: nowSec + 60 })).toString('base64url')
  const mockJwt = `${headerB64}.${payloadB64}.sig`

  const manager = new PersonaAuthManager({
    resolveHost: async () => ['93.184.216.34'],
    fetchImpl: (async (input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      if (url.endsWith('/v1/client')) {
        return new Response(JSON.stringify({
          response: {
            id: 'client_123',
            last_active_session_id: 'sess_abc',
            sessions: [{
              id: 'sess_abc',
              status: 'active',
              user: {
                id: 'user_123',
                two_factor_enabled: false,
                second_factor_verification: null,
                supported_second_factors: [],
                primary_email_address: { email_address: 'real@dyad.example' },
              },
            }],
          },
          errors: [],
        }), { status: 200, headers: { 'content-type': 'application/json' } })
      }
      if (url.includes('/v1/client/sessions/sess_abc/tokens')) {
        return new Response(JSON.stringify({ jwt: mockJwt }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      }
      return new Response('not found', { status: 404 })
    }) as typeof fetch,
  })

  try {
    const project = store.createProject({
      requestId: randomUUID(),
      name: 'Clerk Schema App',
      seeds: ['https://app.dyad.example'],
      environment: 'public',
      includeSubdomains: false,
    })

    const created = createProjectPersona(store, {
      requestId: randomUUID(),
      projectId: project.id,
      handle: 'dyad-user',
      roleLabel: 'Dyad User',
      originAllowlist: ['https://app.dyad.example'],
      authKind: 'login',
      loginConfig: {
        adapter: 'clerk_client',
        loginUrl: 'https://clerk.dyad.example',
      },
      secret: '__client=mock_client_cookie_value_12345',
      canaryMarkers: [],
    })

    const result = await manager.authenticatePersona(store, project.id, created.id)
    assert.equal(result.adapterUsed, 'clerk')
    assert.equal(result.headerType, 'cookie')
    const resolved = resolveRunPersonas(store, project.id, [created.id]).get(created.handle)!
    assert.ok(resolved.sessionPath && existsSync(resolved.sessionPath))
    assert.ok(readFileSync(resolved.sessionPath, 'utf8').includes(`__session=${mockJwt}`))
  } finally {
    manager.stopAll()
    store.close()
    rmSync(dir, { recursive: true, force: true })
  }
})
