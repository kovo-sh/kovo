import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { test } from 'node:test'
import { createPersona, personaLoginConfigSchema } from '../src/domain.ts'

test('persona login config round-trips the optional refresh/CSRF knobs through validate → parse', () => {
  const config = {
    adapter: 'json' as const,
    email: 'user@northstar.example',
    loginUrl: 'https://app.northstar.example/api/auth/login',
    emailField: 'username',
    passwordField: 'password',
    tokenJsonPath: 'data.access_token',
    refreshIntervalSec: 120,
    refreshUrl: 'https://app.northstar.example/api/auth/refresh',
    refreshTokenJsonPath: 'data.refresh_token',
    csrfPrefetchUrl: 'https://app.northstar.example/api/auth/csrf',
  }

  const parsed = personaLoginConfigSchema.parse(config)
  assert.equal(parsed.refreshUrl, 'https://app.northstar.example/api/auth/refresh')
  assert.equal(parsed.refreshTokenJsonPath, 'data.refresh_token')
  assert.equal(parsed.csrfPrefetchUrl, 'https://app.northstar.example/api/auth/csrf')

  // Persisted persona JSON must re-validate without dropping the fields.
  const roundTrip = personaLoginConfigSchema.parse(JSON.parse(JSON.stringify(parsed)))
  assert.deepEqual(roundTrip, parsed)

  // The API validator used by the Persona Vault UI keeps the same fields.
  const persona = createPersona.parse({
    requestId: randomUUID(),
    projectId: randomUUID(),
    handle: 'user_a',
    roleLabel: 'Standard User',
    originAllowlist: ['https://app.northstar.example'],
    authKind: 'login',
    loginConfig: config,
    secret: 'fixture-secret-not-real',
    canaryMarkers: [],
  })
  assert.equal(persona.loginConfig?.refreshUrl, 'https://app.northstar.example/api/auth/refresh')
  assert.equal(persona.loginConfig?.refreshTokenJsonPath, 'data.refresh_token')
  assert.equal(persona.loginConfig?.csrfPrefetchUrl, 'https://app.northstar.example/api/auth/csrf')

  // All three remain optional for older persisted configs.
  const minimal = personaLoginConfigSchema.parse({ email: 'user@northstar.example' })
  assert.equal(minimal.refreshUrl, undefined)
  assert.equal(minimal.refreshTokenJsonPath, undefined)
  assert.equal(minimal.csrfPrefetchUrl, undefined)

  // URLs are validated as HTTP(S) origins/paths with no embedded credentials.
  assert.equal(personaLoginConfigSchema.safeParse({ email: 'user@northstar.example', refreshUrl: 'javascript:alert(1)' }).success, false)
  assert.equal(personaLoginConfigSchema.safeParse({ email: 'user@northstar.example', csrfPrefetchUrl: 'https://user:pass@app.northstar.example/csrf' }).success, false)
})
