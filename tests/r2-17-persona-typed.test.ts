import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { loadPersonaFile } from '../scripts/cli.ts'
import { personaPicks, type EnginePersona } from '../src/server/deterministic-engine.ts'
import { floorActorFor } from '../src/server/floor-recipe-engine.ts'
import {
  actorFromPersona,
  assessImpactEvidence,
  getPersonaIdentityFallbackCount,
  resetPersonaIdentityFallbackCount,
  resolvePersonaIdentity,
  type ImpactStep,
  type PersonaCredentialSource,
} from '../src/server/oracle-invariants.ts'
import {
  createBrowserSessionPersona,
  createProjectPersona,
  listProjectPersonas,
  resolveRunPersonas,
  updateBrowserSessionPersona,
  updateProjectPersona,
} from '../src/server/persona-vault.ts'
import { STORE_SCHEMA_VERSION, Store } from '../src/server/store.ts'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))

function readRepo(relPath: string): string {
  return readFileSync(join(REPO_ROOT, relPath), 'utf8')
}

test('R2-17: schema v12 migration adds tenant_ref & privilege, verifies schema, and round-trips typed personas', t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-r2-17-v12-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))

  const origin = 'https://app.example.test'
  // 1. Seed a DB, then downgrade personas table to simulated v11 (missing tenant_ref & privilege).
  const initial = new Store(dir)
  const project = initial.createProject({
    requestId: randomUUID(),
    name: 'r2-17-migration-proj',
    seeds: [origin],
    environment: 'public',
  })
  const legacy = createProjectPersona(initial, {
    requestId: randomUUID(),
    projectId: project.id,
    handle: 'legacy-owner',
    roleLabel: 'owner (acme)',
    originAllowlist: [origin],
    authKind: 'bearer',
    secret: 'tok-legacy-owner-123456',
    canaryMarkers: [],
  })
  initial.close()

  const rawDb = new DatabaseSync(join(dir, 'kovo.sqlite'))
  rawDb.exec('ALTER TABLE personas DROP COLUMN tenant_ref;')
  rawDb.exec('ALTER TABLE personas DROP COLUMN privilege;')
  rawDb.exec('PRAGMA user_version = 11;')
  const v11Cols = new Set(
    (rawDb.prepare('PRAGMA table_info(personas)').all() as Array<{ name: string }>).map(r => r.name),
  )
  assert.equal(v11Cols.has('tenant_ref'), false)
  assert.equal(v11Cols.has('privilege'), false)
  rawDb.close()

  // 2. Reopen with Store — v12 migration runs idempotently and Store.verifySchema() passes.
  const store = new Store(dir)
  t.after(() => { try { store.close() } catch { /* already closed */ } })
  const version = Number(
    (store.client.prepare('PRAGMA user_version').get() as { user_version: number }).user_version,
  )
  assert.equal(version, 12)
  assert.equal(STORE_SCHEMA_VERSION, 12)
  Store.verifySchema(store.client)

  const v12Cols = new Set(
    (store.client.prepare('PRAGMA table_info(personas)').all() as Array<{ name: string }>).map(r => r.name),
  )
  assert.equal(v12Cols.has('tenant_ref'), true)
  assert.equal(v12Cols.has('privilege'), true)

  // Legacy row preserved with null typed fields.
  const listedBefore = listProjectPersonas(store, project.id)
  const legacyRow = listedBefore.find(p => p.id === legacy.id)
  assert.ok(legacyRow)
  assert.equal(legacyRow.tenantRef, null)
  assert.equal(legacyRow.privilege, null)

  // 3. Create opaque-label persona with typed tenantRef + privilege.
  const created = createProjectPersona(store, {
    requestId: randomUUID(),
    projectId: project.id,
    handle: 'user-a',
    roleLabel: 'User A',
    tenantRef: 'acme',
    privilege: 'member',
    originAllowlist: [origin],
    authKind: 'bearer',
    secret: 'tok-user-a-123456',
    canaryMarkers: [],
  })

  const listed = listProjectPersonas(store, project.id)
  const pub = listed.find(p => p.id === created.id)
  assert.ok(pub)
  assert.equal(pub.roleLabel, 'User A')
  assert.equal(pub.tenantRef, 'acme')
  assert.equal(pub.privilege, 'member')

  const resolved = resolveRunPersonas(store, project.id, [created.id])
  const resPersona = resolved.get('user-a')
  assert.ok(resPersona)
  assert.equal(resPersona.tenantRef, 'acme')
  assert.equal(resPersona.privilege, 'member')

  // 4. Update typed fields, preserve when omitted, clear when explicitly null.
  updateProjectPersona(store, {
    requestId: randomUUID(),
    projectId: project.id,
    personaId: created.id,
    roleLabel: 'User A',
    tenantRef: 'globex',
    privilege: 'owner',
    originAllowlist: [origin],
    authKind: 'bearer',
  })
  const afterUpdate = listProjectPersonas(store, project.id).find(p => p.id === created.id)!
  assert.equal(afterUpdate.tenantRef, 'globex')
  assert.equal(afterUpdate.privilege, 'owner')

  updateProjectPersona(store, {
    requestId: randomUUID(),
    projectId: project.id,
    personaId: created.id,
    roleLabel: 'User A renamed',
    originAllowlist: [origin],
    authKind: 'bearer',
  })
  const afterOmit = listProjectPersonas(store, project.id).find(p => p.id === created.id)!
  assert.equal(afterOmit.tenantRef, 'globex')
  assert.equal(afterOmit.privilege, 'owner')

  updateProjectPersona(store, {
    requestId: randomUUID(),
    projectId: project.id,
    personaId: created.id,
    roleLabel: 'User A cleared',
    tenantRef: null,
    privilege: null,
    originAllowlist: [origin],
    authKind: 'bearer',
  })
  const afterClear = listProjectPersonas(store, project.id).find(p => p.id === created.id)!
  assert.equal(afterClear.tenantRef, null)
  assert.equal(afterClear.privilege, null)

  // 5. Browser session persona create/update also round-trips typed tenantRef & privilege.
  const browserCreated = createBrowserSessionPersona(store, {
    requestId: randomUUID(),
    projectId: project.id,
    handle: 'browser-b',
    roleLabel: 'User B',
    tenantRef: 'beta',
    privilege: 'admin',
    originAllowlist: [origin],
    storageState: {
      cookies: [{
        name: 'sid',
        value: 'browser-session-cookie-val-1234',
        domain: 'app.example.test',
        path: '/',
        expires: -1,
        httpOnly: true,
        secure: true,
        sameSite: 'Lax',
      }],
      origins: [],
    },
  })
  const browserPub = listProjectPersonas(store, project.id).find(p => p.id === browserCreated.id)!
  assert.equal(browserPub.tenantRef, 'beta')
  assert.equal(browserPub.privilege, 'admin')

  updateBrowserSessionPersona(store, {
    requestId: randomUUID(),
    projectId: project.id,
    personaId: browserCreated.id,
    roleLabel: 'User B',
    tenantRef: 'gamma',
    privilege: 'viewer',
    originAllowlist: [origin],
  })
  const browserUpdated = resolveRunPersonas(store, project.id, [browserCreated.id]).get('browser-b')!
  assert.equal(browserUpdated.tenantRef, 'gamma')
  assert.equal(browserUpdated.privilege, 'viewer')
})

test('R2-17: resolvePersonaIdentity enforces typed precedence, owner->owner, fail-closed empty, and counted fallbacks', () => {
  resetPersonaIdentityFallbackCount()
  assert.equal(getPersonaIdentityFallbackCount(), 0)

  // Typed fields beat opaque label with 0 fallbacks.
  const typedOpaque = resolvePersonaIdentity({
    roleLabel: 'User A',
    tenantRef: 'org_a',
    privilege: 'member',
  })
  assert.deepEqual(typedOpaque, {
    privilege: 'member',
    role: 'member',
    tenant: 'org_a',
    tenants: ['org_a'],
    source: 'typed',
    usedLabelFallback: false,
  })
  assert.equal(getPersonaIdentityFallbackCount(), 0)

  // Typed fields override contradictory roleLabel with 0 fallbacks.
  const typedOverride = resolvePersonaIdentity({
    roleLabel: 'admin (evil)',
    tenantRef: 'Org_A',
    privilege: 'viewer',
  })
  assert.equal(typedOverride.privilege, 'viewer')
  assert.equal(typedOverride.tenant, 'org_a')
  assert.deepEqual(typedOverride.tenants, ['org_a'])
  assert.equal(typedOverride.usedLabelFallback, false)
  assert.equal(getPersonaIdentityFallbackCount(), 0)

  // Single-tenant typed persona with opaque label has 0 fallbacks.
  const singleTenantTyped = resolvePersonaIdentity({
    roleLabel: 'Account 1',
    tenantRef: null,
    privilege: 'owner',
  })
  assert.equal(singleTenantTyped.privilege, 'owner')
  assert.equal(singleTenantTyped.tenant, null)
  assert.equal(singleTenantTyped.source, 'typed')
  assert.equal(singleTenantTyped.usedLabelFallback, false)
  assert.equal(getPersonaIdentityFallbackCount(), 0)

  // Empty / opaque-without-typed inputs fail closed (NEVER invent 'member') and do not count as fallback.
  for (const emptyInput of [null, undefined, {}, { roleLabel: '' }, { roleLabel: 'Account Alpha' }]) {
    const res = resolvePersonaIdentity(emptyInput)
    assert.equal(res.privilege, null)
    assert.equal(res.role, null)
    assert.equal(res.tenant, null)
    assert.deepEqual(res.tenants, [])
    assert.equal(res.source, 'empty')
    assert.equal(res.usedLabelFallback, false)
  }
  assert.equal(getPersonaIdentityFallbackCount(), 0)

  // Legacy untyped label 'owner (acme)' resolves to privilege='owner', tenant='acme' and increments counter.
  const ownerFallback = resolvePersonaIdentity({ roleLabel: 'owner (acme)' })
  assert.equal(ownerFallback.privilege, 'owner')
  assert.equal(ownerFallback.role, 'owner')
  assert.equal(ownerFallback.tenant, 'acme')
  assert.equal(ownerFallback.source, 'label_fallback')
  assert.equal(ownerFallback.usedLabelFallback, true)
  assert.equal(getPersonaIdentityFallbackCount(), 1)

  // Multi-tenant bracket label with typed primary keeps secondary memberships without counting a fallback.
  const multiTenantTyped = resolvePersonaIdentity({
    roleLabel: 'admin [slug=acme; memberships=admin:org_a,viewer:org_b] (org_a)',
    tenantRef: 'org_a',
    privilege: 'admin',
  })
  assert.equal(multiTenantTyped.privilege, 'admin')
  assert.equal(multiTenantTyped.tenant, 'org_a')
  assert.deepEqual(multiTenantTyped.tenants, ['org_a', 'org_b'])
  assert.equal(multiTenantTyped.usedLabelFallback, false)
  assert.equal(getPersonaIdentityFallbackCount(), 1)
})

test('R2-17: opaque-label ablation produces identical cross-tenant authz confirmation with 0 label fallbacks', () => {
  const buildAuthzSteps = (personas: readonly PersonaCredentialSource[]): ImpactStep[] => {
    const actorA = actorFromPersona('acct_a', personas)
    const actorB = actorFromPersona('acct_b', personas)
    return [
      {
        id: 'ctl-1',
        arm: 'control',
        method: 'GET',
        route: '/api/invoices/inv-42',
        pathAndQuery: '/api/invoices/inv-42',
        status: 200,
        actor: actorA,
        json: { id: 'inv-42', tenantId: 'acme', ownerEmail: 'alice@acme.test', totalCents: 9400 },
      },
      {
        id: 'prb-1',
        arm: 'probe',
        method: 'GET',
        route: '/api/invoices/inv-42',
        pathAndQuery: '/api/invoices/inv-42',
        status: 200,
        actor: actorB,
        json: { id: 'inv-42', tenantId: 'acme', ownerEmail: 'alice@acme.test', totalCents: 9400 },
      },
    ]
  }

  // 1. Baseline: label-shaped personas ('member (acme)' / 'member (beta)').
  resetPersonaIdentityFallbackCount()
  const labelShapedPersonas: PersonaCredentialSource[] = [
    { handle: 'acct_a', roleLabel: 'member (acme)', authKind: 'bearer' },
    { handle: 'acct_b', roleLabel: 'member (beta)', authKind: 'bearer' },
  ]
  const labelResult = assessImpactEvidence({
    impactClass: 'authorization',
    steps: buildAuthzSteps(labelShapedPersonas),
  })
  const labelFallbacks = getPersonaIdentityFallbackCount()
  assert.equal(labelResult.satisfied, true, 'label-shaped cross-tenant BOLA should confirm')
  assert.equal(labelFallbacks, 2, 'untyped label-shaped personas must record 2 label fallbacks')

  // 2. Opaque-label ablation: UI-style labels ('User A' / 'User B') + typed fields.
  resetPersonaIdentityFallbackCount()
  const opaqueTypedPersonas: PersonaCredentialSource[] = [
    { handle: 'acct_a', roleLabel: 'User A', tenantRef: 'acme', privilege: 'member', authKind: 'bearer' },
    { handle: 'acct_b', roleLabel: 'User B', tenantRef: 'beta', privilege: 'member', authKind: 'bearer' },
  ]
  const opaqueTypedResult = assessImpactEvidence({
    impactClass: 'authorization',
    steps: buildAuthzSteps(opaqueTypedPersonas),
  })
  assert.equal(
    getPersonaIdentityFallbackCount(),
    0,
    'opaque-label personas with typed tenantRef & privilege must incur ZERO label fallbacks',
  )
  assert.equal(opaqueTypedResult.satisfied, labelResult.satisfied)
  assert.equal(opaqueTypedResult.reason, labelResult.reason)

  // 3. Control: opaque-label personas WITHOUT typed fields fail closed (never invent tenant/role).
  resetPersonaIdentityFallbackCount()
  const opaqueUntypedPersonas: PersonaCredentialSource[] = [
    { handle: 'acct_a', roleLabel: 'Account A', authKind: 'bearer' },
    { handle: 'acct_b', roleLabel: 'Account B', authKind: 'bearer' },
  ]
  const untypedActorA = actorFromPersona('acct_a', opaqueUntypedPersonas)
  const untypedActorB = actorFromPersona('acct_b', opaqueUntypedPersonas)
  assert.equal(untypedActorA.role, null)
  assert.equal(untypedActorA.tenant, null)
  assert.equal(untypedActorB.role, null)
  assert.equal(untypedActorB.tenant, null)
  const opaqueUntypedResult = assessImpactEvidence({
    impactClass: 'authorization',
    steps: buildAuthzSteps(opaqueUntypedPersonas),
  })
  assert.equal(opaqueUntypedResult.satisfied, false, 'untyped opaque personas without tenant/role must fail closed')

  // 4. Deterministic engine & floorActorFor preserve 'owner' privilege and typed tenant with 0 fallbacks.
  resetPersonaIdentityFallbackCount()
  const enginePersonas: EnginePersona[] = [
    { handle: 'acct_owner', roleLabel: 'Account One', privilege: 'owner', tenant: 'acme' },
    { handle: 'acct_viewer', roleLabel: 'Account Two', privilege: 'viewer', tenant: 'acme' },
    { handle: 'acct_other', roleLabel: 'Account Three', privilege: 'owner', tenant: 'beta' },
  ]
  const picks = personaPicks(enginePersonas)
  assert.equal(picks.owner?.handle, 'acct_owner')
  assert.equal(picks.owner?.privilege, 'owner')
  assert.equal(picks.lower?.handle, 'acct_viewer')
  assert.equal(picks.crossTenant?.handle, 'acct_other')
  const floorActor = floorActorFor('acct_owner', enginePersonas)
  assert.equal(floorActor.role, 'owner')
  assert.equal(floorActor.tenant, 'acme')
  assert.equal(getPersonaIdentityFallbackCount(), 0)
})

test('R2-17: static & CLI guards confirm single resolver wiring across floor lane, patch workflow, UI, and bench writers', t => {
  // exec-floor-lane uses resolvePersonaIdentity and has no local owner->member privilegeOf bug.
  const floorLaneSrc = readRepo('src/server/exec-floor-lane.ts')
  assert.match(floorLaneSrc, /\bresolvePersonaIdentity\s*\(/)
  assert.doesNotMatch(floorLaneSrc, /const\s+privilegeOf\s*=\s*\(roleLabel:\s*string\)/)
  assert.doesNotMatch(floorLaneSrc, /owner\[-_ \]\?admin/)

  // patch-workflow uses resolvePersonaIdentity and never defaults unparsed roles to 'member'.
  const patchSrc = readRepo('src/server/patch-workflow.ts')
  assert.match(patchSrc, /\bresolvePersonaIdentity\s*\(/)
  assert.doesNotMatch(patchSrc, /parsed\.role\s*\|\|\s*'member'/)
  assert.doesNotMatch(patchSrc, /return\s*\{\s*handle:\s*personaHandle,\s*role:\s*'member'/)

  // PersonaFormModal exposes typed privilege & tenantRef inputs without reintroducing handle/canaryMarkers.
  const modalSrc = readRepo('src/components/project/PersonaFormModal.tsx')
  assert.match(modalSrc, /name="privilege"/)
  assert.match(modalSrc, /name="tenantRef"/)
  assert.doesNotMatch(modalSrc, /name=["']handle["']/)
  assert.doesNotMatch(modalSrc, /name=["']canaryMarkers["']/)

  // All 5 benchmark harness writers pass typed tenantRef and privilege fields.
  for (const scriptPath of [
    'scripts/benchmark-realistic.ts',
    'scripts/benchmark-reason.ts',
    'scripts/benchmark-realism.ts',
    'scripts/smoke-agentic.ts',
    'scripts/benchmark-multihop.ts',
  ]) {
    const src = readRepo(scriptPath)
    assert.match(src, /\btenantRef\b/, `${scriptPath} must write typed tenantRef`)
    assert.match(src, /\bprivilege\b/, `${scriptPath} must write typed privilege`)
  }

  // CLI --persona JSON loader preserves typed tenantRef & privilege written by smoke-agentic.
  const dir = mkdtempSync(join(tmpdir(), 'kovo-r2-17-cli-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const credPath = join(dir, 'owner_a.json')
  writeFileSync(credPath, JSON.stringify({
    secret: 'tok-cli-owner-1234',
    authKind: 'bearer',
    roleLabel: 'User A',
    tenantRef: 'acme',
    privilege: 'owner',
    canaryMarkers: [],
  }), { mode: 0o600 })
  const parsed = loadPersonaFile(`owner_a:${credPath}`, ['https://app.example.test'], false)
  assert.equal(parsed.roleLabel, 'User A')
  assert.equal(parsed.tenantRef, 'acme')
  assert.equal(parsed.privilege, 'owner')
})
