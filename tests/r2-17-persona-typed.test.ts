import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join, relative, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import ts from 'typescript'
import { resolveGitState } from '../scripts/bench-ledger.ts'
import {
  parseRealisticArgs,
  planCell,
  resolveObservedEffectiveConfigForRunner,
  writeRealisticCellLedgerRow,
} from '../scripts/benchmark-realistic.ts'
import { loadPersonaFile } from '../scripts/cli.ts'
import { RequestBroker } from '../src/server/broker.ts'
import {
  signHostRecord,
  verifyCompositeReceipt,
  type CompositeProofReceipt,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import { personaPicks, type EnginePersona } from '../src/server/deterministic-engine.ts'
import { floorActorFor } from '../src/server/floor-recipe-engine.ts'
import { HostFactLog } from '../src/server/host-fact-log.ts'
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
import { hydrateV8OracleInput, resolveEntryIdentity } from '../src/server/v8-oracle-hydrate.ts'
import { TranscriptStore, evaluateClaims } from '../src/server/verify-claims.ts'
import { VERIFY_NONCE_HEADER, VERIFY_RPC_HEADER, VerifyRpcServer } from '../src/server/verify-rpc.ts'
import { makeLabGrant } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

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

function collectServerTsFiles(dirAbs: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dirAbs, { withFileTypes: true })) {
    if (entry.isSymbolicLink()) continue
    const full = join(dirAbs, entry.name)
    if (entry.isDirectory()) collectServerTsFiles(full, out)
    else if (entry.isFile() && entry.name.endsWith('.ts')) out.push(full)
  }
  return out
}

function countAstParseRoleLabelCalls(filePath: string): number {
  const sourceText = readFileSync(filePath, 'utf8')
  const sf = ts.createSourceFile(filePath, sourceText, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  let count = 0
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const expr = node.expression
      if (
        (ts.isIdentifier(expr) && expr.text === 'parseRoleLabel')
        || (ts.isPropertyAccessExpression(expr) && expr.name.text === 'parseRoleLabel')
      ) {
        count += 1
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(sf)
  return count
}

function sendRpc(server: VerifyRpcServer, op: string, args: Record<string, unknown>): Promise<{ ok: boolean; result?: unknown; error?: string }> {
  return new Promise((resolvePromise, reject) => {
    const body = JSON.stringify({ op, args })
    const req = httpRequest({
      socketPath: server.socketPath,
      path: '/rpc',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
        [VERIFY_RPC_HEADER]: server.token,
        [VERIFY_NONCE_HEADER]: server.nonce,
      },
    }, res => {
      let data = ''
      res.setEncoding('utf8')
      res.on('data', chunk => { data += chunk })
      res.on('end', () => {
        try { resolvePromise(JSON.parse(data) as { ok: boolean; result?: unknown; error?: string }) } catch (err) { reject(err) }
      })
    })
    req.on('error', reject)
    req.end(body)
  })
}

test('R3-19: monotone AST ratchet restricts direct parseRoleLabel() calls outside oracle-invariants.ts to deferred sites only', () => {
  // Strictly non-increasing per-file allowlist of deferred parseRoleLabel() call sites
  // (remaining 2 files owned by parallel streams r3-11 & r3-14; all R3-19 kernel files = 0).
  const DEFERRED_ALLOWLIST: Record<string, number> = {
    'src/server/exec-verify.ts': 3,
    'src/server/agent-script-proof.ts': 1,
  }
  const serverDir = join(REPO_ROOT, 'src', 'server')
  const actualCounts: Record<string, number> = {}
  let totalOutsideInvariants = 0
  for (const absPath of collectServerTsFiles(serverDir).sort()) {
    const rel = relative(REPO_ROOT, absPath).replace(/\\/g, '/')
    if (rel === 'src/server/oracle-invariants.ts') continue
    const calls = countAstParseRoleLabelCalls(absPath)
    if (calls > 0) {
      actualCounts[rel] = calls
      totalOutsideInvariants += calls
    }
  }

  for (const [rel, calls] of Object.entries(actualCounts)) {
    const cap = DEFERRED_ALLOWLIST[rel] ?? 0
    assert.ok(
      calls <= cap,
      `R3-19 ratchet violated: ${rel} has ${calls} parseRoleLabel() call(s), max allowed is ${cap}`,
    )
  }
  assert.ok(
    totalOutsideInvariants <= 4,
    `R3-19 ratchet violated: total parseRoleLabel() calls outside oracle-invariants.ts = ${totalOutsideInvariants}, max allowed is 4`,
  )
  // Every R3-19 kernel file must have 0 direct parseRoleLabel() calls.
  for (const migrated of [
    'src/server/verify-rpc.ts',
    'src/server/verify-claims.ts',
    'src/server/v8-oracle-hydrate.ts',
    'src/server/host-fact-log.ts',
    'src/server/composite-receipt.ts',
    'src/server/floor-recipe-engine.ts',
  ]) {
    assert.equal(actualCounts[migrated] ?? 0, 0, `${migrated} must route through resolvePersonaIdentity (0 direct parseRoleLabel calls)`)
  }
})

test('R3-19: VerifyRpcServer stamps host-signed actorTenant & actorPrivilege strictly from ResolvedPersona and confirms opaque-label cross-tenant claims with 0 fallbacks', async t => {
  const srv = createServer((req, res) => {
    const auth = String(req.headers.authorization ?? '')
    res.setHeader('content-type', 'application/json')
    if (req.url === '/api/invoices/inv-99') {
      if (auth === 'Bearer tok-alpha' || auth === 'Bearer tok-beta') {
        res.statusCode = 200
        res.end(JSON.stringify({ id: 'inv-99', tenantId: 'acme', ownerEmail: 'alice@acme.test', totalCents: 12500 }))
        return
      }
      res.statusCode = 403
      res.end(JSON.stringify({ error: 'forbidden' }))
      return
    }
    res.statusCode = 404
    res.end(JSON.stringify({ error: 'not_found' }))
  })
  srv.listen(0, '127.0.0.1')
  await once(srv, 'listening')
  t.after(() => srv.close())
  const port = (srv.address() as AddressInfo).port
  const origin = `http://127.0.0.1:${port}`

  const grant = makeLabGrant(origin, {
    tier: 3,
    personas: new Map([
      ['acct_alpha', {
        id: 'p-alpha', handle: 'acct_alpha', roleLabel: 'Account 1', tenantRef: 'acme', privilege: 'owner',
        originAllowlist: [origin], authKind: 'bearer', headerName: 'authorization', secret: 'tok-alpha', canaryMarkers: [],
      }],
      ['acct_beta', {
        id: 'p-beta', handle: 'acct_beta', roleLabel: 'Account 2', tenantRef: 'globex', privilege: 'member',
        originAllowlist: [origin], authKind: 'bearer', headerName: 'authorization', secret: 'tok-beta', canaryMarkers: [],
      }],
      ['acct_gamma', {
        id: 'p-gamma', handle: 'acct_gamma', roleLabel: 'Account 3', tenantRef: 'globex', privilege: 'viewer',
        originAllowlist: [origin], authKind: 'bearer', headerName: 'authorization', secret: 'tok-gamma', canaryMarkers: [],
      }],
    ]),
  })
  const broker = new RequestBroker()
  const rpc = new VerifyRpcServer({ broker, grant, runId: `r3-19-${randomUUID()}`, assignmentId: 'asgn-r3-19' })
  await rpc.start()
  t.after(async () => { await rpc.close() })

  resetPersonaIdentityFallbackCount()
  // Attempt to spoof worker-supplied actorTenant/actorPrivilege/actorRoleLabel — host MUST ignore worker input!
  const ctlEntitled = await sendRpc(rpc, 'http', {
    origin, method: 'GET', pathAndQuery: '/api/invoices/inv-99', persona: 'acct_alpha', arm: 'control',
    actorTenant: 'spoofed-tenant', actorPrivilege: 'viewer', actorRoleLabel: 'viewer (spoofed)',
  })
  const ctlDenied = await sendRpc(rpc, 'http', {
    origin, method: 'GET', pathAndQuery: '/api/invoices/inv-99', persona: 'acct_gamma', arm: 'control',
  })
  const probe = await sendRpc(rpc, 'http', {
    origin, method: 'GET', pathAndQuery: '/api/invoices/inv-99', persona: 'acct_beta', arm: 'probe',
    actorTenant: 'acme', actorPrivilege: 'owner',
  })
  assert.equal(ctlEntitled.ok, true)
  assert.equal(ctlDenied.ok, true)
  assert.equal(probe.ok, true)

  const entitledId = (ctlEntitled.result as { exchangeId: string }).exchangeId
  const deniedId = (ctlDenied.result as { exchangeId: string }).exchangeId
  const probeId = (probe.result as { exchangeId: string }).exchangeId

  // Inspect signed TranscriptStore records: host-signed actorTenant & actorPrivilege come strictly from ResolvedPersona.
  const recAlpha = rpc.transcript.get(entitledId)!
  const recBeta = rpc.transcript.get(probeId)!
  assert.equal(recAlpha.request?.actorRoleLabel, 'Account 1')
  assert.equal(recAlpha.request?.actorTenant, 'acme')
  assert.equal(recAlpha.request?.actorPrivilege, 'owner')
  assert.equal(recBeta.request?.actorRoleLabel, 'Account 2')
  assert.equal(recBeta.request?.actorTenant, 'globex')
  assert.equal(recBeta.request?.actorPrivilege, 'member')

  // Evaluate claims via both raw TranscriptStore (verify-claims.ts) AND HostFactLog.fromTranscriptStore (host-fact-log.ts).
  const claim = {
    kind: 'impact' as const,
    impactClass: 'authorization' as const,
    probeExchangeId: probeId,
    controlExchangeIds: [entitledId, deniedId],
    resourceTenant: 'acme',
  }
  const directVerdict = evaluateClaims(rpc.transcript, [claim])
  assert.equal(directVerdict.passed, true, 'verify-claims must confirm opaque-label cross-tenant BOLA via host-signed typed meta')

  const hostTranscript = rpc.buildHostSignedTranscript()
  const factLog = HostFactLog.fromTranscriptStore(rpc.transcript, { hostTranscript })
  const factBeta = factLog.getExchange(probeId)!
  assert.equal(factBeta.actorTenant, 'globex')
  assert.equal(factBeta.actorRole, 'member')
  assert.equal(factBeta.actorPrivilege, 'member')
  const factVerdict = evaluateClaims(rpc.transcript, [claim], { factLog })
  assert.equal(factVerdict.passed, true, 'HostFactLog-backed evaluateClaims must confirm opaque-label cross-tenant BOLA')

  // Check host-signed transcript entries + v8-oracle-hydrate resolveEntryIdentity with 0 fallbacks.
  const signedBeta = hostTranscript.entries!.find(e => e.exchangeId === probeId)!
  assert.equal(signedBeta.actorTenant, 'globex')
  assert.equal(signedBeta.actorPrivilege, 'member')
  assert.equal(rpc.verifyHostSignature(signedBeta), true)
  assert.deepEqual(resolveEntryIdentity(signedBeta), {
    privilege: 'member',
    role: 'member',
    tenant: 'globex',
    tenants: ['globex'],
    source: 'typed',
    usedLabelFallback: false,
  })
  assert.equal(
    getPersonaIdentityFallbackCount(),
    0,
    'end-to-end opaque-label typed kernel path must incur ZERO label fallbacks',
  )
})

test('R3-19: floorActorFor removes legacy-mock shim, legacy untyped fallback stays counted, and composite/hydrate honor typed meta', () => {
  // 1. floorActorFor: typed privilege always beats contradictory roleLabel (legacy-mock shim removed).
  resetPersonaIdentityFallbackCount()
  const contradictory: EnginePersona[] = [
    { handle: 'acct_x', roleLabel: 'owner@acme', privilege: 'member' },
  ]
  const actor = floorActorFor('acct_x', contradictory)
  assert.equal(actor.role, 'member', 'typed privilege=member must NOT be overridden by owner@... label')
  assert.equal(actor.tenant, 'acme', 'missing typed tenant still falls back via counted resolver')
  assert.equal(getPersonaIdentityFallbackCount(), 1)

  // 2. HostFactLog + verify-claims preserve counted label fallback when typed tenant/privilege are absent.
  resetPersonaIdentityFallbackCount()
  const store = new TranscriptStore(Buffer.alloc(32, 9))
  const legacyRec = store.record({
    op: 'http',
    startedAt: 1_700_000_000_000,
    durationMs: 5,
    request: {
      origin: 'https://legacy.example.test',
      method: 'GET',
      pathAndQuery: '/api/records/1',
      headers: { authorization: 'Bearer legacy-tok' },
      bodyBytes: 0,
      bodySha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      personaHandle: 'legacy_u',
      sessionRole: 'probe',
      actorRoleLabel: 'owner (legacy-org)',
      nonce: 'n-legacy',
    },
    response: {
      status: 200,
      headers: { 'content-type': 'application/json' },
      bodyBytes: 2,
      bodySha256: '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
      mediaType: 'application/json',
    },
    body: '{}',
  })
  const legacyLog = HostFactLog.fromTranscriptStore(store)
  const legacyFact = legacyLog.getExchange(legacyRec.exchangeId)!
  assert.equal(legacyFact.actorRole, 'owner')
  assert.equal(legacyFact.actorTenant, 'legacy-org')
  assert.ok(getPersonaIdentityFallbackCount() >= 1, 'legacy untyped label fallback must be counted')

  // 3. Composite + v8-oracle-hydrate use host-signed actorTenant & actorPrivilege with 0 fallbacks on opaque labels.
  resetPersonaIdentityFallbackCount()
  const signingKey = 'r3-19-composite-key-1234567890'
  const mkEntry = (partial: Omit<HostTranscriptEntry, 'hostSignature'>): HostTranscriptEntry => ({
    ...partial,
    hostSignature: signHostRecord(partial, signingKey),
  })
  const entries: HostTranscriptEntry[] = [
    mkEntry({
      exchangeId: 'h1', seq: 1, timestampMs: 1000, origin: 'https://app.example.test',
      actorPersona: 'acct_a', actorRoleLabel: 'Account 1', actorTenant: 'org_a', actorPrivilege: 'member',
      emittedCapabilities: ['cap:hop_1:exp_tok'], cleanSession: true,
      step: {
        id: 'h1', arm: 'setup', method: 'POST', route: '/v1/exports', pathAndQuery: '/v1/exports', status: 201,
        actor: { handle: 'acct_a', role: 'member', tenant: 'org_a', auth: 'bearer', sameSite: null },
        json: { downloadToken: 'tok_r319_xyz123' }, body: '{"downloadToken":"tok_r319_xyz123"}',
      },
    }),
    mkEntry({
      exchangeId: 'h2_ctl', seq: 2, timestampMs: 1200, origin: 'https://app.example.test',
      actorPersona: 'acct_v', actorRoleLabel: 'Account 2', actorTenant: 'org_a', actorPrivilege: 'viewer', cleanSession: true,
      step: {
        id: 'h2_ctl', arm: 'control', method: 'GET', route: '/v1/exports/dl', pathAndQuery: '/v1/exports/dl?token=bad', status: 403,
        actor: { handle: 'acct_v', role: 'viewer', tenant: 'org_a', auth: 'bearer', sameSite: null },
        json: { error: 'forbidden' }, body: '{"error":"forbidden"}',
      },
    }),
    mkEntry({
      exchangeId: 'h2_prb', seq: 3, timestampMs: 1400, origin: 'https://app.example.test',
      actorPersona: 'acct_a', actorRoleLabel: 'Account 1', actorTenant: 'org_a', actorPrivilege: 'member',
      consumedCapabilities: ['cap:hop_1:exp_tok'], cleanSession: true,
      step: {
        id: 'h2_prb', arm: 'probe', method: 'GET', route: '/v1/exports/dl', pathAndQuery: '/v1/exports/dl?token=tok_r319_xyz123', status: 200,
        actor: { handle: 'acct_a', role: 'member', tenant: 'org_a', auth: 'bearer', sameSite: null },
        json: { tenant_id: 'org_b', payroll_email: 'cfo@org-b.example', total_cents: 99000 },
        body: '{"tenant_id":"org_b","payroll_email":"cfo@org-b.example","total_cents":99000}',
      },
    }),
  ]
  const transcript: HostSignedTranscript = { entries, oobEvents: [], browserTraces: [], asyncPollRecords: [] }
  const receipt: CompositeProofReceipt = {
    chainId: 'r3-19-opaque-chain',
    terminalVulnClass: 'bola',
    hops: [
      {
        hopId: 'hop_1', surface: 'http',
        target: { origin: 'https://app.example.test', method: 'POST', pathAndQuery: '/v1/exports' },
        exchangeIds: ['h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Mints export token',
        producedCapabilities: ['cap:hop_1:exp_tok'], consumedCapabilities: [],
      },
      {
        hopId: 'hop_2', surface: 'http',
        target: { origin: 'https://app.example.test', method: 'GET', pathAndQuery: '/v1/exports/dl?token=tok_r319_xyz123' },
        exchangeIds: ['h2_ctl', 'h2_prb'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Reads foreign org_b payroll',
        producedCapabilities: [], consumedCapabilities: ['cap:hop_1:exp_tok'],
      },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: 'cap:hop_1:exp_tok', sourceExchangeId: 'h1', targetExchangeId: 'h2_prb' }],
    terminalImpact: {
      terminalHopId: 'hop_2', terminalExchangeId: 'h2_prb', claimedImpact: 'Cross-tenant payroll disclosure',
      summary: 'Cross-tenant payroll disclosure', preChainControlExchangeIds: ['h2_ctl'], postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }
  const compVerdict = verifyCompositeReceipt(receipt, transcript, { signingKey, attackerPersonas: ['acct_a', 'acct_v'] })
  assert.equal(compVerdict.confirmed, true, `expected opaque-label composite confirmation, got: ${compVerdict.reason}`)
  const hydrated = hydrateV8OracleInput(
    'dual_tenant_abac',
    { mode: 'cross_org_transfer', transferExchangeId: 'h2_prb', sourceControlExchangeId: 'h2_ctl' },
    { entriesById: new Map(entries.map(e => [e.exchangeId, e])) },
    'sig-fallback',
  )
  assert.deepEqual(hydrated.actor, { actorId: 'acct_a', rolesByTenant: { org_a: 'member' } })
  assert.equal(getPersonaIdentityFallbackCount(), 0, 'opaque-label typed composite + hydration must incur ZERO fallbacks')
})

test('R3-19: benchmark-realistic --opaque-labels flag generates opaque UI labels with typed metadata and stamps ledger/effectiveConfig', t => {
  const parsedDefault = parseRealisticArgs(['--app', 'acme-saas', '--seed', '42', '--no-llm'])
  assert.equal(parsedDefault.opaqueLabels, false)
  const parsedOpaque = parseRealisticArgs(['--app', 'acme-saas', '--seed', '42', '--no-llm', '--opaque-labels'])
  assert.equal(parsedOpaque.opaqueLabels, true)

  const briefing = {
    app: 'acme-saas' as const,
    mode: 'grey-box' as const,
    origin: 'http://127.0.0.1:41234',
    personas: [
      { id: 'persona_a' as const, role: 'owner' as const, tenant: 'acme', email: 'owner@acme.test', password: 'pw1' },
      { id: 'persona_b' as const, role: 'member' as const, tenant: 'globex', email: 'member@globex.test', password: 'pw2' },
    ],
    apiReference: [{ routeKey: 'login', method: 'POST', path: '/api/login', params: ['email', 'password'] }],
  }
  const labelPlan = planCell(briefing, '/api/login')
  assert.equal(labelPlan.personas[0]!.roleLabel, 'owner (acme)')
  assert.equal(labelPlan.personas[0]!.tenantRef, 'acme')
  assert.equal(labelPlan.personas[0]!.privilege, 'owner')

  const opaquePlan = planCell(briefing, '/api/login', { opaqueLabels: true })
  assert.equal(opaquePlan.personas[0]!.roleLabel, 'Account 1')
  assert.equal(opaquePlan.personas[0]!.tenantRef, 'acme')
  assert.equal(opaquePlan.personas[0]!.privilege, 'owner')
  assert.equal(opaquePlan.personas[1]!.roleLabel, 'Account 2')
  assert.equal(opaquePlan.personas[1]!.tenantRef, 'globex')
  assert.equal(opaquePlan.personas[1]!.privilege, 'member')

  const cfgDefault = resolveObservedEffectiveConfigForRunner({
    observed: { deterministicOnly: true, environment: 'local-lab', approvalPolicy: 'auto_review', wordlistOn: false, proofReceiptMode: 'strict' },
    deterministicOnly: true,
    verifierBackend: 'local-jq',
    mode: 'grey-box',
    opaqueLabels: false,
  })
  const cfgOpaque = resolveObservedEffectiveConfigForRunner({
    observed: { deterministicOnly: true, environment: 'local-lab', approvalPolicy: 'auto_review', wordlistOn: false, proofReceiptMode: 'strict' },
    deterministicOnly: true,
    verifierBackend: 'local-jq',
    mode: 'grey-box',
    opaqueLabels: true,
  })
  assert.equal(cfgOpaque.effectiveConfig?.extra?.opaqueLabels, true)
  assert.notEqual(cfgOpaque.effectiveConfigHash, cfgDefault.effectiveConfigHash, 'opaque-label cell must have a distinct effectiveConfigHash')

  const runsDir = mkdtempSync(join(tmpdir(), 'kovo-r3-19-ledger-'))
  t.after(() => rmSync(runsDir, { recursive: true, force: true }))
  const ledgerRes = writeRealisticCellLedgerRow({
    scorecard: {
      app: 'acme-saas', seed: 42, mode: 'grey-box', targets: 1, confirmed: 1,
      decoyFalsePositives: 0, unmatchedFalsePositives: 0, totalCostUsd: 0,
      funnel: {}, failureBuckets: {}, vulns: [{ siteId: 'v1', outcome: 'confirmed' }],
    } as never,
    app: 'acme-saas',
    split: 'dev',
    mode: 'grey-box',
    llm: 'deterministic-no-llm',
    seed: 42,
    recordedAt: '2026-11-26T18:00:00.000Z',
    gitSha: resolveGitState(REPO_ROOT).gitSha,
    dirty: false,
    benchmarkVersion: 'a'.repeat(64),
    effectiveConfigHash: cfgOpaque.effectiveConfigHash,
    effectiveConfig: cfgOpaque.effectiveConfig,
    observedEffectiveConfig: true,
    inert: false,
    conventionalWordlist: false,
    durationMs: 1200,
    opaqueLabels: true,
    runsDir,
  })
  assert.ok(ledgerRes.row)
  assert.equal((ledgerRes.row as unknown as { opaqueLabels?: boolean }).opaqueLabels, true)
  assert.ok(ledgerRes.row.notes?.includes('opaque_labels'))
})
