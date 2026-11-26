import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import {
  bogusIdFor,
  CONSERVED_AMOUNT_FIELD_RE,
  CONSERVED_BALANCE_FIELD_RE,
  CONSERVED_ECHO_FIELD_RE,
  escalatePrivilegeBody,
  fillResourceId,
  hasDynamicIdSegment,
  IDENTITY_ASSUMPTION_ROUTE_RE,
  isAuthzMatrixHitAdmissible,
  isIdentityAssignmentField,
  isSafeFieldName,
  isSafeIdentifier,
  isSafePersonaHandle,
  isSafeResourceId,
  pathHasNounSegment,
  pathHasPrivilegedHint,
  pickBaselineWrite,
  PRIVILEGED_ACTION_RE,
  privilegeBaselineFor,
  resolveAuthzReadbackTemplate,
  rolePrivilegeRank,
  SENSITIVE_READ_ROUTE_RE,
  withoutIdentityFields,
} from '../src/server/floor-heuristics.ts'
import { bogusIdFor as specBogusIdFor, synthesizeEngineSpecs } from '../src/server/deterministic-specs.ts'
import type { EngineHypothesis } from '../src/server/deterministic-specs.ts'
import {
  hasDynamicIdSegment as engineHasDynamicIdSegment,
  IDENTITY_ASSUMPTION_ROUTE_RE as ENGINE_IDENTITY_ASSUMPTION_ROUTE_RE,
  isIdentityAssignmentField as engineIsIdentityAssignmentField,
  pathHasPrivilegedHint as enginePathHasPrivilegedHint,
  withoutIdentityFields as engineWithoutIdentityFields,
} from '../src/server/deterministic-engine.ts'
import { classifyRetestHealth, planFloorRecipe, proofReceiptMode, receiptVulnClassFor } from '../src/server/floor-recipe-engine.ts'
import { wiredRecipeForSpecKind } from '../src/server/floor-recipes.ts'
import type { FloorRecipeExecution, PersistedMutationArgs } from '../src/server/floor-recipes.ts'
import type { DifferentialResult } from '../src/server/surface-engine.ts'

const origin = 'http://fixture.invalid'
const hypothesis = (): EngineHypothesis => ({
  key: 'authz|widget|w-1',
  endpoint: { id: 'ep-widget', origin, method: 'PATCH', pathTemplate: '/api/widgets/{{id}}/promote', params: [] },
  probeClass: 'authz_matrix',
  intent: 'authz',
  method: 'PATCH',
  pathAndQuery: '/api/widgets/{{id}}/promote',
  ownerPersona: 'owner',
  otherPersona: 'viewer',
  resourceIds: ['w-1'],
  jsonBody: { role: 'admin', title: 'alpha' },
  readbackPath: '/api/widgets/{{id}}',
  authzRequiredRole: 'admin',
  risk: 80,
})
const authzSignal = (): DifferentialResult => ({
  probeClass: 'authz_matrix', origin, pathAndQuery: '/api/widgets/{{id}}/promote', verdict: 'signal',
  summary: 'cross-actor mutation', requestsSent: 0, exchangeIds: [], stoppedReason: null, notes: [], durationMs: 1,
  anomalies: [{ type: 'unauthorized_access', method: 'PATCH', resourceId: 'w-1', actor: 'other_persona', similarityToOwner: 1, bodyTemplate: { role: 'admin', title: 'alpha' } }],
  details: { matrix: [
    { resourceId: 'w-1', actor: 'owner', accessible: true, status: 200, bodyBytes: 32 },
    { resourceId: 'w-1', actor: 'other_persona', accessible: true, status: 200, bodyBytes: 32, similarityToOwner: 1 },
  ] },
} as DifferentialResult)

test('P3 Cut A: shared route, field, template, and conserved-value classifiers stay linear and bounded', () => {
  assert.ok(PRIVILEGED_ACTION_RE.test('/api/administrator/feature-flags'))
  assert.ok(SENSITIVE_READ_ROUTE_RE.test('/api/audit-log'))
  assert.ok(IDENTITY_ASSUMPTION_ROUTE_RE.test('/api/switch-tenant'))
  assert.ok(hasDynamicIdSegment('/api/widgets/:widgetId?view=full'))
  assert.ok(pathHasNounSegment('/api/products/42', 'product'))
  assert.ok(pathHasNounSegment('/api/products', 'product', true))
  assert.equal(pathHasNounSegment('/api/product-archive', 'product'), false)
  assert.ok(CONSERVED_BALANCE_FIELD_RE.test('remaining_quantity'))
  assert.ok(CONSERVED_ECHO_FIELD_RE.test('reserved_qty'))
  assert.ok(CONSERVED_AMOUNT_FIELD_RE.test('item_amount'))
  assert.ok(isIdentityAssignmentField('tenantId'))
  assert.deepEqual(withoutIdentityFields({ role: 'admin', profile: { tenantId: 't-2', name: 'kept' } }), { profile: { name: 'kept' } })
  assert.ok(isSafeResourceId('widget:42') && !isSafeResourceId('widget/42'))
  assert.ok(isSafeFieldName('display_name') && !isSafeFieldName('display name'))
  assert.ok(isSafePersonaHandle('viewer_1') && !isSafePersonaHandle('Viewer'))
  assert.ok(isSafeIdentifier('_claim1') && !isSafeIdentifier('1claim'))
  assert.equal(rolePrivilegeRank('admin')! > rolePrivilegeRank('viewer')!, true)
})

test('P3 Cut A: baseline, privilege, and readback helpers preserve non-idempotent safe writes', () => {
  const baseline = pickBaselineWrite({ tenantId: 't-1', enabled: false })!
  assert.equal(baseline.field, 'enabled')
  assert.deepEqual(baseline.baselineBody, { tenantId: 't-1', enabled: true })
  assert.equal(privilegeBaselineFor({ role: 'admin' }, 'admin')?.baselineValue, 'member')
  assert.deepEqual(escalatePrivilegeBody({ role: 'member', title: 'alpha' }, 'admin'), { role: 'admin', title: 'alpha' })
  assert.equal(escalatePrivilegeBody({ title: 'alpha' }, 'admin'), null)
  assert.deepEqual(resolveAuthzReadbackTemplate({ pathAndQuery: '/api/admin/widgets/{{id}}/promote' }, false), { template: '/api/admin/widgets/{{id}}' })
  assert.deepEqual(resolveAuthzReadbackTemplate({ pathAndQuery: '/api/admin/promote', readbackPath: '/api/profile', readbackPersona: 'viewer' }, true), { template: '/api/profile', persona: 'viewer' })
  assert.equal(fillResourceId('/api/widgets/{{id}}', 'a/b'), '/api/widgets/a%2Fb')
  assert.notEqual(bogusIdFor('42'), '42')
})

test('P3 Cut A: deterministic spec and engine consume the same authorization evidence', () => {
  const hyp = hypothesis()
  const signal = authzSignal()
  const matrix = signal.details.matrix as Record<string, unknown>[]
  assert.equal(isAuthzMatrixHitAdmissible(matrix, signal.anomalies[0]!, { mutating: true, functionLevel: false }), true)
  const publicMatrix = [...matrix, { resourceId: 'w-1', actor: 'anonymous', accessible: true, status: 200, bodySha256: 'same', similarityToOwner: 1 }]
  assert.equal(isAuthzMatrixHitAdmissible(publicMatrix, { ...signal.anomalies[0], method: 'GET' }, { mutating: false, functionLevel: false }), false)

  const candidate = synthesizeEngineSpecs(hyp, signal)[0]!
  assert.ok(candidate)
  assert.equal(wiredRecipeForSpecKind(candidate.kind, candidate.vulnClass), 'access_boundary')
  const plan = planFloorRecipe({ hypothesis: hyp, probe: signal, specKind: candidate.kind, vulnClass: candidate.vulnClass, personas: [
    { handle: 'owner', roleLabel: 'admin', privilege: 'admin' },
    { handle: 'viewer', roleLabel: 'viewer', privilege: 'viewer' },
  ] })
  assert.equal(plan?.recipeId, 'persisted_mutation')
  assert.equal(plan?.skipReason, undefined)
  const args = plan!.args as PersistedMutationArgs
  assert.equal(args.readbackPathAndQuery, '/api/widgets/w-1')
  assert.equal(pickBaselineWrite(hyp.jsonBody)?.field, 'title')
  assert.match(String(args.baselineWrite?.body.title ?? ''), /^kovo-baseline-[a-f0-9]{8}$/)
  assert.equal(specBogusIdFor, bogusIdFor)
  assert.equal(engineHasDynamicIdSegment, hasDynamicIdSegment)
  assert.equal(ENGINE_IDENTITY_ASSUMPTION_ROUTE_RE, IDENTITY_ASSUMPTION_ROUTE_RE)
  assert.equal(engineIsIdentityAssignmentField, isIdentityAssignmentField)
  assert.equal(engineWithoutIdentityFields, withoutIdentityFields)
  assert.equal(enginePathHasPrivilegedHint, pathHasPrivilegedHint)
})

test('P3 Cut A: retest health, CWE-first routing, and envelope default-deny remain fail-closed', () => {
  const execution = (status: number): FloorRecipeExecution => ({
    result: { recipeId: 'access_boundary', confirmed: false, exchangeIds: ['c', 'p'], oobEventIds: [], transcript: { entries: [] }, verification: { rule: 'impact', confirmed: false, reason: 'denied' }, steps: [
      { exchangeId: 'c', role: 'entitled_read', arm: 'control', method: 'GET', pathAndQuery: '/x', status: 200, durationMs: 1 },
      { exchangeId: 'p', role: 'cross_actor', arm: 'probe', method: 'GET', pathAndQuery: '/x', status, durationMs: 1 },
    ] },
    receipt: { vulnClass: 'bola', target: { origin, method: 'GET' }, exchangeIds: ['c', 'p'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'control' },
  } as unknown as FloorRecipeExecution)
  assert.equal(classifyRetestHealth(execution(403)).healthy, true)
  assert.equal(classifyRetestHealth(execution(500)).code, 'probe_status_unhealthy')
  assert.equal(classifyRetestHealth(execution(200)).code, 'access_probe_not_denied')
  const spec = { kind: 'http_chain', cwe: 'CWE-89', category: 'sqli', title: 'SQL injection', impact: 'query injection' } as DeclarativeReplaySpec
  assert.equal(receiptVulnClassFor(spec), 'injection')
  assert.equal(receiptVulnClassFor({ ...spec, title: 'SSRF in search parameter' } as DeclarativeReplaySpec), null)
  assert.equal(proofReceiptMode({}), 'strict')
  const verifier = readFileSync(new URL('../src/server/replay-verifier.ts', import.meta.url), 'utf8')
  assert.ok(verifier.includes("params.envelopeTrust === 'host_persisted' ? 'host_persisted' : 'untrusted'"))
})

test('P3 Cut A: duplicated legacy builders and dynamic engine regexes are retired', () => {
  const specs = readFileSync(new URL('../src/server/deterministic-specs.ts', import.meta.url), 'utf8')
  const engine = readFileSync(new URL('../src/server/deterministic-engine.ts', import.meta.url), 'utf8')
  const recipeEngine = readFileSync(new URL('../src/server/floor-recipe-engine.ts', import.meta.url), 'utf8')
  const recipes = readFileSync(new URL('../src/server/floor-recipes.ts', import.meta.url), 'utf8')
  const heuristics = readFileSync(new URL('../src/server/floor-heuristics.ts', import.meta.url), 'utf8')
  const consumers = `${specs}\n${engine}\n${recipeEngine}\n${recipes}`
  assert.doesNotMatch(consumers, /function (?:bogusIdFor|authzReadbackTemplate|authzReadback|baselineWriteFor|isIdentityAssignmentField|withoutIdentityFields|pathHasPrivilegedHint|specClassFamily)\b/)
  assert.doesNotMatch(consumers, /(?:const|export const) (?:PRIVILEGED_ACTION_RE|BASELINE_STRONG_NUMERIC_FIELD_RE)\s*=/)
  assert.doesNotMatch(consumers, /\^\[A-Za-z0-9_\.:-\]\{1,128\}\$/)
  assert.doesNotMatch(engine, /new\s+RegExp/)
  assert.doesNotMatch(heuristics, /new\s+RegExp/)
  assert.doesNotMatch(`${consumers}\n${heuristics}`, /paygrid|shipforge|nexusiam|connecthub/i)
})
