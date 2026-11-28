import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, test } from 'node:test'
import {
  buildAssignmentBriefPacket,
  buildMultiHopProofContract,
  classifyPersonaPrivilege as classifyFromBrief,
  isMultiHopBriefInput,
} from '../src/server/assignment-brief.ts'
import { classifyPersonaMetadata, classifyPersonaPrivilege } from '../src/server/persona-privilege.ts'
import {
  compileTraceToKovoVerifyScript,
  type RecordedRequestExchange,
} from '../src/server/trace-proof-compiler.ts'

describe('Phase 0 persona-privilege unification & overfitting cleanup', () => {
  test('classifyPersonaMetadata prefers explicit structured config fields over handle substrings and never parses _a/_b or dual regexes', () => {
    // Re-export from assignment-brief points to the exact same authoritative function
    assert.equal(classifyFromBrief, classifyPersonaPrivilege)

    // Real-world SaaS handles that old regexes misclassified
    const botFreeWithRole = classifyPersonaMetadata({ handle: 'support_bot_free', role: 'member', tenant: 'acme' })
    assert.equal(botFreeWithRole.privilege, 'low')
    assert.equal(botFreeWithRole.elevated, false)
    assert.deepEqual(botFreeWithRole.tenants, ['acme'])

    const botFreeNoRole = classifyPersonaMetadata({ handle: 'support_bot_free' })
    assert.equal(botFreeNoRole.privilege, 'low')
    assert.equal(botFreeNoRole.elevated, false)
    assert.deepEqual(botFreeNoRole.tenants, [])

    const realEmail = classifyPersonaMetadata({ handle: 'alice@dyad.sh', privilege: 'member', tenantRef: 'org-dyad' })
    assert.equal(realEmail.privilege, 'low')
    assert.equal(realEmail.elevated, false)
    assert.deepEqual(realEmail.tenants, ['org_dyad'])

    // Explicit privilege always beats handle keywords
    const explicitLowOverride = classifyPersonaMetadata({ handle: 'owner_test_sandbox', privilege: 'viewer', tenant: 'sandbox' })
    assert.equal(explicitLowOverride.privilege, 'low')
    assert.equal(explicitLowOverride.elevated, false)

    const explicitElevated = classifyPersonaMetadata({ handle: 'qa_user_1', privilege: 'admin', tenant: 'corp' })
    assert.equal(explicitElevated.privilege, 'elevated')
    assert.equal(explicitElevated.elevated, true)
    assert.deepEqual(explicitElevated.tenants, ['corp'])

    const explicitRevoked = classifyPersonaMetadata({ handle: 'alice', privilege: 'revoked', tenant: 'corp' })
    assert.equal(explicitRevoked.privilege, 'revoked')
    assert.equal(explicitRevoked.revokedStale, true)
    assert.equal(explicitRevoked.elevated, false)

    // No single-letter _a/_b suffix tenant parsing and no bare `dual` handle regex
    const suffixed = classifyPersonaMetadata({ handle: 'member_a', role: 'member' })
    assert.deepEqual(suffixed.tenants, [])

    const bareDual = classifyPersonaMetadata({ handle: 'dual_monitor_qa', role: 'member' })
    assert.equal(bareDual.privilege, 'low')
    assert.equal(bareDual.multiTenant, false)
    assert.deepEqual(bareDual.tenants, [])

    // Structured memberships produce multiTenant + normalized tenants list
    const multiMixed = classifyPersonaMetadata({
      handle: 'cross_user',
      memberships: [
        { tenant: 'tenant-alpha', role: 'admin' },
        { tenant: 'tenant-beta', role: 'viewer' },
      ],
    })
    assert.equal(multiMixed.privilege, 'low')
    assert.equal(multiMixed.multiTenant, true)
    assert.equal(multiMixed.elevated, false)
    assert.deepEqual(multiMixed.tenants, ['tenant_alpha', 'tenant_beta'])

    const multiAllAdmin = classifyPersonaMetadata({
      handle: 'global_ops',
      memberships: { 'tenant-alpha': 'owner', 'tenant-beta': 'admin' },
    })
    assert.equal(multiAllAdmin.privilege, 'elevated')
    assert.equal(multiAllAdmin.elevated, true)
    assert.equal(multiAllAdmin.multiTenant, false)
    assert.deepEqual(multiAllAdmin.tenants, ['tenant_alpha', 'tenant_beta'])
  })

  test('assignment-brief removes fast_lab, hardened-twin rule, helper-signal regexes, and 2-origin auto-trigger', () => {
    const briefSrc = readFileSync(join(process.cwd(), 'src/server/assignment-brief.ts'), 'utf8')
    assert.equal(briefSrc.includes('MULTIHOP_HARDENED_TWIN_RULE'), false)
    assert.equal(briefSrc.includes('fast_lab'), false)
    assert.equal(briefSrc.includes('CRYPTO_HELPER_SIGNAL_RE'), false)
    assert.equal(briefSrc.includes('ASYNC_HELPER_SIGNAL_RE'), false)

    // 2-subdomain SaaS running class_scan must NOT auto-trigger multiHopProofContract DSL flooding
    assert.equal(
      isMultiHopBriefInput({
        missionKind: 'class_scan',
        publicOrigins: ['https://app.saas.example', 'https://api.saas.example'],
      }),
      false,
    )
    const twoSubdomainBrief = JSON.parse(
      buildAssignmentBriefPacket({
        missionKind: 'class_scan',
        origin: 'https://app.saas.example',
        publicOrigins: ['https://app.saas.example', 'https://api.saas.example'],
        routes: [
          { origin: 'https://app.saas.example', method: 'GET', path: '/dashboard' },
          { origin: 'https://api.saas.example', method: 'GET', path: '/v1/items' },
        ],
      }).text,
    ) as { multiHopProofContract?: unknown }
    assert.equal(twoSubdomainBrief.multiHopProofContract, undefined)

    // Explicit multihop_chain contract stays clean without fast_lab or hardenedTwinRule
    const contract = buildMultiHopProofContract(false)
    assert.equal('hardenedTwinRule' in contract, false)
    assert.equal(JSON.stringify(contract).includes('fast_lab'), false)
  })

  test('trace-proof-compiler removes DUAL_PERSONA_RE, benchmark chain labels, and 400ms setTimeout (uses ctx.await_async)', () => {
    const compilerSrc = readFileSync(join(process.cwd(), 'src/server/trace-proof-compiler.ts'), 'utf8')
    assert.equal(compilerSrc.includes('DUAL_PERSONA_RE'), false)
    assert.equal(compilerSrc.includes('split_refund_ledger_break'), false)
    assert.equal(compilerSrc.includes('forged_settlement'), false)
    assert.equal(compilerSrc.includes('ledger_overcredit'), false)
    assert.equal(compilerSrc.includes('setTimeout(r, 400)'), false)

    const jobId = 'job_async_99112233'
    const exchanges: RecordedRequestExchange[] = [
      {
        exchangeId: 'a1',
        origin: 'https://app.example.test',
        method: 'POST',
        pathAndQuery: '/api/v1/jobs',
        persona: 'alice',
        status: 202,
        responseJson: { jobId },
        timestampMs: 100,
      },
      {
        exchangeId: 'a_poll',
        origin: 'https://app.example.test',
        method: 'GET',
        pathAndQuery: `/api/v1/jobs/${jobId}/status`,
        persona: 'alice',
        status: 200,
        responseJson: { status: 'ready' },
        timestampMs: 200,
      },
      {
        exchangeId: 'a2',
        origin: 'https://app.example.test',
        method: 'GET',
        pathAndQuery: `/api/v1/jobs/${jobId}/result`,
        persona: 'alice',
        status: 200,
        responseJson: { rows: 3 },
        timestampMs: 300,
      },
    ]

    const compiled = compileTraceToKovoVerifyScript({
      submission: {
        title: 'Async job cross-tenant read',
        vulnClass: 'broken_access_control',
        exchangeIds: ['a1', 'a_poll', 'a2'],
        terminalExchangeId: 'a2',
        attackerPersona: 'alice',
      },
      exchanges,
      personaMetadata: [{ handle: 'alice', privilege: 'member', tenant: 'acme' }],
      runOrigin: 'https://app.example.test',
    })
    assert.equal(compiled.ok, true)
    assert.ok(compiled.script)
    assert.doesNotMatch(compiled.script, /setTimeout/)
    assert.match(compiled.script, /ctx\.await_async\(/)
    assert.match(compiled.script, /triggerExchangeId:\s*step_1\.exchangeId/)
    assert.match(compiled.script, /jsonPath:\s*"\$\.status"/)
    assert.match(compiled.script, /equals:\s*"ready"/)
    assert.doesNotMatch(compiled.script, /fast_lab/)

    // When a 202 step has no recorded poll exchange, do not emit any hardcoded setTimeout either
    const compiledNoPoll = compileTraceToKovoVerifyScript({
      submission: {
        title: 'Async job without poll exchange',
        vulnClass: 'broken_access_control',
        exchangeIds: ['a1', 'a2'],
        terminalExchangeId: 'a2',
        attackerPersona: 'alice',
      },
      exchanges: [exchanges[0]!, exchanges[2]!],
      runOrigin: 'https://app.example.test',
    })
    assert.equal(compiledNoPoll.ok, true)
    assert.doesNotMatch(compiledNoPoll.script!, /setTimeout/)
    assert.doesNotMatch(compiledNoPoll.script!, /ctx\.await_async\(/)
  })

  test('exploiter-tools removes overfit persona/continuation regexes and forced complete_intent gates', () => {
    const exploiterSrc = readFileSync(join(process.cwd(), 'src/server/exploiter-tools.ts'), 'utf8')
    for (const removed of [
      'DUAL_TENANT_FLOW_RE',
      'INVITE_ENTRY_FLOW_RE',
      'SHORT_TENANT_PREFIXES',
      'PRIVILEGED_TERMINAL_PATH_RE',
      'checkCompleteIntentRaceEscalationGate',
      'checkCompleteIntentPostEscalationGate',
      'evaluateConfirmedContinuation',
      'dual_org_cache_bleed',
    ]) {
      assert.equal(exploiterSrc.includes(removed), false, `exploiter-tools.ts must not contain ${removed}`)
    }
  })
})
