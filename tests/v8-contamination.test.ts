import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { describe, it } from 'node:test'
import { fileURLToPath } from 'node:url'

import {
  formatContaminationReport,
  scanSourceTreeForContamination,
} from '../scripts/check-v8-contamination.ts'
import {
  ANTI_HEURISTIC_CEILING,
  aggregateMultihopCells,
  assertMultihopPreflight,
  briefingToOpenApiByOrigin,
  buildHopDepthFunnel,
  computeEfficiencyMetrics,
  evaluateAntiHeuristicGate,
  evaluateTwoSideConfirmation,
  formatMultihopPersonaRoleLabel,
  loadMultihopRuntime,
  parseMultihopArgs,
  pickLoginPath,
  pickLoginUrl,
  planCell,
} from '../scripts/benchmark-multihop.ts'
import type { MultihopCellMeta, MultihopChainVerdict, SubmittedCompositeProof } from '../scripts/benchmark-multihop.ts'
import { PreflightError, emptySnapshotMeta } from '../scripts/benchmark-realistic.ts'
import { parseRoleLabel } from '../src/server/oracle-invariants.ts'
import { tenantLabelsFromRoleLabels } from '../src/server/exec-dispatch.ts'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))

function makeTempTree(): string {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-v8-contam-'))
  mkdirSync(join(dir, 'src', 'server'), { recursive: true })
  mkdirSync(join(dir, 'src', 'skills'), { recursive: true })
  return dir
}

describe('v8 anti-contamination lint (scripts/check-v8-contamination.ts)', () => {
  it('passes cleanly on the real repository src/server and src/skills trees', () => {
    const result = scanSourceTreeForContamination(REPO_ROOT)
    assert.equal(result.ok, true, formatContaminationReport(result))
    assert.equal(result.hits.length, 0)
    assert.ok(result.filesScanned > 10, `expected >10 scanned files, got ${result.filesScanned}`)
    assert.ok(result.durationMs < 2000, `expected fast scan (<2s), took ${result.durationMs}ms`)
  })

  it('detects synthetic leaks across all 4 forbidden token families with exact file, line, and token', () => {
    const dir = makeTempTree()
    try {
      writeFileSync(
        join(dir, 'src', 'server', 'engine-leak.ts'),
        [
          'export const ok = true',
          'const archetype = "paygrid"',
          'const other = "ShipForge" + "nexusiam" + "connecthub"',
          'const ids = ["PG-C1", "PG-D2", "SF-C3", "SF-D1", "NX-C4", "NX-D3", "CH-C2", "CH-D1"]',
          'const hosts = ["https://vault.internal/api", "registry.internal", "billing.internal"]',
          'const canary = "mh_fake_secret_99"',
        ].join('\n'),
        'utf8',
      )
      writeFileSync(
        join(dir, 'src', 'skills', 'leaked-skill.md'),
        '# Guide\nNever target vault.internal or PG-C2 directly.\n',
        'utf8',
      )

      const result = scanSourceTreeForContamination(dir)
      assert.equal(result.ok, false)
      assert.equal(result.filesScanned, 2)

      // Exact file/line/token assertions across categories
      const hitKey = (file: string, line: number, token: string, category: string) =>
        result.hits.some(h => h.file === file && h.line === line && h.token === token && h.category === category)

      assert.ok(hitKey('src/server/engine-leak.ts', 2, 'paygrid', 'archetype_name'))
      assert.ok(hitKey('src/server/engine-leak.ts', 3, 'ShipForge', 'archetype_name'))
      assert.ok(hitKey('src/server/engine-leak.ts', 3, 'nexusiam', 'archetype_name'))
      assert.ok(hitKey('src/server/engine-leak.ts', 3, 'connecthub', 'archetype_name'))

      for (const id of ['PG-C1', 'PG-D2', 'SF-C3', 'SF-D1', 'NX-C4', 'NX-D3', 'CH-C2', 'CH-D1']) {
        assert.ok(hitKey('src/server/engine-leak.ts', 4, id, 'chain_or_twin_id'), `missing ${id}`)
      }
      for (const host of ['vault.internal', 'registry.internal', 'billing.internal']) {
        assert.ok(hitKey('src/server/engine-leak.ts', 5, host, 'internal_hostname'), `missing ${host}`)
      }
      assert.ok(hitKey('src/server/engine-leak.ts', 6, 'mh_fake_', 'synthetic_canary'))

      assert.ok(hitKey('src/skills/leaked-skill.md', 2, 'vault.internal', 'internal_hostname'))
      assert.ok(hitKey('src/skills/leaked-skill.md', 2, 'PG-C2', 'chain_or_twin_id'))

      const report = formatContaminationReport(result)
      assert.match(report, /FAIL/)
      assert.match(report, /src\/server\/engine-leak\.ts:2:/)
      assert.match(report, /src\/skills\/leaked-skill\.md:2:/)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('excludes test files and benchmark directories from contamination failure', () => {
    const dir = makeTempTree()
    try {
      mkdirSync(join(dir, 'src', 'server', '__tests__'), { recursive: true })
      mkdirSync(join(dir, 'benchmarks', 'multihop-saas'), { recursive: true })
      writeFileSync(join(dir, 'src', 'server', 'clean.ts'), 'export const value = 42\n', 'utf8')
      writeFileSync(join(dir, 'src', 'server', 'clean.test.ts'), 'const x = "paygrid PG-C1 vault.internal mh_fake_1"\n', 'utf8')
      writeFileSync(join(dir, 'src', 'server', '__tests__', 'fixture.ts'), 'const y = "shipforge"\n', 'utf8')
      writeFileSync(join(dir, 'benchmarks', 'multihop-saas', 'app.ts'), 'const z = "connecthub"\n', 'utf8')

      const result = scanSourceTreeForContamination(dir)
      assert.equal(result.ok, true)
      assert.equal(result.filesScanned, 1)
      assert.equal(result.hits.length, 0)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('CLI exits 0 on clean repo and exits 1 on a contaminated temp root', () => {
    const stdout = execFileSync(process.execPath, ['scripts/check-v8-contamination.ts'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
    })
    assert.match(stdout, /v8-contamination: PASS/)

    const dir = makeTempTree()
    try {
      writeFileSync(join(dir, 'src', 'server', 'bad.ts'), 'export const host = "billing.internal"\n', 'utf8')
      let exitStatus = 0
      let stderr = ''
      try {
        execFileSync(process.execPath, ['scripts/check-v8-contamination.ts', '--root', dir], {
          cwd: REPO_ROOT,
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'pipe'],
        })
      } catch (err) {
        const e = err as { status?: number; stderr?: string }
        exitStatus = e.status ?? -1
        stderr = String(e.stderr ?? '')
      }
      assert.equal(exitStatus, 1)
      assert.match(stderr, /src\/server\/bad\.ts:1:/)
      assert.match(stderr, /billing\.internal/)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

describe('v8 multihop-saas product runner (scripts/benchmark-multihop.ts)', () => {
  it('node scripts/benchmark-multihop.ts --help exits 0 cleanly without benchmarks/multihop-saas present', () => {
    const out = execFileSync(process.execPath, ['scripts/benchmark-multihop.ts', '--help'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
    })
    assert.match(out, /--app <name\|dev\|all>/)
    assert.match(out, /--seed <n>/)
    assert.match(out, /--mode <m>/)
    assert.match(out, /--no-llm/)
    assert.match(out, /--verifier <kind>/)
    assert.match(out, /--budget-usd <n>/)
    assert.match(out, /--max-duration-ms/)
    assert.match(out, /--floor-from/)
    assert.match(out, /--out-dir/)
    assert.match(out, /H1 -> H2 -> H3 -> H4\+ -> FinalOracle -> CompositeReceiptConfirmed/)
  })

  it('parses CLI flags accurately including dev default, all apps, and held-out salt guard', () => {
    const devArgs = parseMultihopArgs(['--seed', '7', '--mode', 'white-box', '--budget-usd', '15', '--max-duration-ms', '60m'])
    assert.deepEqual(devArgs.apps, ['paygrid', 'shipforge', 'nexusiam'])
    assert.deepEqual(devArgs.seeds, [7])
    assert.equal(devArgs.mode, 'white-box')
    assert.equal(devArgs.budgetUsd, 15)
    assert.equal(devArgs.maxDurationMs, 60 * 60_000)

    const allArgs = parseMultihopArgs(['--app', 'all', '--no-llm'])
    assert.deepEqual(allArgs.apps, ['paygrid', 'shipforge', 'nexusiam', 'connecthub'])
    assert.equal(allArgs.noLlm, true)

    assert.throws(
      () => parseMultihopArgs(['--held-out', '--seed', '1000001'], {}),
      /GUARDIAN_RB_HELDOUT_SALT/,
    )
  })

  it('fails fast when a model profile is paired with local-jq unless --no-llm is set', () => {
    assert.throws(
      () => assertMultihopPreflight({
        hasProfiles: true,
        noLlm: false,
        allowInertWorkers: false,
        backendKind: 'local-jq',
        workerSessions: false,
        workerSessionsDetail: 'local-jq is replay-only',
      }),
      (err: unknown) => err instanceof PreflightError && err.exitCode === 2,
    )

    assert.doesNotThrow(() => assertMultihopPreflight({
      hasProfiles: false,
      noLlm: true,
      allowInertWorkers: false,
      backendKind: 'local-jq',
      workerSessions: false,
      workerSessionsDetail: 'local-jq is replay-only',
    }))
  })

  it('enforces Two-Side Confirmation, Hop-Depth Funnel, TP/$, TP/10m, hardened-twin 0-FP, and <=5% anti-heuristic gate', () => {
    const rawChains: MultihopChainVerdict[] = [
      // Confirmed on both sides (4-hop)
      {
        chainId: 'PG-C1',
        expectedHops: 4,
        maxHopReached: 4,
        oracleObserved: true,
        compositeReceiptConfirmed: false,
        twoSideConfirmed: false,
      },
      // Oracle fired, but NO verified CompositeProofReceipt -> rejected (oracleOnly)
      {
        chainId: 'PG-C2',
        expectedHops: 4,
        maxHopReached: 4,
        oracleObserved: true,
        compositeReceiptConfirmed: false,
        twoSideConfirmed: false,
      },
      // Persona shortcut violation -> rejected even with receipt
      {
        chainId: 'PG-C3',
        expectedHops: 5,
        maxHopReached: 5,
        oracleObserved: true,
        forbiddenShortcutViolation: true,
        compositeReceiptConfirmed: true,
        twoSideConfirmed: true,
      },
      // Stopped at H2 -> pivot_not_discovered
      {
        chainId: 'PG-C4',
        expectedHops: 3,
        maxHopReached: 2,
        oracleObserved: false,
        compositeReceiptConfirmed: false,
        twoSideConfirmed: false,
        dropReason: 'pivot_not_discovered',
      },
    ]

    const receipts: SubmittedCompositeProof[] = [
      {
        chainId: 'PG-C1',
        terminalVulnClass: 'maker_checker_bypass',
        hopCount: 4,
        replayMode: 'fresh_clean_replay',
        confirmed: true,
        attackerProvenanceValid: true,
      },
      {
        chainId: 'PG-C3',
        terminalVulnClass: 'cache_tenant_bleed',
        hopCount: 5,
        replayMode: 'fresh_clean_replay',
        confirmed: true,
        attackerProvenanceValid: false,
      },
    ]

    const twoSide = evaluateTwoSideConfirmation(rawChains, receipts)
    assert.equal(twoSide.chainsTotal, 4)
    assert.equal(twoSide.oracleObserved, 2)
    assert.equal(twoSide.compositeReceiptConfirmed, 1)
    assert.equal(twoSide.twoSideConfirmed, 1)
    assert.equal(twoSide.oracleOnlyCount, 1)
    assert.equal(twoSide.shortcutViolations, 1)

    const funnel = buildHopDepthFunnel(twoSide.verdicts)
    assert.equal(funnel.H1, 4)
    assert.equal(funnel.H2, 4)
    assert.equal(funnel.H3, 3)
    assert.equal(funnel.H4Plus, 3)
    assert.equal(funnel.FinalOracle, 2)
    assert.equal(funnel.CompositeReceiptConfirmed, 1)
    assert.equal(funnel.dropReasons.edge_binding_rejected, 1)
    assert.equal(funnel.dropReasons.persona_shortcut_rejected, 1)
    assert.equal(funnel.dropReasons.pivot_not_discovered, 1)

    const eff = computeEfficiencyMetrics({ confirmedChains: 3, costUsd: 5, durationMs: 30 * 60_000 })
    assert.equal(eff.tpPerDollar, 0.6)
    assert.equal(eff.tpPer10m, 1)

    // Anti-Heuristic Gate (<= 5% ceiling) and Hardened-Twin FP Gate (= 0)
    const baseCell: MultihopCellMeta = {
      schemaVersion: 1,
      app: 'paygrid',
      sealed: false,
      seed: 1,
      seedSet: 'dev',
      mode: 'grey-box',
      cell: 'paygrid-seed1-grey-box',
      llm: 'deterministic-no-llm',
      origin: 'http://127.0.0.1:40000',
      publicOrigins: ['http://127.0.0.1:40000'],
      loginPath: '/api/login',
      gitSha: 'deadbeef',
      model: { mode: 'deterministic-no-llm', profiles: [] },
      verifierBackend: 'local-jq',
      workerSessions: false,
      workerSessionsDetail: 'replay-only',
      dataDirIsolated: false,
      dataDirSource: null,
      isolatedProfileNames: [],
      dataDirKept: false,
      budgetUsd: 5,
      maxDurationMs: 1_800_000,
      startedAt: 0,
      endedAt: 600_000,
      durationMs: 600_000,
      timedOut: false,
      terminalStatus: 'complete',
      terminalPhase: 'done',
      runId: 'r1',
      projectId: 'p1',
      chainsTotal: 16,
      chainsOracleObserved: 0,
      chainsCompositeConfirmed: 0,
      chainsConfirmed: 0,
      oracleOnlyCount: 0,
      receiptOnlyCount: 0,
      shortcutViolations: 0,
      modeBViolations: 0,
      recall: 0,
      precision: 1,
      hardenedTwinsTotal: 3,
      hardenedTwinDecoyFps: 0,
      unmatchedFalsePositives: 0,
      costUsd: 0,
      tpPerDollar: null,
      tpPer10m: 0,
      hopFunnel: funnel,
      depthBreakdown: {
        hops3to4: { targets: 12, confirmed: 0, recall: 0 },
        hops5to6: { targets: 4, confirmed: 0, recall: 0 },
      },
      chains: [],
      hardenedTwins: [],
      assignmentsCompleted: 0,
      assignmentsTotal: 0,
      investigationCompleted: 0,
      facts: 0,
      findingsPersisted: 0,
      findingsSubmitted: 0,
      compositeReceiptsExtracted: 0,
      endpointsDiscovered: 10,
      requestCount: 50,
      oracleEventCount: 0,
      inert: false,
      snapshot: emptySnapshotMeta(),
      resumedFrom: null,
      snapshotSkippedMs: 0,
      notes: [],
      shutdown: { engineBusy: 0, appStopped: true, canaryStopped: true },
    }

    assert.equal(ANTI_HEURISTIC_CEILING, 0.05)
    assert.equal(evaluateAntiHeuristicGate([baseCell]).passed, true)
    assert.equal(evaluateAntiHeuristicGate([{ ...baseCell, chainsConfirmed: 1, recall: 1 / 16 }]).passed, false)

    assert.equal(aggregateMultihopCells([baseCell]).hardenedTwinGatePassed, true)
    assert.equal(
      aggregateMultihopCells([{ ...baseCell, hardenedTwinDecoyFps: 1, precision: 0 }]).hardenedTwinGatePassed,
      false,
    )
  })

  it('bridges benchmarks/multihop-saas/run.ts cleanly across paygrid, shipforge, and nexusiam', async () => {
    const prevAllow = process.env.GUARDIAN_ALLOW_LOCAL_LAB
    process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'
    try {
      const runtime = await loadMultihopRuntime()
      const seeds = (await runtime.listSeeds()) as { apps: string[]; dev: number[] }
      assert.ok(Array.isArray(seeds.dev) && seeds.dev.length >= 3)
      for (const appName of ['paygrid', 'shipforge', 'nexusiam'] as const) {
        assert.ok(seeds.apps.includes(appName), `expected ${appName} in discovered apps`)
        const started = await runtime.startMultihopApp({ app: appName, seed: 1 })
        try {
          assert.equal(started.app, appName)
          assert.ok(started.origin.startsWith('http://127.0.0.1:'))
          assert.ok(Array.isArray(started.oracle.events()))
          assert.ok(Array.isArray(started.oracle.requests()))

          const black = runtime.briefingFor(started, 'black-box')
          assert.equal(black.apiReference, undefined)
          assert.equal(black.sourceDir, undefined)
          assert.ok(black.personas.length <= 3)
          assert.ok(black.personas.every(p => typeof p.role === 'string' && p.role.length > 0))
          assert.doesNotThrow(() => planCell(black, null))

          const white = runtime.briefingFor(started, 'white-box')
          assert.ok((white.apiReference?.length ?? 0) > 20)
          assert.ok(typeof white.sourceDir === 'string' && white.sourceDir.length > 0)
          const loginPath = pickLoginPath(white)
          assert.ok(loginPath, `${appName} should expose a login path`)
          const loginUrl = pickLoginUrl(white, loginPath)
          assert.ok(loginUrl && loginUrl.startsWith('http://127.0.0.1:'), `${appName} loginUrl should resolve`)
          const byOrigin = briefingToOpenApiByOrigin(white)
          assert.ok(byOrigin.length >= 2, `${appName} should split OpenAPI across public service origins`)
          assert.doesNotThrow(() => planCell(white, loginPath))

          const card = runtime.gradeRun({
            groundTruth: started.groundTruth,
            findings: [],
            compositeReceipts: [],
            oracleEvents: started.oracle.events(),
            requestLog: started.oracle.requests(),
            egressLog: started.oracle.egress?.() ?? [],
            ...(started.oracle.export ? { oracleExport: started.oracle.export() } : {}),
            telemetry: { startedAtMs: 0, endedAtMs: 100, totalCostUsd: 0, budgetUsd: 5, budgetExhausted: false },
            mode: 'white-box',
          })
          assert.equal(card.chainsTotal, 4)
          assert.equal(card.chainsConfirmed, 0)
          assert.equal(card.precision, 1)
          assert.equal(card.hardenedTwinsTotal, 3)
          assert.equal(card.hardenedTwinDecoyFps, 0)
          assert.equal(card.hardenedTwins?.length, 3)
          assert.equal(card.unmatchedFalsePositives, 0)
          assert.equal(card.chains?.length, 4)
          assert.match(runtime.renderScorecard(card, 'md'), /Hop-Depth Funnel/)
          assert.match(runtime.renderScorecard(card, 'md'), /## Hardened Twins/)
          assert.doesNotThrow(() => JSON.parse(runtime.renderScorecard(card, 'json')))
        } finally {
          await started.stop()
          // Idempotent stop check
          await started.stop()
        }
      }
    } finally {
      if (prevAllow === undefined) delete process.env.GUARDIAN_ALLOW_LOCAL_LAB
      else process.env.GUARDIAN_ALLOW_LOCAL_LAB = prevAllow
    }
  })

  it('populates 3 hardened twins per archetype (9 across dev, 12 across all), catches decoy FPs strictly, and wires tenant-scoped personas without admin_bot', async () => {
    const prevAllow = process.env.GUARDIAN_ALLOW_LOCAL_LAB
    process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'
    try {
      const runtime = await loadMultihopRuntime()
      const expectedTwinsByApp: Record<string, string[]> = {
        paygrid: ['PG-D1', 'PG-D2', 'PG-D3'],
        shipforge: ['SF-D1', 'SF-D2', 'SF-D3'],
        nexusiam: ['NX-D1', 'NX-D2', 'NX-D3'],
        connecthub: ['CH-D1', 'CH-D2', 'CH-D3'],
      }
      const decoyProbeByApp: Record<string, { twinId: string; method: string; path: (prefix: string) => string; vulnClass: string }> = {
        paygrid: {
          twinId: 'PG-D1',
          method: 'GET',
          path: (p) => `${p}/directory/orgs/acme-seed`,
          vulnClass: 'info_disclosure',
        },
        shipforge: {
          twinId: 'SF-D1',
          method: 'POST',
          path: () => '/repos/repo-123/preview-builds',
          vulnClass: 'info_disclosure',
        },
        nexusiam: {
          twinId: 'NX-D3',
          method: 'GET',
          path: () => '/public/profile/acme-seed.css',
          vulnClass: 'cache_deception',
        },
        connecthub: {
          twinId: 'CH-D1',
          method: 'POST',
          path: () => '/authorize',
          vulnClass: 'oauth',
        },
      }

      const makeCellMeta = (
        appName: 'paygrid' | 'shipforge' | 'nexusiam' | 'connecthub',
        card: ReturnType<typeof runtime.gradeRun>,
      ): MultihopCellMeta => ({
        schemaVersion: 1,
        app: appName,
        sealed: appName === 'connecthub',
        seed: 1,
        seedSet: 'dev',
        mode: 'white-box',
        cell: `${appName}-seed1-white-box`,
        llm: 'deterministic-no-llm',
        origin: 'http://127.0.0.1:40000',
        publicOrigins: ['http://127.0.0.1:40000'],
        loginPath: '/login',
        gitSha: 'deadbeef',
        model: { mode: 'deterministic-no-llm', profiles: [] },
        verifierBackend: 'local-jq',
        workerSessions: false,
        workerSessionsDetail: 'replay-only',
        dataDirIsolated: false,
        dataDirSource: null,
        isolatedProfileNames: [],
        dataDirKept: false,
        budgetUsd: 5,
        maxDurationMs: 1_800_000,
        startedAt: 0,
        endedAt: 1000,
        durationMs: 1000,
        timedOut: false,
        terminalStatus: 'complete',
        terminalPhase: 'done',
        runId: 'r1',
        projectId: 'p1',
        chainsTotal: card.chainsTotal,
        chainsOracleObserved: card.chainsOracleObserved ?? 0,
        chainsCompositeConfirmed: card.chainsCompositeConfirmed ?? 0,
        chainsConfirmed: card.chainsConfirmed,
        oracleOnlyCount: 0,
        receiptOnlyCount: 0,
        shortcutViolations: 0,
        modeBViolations: 0,
        recall: card.recall ?? 0,
        precision: card.precision,
        hardenedTwinsTotal: card.hardenedTwinsTotal ?? 0,
        hardenedTwinDecoyFps: card.hardenedTwinDecoyFps ?? 0,
        unmatchedFalsePositives: card.unmatchedFalsePositives,
        costUsd: 0,
        tpPerDollar: null,
        tpPer10m: 0,
        hopFunnel: buildHopDepthFunnel(card.chains ?? []),
        depthBreakdown: {
          hops3to4: { targets: 3, confirmed: 0, recall: 0 },
          hops5to6: { targets: 1, confirmed: 0, recall: 0 },
        },
        chains: card.chains ?? [],
        hardenedTwins: card.hardenedTwins ?? [],
        assignmentsCompleted: 0,
        assignmentsTotal: 0,
        investigationCompleted: 0,
        facts: 0,
        findingsPersisted: 0,
        findingsSubmitted: 0,
        compositeReceiptsExtracted: 0,
        endpointsDiscovered: 10,
        requestCount: 0,
        oracleEventCount: 0,
        inert: false,
        snapshot: emptySnapshotMeta(),
        resumedFrom: null,
        snapshotSkippedMs: 0,
        notes: [],
        shutdown: { engineBusy: 0, appStopped: true, canaryStopped: true },
      })

      const devCleanCells: MultihopCellMeta[] = []
      const allCleanCells: MultihopCellMeta[] = []

      for (const appName of ['paygrid', 'shipforge', 'nexusiam', 'connecthub'] as const) {
        const started = await runtime.startMultihopApp({ app: appName, seed: 1 })
        try {
          const white = runtime.briefingFor(started, 'white-box')
          // All 6 non-bot personas present, never admin_bot, each carrying tenantId + role + orgSlug
          assert.equal(white.personas.length, 6, `${appName} white-box should expose 6 non-bot personas`)
          assert.deepEqual(
            white.personas.map(p => p.id),
            ['owner_a', 'member_a', 'viewer_a', 'dual_member', 'member_b', 'revoked_or_demoted'],
          )
          assert.ok(!white.personas.some(p => p.id === 'admin_bot' || p.role === 'bot'))
          for (const p of white.personas) {
            assert.ok(p.tenantId === 'org_a' || p.tenantId === 'org_b', `${appName}/${p.id} missing tenantId`)
            assert.equal(p.tenantId, p.tenant)
            assert.ok(typeof p.orgSlug === 'string' && p.orgSlug.length > 0, `${appName}/${p.id} missing orgSlug`)
          }

          // planCell emits Execution-parseable tenant-scoped roleLabels ending with (org_a)/(org_b)
          const loginPath = pickLoginPath(white)
          const planned = planCell(white, loginPath)
          assert.equal(planned.personas.length, 6)
          const parsedTenants = tenantLabelsFromRoleLabels(planned.personas.map(p => p.roleLabel))
          assert.deepEqual(parsedTenants, ['org_a', 'org_b'], `${appName} should extract org_a & org_b`)
          for (const p of planned.personas) {
            const parsed = parseRoleLabel(p.roleLabel)
            assert.equal(parsed.tenant, p.tenantId, `${appName}/${p.handle} parseRoleLabel tenant mismatch: ${p.roleLabel}`)
            assert.ok(parsed.role !== null, `${appName}/${p.handle} parseRoleLabel role missing: ${p.roleLabel}`)
            assert.match(p.roleLabel, /\((?:org_a|org_b)\)$/, `${appName}/${p.handle} roleLabel must end with (tenantId)`)
            assert.ok(p.orgSlug && p.roleLabel.includes(`slug=${p.orgSlug}`), `${appName}/${p.handle} should include orgSlug`)
          }
          const dual = planned.personas.find(p => p.handle === 'dual_member')!
          assert.equal(dual.tenantId, 'org_a')
          assert.match(dual.roleLabel, /^admin \[.*memberships=admin:org_a,viewer:org_b\] \(org_a\)$/)

          // Defense-in-depth: injecting admin_bot into a briefing fails closed in planCell
          assert.throws(
            () => planCell({
              ...white,
              personas: [
                ...white.personas,
                { id: 'admin_bot', email: 'bot@org-c.example', password: 'pw', tenant: 'org_c', role: 'admin' },
              ],
            }, loginPath),
            /admin_bot/,
          )

          // Clean run: 3 hardened twins, 0 decoy FPs, precision=1
          const cleanCard = runtime.gradeRun({
            groundTruth: started.groundTruth,
            findings: [],
            compositeReceipts: [],
            oracleEvents: started.oracle.events(),
            requestLog: started.oracle.requests(),
            egressLog: started.oracle.egress?.() ?? [],
            ...(started.oracle.export ? { oracleExport: started.oracle.export() } : {}),
            telemetry: { startedAtMs: 0, endedAtMs: 100, totalCostUsd: 0, budgetUsd: 5, budgetExhausted: false },
            mode: 'white-box',
          })
          assert.equal(cleanCard.hardenedTwinsTotal, 3, `${appName} must report 3 hardened twins`)
          assert.equal(cleanCard.hardenedTwinDecoyFps, 0)
          assert.deepEqual(
            cleanCard.hardenedTwins?.map(t => t.twinId),
            expectedTwinsByApp[appName],
          )
          assert.ok(cleanCard.hardenedTwins?.every(t => t.falsePositive === false))

          const cleanMeta = makeCellMeta(appName, cleanCard)
          allCleanCells.push(cleanMeta)
          if (appName !== 'connecthub') devCleanCells.push(cleanMeta)

          // Synthetic finding hitting a hardened twin's decoy endpoint MUST increment hardenedTwinDecoyFps and fail precision gate
          const prefix = (white.apiReference?.find(r => r.path.includes('/me'))?.path ?? '/v1/me').replace(/\/me$/, '')
          const probe = decoyProbeByApp[appName]!
          const poisonedCard = runtime.gradeRun({
            groundTruth: started.groundTruth,
            findings: [{
              id: `syn-decoy-${appName}`,
              title: 'Synthetic decoy hit',
              vulnClass: probe.vulnClass,
              endpoints: [{ method: probe.method, path: probe.path(prefix) }],
              status: 'confirmed',
              submittedAtMs: 50,
            }],
            compositeReceipts: [],
            oracleEvents: started.oracle.events(),
            requestLog: started.oracle.requests(),
            egressLog: started.oracle.egress?.() ?? [],
            ...(started.oracle.export ? { oracleExport: started.oracle.export() } : {}),
            telemetry: { startedAtMs: 0, endedAtMs: 100, totalCostUsd: 0, budgetUsd: 5, budgetExhausted: false },
            mode: 'white-box',
          })
          assert.equal(poisonedCard.hardenedTwinsTotal, 3)
          assert.equal(poisonedCard.hardenedTwinDecoyFps, 1, `${appName} synthetic decoy finding must trigger hardenedTwinDecoyFps=1`)
          assert.equal(poisonedCard.unmatchedFalsePositives, 0, `${appName} decoy FP must not double-count as unmatched`)
          assert.equal(poisonedCard.precision, 0)
          const hitTwin = poisonedCard.hardenedTwins?.find(t => t.twinId === probe.twinId)
          assert.ok(hitTwin, `${appName} missing verdict for ${probe.twinId}`)
          assert.equal(hitTwin.falsePositive, true)
          assert.deepEqual(hitTwin.matchedFindingIds, [`syn-decoy-${appName}`])

          const poisonedAgg = aggregateMultihopCells([makeCellMeta(appName, poisonedCard)])
          assert.equal(poisonedAgg.hardenedTwinsTotal, 3)
          assert.equal(poisonedAgg.hardenedTwinDecoyFps, 1)
          assert.equal(poisonedAgg.hardenedTwinGatePassed, false)

          // Unrelated non-twin endpoint finding stays unmatchedFalsePositives=1, hardenedTwinDecoyFps=0
          if (appName === 'paygrid') {
            const unrelatedCard = runtime.gradeRun({
              groundTruth: started.groundTruth,
              findings: [{
                id: 'syn-unrelated-bola',
                title: 'Unrelated invoice BOLA FP',
                vulnClass: 'bola',
                endpoints: [{ method: 'GET', path: `${prefix}/invoices/inv_123` }],
                status: 'confirmed',
                submittedAtMs: 50,
              }],
              compositeReceipts: [],
              oracleEvents: started.oracle.events(),
              requestLog: started.oracle.requests(),
              egressLog: started.oracle.egress?.() ?? [],
              ...(started.oracle.export ? { oracleExport: started.oracle.export() } : {}),
              telemetry: { startedAtMs: 0, endedAtMs: 100, totalCostUsd: 0, budgetUsd: 5, budgetExhausted: false },
              mode: 'white-box',
            })
            assert.equal(unrelatedCard.hardenedTwinsTotal, 3)
            assert.equal(unrelatedCard.hardenedTwinDecoyFps, 0)
            assert.equal(unrelatedCard.unmatchedFalsePositives, 1)
            assert.equal(unrelatedCard.precision, 0)
          }
        } finally {
          await started.stop()
        }
      }

      // Aggregate totals: 9 across dev (--app dev), 12 across all (--app all)
      const devAgg = aggregateMultihopCells(devCleanCells)
      assert.equal(devAgg.hardenedTwinsTotal, 9)
      assert.equal(devAgg.hardenedTwinDecoyFps, 0)
      assert.equal(devAgg.hardenedTwinGatePassed, true)

      const allAgg = aggregateMultihopCells(allCleanCells)
      assert.equal(allAgg.hardenedTwinsTotal, 12)
      assert.equal(allAgg.hardenedTwinDecoyFps, 0)
      assert.equal(allAgg.hardenedTwinGatePassed, true)

      // Pure helper sanity check
      assert.equal(
        formatMultihopPersonaRoleLabel({
          id: 'member_b',
          email: 'member@acme-corp.example',
          password: 'pw',
          tenant: 'org_b',
          tenantId: 'org_b',
          orgSlug: 'acme-corp',
          role: 'member',
          rolesByTenant: { org_b: 'member' },
        }),
        'member [slug=acme-corp] (org_b)',
      )
    } finally {
      if (prevAllow === undefined) delete process.env.GUARDIAN_ALLOW_LOCAL_LAB
      else process.env.GUARDIAN_ALLOW_LOCAL_LAB = prevAllow
    }
  })
})
