import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { DEFAULT_PROVIDER } from '../src/domain.ts'
import { Execution } from '../src/server/execution.ts'
import { DEFAULT_GITHUB_PAT_PATH, projectReposDir, syncGithubRepos } from '../src/server/github-connector.ts'
import { saveModelProfile } from '../src/server/model-settings.ts'
import { exportReportMarkdown } from '../src/server/report-export.ts'
import { Store } from '../src/server/store.ts'

// Authorized dyad.sh scope (30 hosts from .guardian/dyad-live/run.ts)
const DYAD_HOSTS = [
  'dyad.sh', 'www.dyad.sh', 'hub.dyad.sh', 'api.dyad.sh', 'docs.dyad.sh', 'engine.dyad.sh',
  'upload-image.dyad.sh', 'upload-logs.dyad.sh', 'bulletin.dyad.sh', 'sandpack.dyad.sh',
  'academy.dyad.sh', 'academy-staging.dyad.sh', 'tasky.dyad.sh', 'login.dyad.sh', 'blog.dyad.sh',
  'clerk.dyad.sh', 'marknote.dyad.sh', 'will.dyad.sh', 'helpchat.dyad.sh', 'oauth.dyad.sh',
  'supabase-oauth.dyad.sh', 'session-dbg.dyad.sh', 'session-dbg-v2.dyad.sh', 'llm-gateway.dyad.sh',
  'llmproxy.dyad.sh', 'share.dyad.sh', 'dmail.dyad.sh', 'eve.dyad.sh', 'accounts.dyad.sh',
  'billingz.dyad.sh',
] as const

const DYAD_ORIGINS = DYAD_HOSTS.map(host => `https://${host}`)
const APPROVED_ORIGIN_SET = new Set<string>(DYAD_ORIGINS)

// Authorized read-only dyad-sh repositories for grey-box context + lockfile CVE correlation
const DYAD_REPOS = [
  'dyad-sh/dyad-cloud',
  'dyad-sh/dyad-llm-engine',
  'dyad-sh/dyad-billingz',
  'dyad-sh/dyad-chat-uploader',
  'dyad-sh/dyad-image-uploader',
  'dyad-sh/sandpack-bundler',
] as const

const OPENROUTER_KEY_PATH = join(homedir(), '.config', 'guardian-fixtures', 'openrouter.key')
const OUTPUT_DIR = join(process.cwd(), '.guardian', 'dyad-v2-smoke')
const DATA_DIR = join(OUTPUT_DIR, 'data')

function readOwnerOnlySecret(path: string, label: string): string {
  const st = statSync(path)
  if ((st.mode & 0o077) !== 0) {
    throw new Error(`${label} credential must have owner-only (0600) permissions.`)
  }
  const value = readFileSync(path, 'utf8').trim()
  if (!value || value.length < 8) {
    throw new Error(`${label} credential file is empty or invalid.`)
  }
  return value
}

async function main() {
  // Ensure live mode (not offline mock mode)
  process.env.GUARDIAN_OFFLINE = '0'
  delete process.env.GUARDIAN_NETWORK_FIXTURE
  delete process.env.GUARDIAN_ALLOW_LOCAL_LAB

  mkdirSync(OUTPUT_DIR, { recursive: true, mode: 0o700 })
  mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 })

  const openrouterKey = readOwnerOnlySecret(OPENROUTER_KEY_PATH, 'OpenRouter')
  const githubPat = readOwnerOnlySecret(DEFAULT_GITHUB_PAT_PATH, 'GitHub PAT')

  const storage = new Store(DATA_DIR)
  const engine = new Execution(storage)
  let stage = 'startup'

  try {
    stage = 'model profile setup'
    console.log('[live-smoke-v2] Verifying OpenRouter connection and saving model profile...')
    const profile = await saveModelProfile({
      name: DEFAULT_PROVIDER.name,
      endpoint: DEFAULT_PROVIDER.endpoint,
      model: DEFAULT_PROVIDER.model,
      protocol: DEFAULT_PROVIDER.protocol,
      key: openrouterKey,
      priority: 100,
      enabled: true,
      contextWindow: DEFAULT_PROVIDER.contextWindow,
      maxTokens: DEFAULT_PROVIDER.maxTokens,
      thinkingLevel: DEFAULT_PROVIDER.thinkingLevel,
      inputCostPerMtok: DEFAULT_PROVIDER.inputCostPerMtok,
      outputCostPerMtok: DEFAULT_PROVIDER.outputCostPerMtok,
    }, storage)
    console.log(`[live-smoke-v2] Model profile ready (${DEFAULT_PROVIDER.model}, id=${profile.id}).`)

    stage = 'project creation'
    const { id: projectId } = storage.createProject({
      requestId: randomUUID(),
      name: 'Dyad v2 Deep Read-Only Assessment',
      seeds: [...DYAD_ORIGINS],
      environment: 'public',
    })

    stage = 'github repo sync (read-only)'
    console.log(`[live-smoke-v2] Cloning ${DYAD_REPOS.length} authorized dyad-sh repos read-only...`)
    const syncedRepos = await syncGithubRepos([...DYAD_REPOS], AbortSignal.timeout(180_000), {
      cloneDir: projectReposDir(DATA_DIR, projectId),
    })
    let totalFiles = 0
    let totalDeps = 0
    let totalSpecs = 0
    const repoSummaries = []
    for (const repo of syncedRepos) {
      totalFiles += repo.files.length
      totalDeps += repo.dependencies.length
      for (const spec of repo.specs) {
        storage.upsertProjectSpecRaw(projectId, {
          name: spec.name,
          kind: spec.kind,
          content: spec.content,
        })
        totalSpecs += 1
      }
      repoSummaries.push({
        fullName: repo.fullName,
        defaultBranch: repo.defaultBranch,
        private: repo.private,
        treeCount: repo.treeCount,
        filesCount: repo.files.length,
        dependenciesCount: repo.dependencies.length,
        specsCount: repo.specs.length,
        warnings: repo.warnings,
      })
    }
    writeFileSync(
      join(OUTPUT_DIR, 'github-sync.json'),
      JSON.stringify({ repos: repoSummaries, totalFiles, totalDeps, totalSpecs }, null, 2) + '\n',
      { mode: 0o600 },
    )
    console.log(`[live-smoke-v2] Synced ${syncedRepos.length} repos: ${totalFiles} files, ${totalDeps} dependencies, ${totalSpecs} project specs.`)

    stage = 'run creation & scope approval'
    const goal = [
      'Perform a Tier 1 Deep Read-Only + Safe Benign Probes defensive security assessment of dyad.sh and its 30 approved subdomains.',
      'Correlate synced dyad-sh repository routes, configs, and lockfile dependencies with live runtime fingerprinting and CVE advisories.',
      'Prioritize highest-risk surfaces (auth/OAuth, API/cloud, uploaders, billing, LLM gateways, sandpack bundler, staging/debug, and dangling DNS/TLS).',
      'Harvest JS bundles, inspect CORS/CSP/cookies/redirects/headers/DNS/TLS, and submit Declarative Replay Specs (with mandatory controls and spaCatchallControl) for Zero-LLM verification.',
      'Strictly read-only GET/HEAD/OPTIONS; zero state mutations and zero RCE payloads.',
    ].join(' ')

    const { id: runId } = storage.createRun({
      requestId: randomUUID(),
      projectId,
      goal,
      sourceMode: 'public',
      capabilityTier: 1,
      budgetUsd: 25,
      budgetRequests: 2500,
      maxRpsPerOrigin: 5,
      workerConcurrency: 6,
      workerMaxTurns: 25,
    })

    storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
    const allAssetIds = storage.run(runId).candidates.map(c => c.id)
    assert.equal(allAssetIds.length, DYAD_ORIGINS.length, 'Expected all 30 dyad.sh origins in inventory.')

    storage.command({
      requestId: randomUUID(),
      runId,
      action: 'scope',
      expectedScopeRevision: 0,
      assetIds: allAssetIds,
      consent: true,
      capabilityTier: 1,
      budgetUsd: 25,
      budgetRequests: 2500,
      maxRpsPerOrigin: 5,
    })

    const unsub = storage.onRunEvent(runId, ev => {
      if (
        ev.kind.startsWith('threat_model.') ||
        ev.kind.startsWith('investigation.') ||
        ev.kind.startsWith('verification.') ||
        ev.kind.startsWith('chain_step.') ||
        ev.kind.startsWith('finding.') ||
        ev.kind.startsWith('retest.') ||
        ev.kind.startsWith('report.') ||
        ev.kind.startsWith('run.') ||
        ev.kind === 'broker.circuit_open'
      ) {
        console.log(`[live-smoke-v2] [${ev.kind}] ${ev.message}`)
      }
    })

    stage = 'live v2 engine execution'
    engine.start()
    engine.wake()

    const maxWaitMs = 15 * 60_000
    const startedAt = Date.now()
    let lastLogAt = Date.now()
    while (Date.now() - startedAt < maxWaitMs) {
      const current = storage.run(runId)
      if (['complete', 'failed', 'stopped', 'paused', 'budget_paused'].includes(current.status)) {
        break
      }
      if (Date.now() - lastLogAt >= 25_000) {
        const d = storage.runDetail(runId)
        console.log(
          `[live-smoke-v2] progress: phase=${current.phase} status=${current.status} round=${current.roundNo} ` +
          `steps=${d.chainSteps.filter(s => s.status === 'complete').length}/${d.chainSteps.length} ` +
          `facts=${d.facts.length} reqs=${current.spentRequests}/${current.budgetRequests} ` +
          `usd=$${current.spentUsd.toFixed(3)}/$${current.budgetUsd} findings=${d.findings.length}`,
        )
        lastLogAt = Date.now()
      }
      await delay(2_000)
    }

    let finalRun = storage.run(runId)
    if (finalRun.status === 'running') {
      console.log('[live-smoke-v2] Reached 15m smoke window; stopping cleanly to checkpoint report...')
      storage.command({ requestId: randomUUID(), runId, action: 'stop' })
      finalRun = storage.run(runId)
    }

    stage = 'one-click verify fix retest'
    let detail = storage.runDetail(runId)
    const confirmedWithSpec = detail.findings.find(f => f.status === 'confirmed' && Boolean(f.replaySpecId))
    let retestSummary: { findingId: string; title: string; verdict: string; summary: string } | null = null
    if (confirmedWithSpec) {
      console.log(`[live-smoke-v2] Running one-click Verify Fix retest for "${confirmedWithSpec.title}"...`)
      storage.command({ requestId: randomUUID(), runId, action: 'retest_finding', findingId: confirmedWithSpec.id })
      engine.wake()
      const retestStart = Date.now()
      while (Date.now() - retestStart < 60_000) {
        const retests = storage.runDetail(runId).retestRuns.filter(r => r.findingId === confirmedWithSpec.id)
        if (retests.length > 0) {
          retestSummary = {
            findingId: confirmedWithSpec.id,
            title: confirmedWithSpec.title,
            verdict: retests[0].verdict,
            summary: retests[0].summary,
          }
          console.log(`[live-smoke-v2] Verify Fix retest verdict: ${retests[0].verdict} — ${retests[0].summary}`)
          break
        }
        await delay(500)
      }
    }

    unsub()
    await engine.stop()

    stage = 'invariants & portable report export'
    detail = storage.runDetail(runId)
    finalRun = detail.run
    assert.ok(detail.threatModel, 'Threat Model must be recorded.')
    assert.equal(detail.threatModel.entries.length, DYAD_ORIGINS.length, 'Threat Model must cover all 30 hosts.')
    assert.ok(detail.chainSteps.length > 0, 'At least one chain_step must be planned.')
    assert.ok(detail.facts.length > 0, 'Structured facts must be recorded.')

    // Verify ZERO out-of-scope broker requests and ZERO non-read-only methods
    const events = storage.eventsAfter(runId, 0, 10_000)
    const allowedBrokerEvents = events.filter(e => e.kind === 'broker.allowed')
    const outOfScopeEvents = allowedBrokerEvents.filter(e => {
      const origin = typeof e.detail?.origin === 'string' ? e.detail.origin : ''
      return !APPROVED_ORIGIN_SET.has(origin)
    })
    assert.equal(outOfScopeEvents.length, 0, `Found out-of-scope broker requests: ${JSON.stringify(outOfScopeEvents)}`)

    const badMethodExchanges = detail.exchangesSummary.filter(ex => !['GET', 'HEAD', 'OPTIONS'].includes(ex.method.toUpperCase()))
    assert.equal(badMethodExchanges.length, 0, `Tier 1 must not execute mutating HTTP methods: ${JSON.stringify(badMethodExchanges)}`)

    const rceSpecs = detail.replaySpecs.filter(s => {
      const specObj = s.spec as Record<string, unknown> | null
      return specObj?.kind === 'rce_proof'
    })
    assert.equal(rceSpecs.length, 0, 'Tier 1 must not execute any rce_proof replay specs.')

    // Every confirmed multi_step_chain finding must have a replaySpecId & verification artifact
    const confirmedChainFindings = detail.findings.filter(f => f.status === 'confirmed' && f.findingKind === 'multi_step_chain')
    for (const finding of confirmedChainFindings) {
      assert.ok(finding.replaySpecId, `Confirmed chain finding ${finding.id} missing replaySpecId.`)
      assert.ok(finding.evidenceIds.length > 0, `Confirmed chain finding ${finding.id} missing evidenceIds.`)
    }

    const latestReport = detail.reports[0]
    assert.ok(latestReport, 'At least one report version must be persisted.')
    const exported = exportReportMarkdown(storage, runId, latestReport.id)
    assert.ok(!exported.content.includes(openrouterKey), 'OpenRouter key leaked into Markdown export!')
    assert.ok(!exported.content.includes(githubPat), 'GitHub PAT leaked into Markdown export!')
    const sqliteBytes = readFileSync(join(DATA_DIR, 'guardian.sqlite'))
    assert.ok(!sqliteBytes.includes(openrouterKey), 'OpenRouter key leaked into SQLite!')
    assert.ok(!sqliteBytes.includes(githubPat), 'GitHub PAT leaked into SQLite!')

    const mdPath = join(OUTPUT_DIR, 'guardian-dyad-v2.md')
    writeFileSync(mdPath, exported.content, { mode: 0o600 })

    const cveFacts = detail.facts.filter(f => {
      const data = f.data as Record<string, unknown> | null
      return data?.subkind === 'cve_hypothesis' || typeof data?.cveId === 'string'
    })
    const confirmedFindings = detail.findings.filter(f => f.status === 'confirmed')
    const severityBreakdown: Record<string, number> = {}
    for (const f of confirmedFindings) {
      severityBreakdown[f.severity] = (severityBreakdown[f.severity] ?? 0) + 1
    }

    const summary = {
      result: finalRun.status === 'complete' ? 'complete' : finalRun.status,
      runId,
      model: DEFAULT_PROVIDER.model,
      capabilityTier: finalRun.capabilityTier,
      approvedHosts: DYAD_ORIGINS.length,
      reposSynced: syncedRepos.length,
      repoFilesSynced: totalFiles,
      repoDependenciesExtracted: totalDeps,
      projectSpecsImported: totalSpecs,
      phase: finalRun.phase,
      status: finalRun.status,
      roundNo: finalRun.roundNo,
      turnsUsed: finalRun.turnsUsed,
      spentRequests: finalRun.spentRequests,
      budgetRequests: finalRun.budgetRequests,
      spentUsd: Number(finalRun.spentUsd.toFixed(4)),
      budgetUsd: finalRun.budgetUsd,
      spentTokens: finalRun.spentTokens,
      threatModelEntries: detail.threatModel.entries.length,
      chainStepsTotal: detail.chainSteps.length,
      chainStepsCompleted: detail.chainSteps.filter(s => s.status === 'complete').length,
      factsTotal: detail.facts.length,
      cveHypothesesCount: cveFacts.length,
      exchangesRecorded: detail.exchangesSummary.length,
      replaySpecsTotal: detail.replaySpecs.length,
      confirmedFindingsTotal: confirmedFindings.length,
      confirmedChainFindingsTotal: confirmedChainFindings.length,
      confirmedBaselineFindingsTotal: confirmedFindings.length - confirmedChainFindings.length,
      severityBreakdown,
      confirmedFindings: confirmedFindings.map(f => ({
        id: f.id,
        origin: f.origin,
        severity: f.severity,
        title: f.title,
        findingKind: f.findingKind ?? 'baseline_check',
        replaySpecId: f.replaySpecId ?? null,
      })),
      owaspCoverageCount: detail.coverageEntries.length,
      outOfScopeBrokerRequests: outOfScopeEvents.length,
      mutatingHttpExchanges: badMethodExchanges.length,
      retest: retestSummary,
      reportVersion: latestReport.version,
      reportPartial: latestReport.partial,
      markdownPath: mdPath,
      markdownBytes: Buffer.byteLength(exported.content, 'utf8'),
      elapsedSec: Math.round((Date.now() - startedAt) / 1000),
    }

    writeFileSync(join(OUTPUT_DIR, 'summary.json'), JSON.stringify(summary, null, 2) + '\n', { mode: 0o600 })
    console.log('[live-smoke-v2] SUMMARY:\n' + JSON.stringify(summary, null, 2))
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    writeFileSync(
      join(OUTPUT_DIR, 'summary.json'),
      JSON.stringify({ result: 'error', stage, message }, null, 2) + '\n',
      { mode: 0o600 },
    )
    console.error(`[live-smoke-v2] Failed at stage "${stage}": ${message}`)
    process.exitCode = 1
  } finally {
    await engine.stop().catch(() => undefined)
    storage.close()
  }
}

await main()
