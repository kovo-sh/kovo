import { createHash } from 'node:crypto'
import { and, desc, eq } from 'drizzle-orm'
import { id as evidenceId } from '../domain.ts'
import type { EvidenceSummary } from '../domain.ts'
import {
  callerCompatibilityLabels,
  capabilityTierLabel,
  checkLabels,
  collapseBaselineHeaderFindings,
  deduplicateChainFindings,
  dynamicRetestLabels,
  findingVerificationTier,
  isConsolidatedHeaderPostureFinding,
  owaspCategoryTitles,
  owaspStatusLabels,
  patchStatusLabels,
  reportEvidenceSource,
  reportHighlights,
  reportPlanLabel,
  retestVerdictLabels,
  suppliedResponseLabel,
  verificationTierLabels,
} from '../report-summary.ts'
import { buildCoverageGapReport, formatCoverageGapMarkdown } from './coverage-gaps.ts'
import type { CompositeProofReceipt } from './composite-receipt.ts'
import { personaSecrets, resolveRunPersonas } from './persona-vault.ts'
import {
  buildPortableCompositeReceiptRecord,
  exportRunReceiptBundle,
  extractStoreCompositeReceipts,
  isPortableCompositeReceiptRecord,
  verifyProofReceiptBundle,
} from './receipt-export.ts'
import type {
  CompositeReceiptExportInput,
  PortableCompositeEdgeBinding,
  PortableCompositeReceiptRecord,
} from './receipt-export.ts'
import { redact, redactHeaders, redactZdr } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import { isReportSource, projectReportEvidence } from './report-evidence.ts'
import { brokerExchanges, facts, replaySpecs, reports, retestRuns } from './schema.ts'
import type { Store } from './store.ts'

type Attachment = {
  number: number
  origin: string
  kind?: EvidenceSummary['kind']
  label?: string
  json?: string
  sources?: Attachment[]
}

const evidenceLabels: Partial<Record<EvidenceSummary['kind'], string>> = {
  observation: 'Response observation',
  'access-policy': 'Supplied access policy records',
  analysis: 'Analysis record',
  verification: 'Deterministic verification',
  replay: 'Zero-LLM replay verification',
  exchange: 'Redacted broker exchange',
  dns: 'DNS inspection',
  tls: 'TLS handshake audit',
  browser: 'Scoped browser capture',
  'threat-model': 'Round-0 threat model',
  digest: 'Cold-graph digest',
  sast: 'Offline SAST scan',
  surface: 'Brokered surface probe',
  patch: 'Air-gapped patch verification',
  ws: 'Brokered WebSocket probe',
}

function inline(value: string, secrets: readonly NamedSecret[]) {
  return redact(value, secrets).replace(/\s+/g, ' ')
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replace(/[\\`*_{}\[\]()#|~]/g, '\\$&')
}

function linkTo({ number }: Attachment) {
  return `[Evidence ${number}](#evidence-${number})`
}

export { exportRunReceiptBundle, verifyProofReceiptBundle }

export type CompositeChainMarkdownInput =
  | PortableCompositeReceiptRecord
  | CompositeProofReceipt
  | CompositeReceiptExportInput

export interface FormatCompositeChainMarkdownOptions {
  secrets?: readonly NamedSecret[]
  zdr?: boolean
}

function scrubMarkdownText(value: string, secrets: readonly NamedSecret[], zdr: boolean): string {
  return zdr ? redactZdr(value, secrets) : redact(value, secrets)
}

function codeSpan(value: string, secrets: readonly NamedSecret[], zdr: boolean): string {
  const clean = scrubMarkdownText(value, secrets, zdr).replace(/[`\r\n]+/g, ' ').trim()
  return `\`${clean}\``
}

function normalizeCompositeForMarkdown(
  item: CompositeChainMarkdownInput,
  secrets: readonly NamedSecret[],
  zdr: boolean,
): PortableCompositeReceiptRecord {
  if (isPortableCompositeReceiptRecord(item)) {
    return item
  }
  const input: CompositeReceiptExportInput = 'receipt' in item && 'hops' in item.receipt
    ? item
    : { receipt: item as CompositeProofReceipt }
  return buildPortableCompositeReceiptRecord(input, { secrets, zdr })
}

function formatEdgeBindingDetail(
  edge: PortableCompositeEdgeBinding,
  secrets: readonly NamedSecret[],
  zdr: boolean,
): string {
  const d = edge.bindingDetail
  if (edge.kind === 'value_binding') {
    const parts: string[] = []
    if (d.capabilityHandle) parts.push(`capability ${codeSpan(d.capabilityHandle, secrets, zdr)}`)
    if (d.valueDigest) parts.push(`digest ${codeSpan(d.valueDigest.slice(0, 16) + '...', secrets, zdr)}`)
    return parts.join(', ') || 'host-signed value handoff'
  }
  if (edge.kind === 'derived_crypto_binding') {
    const parts: string[] = []
    if (d.sourceCapabilityId) parts.push(`source ${codeSpan(d.sourceCapabilityId, secrets, zdr)}`)
    if (d.derivedCapabilityId) parts.push(`derived ${codeSpan(d.derivedCapabilityId, secrets, zdr)}`)
    if (d.alg) parts.push(`alg ${codeSpan(d.alg, secrets, zdr)}`)
    return parts.join(', ') || 'host-attested crypto derivation'
  }
  if (edge.kind === 'state_transition_binding') {
    const parts: string[] = []
    if (d.entityId) parts.push(`entity ${codeSpan(d.entityId, secrets, zdr)}`)
    if (d.mutationKind) parts.push(`mutation ${codeSpan(d.mutationKind, secrets, zdr)}`)
    if (d.ablationExchangeIds?.length) parts.push(`${d.ablationExchangeIds.length} ablation control(s)`)
    return parts.join(', ') || 'clean-session ablation state transition'
  }
  const parts: string[] = []
  if (d.channel) parts.push(`channel ${codeSpan(d.channel, secrets, zdr)}`)
  if (d.correlationId) parts.push(`correlation ${codeSpan(d.correlationId, secrets, zdr)}`)
  return parts.join(', ') || 'async pivot correlation'
}

/**
 * Render multi-hop `CompositeProofReceipt` DAG chains cleanly in Markdown:
 * `Hop 1 -> Hop 2 -> ... -> Terminal Impact`, actor/surface per hop, causal edge binding kind,
 * Mode-A / Mode-B verification badge, and `patchBrokeHopId` when retested against a patch.
 */
export function formatCompositeChainMarkdown(
  receipts: readonly CompositeChainMarkdownInput[],
  options: FormatCompositeChainMarkdownOptions = {},
): string {
  if (!receipts.length) return ''
  const secrets = options.secrets ?? []
  const zdr = options.zdr === true

  const lines: string[] = ['## Multi-Hop Causal Chains', '']
  for (const raw of receipts) {
    const record = normalizeCompositeForMarkdown(raw, secrets, zdr)
    const heading = record.title
      ? `${inline(scrubMarkdownText(record.title, secrets, zdr), secrets)} (${codeSpan(record.chainId, secrets, zdr)})`
      : `Chain ${codeSpan(record.chainId, secrets, zdr)} — ${codeSpan(record.terminalVulnClass, secrets, zdr)}`

    const modeBadge = record.replayMode === 'fresh_clean_replay'
      ? (record.confirmed ? '`[Mode-A Verified]` (fresh_clean_replay)' : '`[Mode-A Unverified]` (fresh_clean_replay)')
      : (record.confirmed ? '`[Mode-B Verified]` (one_shot_transcript)' : '`[Mode-B Unverified]` (one_shot_transcript)')

    const hopSequence = record.hops
      .map(hop => `Hop ${hop.order} (${codeSpan(hop.hopId, secrets, zdr)})`)
      .join(' -> ')

    lines.push(
      `### ${heading}`, '',
      `- **Terminal class** ${codeSpan(record.terminalVulnClass, secrets, zdr)}${record.severity ? ` · **Severity** ${inline(record.severity, secrets)}` : ''}${record.cwe ? ` · **CWE** ${codeSpan(record.cwe, secrets, zdr)}` : ''} · **Hops** ${record.hopCount}`,
      `- **Verification** ${modeBadge}${record.verificationReason ? ` — ${inline(scrubMarkdownText(record.verificationReason, secrets, zdr), secrets)}` : ''}`,
    )
    if (record.patchBrokeHopId) {
      const verdictText = record.patchRetestVerdict ? ` (${record.patchRetestVerdict})` : ''
      lines.push(
        `- **Patch retest** Chain broken at ${codeSpan(record.patchBrokeHopId, secrets, zdr)} (\`patchBrokeHopId\`: ${codeSpan(record.patchBrokeHopId, secrets, zdr)})${verdictText}`,
      )
    }
    lines.push(
      `- **DAG path** ${hopSequence} -> **Terminal Impact** (${codeSpan(record.terminalImpact.terminalHopId, secrets, zdr)})`,
      '',
      '| Hop | Hop ID | Surface | Actor | Target | Causal Binding | Delta |',
      '| :--- | :--- | :--- | :--- | :--- | :--- | :--- |',
    )

    const incomingByHop = new Map<string, PortableCompositeEdgeBinding[]>()
    for (const edge of record.causalEdges) {
      const arr = incomingByHop.get(edge.toHopId) ?? []
      arr.push(edge)
      incomingByHop.set(edge.toHopId, arr)
    }

    for (const hop of record.hops) {
      const incoming = incomingByHop.get(hop.hopId) ?? []
      const bindingCell = incoming.length > 0
        ? incoming.map(e => `${codeSpan(e.fromHopId, secrets, zdr)} --[${codeSpan(e.kind, secrets, zdr)}]-->`).join('; ')
        : 'Root'
      const targetStr = `${hop.method ? `${hop.method} ` : ''}${hop.origin}${hop.pathAndQuery ?? ''}`
      const actorCell = hop.actor ? codeSpan(hop.actor, secrets, zdr) : '_derived-capability_'
      const hopTag = [
        `Hop ${hop.order}`,
        ...(hop.hopId === record.terminalImpact.terminalHopId ? ['**(Terminal)**'] : []),
        ...(record.patchBrokeHopId === hop.hopId ? ['**(Patch broke here)**'] : []),
      ].join(' ')
      lines.push(
        `| ${hopTag} | ${codeSpan(hop.hopId, secrets, zdr)} | ${codeSpan(hop.surface, secrets, zdr)} | ${actorCell} | ${codeSpan(targetStr, secrets, zdr)} | ${bindingCell} | ${inline(scrubMarkdownText(hop.claimedDelta, secrets, zdr), secrets)} |`,
      )
    }

    lines.push(
      '',
      `- **Terminal Impact** (${codeSpan(record.terminalImpact.terminalHopId, secrets, zdr)}): ${inline(scrubMarkdownText(record.terminalImpact.claimedImpact, secrets, zdr), secrets)}`,
    )
    if (record.causalEdges.length > 0) {
      lines.push('', '#### Causal Edge Bindings', '')
      for (const edge of record.causalEdges) {
        const verifiedTag = edge.verified === true ? ' · verified' : edge.verified === false ? ' · unverified' : ''
        lines.push(
          `- ${codeSpan(edge.fromHopId, secrets, zdr)} -> ${codeSpan(edge.toHopId, secrets, zdr)} (${codeSpan(edge.kind, secrets, zdr)}${verifiedTag}) — ${formatEdgeBindingDetail(edge, secrets, zdr)}`,
        )
      }
    }
    lines.push('')
  }

  const raw = lines.join('\n')
  return zdr ? redactZdr(raw, secrets) : redact(raw, secrets)
}

export interface ExportReportMarkdownOptions {
  zdr?: boolean
  tenantId?: string
  compositeReceipts?: readonly CompositeChainMarkdownInput[]
}

export function exportReportMarkdown(
  storage: Store,
  runId: string,
  reportId: string,
  options: ExportReportMarkdownOptions = {},
) {
  const run = storage.run(runId)
  if (options.tenantId !== undefined) {
    storage.assertRunTenantAccess(run.id, options.tenantId)
  }
  const report = storage.db.select().from(reports).where(and(eq(reports.runId, run.id), eq(reports.id, reportId))).get()
  if (!report) throw new Error('Report version not found.')

  const secrets = (() => {
    try {
      return personaSecrets(resolveRunPersonas(storage, run.projectId, run.approvedPersonaIds))
    } catch {
      return [] as NamedSecret[]
    }
  })()

  const { body, createdAt } = report
  const scope = new Map(body.scope.map(asset => [asset.origin, asset.id]))
  const approved = new Set(scope.keys())
  const assignments = new Map(storage.workerList(run.id).map(worker => [worker.id, worker]))
  const runFacts = new Map(
    storage.db.select().from(facts).where(eq(facts.runId, run.id)).all().map(f => [f.id, f]),
  )
  const runSpecs = new Map(
    storage.db.select().from(replaySpecs).where(eq(replaySpecs.runId, run.id)).all().map(s => [s.id, s]),
  )
  const runExchanges = new Map(
    storage.db.select().from(brokerExchanges).where(eq(brokerExchanges.runId, run.id)).all().map(e => [e.id, e]),
  )
  const runRetests = storage.db.select().from(retestRuns)
    .where(eq(retestRuns.runId, run.id)).orderBy(desc(retestRuns.createdAt)).all()
  const retestsByFinding = new Map<string, typeof runRetests>()
  for (const r of runRetests) {
    const arr = retestsByFinding.get(r.findingId) ?? []
    arr.push(r)
    retestsByFinding.set(r.findingId, arr)
  }

  const attachments = new Map<string, Attachment>()

  function includeEvidence(origin: string, id: string, sourceOnly = false): Attachment | undefined {
    const key = 'ev:' + origin + ':' + id
    const existing = attachments.get(key)
    if (existing) return sourceOnly && (!existing.kind || !isReportSource(existing.kind)) ? undefined : existing
    const record = (() => {
      if (!approved.has(origin) || !evidenceId.safeParse(id).success) return
      try { return storage.artifact(run.id, id) } catch { return }
    })()
    if (sourceOnly && record && !isReportSource(record.kind)) return

    const entry: Attachment = { number: attachments.size + 1, origin, kind: record?.kind }
    attachments.set(key, entry)
    if (!record || !evidenceLabels[record.kind]) return entry
    const assignment = assignments.get(record.assignmentId)
    if (!assignment ||
        record.goalRevision !== body.goalRevision ||
        record.scopeRevision > body.scopeRevision ||
        record.createdAt > createdAt) return entry
    if (record.kind === 'observation' && storage.brokerOrigins(assignment).some(host => !approved.has(host))) return entry

    const projected = projectReportEvidence(record.kind, record.content, origin, approved)
    if (!projected) return entry
    const sources = [...new Set(projected.sources ?? [])].map(source => includeEvidence(origin, source, true))
    entry.sources = sources.filter((source): source is Attachment => source !== undefined)
    if (sources.some(source => !source?.json)) return entry
    const rawJson = JSON.stringify({
      kind: record.kind, artifactId: record.id, assignmentId: assignment.id, origin,
      capturedAt: new Date(record.createdAt).toISOString(),
      scopeRevision: record.scopeRevision, goalRevision: record.goalRevision,
      ...(projected.sources ? { inputEvidence: [...new Set(projected.sources)] } : {}),
      ...projected.data,
    }, null, 2)
    entry.json = redact(rawJson, secrets)
    return entry
  }

  function includeExchange(exchangeId: string): Attachment | undefined {
    const key = 'ex:' + exchangeId
    const existing = attachments.get(key)
    if (existing) return existing
    const ex = runExchanges.get(exchangeId)
    if (!ex || ex.scopeRevision > body.scopeRevision || ex.createdAt > createdAt) return undefined
    const allOrigins = [ex.origin, ex.finalOrigin, ...ex.redirectOrigins]
    if (allOrigins.some(o => !approved.has(o))) return undefined
    const payload = JSON.stringify({
      kind: 'exchange',
      exchangeId: ex.id,
      assignmentId: ex.assignmentId,
      origin: ex.origin,
      finalOrigin: ex.finalOrigin,
      redirectOrigins: ex.redirectOrigins,
      method: ex.method,
      pathAndQuery: redact(ex.pathAndQuery, secrets),
      personaHandle: ex.personaHandle,
      status: ex.status,
      mediaType: ex.mediaType,
      reqHeaders: redactHeaders(ex.reqHeaders, secrets),
      respHeaders: redactHeaders(ex.respHeaders, secrets),
      bodySha256: ex.bodySha256,
      bodyPreview: redact(ex.bodyPreview.slice(0, 2048), secrets),
      durationMs: ex.durationMs,
      capturedAt: new Date(ex.createdAt).toISOString(),
    }, null, 2)
    const entry: Attachment = {
      number: attachments.size + 1,
      origin: ex.origin,
      kind: 'exchange',
      label: `Redacted HTTP exchange (${ex.method} ${ex.status})`,
      json: redact(payload, secrets),
    }
    attachments.set(key, entry)
    return entry
  }

  function evidenceLinks(origin: string, ids: string[], exchangeIds: string[] = []) {
    const links: string[] = []
    for (const id of new Set(ids)) {
      const entry = includeEvidence(origin, id)
      if (entry) links.push(linkTo(entry))
    }
    for (const exId of new Set(exchangeIds)) {
      const entry = includeExchange(exId)
      if (entry) links.push(linkTo(entry))
    }
    return links.join(' · ')
  }

  const rawFindings = body.findings.filter(item =>
    approved.has(item.origin) || item.status === 'static_verified' || item.verificationTier === 'static_verified',
  )
  const { findings } = collapseBaselineHeaderFindings(deduplicateChainFindings(rawFindings))
  const prominentFindings = findings.filter(item => !isConsolidatedHeaderPostureFinding(item))
  const headerPostureFindings = findings.filter(item => isConsolidatedHeaderPostureFinding(item))
  const { coverage, confirmed, staticVerified, chainConfirmed, priority } = reportHighlights(body)
  const plan = reportPlanLabel(body.selectedChecks)
  const confirmedFindings = findings.filter(item => item.status === 'confirmed')
  const staticVerifiedFindings = findings.filter(item => item.status === 'static_verified')
  const confirmedProminent = prominentFindings.filter(item => item.status === 'confirmed')
  const severityCounts = ['critical', 'high', 'medium', 'low', 'informational'].flatMap(severity => {
    const count = confirmedFindings.filter(item => item.severity === severity).length
    return count ? [`- **${severity[0].toUpperCase() + severity.slice(1)}** ${count}`] : []
  })
  const staticSeverityCounts = ['critical', 'high', 'medium', 'low', 'informational'].flatMap(severity => {
    const count = staticVerifiedFindings.filter(item => item.severity === severity).length
    return count ? [`- **${severity[0].toUpperCase() + severity.slice(1)} (static verified)** ${count}`] : []
  })

  const openProofGaps = body.openProofGaps?.length
    ? body.openProofGaps.filter(g => approved.has(g.origin))
    : storage.listOpenProofGaps(run.id, body.goalRevision)
        .filter(g => approved.has(g.origin))
        .map(g => ({
          origin: g.origin,
          category: g.category,
          summary: g.summary,
          proofGapReason: g.proofGapReason || g.summary,
        }))

  const patchProposals = body.patchProposals?.length
    ? body.patchProposals
    : storage.listPatchProposals(run.id).filter(p => findings.some(f => f.id === p.findingId))

  const lines = [
    `# Kovo Hunter v3 ${report.partial ? 'partial' : 'complete'} report`, '',
    `**${confirmed} runtime/baseline confirmed ${confirmed === 1 ? 'finding' : 'findings'}**` +
      `${chainConfirmed ? ` (${chainConfirmed} multi-step ${chainConfirmed === 1 ? 'chain' : 'chains'})` : ''}` +
      `${staticVerified ? ` · **${staticVerified} static-verified ${staticVerified === 1 ? 'finding' : 'findings'}**` : ''}`, '',
    ...(coverage ? [inline(coverage, secrets), ''] : []),
    `- **Run** ${run.id}`,
    `- **Report version** ${report.version}`,
    `- **Saved** ${new Date(createdAt).toISOString()}`,
    `- **Goal** ${inline(body.goal, secrets)}`,
    `- **Capability tier** ${inline(capabilityTierLabel(body.capabilityTier), secrets)}`,
    `- **Scope revision** ${body.scopeRevision} · **Goal revision** ${body.goalRevision}`,
    `- **Evidence source** ${inline(reportEvidenceSource(run.sourceMode, body.selectedChecks), secrets)}`,
    ...(plan ? ['- ' + inline(plan, secrets)] : []),
    ...(body.metrics ? [
      `- **Execution metrics** ${body.metrics.turnsUsed} turns · ${body.metrics.requestsUsed} brokered requests · ${body.metrics.factsRecorded} facts · ${body.metrics.chainStepsCompleted} chain steps completed (${body.metrics.chainStepsUntested} untested) · $${body.metrics.spentUsd.toFixed(2)} USD`,
    ] : []),
    '', '## Executive summary', '',
    ...(confirmedFindings.length || staticVerifiedFindings.length ? [
      ...(confirmedFindings.length ? [
        `${confirmedFindings.length} evidence-backed ${confirmedFindings.length === 1 ? 'finding was' : 'findings were'} confirmed within the approved scope via Zero-LLM deterministic verification. ` +
          `${severityCounts.length ? 'The confirmed severity distribution is listed below.' : ''}`, '',
        ...severityCounts, '',
      ] : []),
      ...(staticVerifiedFindings.length ? [
        `${staticVerifiedFindings.length} additional white-box ${staticVerifiedFindings.length === 1 ? 'finding was' : 'findings were'} verified statically via deterministic offline AST/SAST re-execution (\`static_verified\` tier — distinct from runtime confirmation).`, '',
        ...staticSeverityCounts, '',
      ] : []),
    ] : ['No evidence-backed security gap was confirmed in the completed checks. This does not mean the approved assets are free of vulnerabilities.', '']),
    ...(priority ? [
      '## Fix first', '',
      ...(priority.finding ? [
        `**${inline(priority.label, secrets)}** · ${inline(priority.finding.origin, secrets)}`, '', inline(priority.finding.remediation, secrets),
      ] : [inline(priority.label, secrets), '', '[Findings](#findings)']),
    ] : []),
    '', '## Approved scope', '',
    ...(approved.size ? [...approved].map(origin => '- ' + inline(origin, secrets)) : ['No approved hosts.']),
    '',
  ]

  if (body.threatModel?.length) {
    lines.push('## Threat model prioritization', '', '| Host | Risk tier | Surface tags | Rationale |', '| :--- | :--- | :--- | :--- |')
    for (const entry of body.threatModel.filter(e => approved.has(e.origin))) {
      lines.push(
        `| ${inline(entry.origin, secrets)} | **${inline(entry.riskTier, secrets)}** | ${inline(entry.surfaceTags.join(', ') || 'general', secrets)} | ${inline(entry.rationale, secrets)} |`,
      )
    }
    lines.push('')
  }

  lines.push('## Findings', '')
  if (!findings.length) lines.push('No findings recorded.', '')
  if (findings.length && !prominentFindings.length) {
    lines.push('No Medium, High, Critical, or non-header findings were recorded. Baseline HTTP security header posture is summarized below.', '')
  }
  for (const finding of prominentFindings) {
    const links = evidenceLinks(finding.origin, finding.evidenceIds, finding.exchangeIds ?? [])
    const specRow = finding.replaySpecId ? runSpecs.get(finding.replaySpecId) : undefined
    const retests = retestsByFinding.get(finding.id) ?? []
    const tier = findingVerificationTier(finding)
    lines.push(
      `### ${inline(finding.title, secrets)}`, '',
      `- **Host** ${inline(finding.origin, secrets)}`,
      `- **Severity** ${inline(finding.severity, secrets)} · **Status** ${inline(finding.status, secrets)}${tier ? ` · **Verification tier** ${inline(verificationTierLabels[tier], secrets)}` : ''}${finding.findingKind === 'multi_step_chain' ? ' · **Type** Multi-step chain' : ''}`,
      ...(finding.category ? [`- **Class** ${inline(finding.category, secrets)}${finding.cwe ? ` · ${inline(finding.cwe, secrets)}` : ''}`] : []),
      ...(finding.confidence ? [`- **Confidence** ${inline(finding.confidence, secrets)}${finding.confidenceRationale ? ` — ${inline(finding.confidenceRationale, secrets)}` : ''}`] : []),
      ...(finding.check ? [
        `- **Observed** ${inline(finding.check.observed ?? 'Unavailable', secrets)}`,
        `- **Expected** ${inline(finding.check.expected, secrets)}`,
      ] : []),
      `- **Result** ${inline(finding.reason, secrets)}`,
      ...(finding.impact ? [`- **Impact** ${inline(finding.impact, secrets)}`] : []),
      ...(finding.counterevidence ? [`- **Counterevidence** ${inline(finding.counterevidence, secrets)}`] : []),
      ...(finding.severityChangeConditions ? [`- **Severity change conditions** ${inline(finding.severityChangeConditions, secrets)}`] : []),
      ...(finding.runtimeProofGap ? [`- **Runtime proof gap** ${inline(finding.runtimeProofGap, secrets)}`] : []),
      ...(finding.codeLocations?.length ? [
        `- **Code locations** ${finding.codeLocations.map(loc => `\`${loc.repo}/${loc.file}:${loc.startLine}${loc.endLine > loc.startLine ? `-${loc.endLine}` : ''}\``).join(', ')}`,
      ] : []),
      ...(finding.verification ? [`- **Verification** ${inline(finding.verification, secrets)}`] : []),
      ...(specRow ? [`- **Replay spec** \`${specRow.spec.kind}\` · SHA-256 \`${specRow.specSha256}\``] : []),
      ...(retests.length ? [`- **Latest Verify Fix retest** ${inline(retestVerdictLabels[retests[0].verdict], secrets)} (${new Date(retests[0].createdAt).toISOString()}) — ${inline(retests[0].summary, secrets)}`] : []),
      `- **${finding.status === 'confirmed' || finding.status === 'static_verified' ? 'Remediation' : 'Follow-up'}** ${inline(finding.remediation, secrets)}`,
      ...(finding.recheck ? [`- **Check the fix** ${inline(finding.recheck, secrets)}`] : []),
      ...(links ? ['- **Evidence** ' + links] : []), '',
    )

    if (finding.chainFactIds?.length || specRow) {
      lines.push('#### Chain timeline', '')
      let stepNum = 1
      for (const fId of finding.chainFactIds ?? []) {
        const fact = runFacts.get(fId)
        if (!fact || fact.tainted || !approved.has(fact.origin)) continue
        lines.push(`${stepNum++}. **[Fact · ${inline(fact.kind, secrets)}]** ${inline(fact.origin, secrets)} — ${inline(fact.summary, secrets)}`)
      }
      if (specRow) {
        if (specRow.spec.kind === 'http_chain') {
          for (const step of specRow.spec.steps) {
            lines.push(`${stepNum++}. **[Replay · ${inline(step.role, secrets)}]** \`${step.request.method}\` ${inline(step.request.origin + step.request.pathAndQuery, secrets)} — ${inline(step.description, secrets)}`)
          }
        } else if (specRow.spec.kind === 'browser_chain') {
          for (const step of specRow.spec.steps) {
            lines.push(`${stepNum++}. **[Replay · ${inline(step.role, secrets)} · ${inline(step.action, secrets)}]** ${inline(step.origin + (step.pathAndQuery ?? ' (reusePage)'), secrets)} — ${inline(step.description, secrets)}`)
          }
        } else if (specRow.spec.kind === 'race_burst') {
          if (specRow.spec.controlStep) {
            lines.push(`${stepNum++}. **[Replay · control]** \`${specRow.spec.controlStep.request.method}\` ${inline(specRow.spec.controlStep.request.origin + specRow.spec.controlStep.request.pathAndQuery, secrets)} — ${inline(specRow.spec.controlStep.description, secrets)}`)
          }
          const firstReq = specRow.spec.burst[0]
          lines.push(`${stepNum++}. **[Replay · race_burst (${specRow.spec.burst.length}x concurrent)]** \`${firstReq.method}\` ${inline(firstReq.origin + firstReq.pathAndQuery, secrets)}`)
          if (specRow.spec.postCheckStep) {
            lines.push(`${stepNum++}. **[Replay · post-check]** \`${specRow.spec.postCheckStep.request.method}\` ${inline(specRow.spec.postCheckStep.request.origin + specRow.spec.postCheckStep.request.pathAndQuery, secrets)} — ${inline(specRow.spec.postCheckStep.description, secrets)}`)
          }
        } else if (specRow.spec.kind === 'rce_proof') {
          lines.push(`${stepNum++}. **[Replay · control]** \`${specRow.spec.controlStep.request.method}\` ${inline(specRow.spec.controlStep.request.origin + specRow.spec.controlStep.request.pathAndQuery, secrets)} — ${inline(specRow.spec.controlStep.description, secrets)}`)
          lines.push(`${stepNum++}. **[Replay · ${inline(specRow.spec.proofMode, secrets)} probe]** \`${specRow.spec.probeStep.request.method}\` ${inline(specRow.spec.probeStep.request.origin + specRow.spec.probeStep.request.pathAndQuery, secrets)} — ${inline(specRow.spec.probeStep.description, secrets)}`)
        } else if (specRow.spec.kind === 'sql_boolean_diff') {
          lines.push(`${stepNum++}. **[Replay · sql_boolean_diff]** \`${specRow.spec.method}\` ${inline(specRow.spec.targetOrigin + specRow.spec.pathAndQuery, secrets)} (3 randomized boolean pairs)`)
        } else if (specRow.spec.kind === 'ws_chain') {
          for (const step of specRow.spec.steps) {
            lines.push(`${stepNum++}. **[Replay · ws_chain · ${inline(step.role, secrets)}]** ${inline(step.origin + step.pathAndQuery, secrets)} — ${inline(step.description, secrets)}`)
          }
        } else if (specRow.spec.kind === 'upload_probe') {
          lines.push(`${stepNum++}. **[Replay · upload_probe]** \`${specRow.spec.uploadStep.method}\` ${inline(specRow.spec.uploadStep.origin + specRow.spec.uploadStep.pathAndQuery, secrets)} (${inline(specRow.spec.uploadStep.filename, secrets)}) → fetch ${inline(specRow.spec.fetchStep.request.origin + specRow.spec.fetchStep.request.pathAndQuery, secrets)}`)
        } else if (specRow.spec.kind === 'static_ast_proof') {
          lines.push(`${stepNum++}. **[Static AST · ${inline(specRow.spec.engine, secrets)}]** \`${specRow.spec.repo}/${specRow.spec.file}:${specRow.spec.startLine}-${specRow.spec.endLine}\` — ${inline(specRow.spec.runtimeProofGap, secrets)}`)
        } else {
          const target = 'targetOrigin' in specRow.spec && typeof specRow.spec.targetOrigin === 'string'
            ? specRow.spec.targetOrigin
            : specRow.spec.origin
          lines.push(`${stepNum++}. **[Replay · ${inline(specRow.spec.kind, secrets)}]** ${inline(target, secrets)}`)
        }
      }
      lines.push('')
    }
  }

  if (headerPostureFindings.length) {
    lines.push(
      '### HTTP Security Header Posture (Baseline Hygiene)', '',
      'Repetitive per-origin missing-header baseline checks (CSP, frame protection, `X-Content-Type-Options`, `Referrer-Policy`, and `Server` disclosure) are consolidated below:', '',
      '| Host | Severity | Status | Summary | Evidence |',
      '| :--- | :--- | :--- | :--- | :--- |',
    )
    for (const posture of headerPostureFindings) {
      const links = evidenceLinks(posture.origin, posture.evidenceIds, posture.exchangeIds ?? [])
      lines.push(
        `| ${inline(posture.origin, secrets)} | ${inline(posture.severity, secrets)} | ${inline(posture.status, secrets)} | ${inline(posture.reason, secrets)} | ${links || '—'} |`,
      )
    }
    lines.push('')
  }

  const findingsMetaById = new Map(findings.map(f => [f.id, { title: f.title, severity: f.severity, cwe: f.cwe ?? null }]))
  const storeCompositeInputs = extractStoreCompositeReceipts([...runSpecs.values()], runRetests, findingsMetaById)
  const compositeByChain = new Map<string, PortableCompositeReceiptRecord>()
  const addCompositeIfInScope = (item: CompositeChainMarkdownInput) => {
    const normalized = normalizeCompositeForMarkdown(item, secrets, options.zdr === true)
    if (normalized.hops.some(h => !approved.has(h.origin))) return
    compositeByChain.set(normalized.chainId, normalized)
  }
  for (const item of storeCompositeInputs) addCompositeIfInScope(item)
  for (const item of options.compositeReceipts ?? []) addCompositeIfInScope(item)
  const compositeChains = [...compositeByChain.values()].sort((a, b) => a.chainId.localeCompare(b.chainId))
  if (compositeChains.length > 0) {
    lines.push(formatCompositeChainMarkdown(compositeChains, { secrets, zdr: options.zdr === true }))
  }

  if (confirmedFindings.length || staticVerifiedFindings.length) {
    lines.push('## Remediation plan', '')
    const orderedRemediation = [
      ...confirmedProminent,
      ...staticVerifiedFindings,
      ...headerPostureFindings.filter(item => item.status === 'confirmed'),
    ]
    for (const [index, finding] of orderedRemediation.entries()) {
      const tier = findingVerificationTier(finding)
      lines.push(`${index + 1}. **${inline(finding.title, secrets)}**${tier ? ` [${verificationTierLabels[tier]}]` : ''} — ${inline(finding.remediation, secrets)} Recheck: ${inline(finding.recheck ?? 'repeat the verified replay check after the change.', secrets)}`)
    }
    lines.push('')
  }

  if (patchProposals.length) {
    lines.push('## Verified Patch Diffs', '')
    for (const patch of patchProposals) {
      const finding = findings.find(f => f.id === patch.findingId)
      const title = finding ? finding.title : patch.findingId
      lines.push(
        `### ${inline(title, secrets)} · ${inline(patch.repo, secrets)}`, '',
        `- **Patch status** ${inline(patchStatusLabels[patch.status], secrets)} · **Caller compatibility** ${inline(callerCompatibilityLabels[patch.callerCompatibility], secrets)} · **Dynamic retest** ${inline(dynamicRetestLabels[patch.dynamicRetestVerdict], secrets)}`,
        ...(patch.codeLocations.length ? [`- **Locations** ${patch.codeLocations.map(l => `\`${l.file}:${l.startLine}-${l.endLine}\``).join(', ')}`] : []),
        ...(patch.reviewNotes ? [`- **Review notes** ${inline(patch.reviewNotes, secrets)}`] : []),
        '',
      )
      if (patch.status === 'approved' && patch.diff.trim()) {
        lines.push('~~~diff', redact(patch.diff, secrets), '~~~', '')
      } else if (patch.status === 'withheld') {
        lines.push('_Patch diff withheld automatically by independent Patch Reviewer because it may break legitimate callers or failed a verification gate._', '')
      }
    }
  }

  if (openProofGaps.length) {
    lines.push('## Open Proof Gaps', '', '| Host | Category | Proof Gap Reason | Summary |', '| :--- | :--- | :--- | :--- |')
    for (const gap of openProofGaps) {
      const catLabel = owaspCategoryTitles[gap.category as keyof typeof owaspCategoryTitles] ?? gap.category
      lines.push(
        `| ${inline(gap.origin, secrets)} | ${inline(catLabel, secrets)} | ${inline(gap.proofGapReason, secrets)} | ${inline(gap.summary, secrets)} |`,
      )
    }
    lines.push('')
  }

  if (body.owaspCoverage?.length) {
    lines.push('## OWASP & API Top 10 coverage matrix', '', '| Host | Category | Status | Enforcing Control / Proof Gap | Summary |', '| :--- | :--- | :--- | :--- | :--- |')
    for (const entry of body.owaspCoverage.filter(e => approved.has(e.origin))) {
      const detail = entry.enforcingControl
        ? `Control: ${entry.enforcingControl}`
        : entry.proofGapReason
          ? `Gap: ${entry.proofGapReason}`
          : '—'
      lines.push(
        `| ${inline(entry.origin, secrets)} | ${inline(owaspCategoryTitles[entry.category] ?? entry.category, secrets)} | ${inline(owaspStatusLabels[entry.status] ?? entry.status, secrets)} | ${inline(detail, secrets)} | ${inline(entry.summary, secrets)} |`,
      )
    }
    lines.push('')
  }

  lines.push('## Baseline host coverage', '')
  for (const row of body.coverage.filter(item => approved.has(item.origin))) {
    const ids = [row.evidenceId, row.analysisEvidenceId, row.accessEvidence?.id].filter((item): item is string => Boolean(item))
    const links = evidenceLinks(row.origin, ids)
    lines.push(`### ${inline(row.origin, secrets)}`, '', `- ${inline(row.status, secrets)}`)
    if (row.accessEvidence?.recordedAt) lines.push('- **Access decisions recorded** ' + inline(row.accessEvidence.recordedAt, secrets))
    if (links) lines.push('- **Evidence** ' + links)
    for (const check of row.checks ?? []) {
      lines.push(
        `- **${inline(check.title, secrets)}** · ${checkLabels[check.status]}`,
        ...(check.status === 'untested' ? [] : [`  - **Observed** ${inline(check.observed ?? 'Unavailable', secrets)}`]),
        `  - **Expected** ${inline(check.expected, secrets)}`,
        `  - ${inline(check.reason, secrets)}`,
      )
    }
    lines.push('')
  }

  if (runRetests.length) {
    lines.push('## Fix verification retests', '')
    for (const rt of runRetests) {
      const f = findings.find(item => item.id === rt.findingId)
      if (!f) continue
      const rtLinks = evidenceLinks(f.origin, rt.evidenceIds, rt.exchangeIds)
      lines.push(
        `- **${inline(f.title, secrets)}** (${inline(f.origin, secrets)}) · **${inline(retestVerdictLabels[rt.verdict], secrets)}** · ${new Date(rt.createdAt).toISOString()} — ${inline(rt.summary, secrets)}${rtLinks ? ' · ' + rtLinks : ''}`,
      )
    }
    lines.push('')
  }

  if (body.gaps.length) lines.push('## Coverage gaps', '', ...body.gaps.map(gap => '- ' + inline(gap, secrets)), '')

  const operationalGaps = buildCoverageGapReport(storage, run.id, {
    approvedOrigins: approved,
    secrets,
    zdr: options.zdr === true,
  })
  if (operationalGaps.totalGaps > 0) {
    lines.push(formatCoverageGapMarkdown(operationalGaps))
  }

  lines.push('## Methodology and limitations', '',
    '- Kovo Hunter evaluated only the approved hosts, capability tier, personas, and recorded evidence identified in this report.',
    '- A confirmed finding strictly requires a deterministic Zero-LLM Replay Verification or air-gapped baseline comparison linked to its source evidence. Model commentary and CVE version matches alone cannot confirm a finding.',
    '- All target network traffic and headless browser requests were mediated by the host RequestBroker with DNS-rebinding defense, persona credential isolation, and secret redaction.',
    '- Inconclusive, ruled-out, not-applicable, and untested checks are retained in coverage instead of being treated as passes.',
    '- This evidence-led review is not a guarantee that no other vulnerability exists. New routes, authenticated roles, application state, and infrastructure changes can alter the result.', '')

  if (attachments.size) lines.push('## Evidence & redacted exchange appendices', '')
  for (const entry of attachments.values()) {
    lines.push(`### Evidence ${entry.number}`, '')
    if (!entry.json) {
      lines.push('Supporting record unavailable for this report version.', '')
      continue
    }
    const sha = createHash('sha256').update(entry.json).digest('hex')
    const label = entry.label ?? (entry.kind === 'observation' && run.sourceMode === 'prepared'
      ? suppliedResponseLabel : entry.kind && evidenceLabels[entry.kind]) ?? 'Evidence'
    lines.push(
      `${label} · ${inline(entry.origin, secrets)}`, '',
      ...(entry.sources?.length ? ['**Inputs** ' + entry.sources.map(linkTo).join(' · '), ''] : []),
      `**SHA-256 of the JSON below** \`${sha}\``, '',
      '~~~json', entry.json, '~~~', '',
    )
  }

  const rawContent = lines.join('\n')
  const content = options.zdr ? redactZdr(rawContent, secrets) : redact(rawContent, secrets)
  return { filename: `kovo-report-${run.id.slice(0, 8)}-v${report.version}.md`, content }
}
