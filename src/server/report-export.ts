import { createHash } from 'node:crypto'
import { and, desc, eq } from 'drizzle-orm'
import { id as evidenceId } from '../domain.ts'
import type { EvidenceSummary } from '../domain.ts'
import {
  capabilityTierLabel,
  checkLabels,
  owaspCategoryTitles,
  owaspStatusLabels,
  reportEvidenceSource,
  reportHighlights,
  reportPlanLabel,
  retestVerdictLabels,
  suppliedResponseLabel,
} from '../report-summary.ts'
import { personaSecrets, resolveRunPersonas } from './persona-vault.ts'
import { redact, redactHeaders } from './redact.ts'
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
}

function inline(value: string, secrets: readonly NamedSecret[]) {
  return redact(value, secrets).replace(/\s+/g, ' ')
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replace(/[\\`*_{}\[\]()#|~]/g, '\\$&')
}

function linkTo({ number }: Attachment) {
  return `[Evidence ${number}](#evidence-${number})`
}

export function exportReportMarkdown(storage: Store, runId: string, reportId: string) {
  const run = storage.run(runId)
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

  const findings = body.findings.filter(item => approved.has(item.origin))
  const { coverage, confirmed, chainConfirmed, priority } = reportHighlights(body)
  const plan = reportPlanLabel(body.selectedChecks)
  const confirmedFindings = findings.filter(item => item.status === 'confirmed')
  const severityCounts = ['critical', 'high', 'medium', 'low', 'informational'].flatMap(severity => {
    const count = confirmedFindings.filter(item => item.severity === severity).length
    return count ? [`- **${severity[0].toUpperCase() + severity.slice(1)}** ${count}`] : []
  })

  const lines = [
    `# Guardian v2 ${report.partial ? 'partial' : 'complete'} report`, '',
    `**${confirmed} confirmed ${confirmed === 1 ? 'finding' : 'findings'}**${chainConfirmed ? ` (${chainConfirmed} multi-step ${chainConfirmed === 1 ? 'chain' : 'chains'})` : ''}`, '',
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
    ...(confirmedFindings.length ? [
      `${confirmedFindings.length} evidence-backed ${confirmedFindings.length === 1 ? 'finding was' : 'findings were'} confirmed within the approved scope via Zero-LLM deterministic verification. ` +
        `${severityCounts.length ? 'The confirmed severity distribution is listed below.' : ''}`, '',
      ...severityCounts, '',
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
  for (const finding of findings) {
    const links = evidenceLinks(finding.origin, finding.evidenceIds, finding.exchangeIds ?? [])
    const specRow = finding.replaySpecId ? runSpecs.get(finding.replaySpecId) : undefined
    const retests = retestsByFinding.get(finding.id) ?? []
    lines.push(
      `### ${inline(finding.title, secrets)}`, '',
      `- **Host** ${inline(finding.origin, secrets)}`,
      `- **Severity** ${inline(finding.severity, secrets)} · **Status** ${inline(finding.status, secrets)}${finding.findingKind === 'multi_step_chain' ? ' · **Type** Multi-step chain' : ''}`,
      ...(finding.category ? [`- **Class** ${inline(finding.category, secrets)}${finding.cwe ? ` · ${inline(finding.cwe, secrets)}` : ''}`] : []),
      ...(finding.confidence ? [`- **Confidence** ${inline(finding.confidence, secrets)}`] : []),
      ...(finding.check ? [
        `- **Observed** ${inline(finding.check.observed ?? 'Unavailable', secrets)}`,
        `- **Expected** ${inline(finding.check.expected, secrets)}`,
      ] : []),
      `- **Result** ${inline(finding.reason, secrets)}`,
      ...(finding.impact ? [`- **Impact** ${inline(finding.impact, secrets)}`] : []),
      ...(finding.verification ? [`- **Verification** ${inline(finding.verification, secrets)}`] : []),
      ...(specRow ? [`- **Replay spec** \`${specRow.spec.kind}\` · SHA-256 \`${specRow.specSha256}\``] : []),
      ...(retests.length ? [`- **Latest Verify Fix retest** ${inline(retestVerdictLabels[retests[0].verdict], secrets)} (${new Date(retests[0].createdAt).toISOString()}) — ${inline(retests[0].summary, secrets)}`] : []),
      `- **${finding.status === 'confirmed' ? 'Remediation' : 'Follow-up'}** ${inline(finding.remediation, secrets)}`,
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
        } else if (specRow.spec.kind === 'rce_proof') {
          lines.push(`${stepNum++}. **[Replay · control]** \`${specRow.spec.controlStep.request.method}\` ${inline(specRow.spec.controlStep.request.origin + specRow.spec.controlStep.request.pathAndQuery, secrets)} — ${inline(specRow.spec.controlStep.description, secrets)}`)
          lines.push(`${stepNum++}. **[Replay · ${inline(specRow.spec.proofMode, secrets)} probe]** \`${specRow.spec.probeStep.request.method}\` ${inline(specRow.spec.probeStep.request.origin + specRow.spec.probeStep.request.pathAndQuery, secrets)} — ${inline(specRow.spec.probeStep.description, secrets)}`)
        } else {
          lines.push(`${stepNum++}. **[Replay · ${inline(specRow.spec.kind, secrets)}]** ${inline(specRow.spec.targetOrigin, secrets)}`)
        }
      }
      lines.push('')
    }
  }

  if (confirmedFindings.length) {
    lines.push('## Remediation plan', '')
    for (const [index, finding] of confirmedFindings.entries()) {
      lines.push(`${index + 1}. **${inline(finding.title, secrets)}** — ${inline(finding.remediation, secrets)} Recheck: ${inline(finding.recheck ?? 'repeat the verified replay check after the change.', secrets)}`)
    }
    lines.push('')
  }

  if (body.owaspCoverage?.length) {
    lines.push('## OWASP & API Top 10 coverage matrix', '', '| Host | Category | Status | Summary |', '| :--- | :--- | :--- | :--- |')
    for (const entry of body.owaspCoverage.filter(e => approved.has(e.origin))) {
      lines.push(
        `| ${inline(entry.origin, secrets)} | ${inline(owaspCategoryTitles[entry.category] ?? entry.category, secrets)} | ${inline(owaspStatusLabels[entry.status] ?? entry.status, secrets)} | ${inline(entry.summary, secrets)} |`,
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

  lines.push('## Methodology and limitations', '',
    '- Guardian evaluated only the approved hosts, capability tier, personas, and recorded evidence identified in this report.',
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

  return { filename: `guardian-report-${run.id.slice(0, 8)}-v${report.version}.md`, content: redact(lines.join('\n'), secrets) }
}
