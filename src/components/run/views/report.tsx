// Report: the real report body as a document (F), with every capability of
// the previous report UI: versions (partial vs final), Markdown / SARIF /
// plain-text export, fix-first, findings with expandable detail (evidence,
// Verify Fix retest, verified patch generation), baseline checks by origin,
// coverage by category, threat-model ranking, open proof gaps, patch
// proposals, gaps and methodology. Evidence opens in the inspector.
import { Fragment, useCallback, useEffect, useMemo, useState } from 'react'
import { downloadReportMarkdown, exportSarifAction, generatePatchAction } from '../../../actions.ts'
import type { CapabilityTier, Finding as ReportFinding } from '../../../domain.ts'
import {
  callerCompatibilityLabels, capabilityTierLabel, checkLabels, dynamicRetestLabels, findingVerificationTier,
  owaspCategoryTitles, owaspStatusLabels, patchStatusLabels, reportEvidenceSource, reportHighlights, reportPlanLabel,
  retestVerdictLabels, verificationTierLabels,
} from '../../../report-summary.ts'
import { capabilityTierMeta } from '../../run-state.ts'
import { Dropdown } from '../controls.tsx'
import { useRun, useRunModel, useVerdict } from '../data.tsx'
import { Disclosure, EmptyState, Tag } from '../display.tsx'
import { fmtDate, fmtN, fmtUsd, host, plural, readRunUrlParam, syncRunUrlParam } from '../format.ts'
import { CovSwatch, SevGlyph, StatusGlyph, TierBars } from '../glyphs.tsx'
import { Icon } from '../icons.tsx'
import { CATS, COV_L, FSTAT_ORDER, normFStatus, PHASE_LABEL, prettyCat, RISKL, SEV, SEV_COL, SEV_LABEL, SEV_ORDER, stLabel } from '../meta.ts'
import type { RiskTier } from '../meta.ts'
import { reducedMotion } from '../motion.tsx'
import { useLinks, useNav, useViewState } from '../nav.tsx'
import { usePaletteCommands } from '../palette.tsx'
import type { InspectorMap } from '../pane.tsx'
import { useToast } from '../toast.tsx'


function download(content: string, filename: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }))
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}

const CHECK_SHORT: Record<string, string> = {
  hsts: 'HSTS', nosniff: 'nosniff', 'referrer-policy': 'Referrer', 'content-security-policy': 'CSP', 'frame-protection': 'Frames',
  'server-disclosure': 'Server', 'cors-policy': 'CORS', 'error-exposure': 'Errors', 'session-cookie': 'Cookies', 'access-policy': 'Access',
}
const checkGlyph = (st: string) => st === 'met' ? 'complete' : st === 'gap' ? 'needs_follow_up' : st === 'inconclusive' ? 'inconclusive' : st === 'untested' ? 'untested' : 'not_applicable'
const REPLAY: Record<string, string> = {
  http_chain: 'HTTP chain replay', dns_takeover: 'DNS takeover replay', tls_audit: 'TLS audit replay', browser_dom: 'Browser DOM replay',
  browser_chain: 'Interactive browser chain', race_burst: 'Race-condition burst', rce_proof: 'Non-destructive execution proof',
  sql_boolean_diff: 'SQL injection differential', ws_chain: 'WebSocket chain replay', upload_probe: 'Upload pipeline check', static_ast_proof: 'Static code analysis',
}

export function ReportView() {
  const { detail } = useRun()
  const nav = useNav()
  const r = detail.run
  const reports = detail.reports
  const latestVersion = useMemo(() => reports.reduce((max, x) => Math.max(max, x.version), 0), [reports])
  const [version, setVersionState] = useViewState<number | null>('report.version', null)
  const setVersion = useCallback((v: number) => {
    setVersionState(v)
    syncRunUrlParam('version', v === latestVersion ? null : String(v))
  }, [setVersionState, latestVersion])
  useEffect(() => {
    const parseVer = (raw: string | null) => {
      if (!raw) return null
      const n = Number(raw)
      return Number.isInteger(n) && reports.some(x => x.version === n) ? n : null
    }
    const fromUrl = parseVer(readRunUrlParam('version'))
    if (fromUrl != null) {
      if (fromUrl !== version) setVersionState(fromUrl)
    } else if (version != null && version !== latestVersion) {
      syncRunUrlParam('version', String(version))
    }
    const onPop = () => {
      setVersionState(parseVer(readRunUrlParam('version')))
    }
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reports.length, latestVersion])
  const rep = reports.find(x => x.version === version) ?? reports.slice().sort((a, b) => b.version - a.version)[0]
  if (!rep) {
    const msg = r.status === 'waiting'
      ? 'The report is assembled after verification. This run hasn’t started.'
      : 'This run is ' + stLabel(r.status).toLowerCase() + ' in ' + (PHASE_LABEL[r.phase] ?? r.phase).toLowerCase() + '. The report is assembled once verification finishes, or as a partial checkpoint when the run pauses at its budget.'
    return <EmptyState icon="report" title="No report yet"
      action={<button type="button" className="btn" onClick={() => nav.setView('overview')}>{r.status === 'waiting' ? 'Review scope' : 'See the provisional summary'}</button>}>{msg}</EmptyState>
  }
  return <ReportDoc key={rep.id} rep={rep} versions={reports.map(x => x.version).sort((a, b) => b - a)} setVersion={setVersion} />
}

type Rep = ReturnType<typeof useRun>['detail']['reports'][number]

function ReportDoc({ rep, versions, setVersion }: { rep: Rep; versions: number[]; setVersion: (v: number) => void }) {
  const { detail, send, pending } = useRun()
  const model = useRunModel()
  const verdict = useVerdict()
  const links = useLinks()
  const toast = useToast()
  const b = rep.body
  const m = b.metrics
  const latest = versions[0] === rep.version
  const [exporting, setExporting] = useState(false)
  const [open, setOpen] = useViewState<Record<string, boolean>>('report.open', {})
  const [allF, setAllF] = useState(false)
  const [allT, setAllT] = useState(false)
  const [patching, setPatching] = useState<string | null>(null)

  const fs = useMemo(() => b.findings.slice().sort((x, y) => (SEV_ORDER[x.severity] - SEV_ORDER[y.severity]) || ((FSTAT_ORDER[x.status] ?? 9) - (FSTAT_ORDER[y.status] ?? 9))), [b.findings])
  const sevC: Record<string, number> = {}
  fs.forEach(f => { sevC[f.severity] = (sevC[f.severity] ?? 0) + 1 })
  const conf = fs.filter(f => normFStatus(f.status) === 'confirmed').length
  const { coverage: covLine, confirmed: runtimeConf, staticVerified, chainConfirmed, priority } = reportHighlights(b)
  const checks = b.selectedChecks?.checks ?? []
  const checkRows = b.coverage.filter(c => (c.checks ?? []).length)
  const threat = b.threatModel?.length ? b.threatModel : (detail.threatModel?.entries ?? [])
  const owasp = b.owaspCoverage?.length ? b.owaspCoverage : detail.coverageEntries
  const gapsOpen = b.openProofGaps?.length ? b.openProofGaps
    : (detail.openProofGaps ?? []).map(g => ({ origin: g.origin, category: g.category, summary: g.summary, proofGapReason: g.proofGapReason || g.summary }))
  const patches = b.patchProposals?.length ? b.patchProposals : (detail.patchProposals ?? [])
  const titleById = new Map(b.findings.map(f => [f.id, f.title]))
  const replayById = new Map(detail.replaySpecs.map(x => [x.id, x]))
  const replayByFinding = new Map(detail.replaySpecs.map(x => [x.findingId, x]))
  const retests = new Map<string, typeof detail.retestRuns>()
  detail.retestRuns.forEach(x => retests.set(x.findingId, [...(retests.get(x.findingId) ?? []), x]))
  const activeRetest = detail.assignments.filter(a => a.phase === 'retest' && (a.status === 'queued' || a.status === 'running')).map(a => a.objective)
  const evidenceTitle = (id: string) => model.evidenceById.get(id)?.title ?? 'Evidence ' + id.slice(0, 8)
  const ev = (id: string) => { if (model.evidenceById.has(id)) links.evidence(id); else toast.show('This evidence isn’t in the run snapshot', { tone: 'error' }) }

  // owasp coverage → host × category matrix
  const covHosts = useMemo(() => {
    const map = new Map<string, Map<string, (typeof owasp)[number]>>()
    owasp.forEach(x => { if (!map.has(x.origin)) map.set(x.origin, new Map()); map.get(x.origin)!.set(x.category, x) })
    return [...map.entries()].sort((a, c) => host(a[0]).localeCompare(host(c[0])))
  }, [owasp])

  const exportMd = async () => {
    setExporting(true)
    try { const x = await downloadReportMarkdown({ data: { runId: detail.run.id, reportId: rep.id } }); download(x.content, x.filename, 'text/markdown; charset=utf-8'); toast.show('Exported Markdown', { icon: 'download', sub: x.filename }) }
    catch { toast.show('Kovo Hunter could not export this report. Try again.', { tone: 'error' }) }
    finally { setExporting(false) }
  }
  const exportSarif = async () => {
    setExporting(true)
    try { const x = await exportSarifAction({ data: { runId: detail.run.id, reportId: rep.id } }); download(x.content, x.filename, 'application/sarif+json; charset=utf-8'); toast.show('Exported SARIF 2.1.0', { icon: 'download', sub: x.filename }) }
    catch { toast.show('Kovo Hunter could not export SARIF 2.1.0 for this report. Try again.', { tone: 'error' }) }
    finally { setExporting(false) }
  }
  const exportText = () => {
    const lines = [
      `Kovo Hunter ${rep.partial ? 'partial report' : 'complete report'} • Version ${rep.version}`, '',
      verdict.hed, ...(covLine ? [covLine] : []), '', b.goal, '',
      reportEvidenceSource(detail.run.sourceMode, b.selectedChecks, b.capabilityTier),
      `Capability tier: ${capabilityTierLabel(b.capabilityTier)}`, `Scope revision ${b.scopeRevision} · Goal revision ${b.goalRevision}`,
      ...(reportPlanLabel(b.selectedChecks) ? [reportPlanLabel(b.selectedChecks)!] : []),
      ...b.scope.map(a => a.origin),
      ...(threat.length ? ['', 'Threat model', ...threat.map(e => `${e.origin} · ${e.riskTier} · [${e.surfaceTags.join(', ')}] · ${e.rationale}`)] : []),
      ...(priority ? ['', 'Fix first', priority.label, ...(priority.finding ? [priority.finding.origin, priority.finding.remediation] : [])] : []),
      '', 'Findings',
      ...fs.flatMap(f => {
        const rt = retests.get(f.id)?.[0]
        return [
          `${f.title} · ${f.origin} · ${f.severity} · ${f.status}${f.findingKind === 'multi_step_chain' ? ' · multi-step chain' : ''}`,
          ...(f.category ? [`Class: ${f.category}${f.cwe ? ` · ${f.cwe}` : ''}`] : []),
          ...(f.confidence ? [`Confidence: ${f.confidence}`] : []),
          ...(f.check ? [`Observed: ${f.check.observed ?? 'Unavailable'}`, `Expected: ${f.check.expected}`] : []),
          f.reason, ...(f.impact ? [`Impact: ${f.impact}`] : []), ...(f.verification ? [`Verification: ${f.verification}`] : []),
          `Remediation: ${f.remediation}`, ...(f.recheck ? [`Check the fix: ${f.recheck}`] : []),
          ...(rt ? [`Latest Verify Fix retest: ${retestVerdictLabels[rt.verdict]} — ${rt.summary}`] : []),
          `Evidence ${f.evidenceIds.join(', ')}`, '',
        ]
      }),
      ...(owasp.length ? ['OWASP / API Top 10 coverage', ...owasp.map(x => `${x.origin} · ${owaspCategoryTitles[x.category as keyof typeof owaspCategoryTitles] ?? x.category} · ${owaspStatusLabels[x.status as keyof typeof owaspStatusLabels] ?? x.status} · ${x.summary}`), ''] : []),
      'Coverage',
      ...b.coverage.flatMap(c => [[c.origin, c.status, c.evidenceId && `Evidence ${c.evidenceId}`].filter(Boolean).join(' · '),
        ...(c.checks ?? []).flatMap(ch => [`  ${ch.title} · ${checkLabels[ch.status]}`, ...(ch.status === 'untested' ? [] : [`    Observed: ${ch.observed ?? 'Unavailable'}`]), `    Expected: ${ch.expected}`, `    ${ch.reason}`])]),
      '', 'Coverage gaps', ...b.gaps,
    ]
    download(lines.join('\n'), `kovo-hunter-report-${rep.version}.txt`, 'text/plain')
    toast.show('Exported plain text', { icon: 'download' })
  }
  const patch = async (f: ReportFinding) => {
    setPatching(f.id)
    try { await generatePatchAction({ data: { runId: detail.run.id, findingId: f.id, repo: f.codeLocations?.[0]?.repo } }); toast.show('Verified patch generated', { icon: 'check', sub: f.title }) }
    catch (e) { toast.show(e instanceof Error ? e.message : 'Kovo Hunter could not generate a verified patch.', { tone: 'error' }) }
    finally { setPatching(null) }
  }

  usePaletteCommands([
    { id: 'rep.md', section: 'Actions', label: 'Export the report as Markdown', icon: 'download', run: () => void exportMd() },
    { id: 'rep.sarif', section: 'Actions', label: 'Export the report as SARIF 2.1.0', icon: 'download', run: () => void exportSarif() },
    { id: 'rep.txt', section: 'Actions', label: 'Export the report as plain text', icon: 'download', run: exportText },
  ])

  const shownF = allF ? fs : fs.slice(0, 40)
  const hed = latest ? verdict.hed : (rep.partial ? 'Partial report' : 'Report') + ' v' + rep.version + ': ' + plural(conf, 'confirmed finding') + ' across ' + plural(b.scope.length, 'host') + '.'

  return <div className="doc"><article className="doc-in" aria-label={rep.partial ? 'Partial report' : 'Complete report'}>
    <div className="rp-top">
      <span className="eyebrow" title={`Tier ${b.capabilityTier}`}><Icon name="report" />Report v{rep.version} · {fmtDate(rep.createdAt)} · {capabilityTierMeta[b.capabilityTier as CapabilityTier]?.short ?? capabilityTierLabel(b.capabilityTier)}</span>
      {rep.partial ? <Tag tone="warn" title="Saved as a checkpoint before verification finished">Partial</Tag> : <Tag>Final</Tag>}
      <span className="tb-sp" />
      {versions.length > 1 && <Dropdown label={<><span className="dim">Version</span><span>v{rep.version}</span></>} menuClassName="small">
        {close => versions.map(v => <button key={v} type="button" role="menuitem" className={'dd-item' + (v === rep.version ? ' on' : '')} onClick={() => { setVersion(v); close() }}>
          Version {v}{v === versions[0] && <span className="ct">latest</span>}</button>)}
      </Dropdown>}
      <Dropdown icon="download" label={exporting ? 'Exporting…' : 'Export'} menuClassName="small" btnClassName="btn dd-btn">
        {close => <>
          <button type="button" role="menuitem" className="dd-item" disabled={exporting} onClick={() => { close(); void exportMd() }}><Icon name="report" />Markdown with evidence</button>
          <button type="button" role="menuitem" className="dd-item" disabled={exporting} onClick={() => { close(); void exportSarif() }}><Icon name="shield" />SARIF 2.1.0</button>
          <button type="button" role="menuitem" className="dd-item" onClick={() => { close(); exportText() }}><Icon name="list" />Plain text</button>
        </>}
      </Dropdown>
    </div>
    <h1>{hed}</h1>
    <p className="sub">{b.goal}</p>
    <div className="metrics num">
      <div><div className="k">Findings</div><div className="v">{fs.length}</div></div>
      <div><div className="k">Confirmed by replay</div><div className="v">{conf}</div></div>
      <div><div className="k">Requests</div><div className="v">{fmtN(m?.requestsUsed)}</div></div>
      <div><div className="k">Verified steps</div><div className="v">{fmtN(m?.chainStepsCompleted)}{m && m.chainStepsUntested > 0 && <span className="rp-vs"> · {m.chainStepsUntested} remaining</span>}</div></div>
      <div><div className="k">Spent</div><div className="v">{fmtUsd(m?.spentUsd)}</div></div>
    </div>
    <p className="rp-meta">
      {plural(b.scope.length, 'approved host')}
      {runtimeConf ? ` · ${plural(runtimeConf, 'runtime-confirmed finding')}` : ''}
      {staticVerified ? ` · ${plural(staticVerified, 'static-verified finding')}` : ''}
      {chainConfirmed ? ` · ${plural(chainConfirmed, 'multi-step chain')}` : ''}
      {covLine ? <> · {covLine}</> : null}
    </p>

    {priority && <div className="banner rp-fix">
      <Icon name="flag" />
      <span className="rp-fixt"><b>Fix first.</b> {priority.label}{priority.finding && <span className="muted"> · {host(priority.finding.origin)} · {priority.finding.remediation}</span>}</span>
      {priority.finding && <button type="button" className="btn ghost" onClick={() => {
        const id = priority.finding!.id
        const i = fs.findIndex(f => f.id === id)
        if (i >= 40) setAllF(true)
        setOpen(o => ({ ...o, [id]: true }))
        requestAnimationFrame(() => document.querySelector(`.rw .rp-fr[data-fid="${CSS.escape(id)}"]`)?.scrollIntoView({ block: 'start', behavior: reducedMotion() ? 'auto' : 'smooth' }))
      }}>Show</button>}
    </div>}

    {fs.length > 0 && <>
      <h2>Severity</h2>
      <div className="sevbar">{SEV.filter(k => sevC[k]).map(k => <i key={k} style={{ flex: sevC[k], background: SEV_COL[k] }} title={`${SEV_LABEL[k]}: ${sevC[k]}`} />)}</div>
      <div className="legend num rp-legend">{SEV.filter(k => sevC[k]).map(k => <span key={k}><SevGlyph sev={k} />{SEV_LABEL[k]} <span className="muted">{sevC[k]}</span></span>)}</div>
    </>}

    <h2>Findings</h2>
    {!fs.length ? <p className="rp-p">No findings were recorded in this version of the report.</p> : <table className="dtable rp-ft"><tbody>
      {shownF.map(f => {
        const isOpen = !!open[f.id]
        const st = normFStatus(f.status)
        const tier = findingVerificationTier(f)
        const rs = (f.replaySpecId ? replayById.get(f.replaySpecId) : undefined) ?? replayByFinding.get(f.id)
        const rk = rs?.spec && typeof rs.spec === 'object' ? REPLAY[String((rs.spec as Record<string, unknown>).kind)] : undefined
        const rt = retests.get(f.id)?.[0]
        const queued = activeRetest.some(o => o.includes(f.id))
        const canRetest = f.status === 'confirmed' && !!(f.replaySpecId || rs)
        const canPatch = (f.status === 'confirmed' || f.status === 'static_verified') && (f.codeLocations?.length ?? 0) > 0
        const live = model.findingById.has(f.id)
        return <Fragment key={f.id}>
          <tr className={'rp-fr' + (isOpen ? ' open' : '')} data-fid={f.id} onClick={() => setOpen(o => ({ ...o, [f.id]: !isOpen }))} aria-expanded={isOpen}>
            <td className="g-c"><SevGlyph sev={f.severity} /></td>
            <td className="g-c" title={stLabel(f.status)}><StatusGlyph status={st} /></td>
            <td>
              <div className="t">{f.title}</div>
              <div className="m mono">{host(f.origin)}{f.cwe ? ' · ' + f.cwe : ''} · {prettyCat(f.category)}{f.findingKind === 'multi_step_chain' ? ' · chain' : ''}</div>
            </td>
            <td className="rp-chev"><Icon name="chev" /></td>
          </tr>
          {isOpen && <tr className="rp-fd"><td /><td colSpan={3}>
            <div className="rp-tags">
              <Tag><SevGlyph sev={f.severity} />{SEV_LABEL[f.severity] ?? f.severity}</Tag>
              <Tag tone={st === 'confirmed' ? 'accent' : undefined}><StatusGlyph status={st} />{stLabel(f.status)}</Tag>
            </div>
            {f.check && <div className="cmp"><div><span>Expected</span><span>{f.check.expected}</span></div><div><span>Observed</span><span className="obs mono">{f.check.observed ?? <span className="muted">Unavailable</span>}</span></div></div>}
            <dl className="rp-dl">
              {(!f.check || f.status !== 'confirmed') && <><dt>{st === 'confirmed' ? 'Observation' : 'Reason'}</dt><dd>{f.reason}</dd></>}
              {f.impact && <><dt>Impact</dt><dd>{f.impact}</dd></>}
              {(f.codeLocations?.length ?? 0) > 0 && <><dt>Code</dt><dd className="mono">{f.codeLocations!.map(l => `${l.repo}/${l.file}:${l.startLine}${l.endLine > l.startLine ? '-' + l.endLine : ''}`).join(', ')}</dd></>}
              <dt>{st === 'confirmed' ? 'Remediation' : 'Follow-up'}</dt><dd>{f.remediation}</dd>
              {f.recheck && <><dt>Check the fix</dt><dd>{f.recheck}</dd></>}
            </dl>
            {(tier || rk || f.confidence || f.confidenceRationale || f.counterevidence || f.runtimeProofGap || f.verification || (f.chainFactIds?.length ?? 0) > 0) && <Disclosure title="Verification details" right={rk ?? (tier ? verificationTierLabels[tier] : undefined)}>
              <dl className="rp-dl" style={{ marginBottom: 0 }}>
                {tier && <><dt>Tier</dt><dd>{verificationTierLabels[tier]}</dd></>}
                {rk && <><dt>Method</dt><dd>{rk}</dd></>}
                {f.confidence && <><dt>Confidence</dt><dd>{f.confidence}{f.confidenceRationale ? ' — ' + f.confidenceRationale : ''}</dd></>}
                {!f.confidence && f.confidenceRationale && <><dt>Confidence</dt><dd>{f.confidenceRationale}</dd></>}
                {f.verification && <><dt>Verification</dt><dd>{f.verification}</dd></>}
                {f.counterevidence && <><dt>Counterevidence</dt><dd>{f.counterevidence}</dd></>}
                {f.runtimeProofGap && <><dt>Proof gap</dt><dd>{f.runtimeProofGap}</dd></>}
                {(f.chainFactIds?.length ?? 0) > 0 && <><dt>Linked facts</dt><dd>{plural(f.chainFactIds!.length, 'recorded fact')}</dd></>}
              </dl>
            </Disclosure>}
            {(rt || canRetest) && <div className="banner rp-rt">
              {rt ? <><StatusGlyph status={rt.verdict === 'fixed' ? 'complete' : rt.verdict === 'reproduced' ? 'failed' : 'inconclusive'} />
                <span><b>{retestVerdictLabels[rt.verdict]}</b> <span className="muted">· {rt.summary} · {fmtDate(rt.createdAt)}</span></span></>
                : <span className="muted">An automated replay check is ready for fix verification.</span>}
              {canRetest && <button type="button" className="btn" disabled={pending > 0 || queued}
                onClick={e => { e.stopPropagation(); void send({ action: 'retest_finding', findingId: f.id }).then(() => toast.show('Verify Fix queued', { icon: 'replay', sub: f.title }), () => {}) }}>
                <Icon name="replay" />{queued ? 'Verifying fix…' : 'Verify Fix'}</button>}
            </div>}
            <div className="rp-acts">
              {f.evidenceIds.map(id => <button key={id} type="button" className="btn ghost" onClick={() => ev(id)}><Icon name="fact" />{evidenceTitle(id)}</button>)}
              {rt?.evidenceIds.map(id => <button key={'rt' + id} type="button" className="btn ghost" onClick={() => ev(id)}><Icon name="replay" />Retest evidence</button>)}
              {canPatch && <button type="button" className="btn ghost" disabled={patching === f.id} onClick={() => void patch(f)}><Icon name="edit" />{patching === f.id ? 'Generating patch…' : 'Generate verified patch'}</button>}
              {live && <button type="button" className="btn ghost" onClick={() => links.finding(f.id)}>Open in Findings<Icon name="arrowR" /></button>}
            </div>
          </td></tr>}
        </Fragment>
      })}
    </tbody></table>}
    {fs.length > 40 && <button type="button" className="linkbtn" onClick={() => setAllF(v => !v)}>{allF ? 'Show the first 40' : `Show all ${fs.length} findings`}</button>}

    {checks.length > 0 && checkRows.length > 0 && <>
      <h2>Baseline checks by origin</h2>
      <table className="matrix rp-mx"><thead><tr><th>Origin</th>{checks.map(c => <th key={c}>{CHECK_SHORT[c] ?? c}</th>)}<th className="rp-evh">Evidence</th></tr></thead>
        <tbody>{checkRows.map(cv => {
          const map = new Map((cv.checks ?? []).map(ch => [ch.id as string, ch]))
          return <tr key={cv.origin}>
            <td className="mono">{host(cv.origin)}</td>
            {checks.map(id => {
              const ch = map.get(id)
              const st = ch?.status ?? 'not-applicable'
              return <td key={id} title={`${ch?.title ?? id}: ${checkLabels[st as keyof typeof checkLabels] ?? st}${ch?.observed ? ' — observed ' + ch.observed : ''}${ch ? '\nExpected: ' + ch.expected + '\n' + ch.reason : ''}`}>
                <span className="g"><StatusGlyph status={checkGlyph(st)} /></span>
              </td>
            })}
            <td className="rp-ev">
              {cv.evidenceId && <button type="button" className="icon-btn" title="Open evidence" onClick={() => ev(cv.evidenceId!)}><Icon name="fact" /></button>}
              {cv.analysisEvidenceId && <button type="button" className="icon-btn" title="Derived evidence" onClick={() => ev(cv.analysisEvidenceId!)}><Icon name="sparkle" /></button>}
              {cv.accessEvidence && <button type="button" className="icon-btn" title={'Access records' + (cv.accessEvidence.recordedAt ? ' · ' + cv.accessEvidence.recordedAt : '')} onClick={() => ev(cv.accessEvidence!.id)}><Icon name="lock" /></button>}
            </td>
          </tr>
        })}</tbody></table>
      <div className="legend rp-legend muted"><span><StatusGlyph status="complete" />Met</span><span><StatusGlyph status="needs_follow_up" />Gap</span><span><StatusGlyph status="inconclusive" />Inconclusive</span><span><StatusGlyph status="not_applicable" />Not applicable</span></div>
    </>}

    {covHosts.length > 0 && <>
      <h2>Coverage by category</h2>
      <table className="matrix rp-mx rp-cov"><thead><tr><th>Origin</th>{CATS.map(c => <th key={c[0]} title={c[1]}>{c[2]}</th>)}</tr></thead>
        <tbody>{covHosts.map(([o, cats]) => <tr key={o}>
          <td className="mono">{host(o)}</td>
          {CATS.map(c => {
            const x = cats.get(c[0])
            const st = x?.status ?? 'untested'
            return <td key={c[0]} title={`${c[1]}: ${COV_L[st]}${x ? '\n' + x.summary : ''}${x?.enforcingControl ? '\nControl: ' + x.enforcingControl : ''}${x?.proofGapReason ? '\nProof gap: ' + x.proofGapReason : ''}`}>
              <button type="button" className="rp-cell" onClick={() => links.cell(o, c[0])}><CovSwatch status={st} size={[16, 12]} /></button>
            </td>
          })}
        </tr>)}</tbody></table>
      <div className="legend rp-legend muted">{(['reported', 'needs_follow_up', 'no_issue_found', 'ruled_out', 'not_applicable'] as const).map(s => <span key={s}><CovSwatch status={s} size={[14, 11]} />{COV_L[s]}</span>)}</div>
    </>}

    {threat.length > 0 && <>
      <h2>Threat model ranking</h2>
      <table className="dtable rp-tm"><tbody>{(allT ? threat : threat.slice(0, 8)).map((e, i) => <tr key={e.origin} onClick={() => links.host(e.origin)} style={{ cursor: 'pointer' }}>
        <td className="rp-rank num">{i + 1}</td>
        <td className="g-c"><TierBars tier={e.riskTier as RiskTier} /></td>
        <td><div className="t"><span className="mono">{host(e.origin)}</span> <span className="muted">· {RISKL[e.riskTier as RiskTier] ?? e.riskTier}</span></div>
          <div className="m">{e.rationale}</div>
          {e.surfaceTags.length > 0 && <div className="rp-tags sm">{e.surfaceTags.slice(0, 6).map(t => <Tag key={t}>{t}</Tag>)}</div>}</td>
      </tr>)}</tbody></table>
      {threat.length > 8 && <button type="button" className="linkbtn" onClick={() => setAllT(v => !v)}>{allT ? 'Show the top 8' : `Show all ${threat.length} ranked hosts`}</button>}
    </>}

    {gapsOpen.length > 0 && <>
      <h2>Open proof gaps</h2>
      <table className="dtable"><tbody>{gapsOpen.map((g, i) => <tr key={g.origin + g.category + i} onClick={() => links.cell(g.origin, g.category)} style={{ cursor: 'pointer' }}>
        <td className="g-c"><StatusGlyph status="needs_follow_up" /></td>
        <td><div className="t">{g.proofGapReason}</div><div className="m"><span className="mono">{host(g.origin)}</span> · {owaspCategoryTitles[g.category as keyof typeof owaspCategoryTitles] ?? prettyCat(g.category)}{g.summary !== g.proofGapReason ? ' · ' + g.summary : ''}</div></td>
      </tr>)}</tbody></table>
    </>}

    {patches.length > 0 && <>
      <h2>Verified patch diffs</h2>
      {patches.map(p => <div key={p.id} className="rp-patch">
        <div className="rp-ph"><b>{titleById.get(p.findingId) ?? p.findingId}</b><span className="muted mono"> · {p.repo}</span></div>
        <div className="rp-tags">
          <Tag tone={p.status === 'withheld' || p.status === 'rejected' ? 'warn' : undefined}>{patchStatusLabels[p.status]}</Tag>
          <Tag>{callerCompatibilityLabels[p.callerCompatibility]}</Tag>
          <Tag>{dynamicRetestLabels[p.dynamicRetestVerdict]}</Tag>
        </div>
        {p.codeLocations.length > 0 && <p className="rp-p mono muted">{p.codeLocations.map(l => `${l.file}:${l.startLine}-${l.endLine}`).join(', ')}</p>}
        {p.reviewNotes && <p className="rp-p">{p.reviewNotes}</p>}
        {p.status === 'approved' && p.diff.trim() ? <pre className="block mono">{p.diff}</pre>
          : p.status === 'withheld' ? <p className="rp-p muted">Diff withheld automatically because the independent patch reviewer flagged caller compatibility or a gate failure.</p> : null}
      </div>)}
    </>}

    {b.gaps.length > 0 && <>
      <h2>Gaps</h2>
      <ul className="gaps">{b.gaps.map((g, i) => <li key={i}>{g}</li>)}</ul>
    </>}

    <h2>Methodology and limitations</h2>
    <p className="rp-p">{reportEvidenceSource(detail.run.sourceMode, b.selectedChecks, b.capabilityTier)}{reportPlanLabel(b.selectedChecks) ? ' ' + reportPlanLabel(b.selectedChecks) : ''}</p>
    <p className="rp-p">Kovo Hunter evaluated only the approved hosts, testing mode ({capabilityTierMeta[b.capabilityTier as CapabilityTier]?.name ?? capabilityTierLabel(b.capabilityTier)}), test accounts, and recorded evidence in this report. AI observations and version matches only create hypotheses; every confirmed finding requires deterministic automated replay verification against a clean control check.</p>
    <p className="rp-p muted">Inconclusive, ruled-out, not-applicable and untested categories remain visible rather than counting as passes. This evidence-led review does not guarantee that no other vulnerability exists.</p>
  </article></div>
}

/** The report has no inspectors of its own: evidence uses the foundation inspector. */
export const reportInspectors: InspectorMap = {}
