// Report: the real report body as a document (F), with every capability of
// the previous report UI: versions (partial vs final), Markdown / SARIF /
// plain-text export, fix-first, findings with expandable detail (evidence,
// Verify Fix retest, verified patch generation), baseline checks by origin,
// coverage by category, threat-model ranking, open proof gaps, patch
// proposals, gaps and methodology. Evidence opens in the inspector.
import { Fragment, useCallback, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { downloadReportMarkdown, exportSarifAction, generatePatchAction } from '../../../actions.ts'
import type { CapabilityTier, Finding as ReportFinding } from '../../../domain.ts'
import { projectRunFindings } from '../../../findings-view.ts'
import type { FindingsViewInputRow } from '../../../findings-view.ts'
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
import { cn, runBtn, runDdItem, runIconBtn, RW } from '../tw.ts'
import {
  canGeneratePatch,
  canVerifyFix,
  CompositeProofDagCard,
  extractCompositeProofSummary,
  PatchProposalReview,
} from './findings-inspector.tsx'
import type { CompositeDagSummary } from './findings-inspector.tsx'

const H2 = 'm-0 mb-2.5 mt-[30px] text-[12px] font-semibold uppercase tracking-[0.02em] text-fg-subtle'
const DL = 'm-0 mb-2.5 grid grid-cols-[112px_minmax(0,1fr)] gap-x-3 gap-y-1 text-[12.5px] leading-[19px] [&_dt]:text-fg-subtle [&_dd]:m-0 [&_dd]:break-words [&_dd]:text-fg-muted'
const DOC_P = 'm-0 mb-2.5 text-[12.5px] leading-5 text-fg-muted'
const TILE_L = 'text-[11.5px] text-fg-subtle'
const TILE_V = 'text-[18px] font-[550] leading-[26px] tracking-[-0.02em] text-fg'
const BL = 'border-b border-line'
const TH_B = `whitespace-nowrap ${BL} px-1 py-1.5 text-[11.5px] font-medium text-fg-subtle`
const TD_B = `whitespace-nowrap ${BL} px-1 py-1`
const TD_C = `whitespace-nowrap ${BL} px-0.5 py-[3px]`
const TD_Y = `${BL} py-[7px] align-top`
const TBL = 'w-full border-collapse'
const LEG = 'inline-flex items-center gap-1.5'
const LEGS = 'mt-2.5 flex flex-wrap gap-3.5 text-[12px] text-fg-subtle'
const ROW_TOP = 'w-[26px] pb-[7px] pt-2.5 align-top'
const ROW_HOVER = 'cursor-pointer hover:bg-hover'
const GHOST_MAX = cn(runBtn({ variant: 'ghost' }), 'max-w-full')
const LINK_NONE = runBtn({ variant: 'link', size: 'none' })
const CALLOUT = 'flex gap-2 rounded-[7px] bg-sunk px-2.5 py-2 text-[12px] leading-[19px] text-fg-muted shadow-[inset_0_0_0_1px_var(--line)]'
const CMP_L = 'min-w-0 border-r border-line bg-sunk px-2.5 py-[7px] text-fg-subtle'
const CMP_R = 'min-w-0 px-2.5 py-[7px]'
const XS_BTN = runIconBtn({ size: 'xs' })
const DD_ITEM = runDdItem()
const DD_MENU = 'top-[30px] w-[200px] p-1.5'
const TD_EXP = `${BL} pb-3.5 pt-0.5 align-top`
const MONO_12 = 'font-mono text-[12px]'
const hOrU = (o?: string | null) => o ? host(o) : 'unknown'
const Tile = ({ l, v, s }: { l: string; v: ReactNode; s?: ReactNode }) => (
  <div className="py-2.5"><div className={TILE_L}>{l}</div><div className={TILE_V}>{v}{s && <span className="text-[12px] font-normal tracking-normal text-fg-subtle">{s}</span>}</div></div>
)
const Dl = ({ k, v, mono }: { k: string; v: ReactNode; mono?: boolean }) =>
  v ? <><dt>{k}</dt><dd className={mono ? MONO_12 : undefined}>{v}</dd></> : null

/** Safely coerce potentially null/object/malformed report fields into text so React never throws. */
export function safeReportText(value: unknown, fallback = ''): string {
  if (value == null) return fallback
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  try { return JSON.stringify(value) } catch { return fallback || String(value) }
}

/** Normalize optional or malformed report body collections before rendering or exporting. */
export function normalizeReportBody(rawBody: Partial<Rep['body']> | null | undefined) {
  const b = (rawBody && typeof rawBody === 'object' ? rawBody : {}) as Partial<Rep['body']>
  const arr = <T,>(x: unknown): T[] => Array.isArray(x) ? (x as T[]) : []
  const strs = (x: unknown) => arr(x).filter((s): s is string => typeof s === 'string')
  const findings = arr<ReportFinding>(b.findings)
    .filter((f): f is ReportFinding => Boolean(f && typeof f === 'object' && !f.supersededByFindingId))
    .map((f, idx) => ({
      ...f,
      id: safeReportText(f.id, `finding-${idx}`),
      title: safeReportText(f.title, 'Untitled finding'),
      origin: safeReportText(f.origin),
      severity: f.severity ?? 'informational',
      status: f.status ?? 'pending',
      category: safeReportText(f.category),
      reason: safeReportText(f.reason),
      remediation: safeReportText(f.remediation),
      evidenceIds: strs(f.evidenceIds),
      codeLocations: Array.isArray(f.codeLocations) ? f.codeLocations.filter(Boolean) : undefined,
      chainFactIds: Array.isArray(f.chainFactIds) ? strs(f.chainFactIds) : undefined,
    }))
  return {
    ...b,
    goal: safeReportText(b.goal),
    capabilityTier: b.capabilityTier ?? 1,
    scopeRevision: b.scopeRevision ?? 0,
    goalRevision: b.goalRevision ?? 0,
    findings,
    scope: arr<Rep['body']['scope'][number]>(b.scope).filter(a => Boolean(a && typeof a === 'object')),
    coverage: arr<Rep['body']['coverage'][number]>(b.coverage).filter(c => Boolean(c && typeof c === 'object')),
    gaps: arr(b.gaps).map(g => safeReportText(g)).filter(Boolean),
  } as Rep['body']
}

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
  const reports = Array.isArray(detail.reports) ? detail.reports : []
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
      action={<button type="button" className={runBtn()} onClick={() => nav.setView('overview')}>{r.status === 'waiting' ? 'Review scope' : 'See the provisional summary'}</button>}>{msg}</EmptyState>
  }
  return <ReportDoc key={rep.id} rep={rep} versions={reports.map(x => x.version).sort((a, b) => b - a)} setVersion={setVersion} />
}

type Rep = ReturnType<typeof useRun>['detail']['reports'][number]

export function ReportDoc({ rep, versions, setVersion }: { rep: Rep; versions: number[]; setVersion: (v: number) => void }) {
  const { detail, send, pending, refresh } = useRun()
  const model = useRunModel()
  const verdict = useVerdict()
  const links = useLinks()
  const toast = useToast()
  const b = useMemo(() => normalizeReportBody(rep?.body), [rep?.body])
  const m = b.metrics
  const latest = versions[0] === rep.version
  const [exporting, setExporting] = useState(false)
  const [open, setOpen] = useViewState<Record<string, boolean>>('report.open', {})
  const [allF, setAllF] = useState(false)
  const [allT, setAllT] = useState(false)
  const [expandedEvidence, setExpandedEvidence] = useState<Record<string, boolean>>({})
  const [expandedTags, setExpandedTags] = useState<Record<string, boolean>>({})
  const [patching, setPatching] = useState<string | null>(null)

  const hydratedFindings = useMemo(() => {
    if (!latest) return b.findings as (ReportFinding & FindingsViewInputRow)[]
    return b.findings.map(f => {
      const live = model.findingById.get(f.id) as (ReportFinding & FindingsViewInputRow) | undefined
      return live?.operatorTriage ? { ...f, operatorTriage: live.operatorTriage } : f
    }) as (ReportFinding & FindingsViewInputRow)[]
  }, [b.findings, latest, model.findingById])
  const taintedFactIds = useMemo(
    () => (latest && Array.isArray(detail.facts) ? detail.facts.filter(f => f.tainted).map(f => f.id) : []),
    [latest, detail.facts],
  )
  const view = useMemo(
    () => projectRunFindings(hydratedFindings, {
      approvedOrigins: b.scope.map(a => a.origin),
      ...(taintedFactIds.length ? { taintedFactIds } : {}),
    }),
    [hydratedFindings, b.scope, taintedFactIds],
  )
  const projectedRows = useMemo(
    () => [...view.confirmed, ...view.advisories, ...view.unverified].sort(
      (x, y) => ((SEV_ORDER[x.effectiveSeverity] ?? 9) - (SEV_ORDER[y.effectiveSeverity] ?? 9))
        || ((FSTAT_ORDER[x.finding.status] ?? 9) - (FSTAT_ORDER[y.finding.status] ?? 9)),
    ),
    [view],
  )
  const fs = useMemo(() => projectedRows.map(x => x.finding), [projectedRows])
  const sevC: Record<string, number> = {}
  projectedRows.forEach(x => { sevC[x.effectiveSeverity] = (sevC[x.effectiveSeverity] ?? 0) + 1 })
  const conf = view.counts.confirmed
  const staticCount = view.counts.advisories
  const reportableCount = view.counts.reportable
  const suppressedItems = view.suppressed
  const { coverage: covLine, confirmed: runtimeConf, staticVerified, chainConfirmed, priority } = reportHighlights(
    { ...b, findings: hydratedFindings },
    taintedFactIds.length ? { taintedFactIds } : undefined,
  )
  const checks = Array.isArray(b.selectedChecks?.checks) ? b.selectedChecks!.checks : []
  const checkRows = b.coverage.filter(c => Array.isArray(c.checks) && c.checks.length > 0)
  const threat = Array.isArray(b.threatModel) && b.threatModel.length
    ? b.threatModel.filter(Boolean)
    : (Array.isArray(detail.threatModel?.entries) ? detail.threatModel!.entries.filter(Boolean) : [])
  const owasp = Array.isArray(b.owaspCoverage) && b.owaspCoverage.length
    ? b.owaspCoverage.filter(Boolean)
    : (Array.isArray(detail.coverageEntries) ? detail.coverageEntries.filter(Boolean) : [])
  const gapsOpen = Array.isArray(b.openProofGaps)
    ? b.openProofGaps.filter(Boolean)
    : latest && Array.isArray(detail.openProofGaps)
      ? detail.openProofGaps.filter(Boolean).map(g => ({
          origin: safeReportText(g.origin),
          category: safeReportText(g.category),
          summary: safeReportText(g.summary),
          proofGapReason: safeReportText(g.proofGapReason || g.summary),
        }))
      : []
  // Merge live patchProposals with snapshot patches (preferring live records) so newly generated patches appear immediately after refresh().
  const patches = useMemo(() => {
    const byId = new Map<string, (typeof detail.patchProposals)[number]>()
    for (const p of Array.isArray(b.patchProposals) ? b.patchProposals : []) {
      if (p && typeof p === 'object' && p.id) byId.set(p.id, p as (typeof detail.patchProposals)[number])
    }
    for (const p of Array.isArray(detail.patchProposals) ? detail.patchProposals : []) {
      if (p && typeof p === 'object' && p.id) byId.set(p.id, p)
    }
    return [...byId.values()]
  }, [b.patchProposals, detail.patchProposals])
  const titleById = new Map(b.findings.map(f => [f.id, f.title]))
  const replaySpecs = Array.isArray(detail.replaySpecs) ? detail.replaySpecs : []
  const replayById = new Map(replaySpecs.map(x => [x.id, x]))
  const replayByFinding = new Map(replaySpecs.map(x => [x.findingId, x]))
  const retests = new Map<string, typeof detail.retestRuns>()
  for (const x of Array.isArray(detail.retestRuns) ? detail.retestRuns : []) {
    if (!x) continue
    retests.set(x.findingId, [...(retests.get(x.findingId) ?? []), x])
  }
  const compositeByFinding = useMemo(() => {
    const map = new Map<string, CompositeDagSummary>()
    for (const f of fs) {
      const rs = (f.replaySpecId ? replayById.get(f.replaySpecId) : undefined) ?? replayByFinding.get(f.id)
      const dag = extractCompositeProofSummary(rs, retests.get(f.id) ?? [])
      if (dag) map.set(f.id, dag)
    }
    return map
  }, [fs, detail.replaySpecs, detail.retestRuns])
  const compositeEntries = useMemo(() => {
    const seen = new Set<string>()
    const out: Array<{ findingId: string; title: string; summary: CompositeDagSummary }> = []
    for (const f of fs) {
      const summary = compositeByFinding.get(f.id)
      if (!summary || seen.has(summary.chainId)) continue
      seen.add(summary.chainId)
      out.push({ findingId: f.id, title: f.title, summary })
    }
    return out
  }, [fs, compositeByFinding])
  const activeRetest = (Array.isArray(detail.assignments) ? detail.assignments : [])
    .filter(a => a && a.phase === 'retest' && (a.status === 'queued' || a.status === 'running'))
    .map(a => safeReportText(a.objective))
  const evidenceTitle = (id: string) => model.evidenceById.get(id)?.title ?? 'Evidence ' + id.slice(0, 8)
  const ev = (id: string) => { if (model.evidenceById.has(id)) links.evidence(id); else toast.show('This evidence isn’t in the run snapshot', { tone: 'error' }) }
  const modeMeta = capabilityTierMeta[b.capabilityTier as CapabilityTier]
  const modeName = modeMeta?.name ?? capabilityTierLabel(b.capabilityTier)

  // owasp coverage → host × category matrix
  const covHosts = useMemo(() => {
    const map = new Map<string, Map<string, (typeof owasp)[number]>>()
    owasp.forEach(x => {
      if (!x || !x.origin) return
      if (!map.has(x.origin)) map.set(x.origin, new Map())
      map.get(x.origin)!.set(x.category, x)
    })
    return [...map.entries()].sort((a, c) => host(a[0]).localeCompare(host(c[0])))
  }, [owasp])

  const runExport = async (fn: (opts: { data: { runId: string; reportId: string } }) => Promise<{ content: string; filename: string }>, mime: string, label: string, errMsg: string) => {
    setExporting(true)
    try { const x = await fn({ data: { runId: detail.run.id, reportId: rep.id } }); download(x.content, x.filename, mime); toast.show('Exported ' + label, { icon: 'download', sub: x.filename }) }
    catch { toast.show(errMsg, { tone: 'error' }) }
    finally { setExporting(false) }
  }
  const exportMd = () => runExport(downloadReportMarkdown, 'text/markdown; charset=utf-8', 'Markdown', 'Kovo Hunter could not export this report. Try again.')
  const exportSarif = () => runExport(exportSarifAction, 'application/sarif+json; charset=utf-8', 'SARIF 2.1.0', 'Kovo Hunter could not export SARIF 2.1.0 for this report. Try again.')
  const exportText = () => {
    const t = safeReportText
    const lines = [
      `Kovo Hunter ${rep.partial ? 'partial' : 'complete'} report • Version ${rep.version}`, '',
      verdict.hed, ...(covLine ? [covLine] : []), '', b.goal, '',
      reportEvidenceSource(detail.run.sourceMode, b.selectedChecks, b.capabilityTier),
      `Testing mode: ${modeName}`, `Scope revision ${b.scopeRevision} · Goal revision ${b.goalRevision}`,
      ...(reportPlanLabel(b.selectedChecks) ? [reportPlanLabel(b.selectedChecks)!] : []),
      ...b.scope.map(a => t(a.origin)),
      ...(threat.length ? ['', 'Threat model', ...threat.map(e => `${t(e.origin)} · ${t(e.riskTier)} · [${(Array.isArray(e.surfaceTags) ? e.surfaceTags : []).join(', ')}] · ${t(e.rationale)}`)] : []),
      ...(priority ? ['', 'Fix first', priority.label, ...(priority.finding ? [t(priority.finding.origin), t(priority.finding.remediation)] : [])] : []),
      '', 'Findings',
      ...projectedRows.flatMap(({ finding: f, effectiveSeverity: sev }) => {
        const rt = retests.get(f.id)?.[0]
        return [
          `${f.title} · ${f.origin} · ${sev} · ${f.status}${f.findingKind === 'multi_step_chain' ? ' · multi-step chain' : ''}`,
          ...(f.category ? [`Class: ${f.category}${f.cwe ? ` · ${t(f.cwe)}` : ''}`] : []),
          ...(f.confidence ? [`Confidence: ${t(f.confidence)}`] : []),
          ...(f.check ? [`Observed: ${t(f.check.observed, 'Unavailable')}`, `Expected: ${t(f.check.expected)}`] : []),
          f.reason, ...(f.impact ? [`Impact: ${t(f.impact)}`] : []), ...(f.verification ? [`Verification: ${t(f.verification)}`] : []),
          `Remediation: ${f.remediation}`, ...(f.recheck ? [`Check the fix: ${t(f.recheck)}`] : []),
          ...(rt ? [`Latest Verify Fix retest: ${retestVerdictLabels[rt.verdict] ?? rt.verdict} — ${t(rt.summary)}`] : []),
          `Evidence ${f.evidenceIds.join(', ')}`, '',
        ]
      }),
      ...(owasp.length ? ['OWASP / API Top 10 coverage', ...owasp.map(x => `${t(x.origin)} · ${owaspCategoryTitles[x.category as keyof typeof owaspCategoryTitles] ?? x.category} · ${owaspStatusLabels[x.status as keyof typeof owaspStatusLabels] ?? x.status} · ${t(x.summary)}`), ''] : []),
      'Coverage',
      ...b.coverage.flatMap(c => [[t(c.origin), t(c.status), c.evidenceId && `Evidence ${c.evidenceId}`].filter(Boolean).join(' · '),
        ...(Array.isArray(c.checks) ? c.checks : []).flatMap(ch => [`  ${t(ch.title)} · ${checkLabels[ch.status] ?? ch.status}`, ...(ch.status === 'untested' ? [] : [`    Observed: ${t(ch.observed, 'Unavailable')}`]), `    Expected: ${t(ch.expected)}`, `    ${t(ch.reason)}`])]),
      '', 'Coverage gaps', ...b.gaps,
    ]
    download(lines.join('\n'), `kovo-hunter-report-${rep.version}.txt`, 'text/plain')
    toast.show('Exported plain text', { icon: 'download' })
  }
  const patch = async (f: ReportFinding) => {
    setPatching(f.id)
    try {
      await generatePatchAction({ data: { runId: detail.run.id, findingId: f.id, repo: f.codeLocations?.[0]?.repo } })
      await refresh()
      toast.show('Verified patch generated', { icon: 'check', sub: f.title })
    } catch (e) {
      toast.show(e instanceof Error ? e.message : 'Kovo Hunter could not generate a verified patch.', { tone: 'error' })
    } finally {
      setPatching(null)
    }
  }

  usePaletteCommands([
    { id: 'rep.md', section: 'Actions', label: 'Export the report as Markdown', icon: 'download', run: () => void exportMd() },
    { id: 'rep.sarif', section: 'Actions', label: 'Export the report as SARIF 2.1.0', icon: 'download', run: () => void exportSarif() },
    { id: 'rep.txt', section: 'Actions', label: 'Export the report as plain text', icon: 'download', run: exportText },
  ])

  const shownF = allF ? projectedRows : projectedRows.slice(0, 40)
  const hed = latest ? verdict.hed : (rep.partial ? 'Partial report' : 'Report') + ' v' + rep.version + ': ' + plural(conf, 'confirmed finding') + ' across ' + plural(b.scope.length, 'host') + '.'

  return <div className="min-h-0 flex-1 overflow-auto"><article className="mx-auto max-w-[780px] px-9 pb-20 pt-[30px]" aria-label={rep.partial ? 'Partial report' : 'Complete report'}>
    <div className="flex min-h-7 items-center gap-2">
      <span className="inline-flex items-center gap-2 text-[12px] font-medium text-fg-muted" title={modeMeta?.name}><Icon name="report" />Report v{rep.version} · {fmtDate(rep.createdAt)} · {modeMeta?.short ?? modeName}</span>
      {rep.partial ? <Tag tone="warn" title="Saved as a checkpoint before verification finished">Partial</Tag> : <Tag>Final</Tag>}
      <span className="min-w-2 flex-1" />
      {versions.length > 1 && <Dropdown label={<><span className="text-fg-subtle">Version</span><span>v{rep.version}</span></>} menuClassName={DD_MENU}>
        {close => versions.map(v => <button key={v} type="button" role="menuitem" className={runDdItem({ active: v === rep.version })} onClick={() => { setVersion(v); close() }}>
          Version {v}{v === versions[0] && <span className="ml-auto text-fg-subtle">latest</span>}</button>)}
      </Dropdown>}
      <Dropdown icon="download" label={exporting ? 'Exporting…' : 'Export'} menuClassName={DD_MENU} btnClassName={runBtn()}>
        {close => <>
          <button type="button" role="menuitem" className={DD_ITEM} disabled={exporting} onClick={() => { close(); void exportMd() }}><Icon name="report" className="text-fg-subtle" />Markdown with evidence</button>
          <button type="button" role="menuitem" className={DD_ITEM} disabled={exporting} onClick={() => { close(); void exportSarif() }}><Icon name="shield" className="text-fg-subtle" />SARIF 2.1.0</button>
          <button type="button" role="menuitem" className={DD_ITEM} onClick={() => { close(); exportText() }}><Icon name="list" className="text-fg-subtle" />Plain text</button>
        </>}
      </Dropdown>
    </div>
    <h1 className="m-0 mb-1.5 mt-2 text-[22px] font-semibold leading-[29px] tracking-[-0.02em] text-fg">{hed}</h1>
    <p className="m-0 mb-[22px] line-clamp-3 text-[13px] leading-5 text-fg-muted">{b.goal}</p>
    <div className={cn('grid border-y border-line tabular-nums', staticCount > 0 ? 'grid-cols-6' : 'grid-cols-5')}>
      <Tile l="Findings" v={reportableCount} s={fs.length > reportableCount ? ` · ${fs.length} total` : undefined} />
      <Tile l="Confirmed by replay" v={conf} />
      {staticCount > 0 && <Tile l="Static advisories" v={staticCount} />}
      <Tile l="Requests" v={fmtN(m?.requestsUsed)} />
      <Tile l="Verified steps" v={fmtN(m?.chainStepsCompleted)} s={m && m.chainStepsUntested > 0 ? ` · ${m.chainStepsUntested} remaining` : undefined} />
      <Tile l="Spent" v={fmtUsd(m?.spentUsd)} />
    </div>
    <p className="m-0 mt-2.5 text-[12px] leading-[19px] text-fg-subtle">
      {[
        plural(b.scope.length, 'approved host'),
        runtimeConf ? plural(runtimeConf, 'runtime-confirmed finding') : '',
        staticVerified ? plural(staticVerified, 'static-verified finding') : '',
        chainConfirmed ? plural(chainConfirmed, 'multi-step chain') : '',
        suppressedItems.length ? plural(suppressedItems.length, 'suppressed finding') : '',
        covLine,
      ].filter(Boolean).join(' · ')}
    </p>

    {priority && <div className={cn(CALLOUT, 'mb-3 mt-4 items-start')}>
      <Icon name="flag" className="mt-0.5 flex-none text-fg-muted" />
      <span className="line-clamp-2 min-w-0 flex-1"><b className="font-medium text-fg">Fix first.</b> {priority.label}{priority.finding && <span className="text-fg-subtle"> · {priority.finding.origin ? host(priority.finding.origin) : 'unknown'} · {safeReportText(priority.finding.remediation)}</span>}</span>
      {priority.finding && <button type="button" className={cn(runBtn({ variant: 'ghost' }), '-mt-[3px] ml-auto')} onClick={() => {
        const id = priority.finding!.id
        const i = fs.findIndex(f => f.id === id)
        if (i >= 40) setAllF(true)
        setOpen(o => ({ ...o, [id]: true }))
        requestAnimationFrame(() => document.querySelector(`[data-fid="${CSS.escape(id)}"]`)?.scrollIntoView({ block: 'start', behavior: reducedMotion() ? 'auto' : 'smooth' }))
      }}>Show</button>}
    </div>}

    {fs.length > 0 && <>
      <h2 className={H2}>Severity</h2>
      <div className="mb-2.5 mt-1.5 flex h-2 gap-0.5 overflow-hidden rounded-lg">{SEV.filter(k => sevC[k]).map(k => <i key={k} className="block h-full" style={{ flex: sevC[k], background: SEV_COL[k] }} title={`${SEV_LABEL[k]}: ${sevC[k]}`} />)}</div>
      <div className="flex flex-wrap gap-3.5 text-[12px] tabular-nums text-fg-muted">{SEV.filter(k => sevC[k]).map(k => <span key={k} className={LEG}><SevGlyph sev={k} />{SEV_LABEL[k]} <span className="text-fg-subtle">{sevC[k]}</span></span>)}</div>
    </>}

    <h2 className={H2}>Findings</h2>
    {!fs.length ? <p className={DOC_P}>No findings were recorded in this version of the report.</p> : <table className="w-full table-fixed border-collapse"><tbody>
      {shownF.map(item => {
        const f = item.finding
        const sev = item.effectiveSeverity
        const isOpen = !!open[f.id]
        const st = normFStatus(f.status)
        const tier = findingVerificationTier(f)
        const rs = (f.replaySpecId ? replayById.get(f.replaySpecId) : undefined) ?? replayByFinding.get(f.id)
        const rk = rs?.spec && typeof rs.spec === 'object' ? REPLAY[String((rs.spec as Record<string, unknown>).kind)] : undefined
        const rt = retests.get(f.id)?.[0]
        const queued = activeRetest.some(o => o.includes(f.id))
        const canRetest = canVerifyFix(f)
        const canPatch = canGeneratePatch(f)
        const live = model.findingById.has(f.id)
        const rowBorder = isOpen ? 'border-b border-transparent' : 'border-b border-line'
        const checkObserved = f.check ? safeReportText(f.check.observed) : ''
        const checkExpected = f.check ? safeReportText(f.check.expected) : ''
        const showReason = Boolean(f.reason) && (!f.check || f.status !== 'confirmed' || f.reason.trim() !== checkObserved.trim())
        const codeLocations = Array.isArray(f.codeLocations) ? f.codeLocations.filter(Boolean) : []
        const rtEvidenceIds = Array.isArray(rt?.evidenceIds) ? rt.evidenceIds.filter((x): x is string => typeof x === 'string') : []
        return <Fragment key={f.id}>
          <tr className={cn('scroll-mt-4', ROW_HOVER)} data-fid={f.id} onClick={() => setOpen(o => ({ ...o, [f.id]: !isOpen }))} aria-expanded={isOpen}>
            <td className={cn(ROW_TOP, rowBorder)}><SevGlyph sev={sev} /></td>
            <td className={cn(ROW_TOP, rowBorder)} title={stLabel(f.status)}><StatusGlyph status={st} /></td>
            <td className={cn('py-[7px] align-top [overflow-wrap:anywhere]', rowBorder)}>
              <div className="text-fg">{f.title}</div>
              <div className={cn(MONO_12, 'text-fg-subtle')}>{hOrU(f.origin)}{f.cwe ? ' · ' + safeReportText(f.cwe) : ''}{f.category ? ' · ' + prettyCat(f.category) : ''}{f.findingKind === 'multi_step_chain' ? ' · chain' : ''}</div>
            </td>
            <td className={cn('w-6 pb-[7px] pt-2.5 text-right align-top text-fg-faint', rowBorder)}>
              <Icon name="chev" className={cn('ml-auto transition-transform duration-[var(--d2)] ease-kovo', isOpen ? 'rotate-0 text-fg-muted' : '-rotate-90')} />
            </td>
          </tr>
          {isOpen && <tr>
            <td className={TD_EXP} />
            <td colSpan={3} className={cn(TD_EXP, '[overflow-wrap:anywhere]')}>
              <div className="mb-2.5 mt-0.5 flex flex-wrap gap-[5px]">
                <Tag><SevGlyph sev={sev} />{SEV_LABEL[sev] ?? safeReportText(sev)}</Tag>
                <Tag tone={st === 'confirmed' ? 'accent' : st === 'static_verified' ? 'solid' : undefined}><StatusGlyph status={st} />{stLabel(st)}</Tag>
              </div>
              {f.check && <div className={RW.cmp}>
                <div className="grid grid-cols-[72px_1fr] text-[12px] leading-[18px]">
                  <span className={CMP_L}>Expected</span>
                  <span className={cn(CMP_R, 'text-fg-muted')}>{checkExpected || <span className="text-fg-subtle">Unavailable</span>}</span>
                </div>
                <div className="grid grid-cols-[72px_1fr] border-t border-line text-[12px] leading-[18px]">
                  <span className={CMP_L}>Observed</span>
                  <span className={cn(CMP_R, 'break-all font-mono text-[12px] text-fg')}>{f.check.observed != null ? checkObserved : <span className="text-fg-subtle">Unavailable</span>}</span>
                </div>
              </div>}
              <dl className={DL}>
                {showReason && <Dl k={st === 'confirmed' ? 'Observation' : 'Reason'} v={f.reason} />}
                <Dl k="Impact" v={safeReportText(f.impact)} />
                <Dl k="Code" mono v={codeLocations.length ? codeLocations.map(l => `${safeReportText(l.repo)}/${safeReportText(l.file)}:${l.startLine ?? 0}${(l.endLine ?? 0) > (l.startLine ?? 0) ? '-' + l.endLine : ''}`).join(', ') : ''} />
                <Dl k={st === 'confirmed' || st === 'static_verified' ? 'Remediation' : 'Follow-up'} v={f.remediation} />
                <Dl k="Check the fix" v={safeReportText(f.recheck)} />
              </dl>
              {compositeByFinding.get(f.id) && <CompositeProofDagCard summary={compositeByFinding.get(f.id)!} compact />}
              {(tier || rk || f.confidence || f.confidenceRationale || f.counterevidence || f.runtimeProofGap || f.verification || (f.chainFactIds?.length ?? 0) > 0) && <Disclosure title="Verification details" right={rk ?? (tier ? verificationTierLabels[tier] : undefined)}>
                <dl className={cn(DL, 'mb-0')}>
                  <Dl k="Verification" v={tier ? verificationTierLabels[tier] : ''} />
                  <Dl k="Method" v={rk} />
                  <Dl k="Confidence" v={[safeReportText(f.confidence), safeReportText(f.confidenceRationale)].filter(Boolean).join(' — ')} />
                  <Dl k="Replay notes" v={safeReportText(f.verification)} />
                  <Dl k="Counterevidence" v={safeReportText(f.counterevidence)} />
                  <Dl k="Proof gap" v={safeReportText(f.runtimeProofGap)} />
                  <Dl k="Linked facts" v={(f.chainFactIds?.length ?? 0) > 0 ? plural(f.chainFactIds!.length, 'recorded fact') : ''} />
                </dl>
              </Disclosure>}
              {(rt || canRetest) && <div className={cn(CALLOUT, 'mb-2.5 items-center')}>
                {rt ? <><StatusGlyph status={rt.verdict === 'fixed' ? 'complete' : rt.verdict === 'reproduced' ? 'failed' : 'inconclusive'} />
                  <span><b className="font-medium text-fg">{retestVerdictLabels[rt.verdict] ?? safeReportText(rt.verdict)}</b> <span className="text-fg-subtle">· {safeReportText(rt.summary)} · {fmtDate(rt.createdAt)}</span></span></>
                  : <span className="text-fg-subtle">An automated replay check is ready for fix verification.</span>}
                {canRetest && <button type="button" className={cn(runBtn(), 'ml-auto')} disabled={pending > 0 || queued}
                  onClick={e => { e.stopPropagation(); void send({ action: 'retest_finding', findingId: f.id }).then(() => toast.show('Verify Fix queued', { icon: 'replay', sub: f.title }), () => {}) }}>
                  <Icon name="replay" />{queued ? 'Verifying fix…' : 'Verify Fix'}</button>}
              </div>}
              <div className="-ml-[9px] flex flex-wrap gap-0.5">
                {(expandedEvidence[f.id] ? f.evidenceIds : f.evidenceIds.slice(0, 8)).map(id => <button key={id} type="button" className={GHOST_MAX} onClick={() => ev(id)}><Icon name="fact" /><span className="truncate">{evidenceTitle(id)}</span></button>)}
                {f.evidenceIds.length > 8 && (
                  <button
                    type="button"
                    className={cn(LINK_NONE, 'px-2 text-[12px]')}
                    onClick={() => setExpandedEvidence(prev => ({ ...prev, [f.id]: !prev[f.id] }))}
                  >
                    {expandedEvidence[f.id] ? 'Show first 8 items' : `Show all ${f.evidenceIds.length} items`}
                  </button>
                )}
                {rtEvidenceIds.map(id => <button key={'rt' + id} type="button" className={GHOST_MAX} onClick={() => ev(id)}><Icon name="replay" />Retest evidence</button>)}
                {canPatch && <button type="button" className={GHOST_MAX} disabled={patching === f.id} onClick={() => void patch(f)}><Icon name="edit" />{patching === f.id ? 'Generating patch…' : 'Generate verified patch'}</button>}
                {live && <button type="button" className={GHOST_MAX} onClick={() => links.finding(f.id)}>Open in Findings<Icon name="arrowR" /></button>}
              </div>
            </td>
          </tr>}
        </Fragment>
      })}
    </tbody></table>}
    {fs.length > 40 && <button type="button" className={cn(LINK_NONE, 'mt-1')} onClick={() => setAllF(v => !v)}>{allF ? 'Show the first 40' : `Show all ${fs.length} findings`}</button>}
    {suppressedItems.length > 0 && <div className="mt-3"><Disclosure title={`Suppressed by operator triage (${suppressedItems.length})`}>
      <ul className="m-0 list-none p-0 text-[12px] text-fg-muted">{suppressedItems.map(s => <li key={s.finding.id} className="border-b border-line py-1.5">
        <span className="text-fg">{s.finding.title}</span> · <span className="font-mono text-fg-subtle">{s.finding.origin ? host(s.finding.origin) : 'unknown'}</span> · <Tag tone={s.suppressedBy === 'false_positive' ? 'warn' : 'solid'}>{s.suppressedBy === 'false_positive' ? 'False positive' : 'Accepted risk'}</Tag>
      </li>)}</ul>
    </Disclosure></div>}

    {compositeEntries.length > 0 && <>
      <h2 className={H2}>Multi-hop causal chains</h2>
      {compositeEntries.map(entry => (
        <CompositeProofDagCard key={entry.summary.chainId} summary={entry.summary} title={entry.title} />
      ))}
    </>}

    {checks.length > 0 && checkRows.length > 0 && <>
      <h2 className={H2}>Baseline checks by origin</h2>
      <table className={TBL}>
        <thead><tr>
          <th className={cn(TH_B, 'text-left')}>Origin</th>
          {checks.map(c => <th key={c} className={cn(TH_B, 'text-center')}>{CHECK_SHORT[c] ?? c}</th>)}
          <th className={cn(TH_B, 'text-right')}>Evidence</th>
        </tr></thead>
        <tbody>{checkRows.map(cv => {
          const map = new Map((Array.isArray(cv.checks) ? cv.checks : []).filter(Boolean).map(ch => [ch.id as string, ch]))
          return <tr key={cv.origin}>
            <td className={cn(TD_B, 'max-w-[220px] truncate text-left font-mono text-[12px] text-fg-muted')}>{cv.origin ? host(cv.origin) : 'unknown'}</td>
            {checks.map(id => {
              const ch = map.get(id)
              const st = ch?.status ?? 'not-applicable'
              return <td key={id} className={cn(TD_B, 'text-center')} title={`${safeReportText(ch?.title, id)}: ${checkLabels[st as keyof typeof checkLabels] ?? st}${ch?.observed != null ? ' — observed ' + safeReportText(ch.observed) : ''}${ch ? '\nExpected: ' + safeReportText(ch.expected) + '\n' + safeReportText(ch.reason) : ''}`}>
                <span className="mx-auto inline-flex size-3.5 items-center justify-center"><StatusGlyph status={checkGlyph(st)} /></span>
              </td>
            })}
            <td className={cn(TD_B, 'text-right')}>
              {cv.evidenceId && <button type="button" className={XS_BTN} title="Open evidence" onClick={() => ev(cv.evidenceId!)}><Icon name="fact" /></button>}
              {cv.analysisEvidenceId && <button type="button" className={XS_BTN} title="Derived evidence" onClick={() => ev(cv.analysisEvidenceId!)}><Icon name="sparkle" /></button>}
              {cv.accessEvidence && <button type="button" className={XS_BTN} title={'Access records' + (cv.accessEvidence.recordedAt ? ' · ' + cv.accessEvidence.recordedAt : '')} onClick={() => ev(cv.accessEvidence!.id)}><Icon name="lock" /></button>}
            </td>
          </tr>
        })}</tbody>
      </table>
      <div className={LEGS}>{([['complete', 'Met'], ['needs_follow_up', 'Gap'], ['inconclusive', 'Inconclusive'], ['not_applicable', 'Not applicable']] as const).map(([s, l]) => <span key={s} className={LEG}><StatusGlyph status={s} />{l}</span>)}</div>
    </>}

    {covHosts.length > 0 && <>
      <h2 className={H2}>Coverage by category</h2>
      <table className={TBL}>
        <thead><tr>
          <th className={cn(TH_B, 'text-left')}>Origin</th>
          {CATS.map(c => <th key={c[0]} className={cn(TH_B, 'text-center')} title={c[1]}>{c[2]}</th>)}
        </tr></thead>
        <tbody>{covHosts.map(([o, cats]) => <tr key={o}>
          <td className={cn(TD_C, 'max-w-[220px] truncate text-left font-mono text-[12px] text-fg-muted')}>{host(o)}</td>
          {CATS.map(c => {
            const x = cats.get(c[0])
            const st = x?.status ?? 'untested'
            return <td key={c[0]} className={cn(TD_C, 'text-center')} title={`${c[1]}: ${COV_L[st]}${x ? '\n' + safeReportText(x.summary) : ''}${x?.enforcingControl ? '\nControl: ' + safeReportText(x.enforcingControl) : ''}${x?.proofGapReason ? '\nProof gap: ' + safeReportText(x.proofGapReason) : ''}`}>
              <button
                type="button"
                className="inline-grid h-auto cursor-pointer place-items-center rounded-[4px] border-0 bg-transparent p-0.5 shadow-none transition-transform duration-[var(--d1)] ease-kovo hover:-translate-y-px hover:bg-transparent"
                onClick={() => links.cell(o, c[0])}
              >
                <CovSwatch status={st} size={[16, 12]} />
              </button>
            </td>
          })}
        </tr>)}</tbody>
      </table>
      <div className={LEGS}>{(['reported', 'needs_follow_up', 'no_issue_found', 'ruled_out', 'not_applicable'] as const).map(s => <span key={s} className={LEG}><CovSwatch status={s} size={[14, 11]} />{COV_L[s]}</span>)}</div>
    </>}

    {threat.length > 0 && <>
      <h2 className={H2}>Threat model ranking</h2>
      <table className={TBL}><tbody>{(allT ? threat : threat.slice(0, 8)).map((e, i) => {
        const tags = Array.isArray(e.surfaceTags) ? e.surfaceTags.filter(Boolean) : []
        const key = e.origin ?? String(i)
        return <tr key={key} className={ROW_HOVER} onClick={() => e.origin && links.host(e.origin)}>
          <td className={cn('w-[22px] pb-[7px] pt-[9px] align-top text-[11.5px] tabular-nums text-fg-faint', BL)}>{i + 1}</td>
          <td className={cn(ROW_TOP, BL)}><TierBars tier={e.riskTier as RiskTier} /></td>
          <td className={TD_Y}>
            <div className="text-fg"><span className="font-mono text-[12px]">{e.origin ? host(e.origin) : 'unknown'}</span> <span className="text-fg-subtle">· {RISKL[e.riskTier as RiskTier] ?? safeReportText(e.riskTier)}</span></div>
            <div className="mt-0.5 text-[12px] leading-[18px] text-fg-subtle">{safeReportText(e.rationale)}</div>
            {tags.length > 0 && <div className="mb-0.5 mt-1.5 flex flex-wrap items-center gap-[5px]">
              {(expandedTags[key] ? tags : tags.slice(0, 6)).map(t => <Tag key={safeReportText(t)}>{safeReportText(t)}</Tag>)}
              {tags.length > 6 && <button type="button" className={cn(LINK_NONE, 'text-[11.5px]')} onClick={evClick => { evClick.stopPropagation(); setExpandedTags(prev => ({ ...prev, [key]: !prev[key] })) }}>{expandedTags[key] ? 'Show first 6' : `Show all ${tags.length} items`}</button>}
            </div>}
          </td>
        </tr>
      })}</tbody></table>
      {threat.length > 8 && <button type="button" className={cn(LINK_NONE, 'mt-1')} onClick={() => setAllT(v => !v)}>{allT ? 'Show the top 8' : `Show all ${threat.length} ranked hosts`}</button>}
    </>}

    {gapsOpen.length > 0 && <>
      <h2 className={H2}>Open proof gaps</h2>
      <table className={TBL}><tbody>{gapsOpen.map((g, i) => <tr key={safeReportText(g.origin) + safeReportText(g.category) + i} className={ROW_HOVER} onClick={() => links.cell(g.origin, g.category)}>
        <td className={cn(ROW_TOP, BL)}><StatusGlyph status="needs_follow_up" /></td>
        <td className={TD_Y}>
          <div className="text-fg">{safeReportText(g.proofGapReason)}</div>
          <div className="text-[12px] text-fg-subtle"><span className="font-mono">{g.origin ? host(g.origin) : 'unknown'}</span> · {owaspCategoryTitles[g.category as keyof typeof owaspCategoryTitles] ?? prettyCat(g.category)}{g.summary && g.summary !== g.proofGapReason ? ' · ' + safeReportText(g.summary) : ''}</div>
        </td>
      </tr>)}</tbody></table>
    </>}

    {patches.length > 0 && <>
      <h2 className={H2}>Verified patch diffs</h2>
      {patches.map(p => {
        const patchLocations = Array.isArray(p.codeLocations) ? p.codeLocations.filter(Boolean) : []
        const patchDiff = typeof p.diff === 'string' ? p.diff : ''
        return <div key={p.id} className="border-b border-line py-2.5">
          <div className="mb-1.5 text-[13px] text-fg"><b className="font-medium">{titleById.get(p.findingId) ?? p.findingId}</b><span className="font-mono text-[12px] text-fg-subtle"> · {safeReportText(p.repo)}</span></div>
          <div className="mb-2.5 mt-0.5 flex flex-wrap gap-[5px]">
            <Tag tone={p.status === 'withheld' || p.status === 'rejected' ? 'warn' : p.status === 'approved' ? 'accent' : undefined}>{patchStatusLabels[p.status] ?? safeReportText(p.status)}</Tag>
            <Tag>{callerCompatibilityLabels[p.callerCompatibility] ?? safeReportText(p.callerCompatibility)}</Tag>
            <Tag>{dynamicRetestLabels[p.dynamicRetestVerdict] ?? safeReportText(p.dynamicRetestVerdict)}</Tag>
          </div>
          {patchLocations.length > 0 && <p className={cn(DOC_P, 'font-mono text-[12px] text-fg-subtle')}>{patchLocations.map(l => `${safeReportText(l.file)}:${l.startLine ?? 0}-${l.endLine ?? 0}`).join(', ')}</p>}
          {p.status === 'approved' && patchDiff.trim() ? <pre className={RW.pre}>{patchDiff}</pre>
            : p.status === 'withheld' ? <p className={cn(DOC_P, 'text-fg-subtle')}>Diff withheld automatically because the independent patch reviewer flagged caller compatibility or a gate failure.</p> : null}
          <PatchProposalReview runId={detail.run.id} proposal={p} onReviewed={refresh} />
        </div>
      })}
    </>}

    {b.gaps.length > 0 && <>
      <h2 className={H2}>Gaps</h2>
      <ul className="m-0 list-none p-0 text-fg-muted">{b.gaps.map((g, i) => <li key={i} className="border-b border-line py-1.5 text-[12.5px]">{g}</li>)}</ul>
    </>}

    <h2 className={H2}>Methodology and limitations</h2>
    <p className={DOC_P}>{reportEvidenceSource(detail.run.sourceMode, b.selectedChecks, b.capabilityTier)}{reportPlanLabel(b.selectedChecks) ? ' ' + reportPlanLabel(b.selectedChecks) : ''}</p>
    <p className={DOC_P}>Kovo Hunter evaluated only the approved hosts, testing mode ({modeName}), test accounts, and recorded evidence in this report. AI observations and version matches only create hypotheses; every confirmed finding requires deterministic automated replay verification against a clean control check.</p>
    <p className={cn(DOC_P, 'text-fg-subtle')}>Inconclusive, ruled-out, not-applicable and untested categories remain visible rather than counting as passes. This evidence-led review does not guarantee that no other vulnerability exists.</p>
  </article></div>
}

/** The report has no inspectors of its own: evidence uses the foundation inspector. */
export const reportInspectors: InspectorMap = {}
