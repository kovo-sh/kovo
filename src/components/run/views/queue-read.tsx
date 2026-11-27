// Reading-view building blocks shared by the Queue inspector and the Finding
// inspector (owned by Agent Q): exchange rows with the checked header,
// coordinator context, cross-link blocks, and the per-kind reading views.
import { useState } from 'react'
import type { ReactNode } from 'react'

import { approvalPolicyMeta, capabilityTierMeta } from '../../run-state.ts'
import { formatExchangeAsCurl } from '../../curl-parser.ts'
import { loadExchange, useFullExchange, useRun, useRunModel } from '../data.tsx'
import { Disclosure, LinkRow, Section, Tag } from '../display.tsx'
import { cap, capF, fmtDate, fmtN, fmtRel, fmtTime, fmtUsd, host, plural, prettyBody, words } from '../format.ts'
import { CovSwatch, SevGlyph, StatusGlyph } from '../glyphs.tsx'
import { Icon } from '../icons.tsx'
import type { IconName } from '../icons.tsx'
import { CHECK_HEADERS, COV_L, covCat, normFStatus, PHASE_LABEL, prettyCat, SEV_LABEL, stLabel } from '../meta.ts'
import { isApprovalExpired } from '../model.ts'
import type { Approval, Exchange, FindingRow, QueueItem, RunModel } from '../model.ts'
import { useLinks } from '../nav.tsx'
import { useToast } from '../toast.tsx'
import { cn, httpCodeClass, runBtn, RW } from '../tw.ts'

type FindingItem = Extract<QueueItem, { kind: 'finding' }>
type ApprovalItem = Extract<QueueItem, { kind: 'approval' }>
type FollowItem = Extract<QueueItem, { kind: 'follow' }>

/** Finding verification state, as E words it ("Unverified" while pending). */
export function VState({ status }: { status: string }) {
  const n = normFStatus(status)
  return <span className="inline-flex items-center gap-[5px] whitespace-nowrap text-[11.5px] text-fg-subtle">
    <StatusGlyph status={n} />{n === 'pending' ? 'Unverified' : stLabel(n)}
  </span>
}

/** Glyph for a queue item: shield (approval), flag (follow-up / consent), severity bars (finding). */
export function QGlyph({ it }: { it: QueueItem }) {
  if (it.kind === 'consent') return <span className="inline-flex size-3.5 flex-none items-center justify-center text-fg-muted"><Icon name="flag" /></span>
  if (it.kind === 'approval') return <span className="inline-flex size-3.5 flex-none items-center justify-center text-warn"><Icon name="shield" /></span>
  if (it.kind === 'follow') return <span className="inline-flex size-3.5 flex-none items-center justify-center text-warn"><Icon name="flag" /></span>
  return <span className="inline-flex size-3.5 flex-none items-center justify-center" title={SEV_LABEL[it.sev]}><SevGlyph sev={it.sev} /></span>
}

const REPLAY_INFRA_ERROR_RE =
  /(?:Replay execution failed:|Worker session|timed out|timeout|ECONNREFUSED|ENOTFOUND|ETIMEDOUT|EHOSTUNREACH|socket hang up|Live replay verification is disabled|Tier 3 (?:approval|Safety Judge)|Replay jq assertion did not emit valid JSON|Invalid DeclarativeReplaySpec|Persisted proof script integrity|Legacy Python agent_script proof|not in approved scope|circuit breaker|BrokerDenied|execution error|sandbox|infrastructure)/i

function unwrapReplayVerificationText(raw: string): string {
  const trimmed = raw.trim()
  const observedMatch = /observed:\s*(.+?)\)\.?$/i.exec(trimmed)
  if (observedMatch?.[1]) return observedMatch[1].trim()
  return trimmed
}

/**
 * Extract a concise replay execution / infrastructure failure reason for unconfirmed or inconclusive
 * findings so the UI can show an amber inline callout below "What happened" without replacing the
 * vulnerability description itself.
 */
export function extractReplayInfraFailure(
  finding: { status?: string; verification?: string | null },
  replayDiff?: unknown,
): string | null {
  const norm = normFStatus(finding.status ?? '')
  if (norm === 'confirmed' || norm === 'dismissed' || finding.status === 'static_verified') {
    return null
  }
  const candidates: string[] = []
  if (replayDiff && typeof replayDiff === 'object') {
    const summary = (replayDiff as { assertionSummary?: { reason?: unknown; observed?: unknown } }).assertionSummary
    if (typeof summary?.reason === 'string' && summary.reason.trim()) candidates.push(summary.reason.trim())
    if (typeof summary?.observed === 'string' && summary.observed.trim()) candidates.push(summary.observed.trim())
  } else if (typeof replayDiff === 'string' && replayDiff.trim()) {
    candidates.push(replayDiff.trim())
  }
  if (typeof finding.verification === 'string' && finding.verification.trim()) {
    candidates.push(unwrapReplayVerificationText(finding.verification))
  }
  for (const candidate of candidates) {
    if (REPLAY_INFRA_ERROR_RE.test(candidate)) {
      return candidate
    }
  }
  return null
}

/** Compact amber inline callout rendered below "What happened" when live verification could not run. */
export function ReplayFailureCallout({ reason }: { reason: string }) {
  return <div
    className="mb-3 flex items-start gap-2 rounded-[7px] bg-warn-soft px-2.5 py-2 text-[12px] leading-[17px] text-fg-muted shadow-[inset_0_0_0_1px_var(--warn-line)]"
    role="status"
    data-testid="replay-failure-callout"
  >
    <Icon name="alert" className="mt-0.5 flex-none text-warn" />
    <div className="min-w-0">
      <div className="font-medium text-fg">Live verification couldn&apos;t run</div>
      <p className="m-0! mt-0.5! break-words text-[12px]! leading-[17px]! text-fg-muted!">{reason}</p>
    </div>
  </div>
}

/** Code locations list shared by Queue and Finding inspectors. */
export function CodeLocations({ codeLocs }: { codeLocs: NonNullable<FindingRow['codeLocations']> }) {
  if (!codeLocs.length) return null
  return <div className="mt-1.5">
    {codeLocs.map((c, i) => <div key={i} className="mb-2.5">
      <div className="flex min-h-6 items-center gap-2 font-mono text-[11.5px] text-fg-muted">
        <Icon name="node" className="flex-none text-fg-subtle" />
        <span className="min-w-0 flex-1 truncate">{c.repo}/{c.file}</span>
        <span className="flex-none tabular-nums text-fg-subtle">L{c.startLine}{c.endLine !== c.startLine ? '–' + c.endLine : ''}</span>
      </div>
      {c.label && <div className="mb-1 ml-[22px] text-[12px] text-fg-subtle">{c.label}</div>}
      {c.snippet && <pre className={cn(RW.pre, 'mt-1 max-h-[200px]')}>{c.snippet}</pre>}
    </div>)}
  </div>
}

// ---------------------------------------------------------------- exchanges

const lower = (h: Record<string, string> | null | undefined) =>
  Object.fromEntries(Object.entries(h ?? {}).map(([k, v]) => [k.toLowerCase(), String(v)]))

/**
 * One evidence exchange: method, status, URL and (for baseline checks) the
 * checked header's value or "absent". Expands to the full response headers
 * with the checked header highlighted. Exchanges outside the loaded window
 * are fetched by id (read-only GET).
 */
export function ExchangeRow({ id, summary, hl = [] }: { id: string; summary?: Exchange; hl?: readonly string[] }) {
  const links = useLinks()
  const [open, setOpen] = useState(false)
  const full = useFullExchange(id, open || hl.length > 0 || !summary)
  const x = summary ?? full
  if (!x) {
    return <div className="-mx-2 flex min-h-[30px] items-center gap-2 rounded-control px-2 text-[12px] text-fg-muted" aria-busy={full === undefined}>
      <span className="w-[38px] flex-none font-mono text-[12px] text-fg-subtle">—</span>
      <span className="min-w-0 flex-1 truncate text-fg-subtle">{full === null ? 'Exchange unavailable' : 'Loading exchange…'}</span>
    </div>
  }
  const H = full ? lower(full.respHeaders) : null
  const k = hl[0]
  let hv: ReactNode = null
  if (k && H) {
    hv = k in H
      ? <span className="max-w-[46%] flex-none truncate font-mono text-[11.5px] text-fg-subtle" title={`${k}: ${H[k]}`}>{k}: {H[k].slice(0, 24)}</span>
      : <span className="max-w-[46%] flex-none truncate font-mono text-[11.5px] text-danger">{k} absent</span>
  }
  const absent = H ? hl.filter(h => !(h in H)) : []
  return <>
    <div
      className="-mx-2 flex min-h-[30px] cursor-pointer items-center gap-2 rounded-control px-2 text-[12px] text-fg-muted transition-[background-color,color] duration-[var(--d1)] hover:bg-hover hover:text-fg"
      role="button"
      tabIndex={0}
      aria-expanded={open}
      onClick={() => setOpen(o => !o)}
      onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setOpen(o => !o) } }}
    >
      <span className="w-[38px] flex-none font-mono text-[12px] text-fg-subtle">{x.method}</span>
      <span className={cn('w-7 flex-none font-mono text-[12px]', httpCodeClass(x.status))}>{x.status}</span>
      <span className="min-w-0 flex-1 truncate font-mono text-[12px]">{host(x.origin)}{x.pathAndQuery}</span>
      {hv}
      <span className={cn('inline-flex flex-none text-fg-subtle transition-transform duration-[var(--d2)] ease-kovo', open ? 'rotate-0' : '-rotate-90')}>
        <Icon name="chev" />
      </span>
    </div>
    {open && <div className="pb-1 pt-0.5">
      {!full ? <p className="text-[12px]! text-fg-subtle!">{full === null ? 'Headers unavailable.' : 'Loading headers…'}</p>
        : <table className={cn(RW.hdrs, 'mb-2 mt-1 font-mono')}>
          <tbody>
            {absent.map(h => <tr key={'a:' + h}>
              <td className="w-[42%] break-all border-b border-line py-[3px] pr-2.5 align-top text-[11.5px] leading-[17px] text-fg">{h}</td>
              <td className="break-all border-b border-line py-[3px] align-top text-[11.5px] leading-[17px] text-danger">absent</td>
            </tr>)}
            {Object.entries(H ?? {}).map(([h, v]) => {
              const isHl = hl.includes(h)
              return <tr key={h}>
                <td className={cn('w-[42%] break-all border-b border-line py-[3px] pr-2.5 align-top text-[11.5px] leading-[17px]', isHl ? 'font-semibold text-fg' : 'text-fg-subtle')}>{h}</td>
                <td className={cn('break-all border-b border-line py-[3px] align-top text-[11.5px] leading-[17px]', isHl ? 'text-fg' : 'text-fg-muted')}>{v}</td>
              </tr>
            })}
          </tbody>
        </table>}
      <LinkRow icon="exchanges" onClick={() => links.exchange(id)}>Open in Exchanges</LinkRow>
    </div>}
  </>
}

// ---------------------------------------------------------------- coordinator context

interface CtxItem { icon: IconName; title: ReactNode; body: ReactNode; worker?: string | null; cell?: [string, string] }

/** "What the run knows": plan steps, chain facts, counterevidence, coverage and planner notes for these origins. */
export function CoordinatorContext({ origins, findings = [], category, excludeCoverageId, follow }: {
  origins: readonly string[]
  findings?: readonly FindingRow[]
  category?: string | null
  excludeCoverageId?: string
  follow?: boolean
}) {
  const { events } = useRun()
  const model = useRunModel()
  const links = useLinks()
  const d = model.detail
  const set = new Set(origins)
  const items: CtxItem[] = []
  d.chainSteps.filter(s => s.sourceOrigins.some(o => set.has(o)))
    .sort((a, b) => Number(b.status === 'complete') - Number(a.status === 'complete') || a.seq - b.seq).slice(0, 2)
    .forEach(s => items.push({ icon: 'workflow', title: <>Step {s.seq} · {cap(s.status)}</>, body: <><b className="font-medium text-fg">{s.title}</b> {s.hypothesis}</>, worker: s.assignedWorkerId }))
  const fids = findings.flatMap(f => f.chainFactIds ?? [])
  fids.map(id => model.factById.get(id)).filter(Boolean).slice(0, 2)
    .forEach(f => items.push({ icon: 'fact', title: <>Fact · {f!.kind}</>, body: f!.summary, worker: f!.assignmentId }))
  const ce = findings.find(f => f.counterevidence)?.counterevidence
  if (ce) items.push({ icon: 'alert', title: 'Counterevidence', body: ce })
  d.coverageEntries.filter(x => set.has(x.origin) && x.id !== excludeCoverageId)
    .sort((a, b) => Number(b.category === category) - Number(a.category === category)).slice(0, follow ? 3 : 2)
    .forEach(x => items.push({ icon: 'surface', title: <>Coverage · {host(x.origin)} · {prettyCat(x.category)} · <b>{COV_L[x.status]}</b></>, body: x.summary, cell: [x.origin, x.category] }))
  const hs = [...set].map(host)
  const pl = [...events].reverse().find(e => e.kind === 'planner.round' && typeof e.detail?.summary === 'string' && hs.some(h => (e.detail.summary as string).includes(h)))
  if (pl) items.push({ icon: 'node', title: <>Planner · round {String(pl.detail.roundNo ?? '')}</>, body: String(pl.detail.summary) })
  if (!items.length) return <p>The coordinator has no other notes on {hs.length > 1 ? 'these origins' : 'this origin'} yet.</p>
  return <div className="flex flex-col divide-y divide-dashed divide-line">
    {items.slice(0, 5).map((c, i) => <div key={i} className="grid grid-cols-[18px_minmax(0,1fr)] gap-2 py-[7px] text-[12px] leading-[18px]">
      <span className="pt-0.5 text-fg-subtle"><Icon name={c.icon} /></span>
      <div className="min-w-0">
        <div className="text-[11.5px] text-fg-subtle [&_b]:font-medium [&_b]:text-fg-muted">{c.title}
          {c.worker && model.workerById.has(c.worker) && <> · <button type="button" className={cn(runBtn({ variant: 'link', size: 'none' }), 'align-baseline text-[11.5px]')} onClick={() => links.worker(c.worker!)}>worker<Icon name="arrowR" size={12} /></button></>}
          {c.cell && <> · <button type="button" className={cn(runBtn({ variant: 'link', size: 'none' }), 'align-baseline text-[11.5px]')} onClick={() => links.cell(c.cell![0], c.cell![1])}>cell<Icon name="arrowR" size={12} /></button></>}
        </div>
        <div className="line-clamp-3 text-fg-muted">{c.body}</div>
      </div>
    </div>)}
  </div>
}

// ---------------------------------------------------------------- cross-links

export function FoundBy({ workers, title = 'Found by' }: { workers: readonly string[]; title?: string }) {
  const model = useRunModel()
  const links = useLinks()
  const ws = workers.map(w => model.workerById.get(w)).filter(Boolean)
  if (!ws.length) return null
  return <Section title={title} right={<span className="tabular-nums">{plural(ws.length, 'worker')}</span>}>
    {ws.slice(0, 6).map(a => <LinkRow key={a!.id} glyph={<StatusGlyph status={a!.status} />} right={PHASE_LABEL[a!.phase] ?? a!.phase} trailing="workflow"
      onClick={() => links.worker(a!.id)}>{a!.title}</LinkRow>)}
    {ws.length > 6 && <p className="mb-2! mt-1! text-[12px]! text-fg-subtle!">+{ws.length - 6} more</p>}
  </Section>
}

export function OnSurface({ origin, category }: { origin: string; category: string }) {
  const model = useRunModel()
  const links = useLinks()
  const cv = model.surface.cov[origin]?.[category]
  const st = cv?.status ?? 'untested'
  return <Section title="On the surface map">
    <LinkRow glyph={<CovSwatch status={st} size={[16, 12]} />} right={COV_L[st]} trailing="surface" onClick={() => links.cell(origin, category)}>
      <span className="font-mono text-[12px]">{host(origin)}</span> · {prettyCat(category)}
    </LinkRow>
  </Section>
}

// ---------------------------------------------------------------- reading views

/** Exchanges a queue finding cites; when none, the baseline responses for its origins (labelled as such). */
function evidenceFor(model: RunModel, it: FindingItem) {
  const ids = [...new Set(it.list.flatMap(f => f.exchangeIds ?? []))]
  if (ids.length) return { ids, inferred: false }
  const out: string[] = []
  for (const o of it.origins.slice(0, 6)) {
    const l = model.exchangesByOrigin.get(o) ?? []
    const x = l.find(e => e.pathAndQuery === '/' && e.method === 'GET') ?? l[0]
    if (x) out.push(x.id)
  }
  return { ids: out, inferred: true }
}

const obsText = (v: unknown) => v == null ? null : typeof v === 'string' ? v : JSON.stringify(v)

/** Inline Copy-as-cURL button sourced from a finding's primary cited exchange. */
export function CopyCurlButton({ exchangeId }: { exchangeId: string | undefined }) {
  const { detail } = useRun()
  const model = useRunModel()
  const toast = useToast()
  const [busy, setBusy] = useState(false)
  if (!exchangeId) return null
  const summary = model.exchangeById.get(exchangeId)
  const copy = async () => {
    setBusy(true)
    try {
      const full = await loadExchange(detail.run.id, exchangeId).catch(() => null)
      const ex = full ?? summary
      if (!ex) {
        toast.show('Exchange details unavailable', { tone: 'error' })
        return
      }
      const cmd = formatExchangeAsCurl({
        method: ex.method,
        origin: ex.origin,
        pathAndQuery: ex.pathAndQuery,
        reqHeaders: full?.reqHeaders,
        personaHandle: ex.personaHandle,
      })
      await navigator.clipboard?.writeText(cmd)
      toast.show('Copied as cURL', {
        icon: 'check',
        sub: full ? `${ex.method} ${host(ex.origin)}${ex.pathAndQuery}` : 'Request URL copied',
      })
    } catch {
      toast.show('Could not copy to clipboard', { tone: 'error' })
    } finally {
      setBusy(false)
    }
  }
  return <button type="button" className={runBtn()} disabled={busy} onClick={() => void copy()} title="Copy primary request as a sanitized cURL command">
    <Icon name="copy" />{busy ? 'Copying…' : 'Copy as cURL'}
  </button>
}

export function ReadFinding({ it }: { it: FindingItem }) {
  const model = useRunModel()
  const F = it.finding
  const chain = F.findingKind === 'multi_step_chain'
  const checkId = F.check?.id ?? ''
  const hl = CHECK_HEADERS[checkId] ?? []
  const ev = evidenceFor(model, it)
  const ws = [...new Set(it.list.flatMap(f => model.findingWorkers.get(f.id) ?? []))]
  const cat = covCat(F.category)
  const codeLocs = F.codeLocations ?? []
  const primaryExchangeId = ev.ids[0]
  let groups: [string, string[]][] = []
  if (it.bundle) {
    const g = new Map<string, string[]>()
    for (const f of it.list) {
      const v = obsText(f.check?.observed) ?? 'Not recorded'
      g.set(v, [...(g.get(v) ?? []), host(f.origin)])
    }
    groups = [...g]
  }
  const obs = obsText(F.check?.observed)
  const replay = model.detail.replaySpecs.find(r => (F.replaySpecId && r.id === F.replaySpecId) || r.findingId === F.id)
  const replayInfraFailure = extractReplayInfraFailure(F, replay?.lastVerificationDiff)
  const techCount = [ev.ids.length ? plural(ev.ids.length, 'exchange') : '', ws.length ? plural(ws.length, 'worker') : ''].filter(Boolean).join(' · ')
  return <>
    <div className="mb-2 flex flex-wrap items-center gap-x-2 gap-y-1 text-[12px] text-fg-subtle">
      <span className="inline-flex items-center gap-1.5 font-medium text-fg-muted"><SevGlyph sev={it.sev} />{SEV_LABEL[it.sev]}</span><span>·</span><VState status={it.status} /><span>·</span>
      <span>{chain ? 'Multi-step chain' : 'Baseline check'}</span>
      {F.cwe && <><span>·</span><span className="font-mono text-[12px]">{F.cwe}</span></>}
    </div>
    <h2 className="m-0 mb-2 break-words text-[15px] font-semibold leading-[22px] tracking-[-0.012em] text-fg">{F.title}</h2>
    <div className="mb-3 flex flex-wrap gap-1">
      {it.origins.slice(0, 6).map(o => <Tag key={o} mono className="text-[11px]">{host(o)}</Tag>)}
      {it.origins.length > 6 && <Tag>+{it.origins.length - 6} more</Tag>}
    </div>

    {(F.reason || F.check || it.bundle) && <Section title="What happened">
      {F.reason && <p className="text-fg!">{F.reason}</p>}
      {it.bundle && <p className="mb-1.5! mt-0.5! text-[12px]! text-fg-subtle!">Same baseline result across {it.origins.length} origins — one decision applies to all of them.</p>}
      {F.check && (F.check.expected || obs !== null) && <div className={cn(RW.cmp, 'divide-y divide-line')}>
        <div className="grid grid-cols-[72px_1fr] text-[12px] leading-[18px]">
          <span className="min-w-0 border-r border-line bg-sunk px-2.5 py-[7px] text-fg-subtle">Expected</span>
          <span className="min-w-0 px-2.5 py-[7px] text-fg-muted">{F.check.expected || '—'}</span>
        </div>
        <div className="grid grid-cols-[72px_1fr] text-[12px] leading-[18px]">
          <span className="min-w-0 border-r border-line bg-sunk px-2.5 py-[7px] text-fg-subtle">Observed</span>
          <span className={cn('min-w-0 break-words px-2.5 py-[7px] text-fg', obs != null && 'font-mono text-[12px]')}>
            {obs ?? <span className="text-fg-subtle">Not recorded</span>}
          </span>
        </div>
      </div>}
      {it.bundle && <div className={cn(RW.olist, 'divide-y divide-line')}>
        {groups.map(([v, hs]) => <div key={v} className="flex gap-2.5 px-2.5 py-[7px] text-[12px] leading-[17px]">
          <div className="min-w-0">
            <div className="break-words font-mono text-[11.5px] text-fg">{v}</div>
            <div className="mt-0.5 text-[11.5px] text-fg-subtle">{hs.join(' · ')}</div>
          </div>
          <span className="ml-auto whitespace-nowrap tabular-nums text-fg-subtle">{hs.length}</span>
        </div>)}
      </div>}
    </Section>}
    {replayInfraFailure && <ReplayFailureCallout reason={replayInfraFailure} />}

    {F.impact && <Section title="Why it matters">
      <p>{F.impact}</p>
    </Section>}

    {(F.remediation || F.recheck || codeLocs.length > 0 || primaryExchangeId) && <Section title="How to fix & verify">
      {F.remediation && <p>{F.remediation}</p>}
      {F.recheck && <p><b className="font-medium text-fg">Recheck.</b> {F.recheck}</p>}
      <CodeLocations codeLocs={codeLocs} />
      {primaryExchangeId && <div className="mb-2.5 mt-2 flex flex-wrap items-center gap-2">
        <CopyCurlButton exchangeId={primaryExchangeId} />
      </div>}
    </Section>}

    <Disclosure title="Technical details & raw evidence" right={techCount || undefined}>
      {F.verification && <Section title="Verification"><p>{F.verification}</p></Section>}
      {F.counterevidence && <Section title="Counterevidence"><p>{F.counterevidence}</p></Section>}
      {(F.confidenceRationale || F.severityChangeConditions || F.runtimeProofGap) && <Section title="Confidence & proof">
        {F.confidenceRationale && <p>{F.confidenceRationale}</p>}
        {F.severityChangeConditions && <p><b className="font-medium text-fg">Severity would change if</b> {F.severityChangeConditions}</p>}
        {F.runtimeProofGap && <p><b className="font-medium text-fg">Runtime proof gap.</b> {F.runtimeProofGap}</p>}
      </Section>}
      <Section title="Coordinator context" right="What the run knows">
        <CoordinatorContext origins={it.origins} findings={it.list} category={cat} />
      </Section>
      <FoundBy workers={ws} />
      {it.origins.length === 1 && cat && <OnSurface origin={it.origins[0]} category={cat} />}
      <Section title="Exchanges" right={<span className="tabular-nums">{plural(ev.ids.length, 'exchange')}</span>}>
        {ev.inferred && ev.ids.length > 0 && <p className="mb-1.5! mt-0.5! text-[12px]! text-fg-subtle!">Baseline responses for {ev.ids.length > 1 ? 'these origins' : 'this origin'}{hl.length ? <>, <span className="font-mono text-[12px]">{hl[0]}</span> highlighted</> : null}.</p>}
        {ev.ids.length
          ? ev.ids.slice(0, 8).map(id => <ExchangeRow key={id} id={id} summary={model.exchangeById.get(id)} hl={hl} />)
          : <p>No exchanges recorded for {it.origins.length > 1 ? 'these origins' : 'this origin'}.</p>}
        {ev.ids.length > 8 && <p className="mb-1.5! mt-0.5! text-[12px]! text-fg-subtle!">+{ev.ids.length - 8} more cited exchanges.</p>}
      </Section>
    </Disclosure>
  </>
}

interface RequestPreview { method?: string; origin?: string; pathAndQuery?: string; headers?: Record<string, string>; bodyPreview?: unknown }
function parsePreview(a: Approval): RequestPreview {
  try { const v = JSON.parse(a.requestPreview) as unknown; return v && typeof v === 'object' ? v as RequestPreview : {} } catch { return {} }
}
export function ReadApproval({ it, now = Date.now(), duplicateCount = 1 }: { it: ApprovalItem; now?: number; duplicateCount?: number }) {
  const model = useRunModel()
  const links = useLinks()
  const a = it.ap
  const asg = model.workerById.get(a.assignmentId)
  const rp = parsePreview(a)
  const raw = !Object.keys(rp).length && a.requestPreview ? a.requestPreview : null
  const body = prettyBody(rp.bodyPreview)
  const win = a.expiresAt && a.createdAt ? Math.round((a.expiresAt - a.createdAt) / 60000) : null
  const persona = a.personaHandle && a.personaHandle !== 'None' ? a.personaHandle : null
  const policy = model.run.approvalPolicy
  const expired = isApprovalExpired(a, now)
  const decidedLabel = [cap(a.status), a.decidedBy].filter(Boolean).join(' · ')
  return <>
    <div className="mb-2 flex flex-wrap items-center gap-x-2 gap-y-1 text-[12px] text-fg-subtle">
      <span className="inline-flex items-center gap-1.5 font-medium text-warn" title="State-changing request requiring approval"><Icon name="shield" />State-change approval</span><span>·</span>
      <span className="tabular-nums">Requested {fmtRel(a.createdAt, model.base)}</span>
      {win != null && win > 0 && <><span>·</span><span>{win}-minute window</span></>}
      <span>·</span><span>Risk {a.riskLevel ? a.riskLevel : 'unrated'}</span>
    </div>
    <h2 className="m-0 mb-2 break-all font-mono text-[13.5px] font-medium leading-[22px] tracking-normal text-fg">
      <span className="mr-2 font-semibold text-warn">{a.method}</span>{host(a.origin)}<span className="text-fg-subtle">{a.pathAndQuery}</span>
    </h2>
    <div className="mb-3 flex flex-wrap gap-1">
      <Tag icon={persona ? 'lock' : undefined}>{persona ?? 'Anonymous'}</Tag>
      {expired
        ? <Tag tone="warn">Expired</Tag>
        : a.status === 'pending'
          ? <Tag className="tabular-nums">Expires {fmtTime(a.expiresAt)}</Tag>
          : <Tag>{decidedLabel}</Tag>}
      {a.status === 'pending' && !expired && duplicateCount > 1 && (
        <span
          className="inline-flex h-5 items-center rounded-[10px] bg-warn-soft px-[7px] text-[11.5px] leading-none tabular-nums text-warn shadow-[inset_0_0_0_1px_var(--warn-line)]"
          data-testid="inspector-dedupe-tag"
        >
          ×{duplicateCount} pending on this route
        </span>
      )}
    </div>
    <Section title="Why">
      <p className="text-fg!">{a.rationale}</p>
      <p>The approval policy is <b className="font-medium text-fg">{approvalPolicyMeta[policy ?? 'auto_review'].label}</b>. {a.policyNote ? a.policyNote + ' ' : 'The safety reviewer deferred this state-changing request to you. '}{expired ? 'This approval window has expired.' : a.status === 'pending' ? 'Nothing is sent until you approve.' : ''}</p>
    </Section>
    <Section title="Request" right="Exactly what will be sent">
      {raw != null ? <pre className={RW.pre}>{raw}</pre> : <pre className={RW.pre}>
        <span className="font-semibold text-warn">{rp.method ?? a.method}</span> {rp.pathAndQuery ?? a.pathAndQuery}{'\n'}
        <span className="text-fg-subtle">Host:</span> {host(rp.origin ?? a.origin)}
        {Object.entries(rp.headers ?? {}).map(([k, v]) => <span key={k}>{'\n'}<span className="text-fg-subtle">{k}:</span> {String(v)}</span>)}
        {body ? '\n\n' + body : <>{'\n\n'}<span className="text-fg-subtle">(empty body)</span></>}
      </pre>}
    </Section>
    {asg && <Section title="Requested by">
      <LinkRow glyph={<StatusGlyph status={asg.status} />} onClick={() => links.worker(asg.id)}
        sub={<>{stLabel(asg.status)} · {asg.turnsUsed}/{asg.maxTurns} turns · {fmtN(asg.requestsUsed)} requests. {asg.objective}</>}>{asg.title}</LinkRow>
    </Section>}
    <Section title="Coordinator context" right="What the run knows">
      <CoordinatorContext origins={[a.origin]} />
    </Section>
  </>
}

export function ReadFollow({ it }: { it: FollowItem }) {
  const model = useRunModel()
  const links = useLinks()
  const x = it.cov
  const risk = model.risk.get(x.origin)?.riskTier
  const related = model.findings.filter(f => f.origin === x.origin)
  return <>
    <div className="mb-2 flex flex-wrap items-center gap-x-2 gap-y-1 text-[12px] text-fg-subtle">
      <span className="inline-flex items-center gap-1.5 font-medium text-warn"><Icon name="flag" />Needs follow-up</span><span>·</span>
      <span>{prettyCat(x.category)}</span>
      {risk && <><span>·</span><span>{cap(risk)} risk surface</span></>}
    </div>
    <h2 className="m-0 mb-2 break-words text-[15px] font-semibold leading-[22px] tracking-[-0.012em] text-fg">{it.title}</h2>
    <div className="mb-3 flex flex-wrap gap-1"><Tag mono className="text-[11px]">{host(x.origin)}</Tag></div>
    <Section title="Coverage note" right="From the worker handoff"><p className="text-fg!">{x.summary}</p>
      {x.proofGapReason && <p><b className="font-medium text-fg">Proof gap.</b> {x.proofGapReason}</p>}
    </Section>
    {related.length > 0 && <Section title="Findings on this origin" right={<span className="tabular-nums">{related.length}</span>}>
      {related.slice(0, 5).map(f => <LinkRow key={f.id} glyph={<SevGlyph sev={f.severity} />} right={<VState status={f.status} />} trailing={null} onClick={() => links.finding(f.id)}>{f.title}</LinkRow>)}
    </Section>}
    <Section title="If queued">
      <p>Kovo sends the coordinator a steering hint for <span className="font-mono text-[12px]">{host(x.origin)}</span> · {prettyCat(x.category)}; it becomes a plan step in the next planner round. Requests requiring higher permissions come back here for approval.</p>
    </Section>
    <Section title="Coordinator context"><CoordinatorContext origins={[x.origin]} category={x.category} excludeCoverageId={x.id} follow /></Section>
    <FoundBy workers={x.assignmentId && model.workerById.has(x.assignmentId) ? [x.assignmentId] : []} title="Recorded by" />
    <OnSurface origin={x.origin} category={x.category} />
  </>
}

export function ReadConsent() {
  const model = useRunModel()
  const r = model.run
  const seeds = model.detail.project.seeds
  const nw = (r.goal || '').split(/\s+/).filter(Boolean).length
  return <>
    <div className="mb-2 flex flex-wrap items-center gap-x-2 gap-y-1 text-[12px] text-fg-subtle">
      <span className="inline-flex items-center gap-1.5 font-medium text-fg-muted"><Icon name="flag" />Consent</span><span>·</span><span>Created {fmtDate(r.createdAt)}</span>
    </div>
    <h2 className="m-0 mb-2 break-words text-[15px] font-semibold leading-[22px] tracking-[-0.012em] text-fg">{r.phase === 'review' ? 'Approve scope to start the run' : 'Approve discovery to start the run'}</h2>
    <div className="mb-3 flex flex-wrap gap-1">
      <Tag className="tabular-nums">{plural(seeds.length, 'host')}</Tag>
      <Tag title={capabilityTierMeta[r.capabilityTier].name}>{capabilityTierMeta[r.capabilityTier].short}</Tag>
      <Tag className="tabular-nums">{fmtUsd(r.budgetUsd)} · {r.budgetRequests ? fmtN(r.budgetRequests) + ' req' : 'uncapped'}</Tag>
    </div>
    <Section title="Goal">
      <p className="text-fg!">“{r.goal}”</p>
      {nw < 6 && <div className="mb-[18px] flex items-start gap-2.5 rounded-lg bg-warn-soft px-3 py-2.5 text-[12.5px] leading-[19px] text-fg-muted shadow-[inset_0_0_0_1px_var(--warn-line)]">
        <Icon name="alert" className="mt-[3px] text-warn" />
        <div>{capF(words(nw))} word{nw === 1 ? '' : 's'} is broad. Use Edit goal in the board or Revise goal in the header menu to focus the budget.</div>
      </div>}
    </Section>
    <Section title="Hosts" right="Project seeds">
      <div className="mb-2.5 grid grid-cols-2 gap-x-3 gap-y-0.5 font-mono text-[12px] text-fg-muted">
        {seeds.map(s => <span key={s} className="truncate">{host(s)}</span>)}
      </div>
    </Section>
  </>
}
