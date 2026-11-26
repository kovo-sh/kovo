// Finding inspector (owned by Agent Q). Opened from Findings, and by every
// cross-link to a finding (Surface, Workflow, Exchanges, palette…).
import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'

import { generatePatchAction } from '../../../actions.ts'
import { reviewPatchProposalAction, triageFindingAction } from '../../../actions-triage.ts'
import type { OperatorSeverityOverride, OperatorTriageStatus, PatchProposalReviewStatus } from '../../../actions-triage.ts'
import { callerCompatibilityLabels, dynamicRetestLabels, patchStatusLabels } from '../../../report-summary.ts'
import { useRun, useRunModel } from '../data.tsx'
import { Disclosure, EmptyState, LinkRow, Props, Section, Tag } from '../display.tsx'
import { cap, fmtDate, host, plural } from '../format.ts'
import { SevGlyph, StatusGlyph } from '../glyphs.tsx'
import { Icon } from '../icons.tsx'
import { covCat, normFStatus, prettyCat, SEV_LABEL, stLabel } from '../meta.ts'
import type { Detail, FindingRow } from '../model.ts'
import { useLinks } from '../nav.tsx'
import { ExchangeLink, PaneBody, PaneHeader } from '../pane.tsx'
import type { InspectorProps } from '../pane.tsx'
import { useToast } from '../toast.tsx'
import { cn, runBtn, RW } from '../tw.ts'
import { getTriageStatusMeta, getTriageStatusOptions } from './findings.tsx'
import type { FindingWithTriage } from './findings.tsx'
import { CodeLocations, CopyCurlButton, FoundBy, OnSurface } from './queue-read.tsx'

/** Unified Verify Fix gate across FindingInspector and ReportView: server requires `replaySpecId`. */
export function canVerifyFix(f: Pick<FindingRow, 'status' | 'replaySpecId'>): boolean {
  return normFStatus(f.status) === 'confirmed' && Boolean(f.replaySpecId)
}

/** Unified Generate Verified Patch gate across FindingInspector and ReportView. */
export function canGeneratePatch(f: Pick<FindingRow, 'status' | 'codeLocations'>): boolean {
  return (f.status === 'confirmed' || f.status === 'static_verified') && (f.codeLocations?.length ?? 0) > 0
}

const TIER_L: Record<string, string> = { runtime_confirmed: 'Runtime confirmed', static_verified: 'Statically verified', baseline_confirmed: 'Baseline confirmed' }
const RETEST_L: Record<string, string> = { reproduced: 'Still reproducible', fixed: 'Verified fixed', inconclusive: 'Inconclusive' }
const RETEST_ST: Record<string, string> = { reproduced: 'failed', fixed: 'confirmed', inconclusive: 'inconclusive' }

const text = (v: unknown) => v == null ? '' : typeof v === 'string' ? v : JSON.stringify(v)

const SEVERITY_OVERRIDE_OPTIONS: readonly { value: OperatorSeverityOverride; label: string }[] = [
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'info', label: 'Info' },
]

export type PatchProposalItem = Detail['patchProposals'][number]

/** Shared Approve / Reject + editable review notes control for patch proposals in FindingInspector and ReportView. */
export function PatchProposalReview({
  runId,
  proposal,
  onReviewed,
  compact = false,
}: {
  runId: string
  proposal: PatchProposalItem
  onReviewed: () => Promise<void>
  compact?: boolean
}) {
  const toast = useToast()
  const [notes, setNotes] = useState(proposal.reviewNotes ?? '')
  const [busy, setBusy] = useState<'approved' | 'rejected' | 'notes' | null>(null)

  useEffect(() => {
    setNotes(proposal.reviewNotes ?? '')
  }, [proposal.id, proposal.updatedAt, proposal.reviewNotes])

  const notesDirty = notes.trim() !== (proposal.reviewNotes ?? '').trim()

  const submit = async (status: PatchProposalReviewStatus, mode: 'approved' | 'rejected' | 'notes') => {
    setBusy(mode)
    try {
      await reviewPatchProposalAction({
        data: {
          runId,
          proposalId: proposal.id,
          status,
          reviewNotes: notes,
        },
      })
      await onReviewed()
      toast.show(
        mode === 'approved' ? 'Patch approved' : mode === 'rejected' ? 'Patch rejected' : 'Patch review notes saved',
        { icon: 'check' },
      )
    } catch (e) {
      toast.show(e instanceof Error ? e.message : 'Kovo Hunter could not update this patch review.', { tone: 'error' })
    } finally {
      setBusy(null)
    }
  }

  const currentReviewStatus: PatchProposalReviewStatus = proposal.status === 'approved'
    ? 'approved'
    : proposal.status === 'rejected'
      ? 'rejected'
      : 'pending'

  return <div className="mt-1.5" data-slot="patch-proposal-review">
    <textarea
      aria-label="Patch review notes"
      rows={compact ? 2 : 2}
      className={cn(RW.fieldTextarea, 'w-full')}
      placeholder="Operator review notes…"
      value={notes}
      disabled={busy !== null}
      onChange={e => setNotes(e.target.value)}
    />
    <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
      <button
        type="button"
        className={runBtn({ variant: proposal.status === 'approved' ? 'primary' : 'default', size: 'sm' })}
        disabled={busy !== null}
        onClick={() => void submit('approved', 'approved')}
      >
        <Icon name="check" />{busy === 'approved' ? 'Approving…' : 'Approve'}
      </button>
      <button
        type="button"
        className={runBtn({ variant: proposal.status === 'rejected' ? 'dangerSolid' : 'default', size: 'sm' })}
        disabled={busy !== null}
        onClick={() => void submit('rejected', 'rejected')}
      >
        <Icon name="x" />{busy === 'rejected' ? 'Rejecting…' : 'Reject'}
      </button>
      {notesDirty && <button
        type="button"
        className={runBtn({ variant: 'ghost', size: 'sm' })}
        disabled={busy !== null}
        onClick={() => void submit(currentReviewStatus, 'notes')}
      >
        {busy === 'notes' ? 'Saving…' : 'Save notes'}
      </button>}
    </div>
  </div>
}

/** Compact operator triage bar persisted alongside machine-verified verdict/severity. */
function TriageBar({ runId, f }: { runId: string; f: FindingWithTriage }) {
  const { refresh } = useRun()
  const toast = useToast()
  const triage = f.operatorTriage ?? null
  const savedStatus: OperatorTriageStatus = triage?.status ?? 'open'
  const savedSeverity: OperatorSeverityOverride | null = triage?.severityOverride ?? null
  const savedNotes = triage?.notes ?? ''

  const [status, setStatus] = useState<OperatorTriageStatus>(savedStatus)
  const [severityOverride, setSeverityOverride] = useState<OperatorSeverityOverride | null>(savedSeverity)
  const [notes, setNotes] = useState(savedNotes)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    setStatus(savedStatus)
    setSeverityOverride(savedSeverity)
    setNotes(savedNotes)
  }, [f.id, triage?.updatedAt, savedStatus, savedSeverity, savedNotes])

  const dirty = status !== savedStatus || severityOverride !== savedSeverity || notes.trim() !== savedNotes.trim()
  const statusOptions = getTriageStatusOptions()

  const save = async () => {
    setSaving(true)
    try {
      await triageFindingAction({
        data: {
          runId,
          findingId: f.id,
          status,
          severityOverride,
          notes,
        },
      })
      await refresh()
      toast.show('Triage saved', { icon: 'check', sub: f.title })
    } catch (e) {
      toast.show(e instanceof Error ? e.message : 'Kovo Hunter could not save triage.', { tone: 'error' })
    } finally {
      setSaving(false)
    }
  }

  return <div data-slot="finding-triage-bar" className="mb-4 rounded-[7px] bg-sunk px-2.5 py-2 shadow-[inset_0_0_0_1px_var(--line)]">
    <div className="mb-1.5 flex items-center justify-between gap-2">
      <span className="text-[11.5px] font-medium text-fg-subtle">Triage</span>
      {triage?.updatedAt ? <span className="text-[11px] text-fg-subtle">Updated {fmtDate(triage.updatedAt)}</span> : null}
    </div>
    <div className="flex flex-wrap items-center gap-1.5">
      <select
        aria-label="Triage status"
        className={cn(RW.fieldInput, 'min-w-[130px] flex-1')}
        value={status}
        disabled={saving}
        onChange={e => setStatus(e.target.value as OperatorTriageStatus)}
      >
        {statusOptions.map(opt => <option key={opt.value} value={opt.value}>{opt.label}</option>)}
      </select>
      <select
        aria-label="Severity override"
        className={cn(RW.fieldInput, 'min-w-[135px]')}
        value={severityOverride ?? ''}
        disabled={saving}
        onChange={e => setSeverityOverride((e.target.value || null) as OperatorSeverityOverride | null)}
      >
        <option value="">Severity: Machine ({SEV_LABEL[f.severity] ?? f.severity})</option>
        {SEVERITY_OVERRIDE_OPTIONS.map(opt => <option key={opt.value} value={opt.value}>Override: {opt.label}</option>)}
      </select>
      <button
        type="button"
        className={runBtn({ variant: dirty ? 'primary' : 'default', size: 'sm' })}
        disabled={!dirty || saving}
        onClick={() => void save()}
      >
        <Icon name="check" />{saving ? 'Saving…' : 'Save'}
      </button>
    </div>
    <textarea
      aria-label="Operator triage notes"
      rows={2}
      className={cn(RW.fieldTextarea, 'mt-1.5 w-full')}
      placeholder="Operator triage notes…"
      value={notes}
      disabled={saving}
      onChange={e => setNotes(e.target.value)}
    />
  </div>
}

/** Primary action row inside Beat 3 ("How to fix & verify"): Copy as cURL + immediate Verify Fix + Generate verified patch + retest & patch history. */
function FixVerifyActions({ f, primaryExchangeId }: { f: FindingRow; primaryExchangeId?: string }) {
  const { detail, send, pending, refresh } = useRun()
  const toast = useToast()
  const [verifying, setVerifying] = useState(false)
  const [patching, setPatching] = useState(false)
  const replay = detail.replaySpecs.find(r => (f.replaySpecId && r.id === f.replaySpecId) || r.findingId === f.id)
  const retests = detail.retestRuns.filter(r => r.findingId === f.id).slice().sort((a, b) => b.createdAt - a.createdAt)
  const patches = (detail.patchProposals ?? []).filter(p => p.findingId === f.id)
  const active = detail.assignments.some(a => a.phase === 'retest' && (a.status === 'queued' || a.status === 'running') && (a.stepId === f.id || a.objective.includes(f.id) || (replay && a.objective.includes(replay.id))))
  const canRetest = canVerifyFix(f)
  const canPatch = canGeneratePatch(f)
  if (!primaryExchangeId && !canRetest && !canPatch && !retests.length && !patches.length) return null

  const runVerifyFix = async () => {
    setVerifying(true)
    try {
      await send({ action: 'retest_finding', findingId: f.id })
      toast.show('Verify Fix queued', { icon: 'replay', sub: f.title })
    } catch {
      // Error toast is already surfaced by `send`.
    } finally {
      setVerifying(false)
    }
  }

  const runGeneratePatch = async () => {
    setPatching(true)
    try {
      await generatePatchAction({ data: { runId: detail.run.id, findingId: f.id, repo: f.codeLocations?.[0]?.repo } })
      await refresh()
      toast.show('Verified patch generated', { icon: 'check', sub: f.title })
    } catch (e) {
      toast.show(e instanceof Error ? e.message : 'Kovo Hunter could not generate a verified patch.', { tone: 'error' })
    } finally {
      setPatching(false)
    }
  }

  return <>
    {(primaryExchangeId || canRetest || canPatch) && <div className="mb-2.5 mt-2 flex flex-wrap items-center gap-2">
      <CopyCurlButton exchangeId={primaryExchangeId} />
      {canRetest && <button type="button" className={runBtn()} disabled={active || verifying || pending > 0} onClick={() => void runVerifyFix()} title="Re-run automated replay after shipping a fix">
        <Icon name="replay" />{active || verifying ? 'Verifying fix…' : 'Verify Fix'}
      </button>}
      {canPatch && <button type="button" className={runBtn()} disabled={patching} onClick={() => void runGeneratePatch()} title="Generate and verify a code patch for this finding">
        <Icon name="edit" />{patching ? 'Generating patch…' : 'Generate verified patch'}
      </button>}
    </div>}
    {retests.length > 0 && <div className="divide-y divide-dashed divide-line">
      {retests.map(r => <div key={r.id} className="grid grid-cols-[14px_minmax(0,1fr)] gap-2 py-1.5 text-[12px] leading-[18px] text-fg-muted">
        <StatusGlyph status={RETEST_ST[r.verdict] ?? r.verdict} />
        <div className="min-w-0">
          <b className="font-medium text-fg">{RETEST_L[r.verdict] ?? cap(r.verdict)}</b>{' '}
          <span className="text-fg-subtle">· {fmtDate(r.createdAt)}</span>
          <div className="text-fg-subtle">{r.summary}</div>
        </div>
      </div>)}
    </div>}
    {patches.length > 0 && <div className="mt-2 divide-y divide-dashed divide-line">
      {patches.map(p => <div key={p.id} className="py-2 text-[12px] leading-[18px] text-fg-muted">
        <div className="mb-1 flex flex-wrap items-center gap-1.5">
          <Tag tone={p.status === 'withheld' || p.status === 'rejected' ? 'warn' : p.status === 'approved' ? 'accent' : undefined}>{patchStatusLabels[p.status]}</Tag>
          <Tag>{callerCompatibilityLabels[p.callerCompatibility]}</Tag>
          <Tag>{dynamicRetestLabels[p.dynamicRetestVerdict]}</Tag>
        </div>
        {p.status === 'approved' && p.diff.trim() && <pre className={cn(RW.pre, 'mt-1.5 max-h-[240px]')}>{p.diff}</pre>}
        <PatchProposalReview runId={detail.run.id} proposal={p} onReviewed={refresh} compact />
      </div>)}
    </div>}
  </>
}

export function FindingInspector({ sel }: InspectorProps) {
  const model = useRunModel()
  const links = useLinks()
  const f = model.findingById.get(sel.id)
  if (!f) {
    return <>
      <PaneHeader title="Finding" sub={<span title={`Finding ${sel.id}`}>Not found</span>} />
      <PaneBody><EmptyState icon="findings" title="Finding not found">It may have been superseded since the run refreshed.</EmptyState></PaneBody>
    </>
  }
  const st = normFStatus(f.status)
  const cat = covCat(f.category)
  const chain = f.findingKind === 'multi_step_chain'
  const replay = model.detail.replaySpecs.find(r => (f.replaySpecId && r.id === f.replaySpecId) || r.findingId === f.id)
  const spans = replay?.sourceOrigins ?? []
  const exIds = f.exchangeIds ?? []
  const primaryExchangeId = exIds[0] ?? (model.exchangesByOrigin.get(f.origin)?.find(e => e.pathAndQuery === '/' && e.method === 'GET') ?? model.exchangesByOrigin.get(f.origin)?.[0])?.id
  const evs = f.evidenceIds.map(id => model.evidenceById.get(id)).filter(Boolean)
  const workers = model.findingWorkers.get(f.id) ?? []
  const superseded = f.supersededByFindingId ? model.findingById.get(f.supersededByFindingId) : undefined
  const obs = f.check?.observed
  const codeLocs = f.codeLocations ?? []
  const diff = replay?.lastVerificationDiff as unknown
  const hasPatches = (model.detail.patchProposals ?? []).some(p => p.findingId === f.id)
  const triage = (f as FindingWithTriage).operatorTriage ?? null
  const triageMeta = triage ? getTriageStatusMeta(triage.status) : null

  const hasTechnicalDetails = Boolean(
    f.verification || replay || diff != null || f.counterevidence
    || f.confidenceRationale || f.severityChangeConditions || f.runtimeProofGap
    || workers.length || cat || exIds.length || evs.length,
  )
  const techSummary = [
    exIds.length ? plural(exIds.length, 'exchange') : '',
    evs.length ? plural(evs.length, 'record') : '',
  ].filter(Boolean).join(' · ')

  const bannerCls = 'mb-3 flex items-center gap-2 rounded-[7px] bg-sunk px-2.5 py-2 text-[12px] text-fg-muted shadow-[inset_0_0_0_1px_var(--line)]'

  return <>
    <PaneHeader title="Finding" sub={<span title={`Finding ${f.id}`}>{SEV_LABEL[f.severity] ?? f.severity} · {host(f.origin)}</span>} />
    <div className="flex min-h-0 flex-1 flex-col">
      <PaneBody><div className={cn(RW.detail, 'pb-6')}>
        {superseded && <div className={bannerCls}><Icon name="alert" /><span>Superseded by a newer finding.</span>
          <button type="button" className={cn(runBtn({ variant: 'ghost' }), 'ml-auto')} onClick={() => links.finding(superseded.id)}>Open<Icon name="arrowR" /></button></div>}
        <div className="mb-2.5 flex flex-wrap gap-1.5">
          <Tag><SevGlyph sev={f.severity} />{SEV_LABEL[f.severity] ?? f.severity}</Tag>
          <Tag tone={st === 'confirmed' ? 'accent' : undefined}><StatusGlyph status={st} />{stLabel(f.status === 'static_verified' ? 'static_verified' : st)}</Tag>
          {triage && triage.status !== 'open' && triageMeta && <Tag tone={triageMeta.tone}>Triage: {triageMeta.short}</Tag>}
          {triage?.severityOverride && <Tag>Override: {SEV_LABEL[triage.severityOverride] ?? triage.severityOverride}</Tag>}
        </div>
        <h2 className="m-0 mb-3 break-words text-[15px] font-semibold leading-[22px] tracking-[-0.012em] text-fg">{f.title}</h2>
        <Props rows={[
          ['Origin', <span className="font-mono text-[12px]">{host(f.origin)}</span>, () => links.host(f.origin)],
          ['Category', <span>{prettyCat(f.category)}</span>, cat ? () => links.cell(f.origin, cat) : undefined],
          ...(f.cwe ? [['Weakness', <span className="font-mono text-[12px]">{f.cwe}</span>] as [string, ReactNode]] : []),
          ...(f.verificationTier ? [['Verified', TIER_L[f.verificationTier] ?? cap(f.verificationTier)] as [string, ReactNode]] : []),
          ...(spans.length > 1 ? [['Spans', <span className="rw-wrap break-all whitespace-normal font-mono text-[11.5px]">{spans.map(host).join(', ')}</span>] as [string, ReactNode]] : []),
        ]} />
        <TriageBar runId={model.detail.run.id} f={f as FindingWithTriage} />

        {(f.reason || (f.check && (f.check.expected || obs !== undefined))) && <Section title="What happened">
          {f.reason && <p className="text-fg!">{f.reason}</p>}
          {f.check && (f.check.expected || obs !== undefined) && <div className={cn(RW.cmp, 'divide-y divide-line')}>
            <div className="grid grid-cols-[72px_1fr] text-[12px] leading-[18px]">
              <span className="min-w-0 border-r border-line bg-sunk px-2.5 py-[7px] text-fg-subtle">Expected</span>
              <span className="min-w-0 px-2.5 py-[7px] text-fg-muted">{f.check.expected || '—'}</span>
            </div>
            <div className="grid grid-cols-[72px_1fr] text-[12px] leading-[18px]">
              <span className="min-w-0 border-r border-line bg-sunk px-2.5 py-[7px] text-fg-subtle">Observed</span>
              <span className="min-w-0 break-words px-2.5 py-[7px] font-mono text-[12px] text-fg">
                {obs == null ? <span className="font-sans text-fg-subtle">No observation</span> : text(obs)}
              </span>
            </div>
          </div>}
        </Section>}

        {f.impact && <Section title="Why it matters">
          <p>{f.impact}</p>
        </Section>}

        {(f.remediation || f.recheck || codeLocs.length > 0 || primaryExchangeId || canVerifyFix(f) || canGeneratePatch(f) || hasPatches) && <Section title="How to fix & verify">
          {f.remediation && <p>{f.remediation}</p>}
          {f.recheck && <p><b className="font-medium text-fg">Recheck.</b> {f.recheck}</p>}
          <CodeLocations codeLocs={codeLocs} />
          <FixVerifyActions f={f} primaryExchangeId={primaryExchangeId} />
        </Section>}

        {hasTechnicalDetails && <Disclosure title="Technical details & raw evidence" right={techSummary || undefined}>
          <Props rows={[
            ['Kind', <>{chain ? <><Icon name="chain" />Multi-step chain</> : 'Baseline check'}{f.check?.id && !chain && <span className="font-mono text-[12px] text-fg-subtle">{f.check.id}</span>}</>],
            ...(f.confidence ? [['Confidence', cap(f.confidence)] as [string, ReactNode]] : []),
          ]} />
          {f.verification && <Section title="Verification"><p>{f.verification}</p></Section>}
          {replay && <Section title="Automated replay" right={replay.verifiedInline ? 'Verified inline' : plural(replay.attemptCount, 'attempt')}>
            <p title={`Replay spec ${replay.id}`}>Automated replay over {replay.sourceOrigins.map(host).join(', ')}. Re-sends the recorded HTTP requests directly and compares control vs. variant responses.</p>
            {diff != null && <pre className={RW.pre}>{text(diff)}</pre>}
          </Section>}
          {f.counterevidence && <Section title="Counterevidence"><p>{f.counterevidence}</p></Section>}
          {(f.confidenceRationale || f.severityChangeConditions || f.runtimeProofGap) && <Section title="Confidence & proof">
            {f.confidenceRationale && <p>{f.confidenceRationale}</p>}
            {f.severityChangeConditions && <p><b className="font-medium text-fg">Severity would change if</b> {f.severityChangeConditions}</p>}
            {f.runtimeProofGap && <p><b className="font-medium text-fg">Runtime proof gap.</b> {f.runtimeProofGap}</p>}
          </Section>}
          <FoundBy workers={workers} />
          {cat && <OnSurface origin={f.origin} category={cat} />}
          {exIds.length > 0 && <Section title="Exchanges" right={<span className="tabular-nums">{exIds.length}</span>}>
            {exIds.slice(0, 12).map(id => <ExchangeLink key={id} id={id} />)}
            {exIds.length > 12 && <p className="mb-1.5! mt-0.5! text-[12px]! text-fg-subtle!">+{exIds.length - 12} more cited exchanges</p>}
          </Section>}
          {evs.length > 0 && <Section title="Evidence records" right={<span className="tabular-nums">{evs.length}</span>}>
            {evs.slice(0, 8).map(e => <LinkRow key={e!.id} icon="fact" right={e!.kind} trailing={null} onClick={() => links.evidence(e!.id)}>{e!.title}</LinkRow>)}
          </Section>}
        </Disclosure>}
      </div></PaneBody>
    </div>
  </>
}
