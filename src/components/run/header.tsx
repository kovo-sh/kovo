// Run line header: breadcrumb with goal, then status · phase track · round ·
// budget meter · request meter · tier and hosts · elapsed. Items drop by
// priority when the line overflows. Primary action + "…" menu carry every
// run-level command: resume/pause, budget, approval policy, scope, goal
// revision, approve-all, exports, lab runner, stop.
import { Link } from '@tanstack/react-router'
import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import type { FormEvent, ReactNode, RefObject } from 'react'
import { checkRunLabHealthAction, downloadReportMarkdown, exportSarifAction, startRunLabAction, stopRunLabAction } from '../../actions.ts'
import { approvalPolicies, maxBudgetRequests, maxRpsPerOriginCeiling } from '../../domain.ts'
import type { ApprovalPolicy } from '../../domain.ts'
import { approvalPolicyMeta, capabilityTierMeta } from '../run-state.ts'
import { useRun, useRunModel } from './data.tsx'
import { fmtDate, fmtDur, fmtN, fmtTime, fmtUsd, host, plural, short } from './format.ts'
import { PhaseTrack, StatusGlyph, TierBars } from './glyphs.tsx'
import { Icon } from './icons.tsx'
import type { IconName } from './icons.tsx'
import { useShortcuts } from './keyboard.tsx'
import { PHASE_LABEL, runStatusLabel } from './meta.ts'
import type { RiskTier } from './meta.ts'
import { Meter } from './motion.tsx'
import { useNav } from './nav.tsx'
import { useOverlays } from './overlays.tsx'
import { useToast } from './toast.tsx'

type Popover = 'menu' | 'budget' | 'policy' | 'scope' | 'goal' | null

/** Hide run-line items by priority (data-p, lowest first) until the line fits. */
function useFitRunline(ref: RefObject<HTMLDivElement | null>, deps: unknown[]) {
  useLayoutEffect(() => {
    const rl = ref.current
    if (!rl) return
    const fit = () => {
      const items = [...rl.querySelectorAll<HTMLElement>('.rl[data-p]')].sort((a, b) => Number(a.dataset.p) - Number(b.dataset.p))
      items.forEach(i => { i.style.display = '' })
      for (const it of items) { if (rl.scrollWidth <= rl.clientWidth + 1) break; it.style.display = 'none' }
      const vis = [...rl.querySelectorAll<HTMLElement>('.rl')].filter(x => x.style.display !== 'none')
      rl.querySelectorAll('.rl').forEach(x => x.classList.toggle('lastv', x === vis[vis.length - 1]))
    }
    fit()
    const ro = new ResizeObserver(fit)
    ro.observe(rl)
    return () => ro.disconnect()
  }, deps)
}

function download(content: string, filename: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }))
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export function RunHeader() {
  const { detail, send, pending, refresh } = useRun()
  const model = useRunModel()
  const nav = useNav()
  const toast = useToast()
  const openScope = useOverlays().editScope
  const r = detail.run
  const [pop, setPop] = useState<Popover>(null)
  const wrap = useRef<HTMLDivElement>(null)
  const rl = useRef<HTMLDivElement>(null)
  const dur = model.end - r.createdAt
  const bPct = r.budgetUsd ? r.spentUsd / r.budgetUsd : 0
  const rPct = r.budgetRequests ? r.spentRequests / r.budgetRequests : 0
  const scopeN = model.scopeOrigins.length
  const editable = !['complete', 'stopped', 'failed'].includes(r.status)
  const pendingApprovals = detail.approvals.filter(a => a.status === 'pending')
  useFitRunline(rl, [r.status, r.phase, r.spentUsd, r.spentRequests, scopeN])

  useEffect(() => {
    if (!pop) return
    const down = (e: MouseEvent) => { if (!wrap.current?.contains(e.target as Node) && !(e.target as HTMLElement).closest?.('.rl-btn')) setPop(null) }
    document.addEventListener('mousedown', down)
    return () => document.removeEventListener('mousedown', down)
  }, [pop])
  useShortcuts([{ key: 'Escape', allowInInput: true, run: () => setPop(null) }], { priority: 50, enabled: pop != null })

  const run = (cmd: Parameters<typeof send>[0], done?: string) => send(cmd).then(() => { if (done) toast.show(done) }, () => {})

  let action: ReactNode = null
  if (r.status === 'paused' || r.status === 'stopped' || r.status === 'failed') {
    action = <button type="button" className="btn" disabled={pending > 0} onClick={() => run({ action: 'resume' }, 'Resuming the run')}><Icon name="play" />Resume</button>
  } else if (r.status === 'budget_paused') {
    action = <button type="button" className="btn primary" onClick={() => setPop(pop === 'budget' ? null : 'budget')}><Icon name="budget" />Raise budget</button>
  } else if (r.status === 'running') {
    action = <button type="button" className="btn" disabled={pending > 0} onClick={() => run({ action: 'pause' }, 'Pausing the run')}><Icon name="pause" />Pause</button>
  } else if (r.status === 'waiting') {
    action = <button type="button" className="btn primary" onClick={() => nav.setView('overview')}>Review scope</button>
  } else if (model.report && nav.view !== 'report') {
    action = <button type="button" className="btn" onClick={() => nav.setView('report')}><Icon name="report" />Report</button>
  }

  const item = (icon: IconName, label: ReactNode, onClick: () => void, opts: { disabled?: boolean; danger?: boolean; right?: ReactNode } = {}) =>
    <button type="button" className={'dd-item' + (opts.danger ? ' danger' : '')} disabled={opts.disabled} onClick={() => { if (!opts.disabled) onClick() }}>
      <Icon name={icon} /><span>{label}</span>{opts.right != null && <span className="r">{opts.right}</span>}
    </button>

  const lab = detail.project.environment === 'local-lab'
  const labAct = async (fn: () => Promise<{ message?: string } | unknown>, ok: string) => {
    setPop(null)
    try {
      const res = await fn() as { message?: string }
      toast.show(res?.message ?? ok)
      await refresh()
    } catch (e) { toast.show(e instanceof Error ? e.message : 'Lab action failed', { tone: 'error' }) }
  }

  return <header className="hdr">
    <div className="hdr-top">
      <Link to="/projects/$projectId" params={{ projectId: detail.project.id }} className="crumb" title="Open project">{detail.project.name}</Link>
      <span className="crumb-sep">/</span>
      <span className="crumb mono" style={{ color: 'var(--fg-2)' }}>{short(r.id)}</span>
      <span className="goal" title={r.goal}>{r.goal}</span>
      <span className="hdr-actions" ref={wrap} style={{ position: 'relative' }}>
        {action}
        <button type="button" className="btn ghost" title="More actions" aria-label="More actions" aria-haspopup="menu" aria-expanded={pop === 'menu'} style={{ padding: '0 6px' }}
          onClick={() => setPop(pop === 'menu' ? null : 'menu')}><Icon name="dots" /></button>
        <button
          type="button"
          className={'btn ghost' + (nav.paneCollapsed ? '' : ' on')}
          title={nav.paneCollapsed ? 'Show panel (])' : 'Hide panel (])'}
          aria-label={nav.paneCollapsed ? 'Show panel' : 'Hide panel'}
          aria-pressed={!nav.paneCollapsed}
          style={{ padding: '0 6px' }}
          onClick={() => nav.togglePane()}
        >
          <Icon name="panelR" />
        </button>
        {pop === 'menu' && <div className="menu" role="menu">
          {item('budget', 'Budget and rate limit…', () => setPop('budget'), { right: fmtUsd(r.budgetUsd) })}
          {r.capabilityTier === 3 && item('shield', 'Approval policy…', () => setPop('policy'), { right: approvalPolicyMeta[r.approvalPolicy ?? 'auto_review'].short })}
          {item('globe', 'Scope hosts…', () => setPop('scope'), { right: plural(scopeN, 'host') })}
          {item('edit', 'Revise goal…', () => setPop('goal'), { disabled: !editable })}
          {pendingApprovals.length > 0 && item('check', `Approve all pending (${pendingApprovals.length})`, () => {
            setPop(null)
            toast.undoable({ message: `Approving ${plural(pendingApprovals.length, 'pending request')}`, icon: 'check', sub: 'Sends when this closes', commit: () => send({ action: 'approve_all_pending' }) })
          })}
          <div className="menu-sep" />
          {item('chat', 'Open the board', () => { setPop(null); nav.openChat(null) }, { right: 'C' })}
          {model.report && item('download', 'Download report (Markdown)', () => {
            setPop(null)
            downloadReportMarkdown({ data: { runId: r.id, reportId: model.report!.id } }).then(res => download(res.content, res.filename, 'text/markdown; charset=utf-8'), () => toast.show('Could not export the report', { tone: 'error' }))
          })}
          {model.report && item('download', 'Export SARIF 2.1.0', () => {
            setPop(null)
            exportSarifAction({ data: { runId: r.id, reportId: model.report!.id } }).then(res => download(res.content, res.filename, 'application/sarif+json; charset=utf-8'), () => toast.show('Could not export SARIF', { tone: 'error' }))
          })}
          {lab && <>
            <div className="menu-sep" />
            {detail.labTarget
              ? item('stop', 'Stop local lab', () => void labAct(() => stopRunLabAction({ data: { runId: r.id } }), 'Lab stack stopped'))
              : item('play', 'Start local lab', () => void labAct(() => startRunLabAction({ data: { runId: r.id } }), 'Lab started'), { disabled: !detail.localLabEnvEnabled || !detail.project.labConfig?.enabled })}
            {item('activity', 'Lab health check', () => void labAct(() => checkRunLabHealthAction({ data: { runId: r.id } }), 'Health checked'))}
          </>}
          {editable && r.status !== 'waiting' && <>
            <div className="menu-sep" />
            {item('stop', 'Stop run', () => {
              setPop(null)
              toast.undoable({ message: 'Stopping the run', sub: 'Sends when this closes; a partial report is saved', icon: 'stop', commit: () => send({ action: 'stop' }) })
            }, { danger: true })}
          </>}
        </div>}
        {pop === 'budget' && <BudgetPopover onClose={() => setPop(null)} />}
        {pop === 'policy' && <PolicyPopover onClose={() => setPop(null)} />}
        {pop === 'scope' && <ScopePopover onClose={() => setPop(null)} onEdit={() => { setPop(null); openScope() }} />}
        {pop === 'goal' && <GoalPopover onClose={() => setPop(null)} />}
      </span>
    </div>
    <div className="runline num" ref={rl}>
      <span className="rl"><StatusGlyph status={r.status} /><b>{runStatusLabel(r.status)}</b></span>
      <span className="rl"><PhaseTrack phase={r.phase} />
        {r.phase !== 'complete' && <span>{PHASE_LABEL[r.phase] ?? r.phase}</span>}
        <span className="dim">{r.phase === 'complete' ? '' : '· '}Round {r.roundNo}</span></span>
      <button type="button" className="rl rl-btn" title={`Budget ${fmtUsd(r.spentUsd)} of ${fmtUsd(r.budgetUsd)} · ${fmtN(r.spentTokens)} tokens`} onClick={() => setPop(pop === 'budget' ? null : 'budget')}>
        <Meter id="hdr.budget" value={bPct} /><b>{fmtUsd(r.spentUsd)}</b><span className="dim">/ {fmtUsd(r.budgetUsd)}</span>
      </button>
      <span className="rl" title="Brokered requests">
        {r.budgetRequests > 0 && <Meter id="hdr.req" value={rPct} />}
        <b>{fmtN(r.spentRequests)}</b><span className="dim">{r.budgetRequests ? '/ ' + fmtN(r.budgetRequests) + ' req' : 'req · uncapped'}</span>
      </span>
      <button type="button" className="rl rl-btn" data-p="2" title={`${capabilityTierMeta[r.capabilityTier].name} · ${approvalPolicyMeta[r.approvalPolicy ?? 'auto_review'].label}`} onClick={() => setPop(pop === 'scope' ? null : 'scope')}>
        <span>Tier {r.capabilityTier}</span><span className="dim">· {plural(scopeN, 'host')}</span>
      </button>
      <span className="rl" data-p="1" title={`Started ${fmtDate(r.createdAt)}`}><span className="dim">{dur > 60_000 ? fmtDur(dur) : 'Created ' + fmtTime(r.createdAt)}</span></span>
    </div>
  </header>
}

function PopShell({ title, sub, children, footer }: { title: ReactNode; sub?: ReactNode; children: ReactNode; footer?: ReactNode }) {
  return <div className="pop" role="dialog" aria-label={typeof title === 'string' ? title : undefined}>
    <div className="pop-h">{title}{sub != null && <span className="muted">{sub}</span>}</div>
    <div className="pop-b">{children}</div>
    {footer && <div className="pop-f">{footer}</div>}
  </div>
}

function BudgetPopover({ onClose }: { onClose: () => void }) {
  const { detail, send, pending } = useRun()
  const r = detail.run
  const editable = !['complete', 'stopped', 'failed'].includes(r.status)
  const [usd, setUsd] = useState(r.status === 'budget_paused' ? Math.min(500, Math.max(r.budgetUsd + 10, Math.ceil(r.spentUsd + 10))) : r.budgetUsd)
  const [rps, setRps] = useState(r.maxRpsPerOrigin)
  const [unlimited, setUnlimited] = useState(r.budgetRequests === 0)
  const [cap, setCap] = useState(r.budgetRequests > 0 ? r.budgetRequests : Math.max(r.spentRequests + 1000, 2500))
  const [err, setErr] = useState('')
  const submit = (e: FormEvent) => {
    e.preventDefault()
    const budgetRequests = unlimited ? 0 : Math.max(r.spentRequests + 1, Math.min(maxBudgetRequests, Math.round(cap)))
    setErr('')
    send({ action: 'raise_budget', budgetUsd: usd, budgetRequests, maxRpsPerOrigin: rps, resume: r.status === 'budget_paused' })
      .then(onClose, (x: unknown) => setErr(x instanceof Error ? x.message : 'Could not update the budget'))
  }
  return <form onSubmit={submit}>
    <PopShell title="Budget and rate limit" sub={editable ? 'Applies live' : runStatusLabel(r.status)}
      footer={<>{err && <span className="err">{err}</span>}<button type="button" className="btn ghost" onClick={onClose}>Cancel</button>
        {editable && <button type="submit" className="btn primary" disabled={pending > 0}>{r.status === 'budget_paused' ? 'Update and resume' : 'Update'}</button>}</>}>
      <p>Spent {fmtUsd(r.spentUsd)} · {fmtN(r.spentRequests)} requests · {fmtN(r.turnsUsed)} turns. Changes apply without restarting workers.</p>
      <label className="fld"><span>Spend cap (USD)</span>
        <input className="field-in num" type="number" min={Math.max(0.1, Number((r.spentUsd + 0.1).toFixed(2)))} max={500} step="any" disabled={!editable} value={usd} onChange={e => setUsd(Number(e.target.value))} /></label>
      <label className="fld"><span>Rate limit<span className="dim num">{rps} req/s per origin</span></span>
        <input type="range" min={1} max={maxRpsPerOriginCeiling} step={1} disabled={!editable} value={rps} onChange={e => setRps(Number(e.target.value))} /></label>
      <label className="chk"><input type="checkbox" checked={unlimited} disabled={!editable} onChange={e => setUnlimited(e.target.checked)} />No request cap</label>
      {!unlimited && <label className="fld"><span>Request cap</span>
        <input className="field-in num" type="number" min={r.spentRequests + 1} max={maxBudgetRequests} step={1} disabled={!editable} value={cap} onChange={e => setCap(Number(e.target.value))} /></label>}
    </PopShell>
  </form>
}

function PolicyPopover({ onClose }: { onClose: () => void }) {
  const { detail, send, pending } = useRun()
  const r = detail.run
  const current: ApprovalPolicy = r.approvalPolicy ?? 'auto_review'
  const editable = !['complete', 'stopped', 'failed'].includes(r.status)
  const [err, setErr] = useState('')
  return <PopShell title="Tier 3 approval policy" sub={editable ? 'Switches live' : runStatusLabel(r.status)} footer={err ? <span className="err">{err}</span> : undefined}>
    {approvalPolicies.map(p => {
      const m = approvalPolicyMeta[p]
      return <button key={p} type="button" className={'opt' + (p === current ? ' on' : '')} disabled={!editable || pending > 0 || p === current}
        onClick={() => send({ action: 'set_approval_policy', approvalPolicy: p }).then(onClose, (x: unknown) => setErr(x instanceof Error ? x.message : 'Could not switch the policy'))}>
        <b>{m.optionLabel}{p === current && <span className="tag accent" style={{ marginLeft: 'auto' }}>Active</span>}</b>
        <small>{m.summary}</small>
      </button>
    })}
  </PopShell>
}

function ScopePopover({ onClose, onEdit }: { onClose: () => void; onEdit: () => void }) {
  const { detail } = useRun()
  const model = useRunModel()
  const r = detail.run
  return <PopShell title="Scope" sub={`${plural(model.scopeOrigins.length, 'host')} · revision ${r.scopeRevision}`}
    footer={<><button type="button" className="btn ghost" onClick={onClose}>Close</button>
      <button type="button" className="btn" onClick={onEdit}><Icon name="edit" />{r.status === 'waiting' ? 'Review scope' : 'Edit scope'}</button></>}>
    <p>{capabilityTierMeta[r.capabilityTier].name}. {capabilityTierMeta[r.capabilityTier].summary}</p>
    <div className="hostlist mono">
      {model.scopeOrigins.map(o => {
        const t = model.risk.get(o)
        return <div key={o} title={o}><span>{host(o)}</span>{t && <TierBars tier={t.riskTier as RiskTier} />}</div>
      })}
    </div>
  </PopShell>
}

function GoalPopover({ onClose }: { onClose: () => void }) {
  const { detail, send, pending } = useRun()
  const [goal, setGoal] = useState(detail.run.goal)
  const [err, setErr] = useState('')
  return <form onSubmit={e => {
    e.preventDefault()
    send({ action: 'revise', goal }).then(onClose, (x: unknown) => setErr(x instanceof Error ? x.message : 'Could not revise the goal'))
  }}>
    <PopShell title="Revise goal" sub={`Revision ${detail.run.goalRevision}`}
      footer={<>{err && <span className="err">{err}</span>}<button type="button" className="btn ghost" onClick={onClose}>Cancel</button>
        <button type="submit" className="btn primary" disabled={pending > 0 || !goal.trim() || goal === detail.run.goal}>Save goal</button></>}>
      <p>The coordinator replans from the revised goal; earlier workers stay in the history.</p>
      <textarea className="field-in" rows={6} maxLength={8000} value={goal} onChange={e => setGoal(e.target.value)} autoFocus aria-label="Goal" />
    </PopShell>
  </form>
}
