// Run line header: breadcrumb with goal, then status · phase track · round ·
// budget meter · request meter · testing mode and hosts · elapsed. Items drop by
// priority when the line overflows. Primary action + "…" menu carry run-level
// commands: resume/pause, budget, approval policy, scope, goal revision,
// exports, stop, delete.
import { Link, useNavigate, useRouter } from '@tanstack/react-router'
import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import type { FormEvent, ReactNode, RefObject } from 'react'
import { downloadReportMarkdown, exportSarifAction, removeRun } from '../../actions.ts'
import { approvalPolicies, maxBudgetRequests, maxRpsPerOriginCeiling } from '../../domain.ts'
import type { ApprovalPolicy } from '../../domain.ts'
import { approvalPolicyMeta, capabilityTierMeta } from '../run-state.ts'
import { Dialog, DialogContent, DialogTitle } from '../ui/dialog.tsx'
import { useRun, useRunModel } from './data.tsx'
import type { Command } from './data.tsx'
import { Tag } from './display.tsx'
import { fmtAgo, fmtDur, fmtFullDateTime, fmtN, fmtTime, fmtUsd, host, plural, short } from './format.ts'
import { PhaseTrack, StatusGlyph, TierBars } from './glyphs.tsx'
import { Icon } from './icons.tsx'
import type { IconName } from './icons.tsx'
import { useShortcuts } from './keyboard.tsx'
import { normFStatus, PHASE_LABEL, runStatusLabel } from './meta.ts'
import type { RiskTier } from './meta.ts'
import { Meter } from './motion.tsx'
import { useNav } from './nav.tsx'
import { useOverlays } from './overlays.tsx'
import { useToast } from './toast.tsx'
import { cn, runBtn, runDdItem, RW } from './tw.ts'

export const PUBLIC_MAX_RPS_CAP = 20

/** Live RPS slider ceiling: polite cap (20) on public targets, 100 on local-lab. */
export function effectiveRpsCap(environment: string): number {
  return environment === 'local-lab' ? maxRpsPerOriginCeiling : PUBLIC_MAX_RPS_CAP
}

/** Build a `raise_budget` command omitting unchanged budget fields so RPS-only edits succeed near cap. */
export function buildBudgetCommand(
  run: { status: string; budgetUsd: number; spentUsd: number; budgetRequests: number; spentRequests: number; maxRpsPerOrigin: number },
  draft: { usd: number; unlimited: boolean; cap: number; rps: number },
  rpsMax: number,
): Extract<Command, { action: 'raise_budget' }> | null {
  const usdChanged = draft.usd !== run.budgetUsd
  const nextBudgetRequests = draft.unlimited ? 0 : Math.min(maxBudgetRequests, Math.round(draft.cap))
  const reqChanged = nextBudgetRequests !== run.budgetRequests
  const clampedRps = Math.min(rpsMax, Math.max(1, Math.round(draft.rps)))
  const rpsChanged = clampedRps !== run.maxRpsPerOrigin
  const isBudgetPaused = run.status === 'budget_paused'
  if (!usdChanged && !reqChanged && !rpsChanged && !isBudgetPaused) return null
  const cmd: Extract<Command, { action: 'raise_budget' }> = {
    action: 'raise_budget',
    resume: isBudgetPaused,
  }
  if (usdChanged || (isBudgetPaused && run.spentUsd >= run.budgetUsd)) {
    cmd.budgetUsd = draft.usd
  }
  if (reqChanged || (isBudgetPaused && run.budgetRequests > 0 && run.spentRequests >= run.budgetRequests)) {
    cmd.budgetRequests = draft.unlimited ? 0 : Math.max(run.spentRequests + 1, nextBudgetRequests)
  }
  if (rpsChanged) {
    cmd.maxRpsPerOrigin = clampedRps
  }
  return cmd
}

type Popover = 'menu' | 'budget' | 'policy' | 'leases' | 'scope' | 'goal' | null

/** Hide run-line items by priority (data-p, lowest first) until the line fits. */
function useFitRunline(ref: RefObject<HTMLDivElement | null>, deps: unknown[]) {
  useLayoutEffect(() => {
    const rl = ref.current
    if (!rl) return
    const fit = () => {
      const items = [...rl.querySelectorAll<HTMLElement>('[data-rl][data-p]')].sort((a, b) => Number(a.dataset.p) - Number(b.dataset.p))
      items.forEach(i => { i.style.display = '' })
      for (const it of items) { if (rl.scrollWidth <= rl.clientWidth + 1) break; it.style.display = 'none' }
      const vis = [...rl.querySelectorAll<HTMLElement>('[data-rl]')].filter(x => x.style.display !== 'none')
      rl.querySelectorAll<HTMLElement>('[data-rl]').forEach(x => {
        if (x === vis[vis.length - 1]) x.dataset.lastv = 'true'
        else delete x.dataset.lastv
      })
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

const rlItemClass =
  'mr-3 inline-flex h-3.5 flex-none items-center gap-1.5 whitespace-nowrap border-r border-line pr-3 last:border-r-0 data-[lastv=true]:border-r-0'
const rlBtnClass =
  'group/rlb mr-3 inline-flex h-3.5 flex-none cursor-pointer items-center gap-1.5 whitespace-nowrap rounded-none border-0 border-r border-line bg-transparent p-0 pr-3 font-sans text-[12.5px] font-normal text-inherit shadow-none last:border-r-0 data-[lastv=true]:border-r-0 hover:bg-transparent'

export function RunHeader() {
  const { detail, send, pending } = useRun()
  const model = useRunModel()
  const nav = useNav()
  const toast = useToast()
  const openScope = useOverlays().editScope
  const navigate = useNavigate()
  const router = useRouter()
  const r = detail.run
  const [pop, setPop] = useState<Popover>(null)
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [editingLabel, setEditingLabel] = useState(false)
  const [labelDraft, setLabelDraft] = useState(r.label ?? '')
  const wrap = useRef<HTMLDivElement>(null)
  const rl = useRef<HTMLDivElement>(null)
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!editingLabel) setLabelDraft(r.label ?? '')
  }, [r.id, r.label, editingLabel])
  useEffect(() => {
    if (r.status !== 'running') return
    setNow(Date.now())
    const id = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(id)
  }, [r.status])
  const dur = r.status === 'running' ? Math.max(0, now - r.createdAt) : Math.max(0, model.end - r.createdAt)
  const bPct = r.budgetUsd ? r.spentUsd / r.budgetUsd : 0
  const rPct = r.budgetRequests ? r.spentRequests / r.budgetRequests : 0
  const scopeN = model.scopeOrigins.length
  const activeLeases = detail.approvalLeases ?? []
  const activePatterns = (detail.approvedEndpointPatterns ?? r.approvedEndpointPatterns ?? []).filter(
    p => p.scopeRevision === undefined || p.scopeRevision === r.scopeRevision,
  )
  const unmatchedPatterns = activePatterns.filter(
    p => !activeLeases.some(
      l => l.origin === p.origin && l.method.toUpperCase() === p.method.toUpperCase() && l.routePattern === p.pathPattern,
    ),
  )
  const totalGrants = activeLeases.length + unmatchedPatterns.length
  const editable = !['complete', 'stopped', 'failed'].includes(r.status)
  const hasActiveWorkers = r.status === 'running'
    || detail.assignments.some(a => a.status === 'running' || a.status === 'waiting_approval')
  const hasRunningLab = Boolean(detail.labTarget)
  useFitRunline(rl, [r.status, r.phase, r.spentUsd, r.spentRequests, scopeN, totalGrants])

  useEffect(() => {
    if (!pop) return
    const down = (e: MouseEvent) => { if (!wrap.current?.contains(e.target as Node) && !(e.target as HTMLElement).closest?.('[data-rl-btn]')) setPop(null) }
    document.addEventListener('mousedown', down)
    return () => document.removeEventListener('mousedown', down)
  }, [pop])
  useShortcuts([{ key: 'Escape', allowInInput: true, run: () => setPop(null) }], { priority: 50, enabled: pop != null })

  const run = (cmd: Parameters<typeof send>[0], done?: string) => send(cmd).then(() => { if (done) toast.show(done) }, () => {})

  let action: ReactNode = null
  if (r.status === 'paused' || r.status === 'stopped' || r.status === 'failed') {
    action = <button type="button" className={runBtn()} disabled={pending > 0} onClick={() => run({ action: 'resume' }, 'Resuming the run')}><Icon name="play" />Resume</button>
  } else if (r.status === 'budget_paused') {
    action = <button type="button" className={runBtn({ variant: 'primary' })} onClick={() => setPop(pop === 'budget' ? null : 'budget')}><Icon name="budget" />Raise budget</button>
  } else if (r.status === 'running') {
    action = <button type="button" className={runBtn()} disabled={pending > 0} onClick={() => run({ action: 'pause' }, 'Pausing the run')}><Icon name="pause" />Pause</button>
  } else if (r.status === 'waiting') {
    action = <button type="button" className={runBtn({ variant: 'primary' })} onClick={() => nav.setView('overview')}>Review scope</button>
  } else if (model.report && nav.view !== 'report') {
    action = <button type="button" className={runBtn()} onClick={() => nav.setView('report')}><Icon name="report" />Report</button>
  }

  const item = (icon: IconName, label: ReactNode, onClick: () => void, opts: { disabled?: boolean; danger?: boolean; right?: ReactNode } = {}) =>
    <button type="button" className={runDdItem({ danger: opts.danger })} disabled={opts.disabled} onClick={() => { if (!opts.disabled) onClick() }}>
      <Icon name={icon} className={opts.danger ? 'text-danger' : 'text-fg-subtle'} />
      <span>{label}</span>
      {opts.right != null && <span className="ml-auto text-[11.5px] text-fg-subtle">{opts.right}</span>}
    </button>

  return <header className="flex-none border-b border-line px-[18px]">
    <div className="flex h-11 min-w-0 items-center gap-2">
      <Link to="/projects/$projectId" params={{ projectId: detail.project.id }} className="whitespace-nowrap text-fg-subtle hover:text-fg" title="Open project">
        {detail.project.name}
      </Link>
      <span className="text-fg-faint">/</span>
      <button
        type="button"
        className="group/cc num -mx-1 -my-0.5 inline-flex h-auto cursor-pointer items-center gap-[5px] whitespace-nowrap rounded-[5px] border-0 bg-transparent px-1.5 py-0.5 font-sans text-[13px] font-normal text-fg-muted shadow-none transition-[background-color,color] duration-[var(--d1)] hover:bg-hover hover:text-fg"
        title={`Copy run ID (${short(r.id)}) · Started ${fmtFullDateTime(r.createdAt)}`}
        aria-label={`Copy run ID ${short(r.id)}`}
        suppressHydrationWarning
        onClick={() => void navigator.clipboard?.writeText(r.id).then(
          () => toast.show('Copied run ID', { icon: 'check', sub: short(r.id) }),
          () => toast.show('Could not copy run ID', { tone: 'error' }),
        )}
      >
        <span>{fmtAgo(r.createdAt)}</span>
        <Icon name="copy" size={11} className="text-fg-subtle opacity-65 transition-[opacity,color] duration-[var(--d1)] group-hover/cc:text-fg-muted group-hover/cc:opacity-100" />
      </button>
      {editingLabel ? (
        <form
          className="flex min-w-0 flex-1 items-center gap-1.5"
          onSubmit={e => {
            e.preventDefault()
            const trimmed = labelDraft.trim()
            const nextLabel = trimmed ? trimmed : null
            void send({ action: 'rename_run', label: nextLabel }).then(
              () => {
                setEditingLabel(false)
                toast.show(nextLabel ? 'Run renamed' : 'Run label cleared', { icon: 'check' })
              },
              (err: unknown) => toast.show(err instanceof Error ? err.message : 'Could not rename the run.', { tone: 'error' }),
            )
          }}
        >
          <input
            className={cn(RW.fieldInput, 'h-7 min-w-[160px] max-w-[420px] flex-1')}
            value={labelDraft}
            maxLength={160}
            placeholder={r.goal}
            aria-label="Run label"
            autoFocus
            onChange={e => setLabelDraft(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Escape') {
                e.preventDefault()
                setEditingLabel(false)
                setLabelDraft(r.label ?? '')
              }
            }}
          />
          <button type="submit" className={runBtn({ variant: 'primary', size: 'xs' })} disabled={pending > 0}>Save</button>
          <button
            type="button"
            className={runBtn({ variant: 'ghost', size: 'xs' })}
            disabled={pending > 0}
            onClick={() => {
              setEditingLabel(false)
              setLabelDraft(r.label ?? '')
            }}
          >
            Cancel
          </button>
        </form>
      ) : (
        <div className="flex min-w-0 flex-1 items-center gap-1">
          <span
            className="min-w-0 cursor-default truncate font-medium text-fg"
            title={r.label ? `${r.label} — Goal: ${r.goal}` : r.goal}
            onDoubleClick={() => {
              setLabelDraft(r.label ?? '')
              setEditingLabel(true)
            }}
          >
            {r.label || r.goal}
          </span>
          <button
            type="button"
            className="inline-flex size-5 flex-none cursor-pointer items-center justify-center rounded-[4px] border-0 bg-transparent p-0 text-fg-subtle opacity-60 transition-[background-color,color,opacity] duration-[var(--d1)] hover:bg-hover hover:text-fg hover:opacity-100"
            title="Rename run"
            aria-label="Rename run"
            onClick={() => {
              setLabelDraft(r.label ?? '')
              setEditingLabel(true)
            }}
          >
            <Icon name="edit" size={11} />
          </button>
        </div>
      )}
      <span className="relative flex items-center gap-1.5" ref={wrap}>
        {action}
        <button
          type="button"
          className={cn(runBtn({ variant: 'ghost' }), 'px-1.5')}
          title="More actions"
          aria-label="More actions"
          aria-haspopup="menu"
          aria-expanded={pop === 'menu'}
          onClick={() => setPop(pop === 'menu' ? null : 'menu')}
        >
          <Icon name="dots" />
        </button>
        <button
          type="button"
          className={cn(runBtn({ variant: nav.paneCollapsed ? 'ghost' : 'ghostOn' }), 'px-1.5')}
          title={nav.paneCollapsed ? 'Show panel (])' : 'Hide panel (])'}
          aria-label={nav.paneCollapsed ? 'Show panel' : 'Hide panel'}
          aria-pressed={!nav.paneCollapsed}
          onClick={() => nav.togglePane()}
        >
          <Icon name="panelR" />
        </button>
        {pop === 'menu' && <div className="absolute right-0 top-8 z-30 min-w-[232px] origin-top-right rounded-card bg-raise p-1.5 shadow-popover" role="menu">
          {item('budget', 'Budget and rate limit…', () => setPop('budget'), { right: fmtUsd(r.budgetUsd) })}
          {r.capabilityTier === 3 && item('shield', 'Approval policy…', () => setPop('policy'), { right: approvalPolicyMeta[r.approvalPolicy ?? 'auto_review'].short })}
          {(totalGrants > 0 || r.capabilityTier === 3) && item('lock', 'Approval leases…', () => setPop('leases'), { right: totalGrants > 0 ? String(totalGrants) : 'None' })}
          {item('globe', 'Scope hosts…', () => setPop('scope'), { right: plural(scopeN, 'host') })}
          {item('edit', 'Rename run', () => { setPop(null); setLabelDraft(r.label ?? ''); setEditingLabel(true) })}
          {item('edit', 'Revise goal…', () => setPop('goal'), { disabled: !editable })}
          <div className={RW.menuSep} />
          {item('chat', 'Open the board', () => { setPop(null); nav.openChat(null) }, { right: 'C' })}
          {model.report && item('download', 'Download report (Markdown)', () => {
            setPop(null)
            downloadReportMarkdown({ data: { runId: r.id, reportId: model.report!.id } }).then(res => download(res.content, res.filename, 'text/markdown; charset=utf-8'), () => toast.show('Could not export the report', { tone: 'error' }))
          })}
          {model.report && item('download', 'Export SARIF 2.1.0', () => {
            setPop(null)
            exportSarifAction({ data: { runId: r.id, reportId: model.report!.id } }).then(res => download(res.content, res.filename, 'application/sarif+json; charset=utf-8'), () => toast.show('Could not export SARIF', { tone: 'error' }))
          })}
          <div className={RW.menuSep} />
          {editable && r.status !== 'waiting' && item('stop', 'Stop run', () => {
            setPop(null)
            void send({ action: 'stop' }).then(
              () => toast.show('Stopping the run', { sub: 'A partial report is saved', icon: 'stop' }),
              (e: unknown) => toast.show(e instanceof Error ? e.message : 'Could not stop the run.', { tone: 'error' }),
            )
          }, { danger: true })}
          {item('trash', 'Delete run…', () => {
            setPop(null)
            setDeleteOpen(true)
          }, { danger: true })}
        </div>}
        {pop === 'budget' && <BudgetPopover onClose={() => setPop(null)} />}
        {pop === 'policy' && <PolicyPopover onClose={() => setPop(null)} />}
        {pop === 'leases' && <LeasesPopover onClose={() => setPop(null)} />}
        {pop === 'scope' && <ScopePopover onClose={() => setPop(null)} onEdit={() => { setPop(null); openScope() }} />}
        {pop === 'goal' && <GoalPopover onClose={() => setPop(null)} />}
      </span>
    </div>
    {deleteOpen && <DeleteRunDialog
      hasActiveWorkers={hasActiveWorkers}
      hasRunningLab={hasRunningLab}
      onClose={() => setDeleteOpen(false)}
      onDeleted={async () => {
        setDeleteOpen(false)
        toast.show('Run deleted', { icon: 'check' })
        await router.invalidate()
        await navigate({ to: '/projects/$projectId', params: { projectId: detail.project.id }, replace: true })
      }}
    />}
    <div className="num -mt-1.5 flex h-[34px] items-center overflow-hidden whitespace-nowrap text-[12.5px] text-fg-muted" ref={rl}>
      <span className={rlItemClass} data-rl=""><StatusGlyph status={r.status} /><b className="font-medium text-fg">{runStatusLabel(r.status)}</b></span>
      <span className={rlItemClass} data-rl="">
        <PhaseTrack phase={r.phase} />
        {r.phase !== 'complete' && <span>{PHASE_LABEL[r.phase] ?? r.phase}</span>}
        <span className="text-fg-subtle">{r.phase === 'complete' ? '' : '· '}Round {r.roundNo}</span>
      </span>
      <button
        type="button"
        className={rlBtnClass}
        data-rl=""
        data-rl-btn=""
        title={`Budget ${fmtUsd(r.spentUsd)} of ${fmtUsd(r.budgetUsd)} · ${fmtN(r.spentTokens)} tokens`}
        onClick={() => setPop(pop === 'budget' ? null : 'budget')}
      >
        <Meter id="hdr.budget" value={bPct} />
        <b className="font-medium text-fg">{fmtUsd(r.spentUsd)}</b>
        <span className="text-fg-subtle group-hover/rlb:text-fg-muted">/ {fmtUsd(r.budgetUsd)}</span>
      </button>
      <span className={rlItemClass} data-rl="" title="HTTP requests sent through the safety proxy">
        {r.budgetRequests > 0 && <Meter id="hdr.req" value={rPct} />}
        <b className="font-medium text-fg">{fmtN(r.spentRequests)}</b>
        <span className="text-fg-subtle">{r.budgetRequests ? '/ ' + fmtN(r.budgetRequests) + ' req' : 'req · uncapped'}</span>
      </span>
      <button
        type="button"
        className={rlBtnClass}
        data-rl=""
        data-rl-btn=""
        data-p="2"
        title={`${capabilityTierMeta[r.capabilityTier].name} · ${approvalPolicyMeta[r.approvalPolicy ?? 'auto_review'].label}`}
        onClick={() => setPop(pop === 'scope' ? null : 'scope')}
      >
        <span className="group-hover/rlb:text-fg">{capabilityTierMeta[r.capabilityTier].short}</span>
        <span className="text-fg-subtle group-hover/rlb:text-fg-muted">· {plural(scopeN, 'host')}</span>
      </button>
      {totalGrants > 0 && <button
        type="button"
        className={rlBtnClass}
        data-rl=""
        data-rl-btn=""
        data-p="3"
        title="Active route approval leases — click to inspect or revoke"
        onClick={() => setPop(pop === 'leases' ? null : 'leases')}
      >
        <Icon name="lock" size={12} className="text-fg-subtle group-hover/rlb:text-fg" />
        <span className="group-hover/rlb:text-fg">Leases</span>
        <span className="text-fg-subtle group-hover/rlb:text-fg-muted">· {totalGrants}</span>
      </button>}
      <span className={rlItemClass} data-rl="" data-p="1" title={`Started ${fmtFullDateTime(r.createdAt)}`} suppressHydrationWarning>
        <span className="text-fg-subtle">{r.status === 'running' || dur > 60_000 ? fmtDur(dur) : 'Created ' + fmtTime(r.createdAt)}</span>
      </span>
    </div>
  </header>
}

function PopShell({ title, sub, children, footer }: { title: ReactNode; sub?: ReactNode; children: ReactNode; footer?: ReactNode }) {
  return <div className="absolute right-0 top-8 z-[31] w-[340px] origin-top-right overflow-hidden rounded-card bg-raise shadow-popover" role="dialog" aria-label={typeof title === 'string' ? title : undefined}>
    <div className="flex items-center gap-2 border-b border-line px-3.5 pb-[9px] pt-[11px] font-medium text-fg">
      {title}
      {sub != null && <span className="ml-auto text-[12px] font-normal text-fg-subtle">{sub}</span>}
    </div>
    <div className="flex max-h-[60vh] flex-col gap-2.5 overflow-auto px-3.5 pb-3 pt-2.5 [&_p]:m-0 [&_p]:text-[12px] [&_p]:leading-[18px] [&_p]:text-fg-subtle">{children}</div>
    {footer && <div className="flex items-center justify-end gap-1.5 border-t border-line bg-sunk px-3 py-[9px]">{footer}</div>}
  </div>
}

function BudgetPopover({ onClose }: { onClose: () => void }) {
  const { detail, send, pending } = useRun()
  const r = detail.run
  const editable = !['complete', 'stopped', 'failed'].includes(r.status)
  const isLocalLab = detail.project.environment === 'local-lab'
  const rpsMax = effectiveRpsCap(detail.project.environment)
  const [usd, setUsd] = useState(r.status === 'budget_paused' ? Math.min(500, Math.max(r.budgetUsd + 10, Math.ceil(r.spentUsd + 10))) : r.budgetUsd)
  const [rps, setRps] = useState(() => Math.min(r.maxRpsPerOrigin, rpsMax))
  const [unlimited, setUnlimited] = useState(r.budgetRequests === 0)
  const [cap, setCap] = useState(r.budgetRequests > 0 ? r.budgetRequests : Math.max(r.spentRequests + 1000, 2500))
  const [err, setErr] = useState('')
  const usdChanged = usd !== r.budgetUsd
  const nextBudgetRequests = unlimited ? 0 : Math.min(maxBudgetRequests, Math.round(cap))
  const reqChanged = nextBudgetRequests !== r.budgetRequests
  const minUsd = r.status === 'budget_paused' || usdChanged
    ? Math.max(0.1, Number((r.spentUsd + 0.01).toFixed(2)))
    : Math.max(0.1, Math.min(r.budgetUsd, Number((r.spentUsd + 0.01).toFixed(2))))
  const minReqCap = r.status === 'budget_paused' || reqChanged
    ? r.spentRequests + 1
    : Math.min(r.budgetRequests || 1, r.spentRequests + 1)
  const submit = (e: FormEvent) => {
    e.preventDefault()
    const cmd = buildBudgetCommand(r, { usd, unlimited, cap, rps }, rpsMax)
    if (!cmd) {
      onClose()
      return
    }
    setErr('')
    send(cmd)
      .then(onClose, (x: unknown) => setErr(x instanceof Error ? x.message : 'Could not update the budget'))
  }
  return <form onSubmit={submit}>
    <PopShell
      title="Budget and rate limit"
      sub={editable ? 'Applies live' : runStatusLabel(r.status)}
      footer={<>
        {err && <span className="mr-auto text-[12px] text-danger">{err}</span>}
        <button type="button" className={runBtn({ variant: 'ghost' })} onClick={onClose}>Cancel</button>
        {editable && <button type="submit" className={runBtn({ variant: 'primary' })} disabled={pending > 0}>{r.status === 'budget_paused' ? 'Update and resume' : 'Update'}</button>}
      </>}
    >
      <p>Spent {fmtUsd(r.spentUsd)} · {fmtN(r.spentRequests)} requests · {fmtN(r.turnsUsed)} turns. Changes apply without restarting workers.</p>
      <label className="flex flex-col gap-1 text-[12px] text-fg-muted">
        <span className="flex items-center gap-1.5">Spend cap (USD)</span>
        <input className={cn(RW.fieldInput, 'num')} type="number" min={minUsd} max={500} step="any" disabled={!editable} value={usd} onChange={e => setUsd(Number(e.target.value))} />
      </label>
      <label className="flex flex-col gap-1 text-[12px] text-fg-muted">
        <span className="flex items-center gap-1.5">Rate limit<span className="num ml-auto text-fg-subtle">{rps} req/s per origin</span></span>
        <input className="w-full accent-[var(--accent)]" type="range" min={1} max={rpsMax} step={1} disabled={!editable} value={rps} onChange={e => setRps(Number(e.target.value))} />
        {!isLocalLab && <span className="text-[11px] text-fg-subtle">Public targets are capped at {PUBLIC_MAX_RPS_CAP} req/s per origin.</span>}
      </label>
      <label className="flex cursor-pointer select-none items-center gap-2 text-[12.5px] text-fg-muted">
        <input className="m-0 size-[13px] accent-[var(--accent)]" type="checkbox" checked={unlimited} disabled={!editable} onChange={e => setUnlimited(e.target.checked)} />
        No request cap
      </label>
      {!unlimited && <label className="flex flex-col gap-1 text-[12px] text-fg-muted">
        <span className="flex items-center gap-1.5">Request cap</span>
        <input className={cn(RW.fieldInput, 'num')} type="number" min={minReqCap} max={maxBudgetRequests} step={1} disabled={!editable} value={cap} onChange={e => setCap(Number(e.target.value))} />
      </label>}
    </PopShell>
  </form>
}

function LeasesList({ onError }: { onError: (msg: string) => void }) {
  const { detail, send, pending } = useRun()
  const toast = useToast()
  const r = detail.run
  const activeLeases = detail.approvalLeases ?? []
  const activePatterns = (detail.approvedEndpointPatterns ?? r.approvedEndpointPatterns ?? []).filter(
    p => p.scopeRevision === undefined || p.scopeRevision === r.scopeRevision,
  )
  const unmatchedPatterns = activePatterns.filter(
    p => !activeLeases.some(
      l => l.origin === p.origin && l.method.toUpperCase() === p.method.toUpperCase() && l.routePattern === p.pathPattern,
    ),
  )

  if (!activeLeases.length && !unmatchedPatterns.length) {
    return <p>No active route approval leases in this scope revision.</p>
  }

  return <div className="flex flex-col gap-1.5" data-testid="approval-leases-list">
    {activeLeases.map(lease => (
      <div
        key={lease.id}
        className="flex items-center gap-2 rounded-[7px] border border-line bg-sunk px-2.5 py-2"
      >
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5 font-mono text-[11.5px] text-fg">
            <span className="rounded bg-panel px-1 py-0.5 text-[10.5px] font-semibold">{lease.method}</span>
            <span className="truncate" title={`${lease.origin}${lease.routePattern}`}>
              {host(lease.origin)}{lease.routePattern}
            </span>
          </div>
          <div className="mt-0.5 text-[11px] text-fg-subtle">
            {lease.expiresAt ? `Expires ${fmtTime(lease.expiresAt)}` : 'No expiry'}
            {' · '}
            {plural(lease.uses, 'use')}
            {lease.personaHandle ? ` · @${lease.personaHandle}` : ''}
          </div>
        </div>
        <button
          type="button"
          className={runBtn({ variant: 'ghost', size: 'xs' })}
          disabled={pending > 0}
          aria-label={`Revoke ${lease.method} ${lease.routePattern}`}
          onClick={() => {
            onError('')
            void send({ action: 'revoke_approval_lease', leaseId: lease.id }).then(
              () => toast.show('Approval lease revoked'),
              (x: unknown) => onError(x instanceof Error ? x.message : 'Could not revoke the lease'),
            )
          }}
        >
          Revoke
        </button>
      </div>
    ))}
    {unmatchedPatterns.map(pattern => (
      <div
        key={`${pattern.origin}:${pattern.method}:${pattern.pathPattern}:${pattern.scopeRevision ?? 'any'}`}
        className="flex items-center gap-2 rounded-[7px] border border-line bg-sunk px-2.5 py-2"
      >
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5 font-mono text-[11.5px] text-fg">
            <span className="rounded bg-panel px-1 py-0.5 text-[10.5px] font-semibold">{pattern.method.toUpperCase()}</span>
            <span className="truncate" title={`${pattern.origin}${pattern.pathPattern}`}>
              {host(pattern.origin)}{pattern.pathPattern}
            </span>
          </div>
          <div className="mt-0.5 text-[11px] text-fg-subtle">
            Pattern rule · Scope rev {pattern.scopeRevision ?? r.scopeRevision}
          </div>
        </div>
        <button
          type="button"
          className={runBtn({ variant: 'ghost', size: 'xs' })}
          disabled={pending > 0}
          aria-label={`Revoke ${pattern.method.toUpperCase()} ${pattern.pathPattern}`}
          onClick={() => {
            onError('')
            void send({
              action: 'remove_approved_pattern',
              origin: pattern.origin,
              method: pattern.method,
              pathPattern: pattern.pathPattern,
              ...(pattern.scopeRevision !== undefined ? { scopeRevision: pattern.scopeRevision } : {}),
            }).then(
              () => toast.show('Approved pattern removed'),
              (x: unknown) => onError(x instanceof Error ? x.message : 'Could not remove the pattern'),
            )
          }}
        >
          Revoke
        </button>
      </div>
    ))}
  </div>
}

function LeasesPopover({ onClose }: { onClose: () => void }) {
  const { detail } = useRun()
  const r = detail.run
  const activeLeases = detail.approvalLeases ?? []
  const activePatterns = (detail.approvedEndpointPatterns ?? r.approvedEndpointPatterns ?? []).filter(
    p => p.scopeRevision === undefined || p.scopeRevision === r.scopeRevision,
  )
  const unmatchedPatterns = activePatterns.filter(
    p => !activeLeases.some(
      l => l.origin === p.origin && l.method.toUpperCase() === p.method.toUpperCase() && l.routePattern === p.pathPattern,
    ),
  )
  const totalGrants = activeLeases.length + unmatchedPatterns.length
  const [err, setErr] = useState('')

  return <PopShell
    title="Approval leases"
    sub={totalGrants > 0 ? `${totalGrants} active` : 'None'}
    footer={<>
      {err && <span className="mr-auto text-[12px] text-danger">{err}</span>}
      <button type="button" className={runBtn({ variant: 'ghost' })} onClick={onClose}>Close</button>
    </>}
  >
    <p>Route-level write approvals granted in scope revision {r.scopeRevision}. Revoking requires approval again for future writes.</p>
    <LeasesList onError={setErr} />
  </PopShell>
}

function PolicyPopover({ onClose }: { onClose: () => void }) {
  const { detail, send, pending } = useRun()
  const r = detail.run
  const current: ApprovalPolicy = r.approvalPolicy ?? 'auto_review'
  const editable = !['complete', 'stopped', 'failed'].includes(r.status)
  const activeLeases = detail.approvalLeases ?? []
  const activePatterns = (detail.approvedEndpointPatterns ?? r.approvedEndpointPatterns ?? []).filter(
    p => p.scopeRevision === undefined || p.scopeRevision === r.scopeRevision,
  )
  const unmatchedPatterns = activePatterns.filter(
    p => !activeLeases.some(
      l => l.origin === p.origin && l.method.toUpperCase() === p.method.toUpperCase() && l.routePattern === p.pathPattern,
    ),
  )
  const totalGrants = activeLeases.length + unmatchedPatterns.length
  const [err, setErr] = useState('')
  return <PopShell title="Approval policy" sub={editable ? 'Switches live' : runStatusLabel(r.status)} footer={err ? <span className="mr-auto text-[12px] text-danger">{err}</span> : undefined}>
    {approvalPolicies.map(p => {
      const m = approvalPolicyMeta[p]
      const on = p === current
      return <button
        key={p}
        type="button"
        className={cn(
          'flex h-auto w-full cursor-pointer flex-col gap-0.5 whitespace-normal rounded-[7px] border-0 px-2.5 py-2 text-left font-sans transition-[background-color,box-shadow] duration-[var(--d1)] disabled:cursor-default disabled:opacity-50',
          on
            ? 'bg-accent-soft shadow-[inset_0_0_0_1.5px_var(--accent-line)] hover:bg-accent-soft'
            : 'bg-transparent shadow-[inset_0_0_0_1px_var(--line)] hover:bg-hover',
        )}
        disabled={!editable || pending > 0 || on}
        onClick={() => send({ action: 'set_approval_policy', approvalPolicy: p }).then(onClose, (x: unknown) => setErr(x instanceof Error ? x.message : 'Could not switch the policy'))}
      >
        <b className="flex w-full items-center gap-1.5 text-[12.5px] font-medium text-fg">
          {m.optionLabel}
          {on && <Tag tone="accent" className="ml-auto">Active</Tag>}
        </b>
        <small className="text-[11.5px] font-normal leading-4 text-fg-subtle">{m.summary}</small>
      </button>
    })}
    {totalGrants > 0 && <div className="mt-1 border-t border-line pt-2.5">
      <div className="mb-1.5 flex items-center justify-between text-[11.5px] font-medium text-fg-muted">
        <span>Active leases</span>
        <span className="num text-fg-subtle">{totalGrants}</span>
      </div>
      <LeasesList onError={setErr} />
    </div>}
  </PopShell>
}

function ScopePopover({ onClose, onEdit }: { onClose: () => void; onEdit: () => void }) {
  const { detail } = useRun()
  const model = useRunModel()
  const r = detail.run
  return <PopShell
    title="Scope"
    sub={`${plural(model.scopeOrigins.length, 'host')} · revision ${r.scopeRevision}`}
    footer={<>
      <button type="button" className={runBtn({ variant: 'ghost' })} onClick={onClose}>Close</button>
      {r.phase !== 'consent' && <button type="button" className={runBtn()} onClick={onEdit}><Icon name="edit" />{r.status === 'waiting' ? 'Review scope' : 'Edit scope'}</button>}
    </>}
  >
    <p>{capabilityTierMeta[r.capabilityTier].name}. {capabilityTierMeta[r.capabilityTier].summary}</p>
    <div className="-mx-1.5 flex flex-col font-mono">
      {model.scopeOrigins.map(o => {
        const t = model.risk.get(o)
        return <div key={o} className="flex h-[26px] items-center gap-2 rounded-[5px] px-1.5 text-[12px] text-fg-muted hover:bg-hover" title={o}>
          <span className="truncate">{host(o)}</span>
          {t && <TierBars tier={t.riskTier as RiskTier} className="ml-auto" />}
        </div>
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
    <PopShell
      title="Revise goal"
      sub={`Revision ${detail.run.goalRevision}`}
      footer={<>
        {err && <span className="mr-auto text-[12px] text-danger">{err}</span>}
        <button type="button" className={runBtn({ variant: 'ghost' })} onClick={onClose}>Cancel</button>
        <button type="submit" className={runBtn({ variant: 'primary' })} disabled={pending > 0 || !goal.trim() || goal === detail.run.goal}>Save goal</button>
      </>}
    >
      <p>The coordinator replans from the revised goal; earlier workers stay in the history.</p>
      <textarea className={RW.fieldTextarea} rows={6} maxLength={8000} value={goal} onChange={e => setGoal(e.target.value)} autoFocus aria-label="Goal" />
    </PopShell>
  </form>
}

function DeleteRunDialog({ hasActiveWorkers, hasRunningLab, onClose, onDeleted }: {
  hasActiveWorkers: boolean
  hasRunningLab: boolean
  onClose: () => void
  onDeleted: () => Promise<void>
}) {
  const { detail } = useRun()
  const model = useRunModel()
  const r = detail.run
  const [deleting, setDeleting] = useState(false)
  const [err, setErr] = useState('')
  const totalFindings = model.findings.length
  const confirmedFindings = model.findings.filter(f => normFStatus(f.status) === 'confirmed').length
  const isActive = hasActiveWorkers || hasRunningLab
  const dialogTitle = hasActiveWorkers ? 'Stop & delete run' : hasRunningLab ? 'Stop lab & delete run' : 'Delete run'
  const activeWarning = hasActiveWorkers && hasRunningLab
    ? 'This run has active workers and a running local lab container. Confirming will stop active workers and clean up the lab container before deleting.'
    : hasActiveWorkers
      ? 'This run has active workers running. Confirming will stop active workers before deleting.'
      : 'This run still has a running local lab container. Confirming will stop and clean up the lab container before deleting.'
  const confirmIdleLabel = hasActiveWorkers ? 'Stop & delete run' : hasRunningLab ? 'Stop lab & delete run' : 'Delete run'
  const confirmBusyLabel = hasActiveWorkers ? 'Stopping & deleting…' : hasRunningLab ? 'Stopping lab & deleting…' : 'Deleting…'

  useShortcuts([{ key: 'Escape', allowInInput: true, run: () => { if (!deleting) onClose() } }], { priority: 100, exclusive: true })

  async function handleConfirm() {
    if (deleting) return
    setDeleting(true)
    setErr('')
    try {
      await removeRun({ data: { runId: r.id, stopActive: isActive } })
      await onDeleted()
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Could not delete the run.')
      setDeleting(false)
    }
  }

  return <Dialog open closeOnEscape={!deleting} onOpenChange={open => { if (!open && !deleting) onClose() }}>
    <DialogContent className="max-w-[460px] overflow-hidden rounded-2xl border-line-2 p-0" role="alertdialog">
      <div className={RW.sheetH}>
        <Icon name="trash" className="text-danger" />
        <DialogTitle className="text-[13.5px] font-medium text-fg">{dialogTitle}</DialogTitle>
        <button
          type="button"
          className={cn(runBtn({ variant: 'ghost' }), 'ml-auto px-1.5')}
          disabled={deleting}
          onClick={onClose}
          aria-label="Close"
        >
          <Icon name="close" />
        </button>
      </div>
      <div className="flex flex-col gap-3 px-4 py-3.5">
        <p className="m-0 text-[12.5px] leading-[18px] text-fg-muted">
          Permanently delete this run and all of its findings, HTTP traffic, reports, and artifacts. This cannot be undone.
        </p>
        <div className="flex flex-col gap-1.5 rounded-lg border border-line bg-sunk px-3 py-2.5">
          <div className="line-clamp-2 text-[13px] font-medium text-fg" title={r.goal}>{r.label || r.goal}</div>
          <div className="num flex flex-wrap items-center gap-1.5 text-[12px] text-fg-subtle">
            <StatusGlyph status={r.status} />
            <span>{runStatusLabel(r.status)}</span>
            <span className="text-fg-faint">·</span>
            <span>{plural(totalFindings, 'finding')}{confirmedFindings > 0 ? ` (${confirmedFindings} confirmed)` : ''}</span>
            <span className="text-fg-faint">·</span>
            <span>{fmtN(r.spentRequests)} req · {fmtUsd(r.spentUsd)}</span>
          </div>
        </div>
        {isActive && <div className="flex items-start gap-2 rounded-lg bg-warn-soft px-[11px] py-[9px] text-[12px] leading-[17px] text-fg shadow-[inset_0_0_0_1px_var(--warn-line)]" role="status">
          <Icon name="alert" className="mt-0.5 flex-none text-warn" />
          <span>{activeWarning}</span>
        </div>}
        {err && <p className="m-0 text-[12px] text-danger" role="alert">{err}</p>}
      </div>
      <div className={cn(RW.sheetF, 'justify-end')}>
        <button type="button" className={runBtn({ variant: 'ghost' })} disabled={deleting} onClick={onClose}>Cancel</button>
        <button type="button" className={runBtn({ variant: 'dangerSolid' })} disabled={deleting} onClick={() => void handleConfirm()}>
          <Icon name="trash" />
          {deleting ? confirmBusyLabel : confirmIdleLabel}
        </button>
      </div>
    </DialogContent>
  </Dialog>
}
