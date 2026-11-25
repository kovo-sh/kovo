// Board pane (swarm message board) in the right pane: shown when nothing is
// selected, on chat-first views, or after C / "Board".
//
// - Compact filter bar + Agents dropdown with live state (working / waiting /
//   paused / retired); a member filters the timeline, ↗ opens its active worker.
// - Pending approvals pinned on top (shared decision store: stamp now, send
//   `decide_approval` when the 6 s undo window closes).
// - Timeline: board posts (kind label, mentions, reply, fact / exchange /
//   finding / step chips with inline detail + cross-link, inline approval cards)
//   merged with the coordinator thread.
// - Composer: plain text sends `message`; text with @mentions sends `board_post`.
import { useEffect, useLayoutEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react'
import type { ReactNode } from 'react'
import { canonicalBoardHandles, maxBoardBodyLength, parseBoardMentions, specialistProfileByHandle } from '../../domain.ts'
import type { BoardMessageKind } from '../../domain.ts'
import { boardRoleLabels, boardStateMeta } from '../run-state.ts'
import { Dropdown } from './controls.tsx'
import { useRun, useRunModel } from './data.tsx'
import { ACTIONS, approvalCommand, useDecisions } from './decisions.tsx'
import { Kbd } from './display.tsx'
import { cap, capF, fmtDay, fmtTime, host, plural, short, words } from './format.ts'
import { StatusGlyph } from './glyphs.tsx'
import { Icon } from './icons.tsx'
import { useShortcuts } from './keyboard.tsx'
import { PHASE_LABEL, runStatusLabel, stLabel } from './meta.ts'
import type { Approval, Detail, Message } from './model.ts'
import { useLinks, useNav } from './nav.tsx'
import { useToast } from './toast.tsx'
import { cn, runBtn, runDdItem, runIconBtn } from './tw.ts'

type BoardMessage = Detail['boardMessages'][number]
type BoardMember = Detail['boardMembers'][number]
type Filter = 'all' | 'approvals' | 'verdicts' | string
type RefKind = 'fact' | 'exchange' | 'finding' | 'step'

const FILTERS: [Filter, string][] = [['all', 'All'], ['approvals', 'Approvals'], ['verdicts', 'Verdicts']]

const QUIET_KIND_LABELS: Record<BoardMessageKind, string> = {
  brief: 'Brief',
  claim: 'Claim',
  handoff: 'Handoff',
  lead: 'Lead',
  blocker: 'Blocker',
  approval: 'Approval',
  verdict: 'Verdict',
  status: 'Status',
  note: 'Note',
}

function kindColorClass(kind: string): string {
  switch (kind) {
    case 'handoff': case 'lead': case 'claim': return 'text-fg-muted'
    case 'verdict': return 'text-ok'
    case 'blocker': return 'text-danger'
    case 'approval': return 'text-warn'
    default: return 'text-fg-subtle'
  }
}

function memberDotClass(state: string): string {
  if (state === 'working') return 'bg-ok shadow-none animate-pulse motion-reduce:animate-none'
  if (state === 'paused') return 'bg-warn shadow-none'
  if (state === 'retired') return 'bg-fg-faint shadow-none'
  return 'shadow-[inset_0_0_0_1.5px_var(--fg-4)]'
}

function matches(m: BoardMessage, f: Filter) {
  if (f === 'all') return true
  if (f === 'verdicts') return m.kind === 'verdict' || m.kind === 'handoff'
  if (f === 'approvals') return m.kind === 'approval' || Boolean(m.refApprovalId)
  return m.authorHandle === f || m.mentions.includes(f)
}

// ---------------------------------------------------------------- unread (Board button badge)

const seen = new Map<string, number>()
const seenSubs = new Set<() => void>()
const markSeen = (runId: string, seq: number) => {
  if ((seen.get(runId) ?? -1) >= seq) return
  seen.set(runId, seq)
  seenSubs.forEach(f => f())
}
/** Board posts by others since the operator last had the board open (0 while it is open). */
export function useBoardUnread() {
  const { detail } = useRun()
  const runId = detail.run.id
  const last = useSyncExternalStore(cb => { seenSubs.add(cb); return () => { seenSubs.delete(cb) } }, () => seen.get(runId), () => undefined)
  const msgs = detail.boardMessages
  if (last === undefined) return 0
  return msgs.filter(m => m.seq > last && m.authorRole !== 'operator').length
}
/** Seed the read marker when a run is first shown, so only new posts count as unread. */
export function useBoardSeen() {
  const { detail } = useRun()
  const latest = detail.boardMessages.reduce((n, m) => Math.max(n, m.seq), 0)
  useEffect(() => { if (!seen.has(detail.run.id)) markSeen(detail.run.id, latest) }, [detail.run.id, latest])
}

// ---------------------------------------------------------------- approvals

function useApprovalDecide() {
  const model = useRunModel()
  const q = useDecisions()
  return (id: string, act: 'approve' | 'deny') => {
    const a = model.approvalById.get(id)
    q.decide('ap:' + id, act, { command: approvalCommand(id, act), message: `${ACTIONS[act].label} ${a?.method ?? ''} ${host(a?.origin)}${a?.pathAndQuery ?? ''}` })
  }
}

/** One approval row: method · host/path, then ✓ / ✕ (or the decision with Undo). */
function ApprovalRow({ a, inset = false }: { a: Approval; inset?: boolean }) {
  const q = useDecisions()
  const links = useLinks()
  const decide = useApprovalDecide()
  const d = q.get('ap:' + a.id)
  const done = Boolean(d || a.status !== 'pending')
  return <div
    className={cn(
      'flex h-[34px] items-center gap-2 border-t border-line first:border-t-0 text-[12px] transition-[opacity,background-color] duration-[var(--d1)] hover:bg-hover',
      inset ? 'px-0' : 'pl-4 pr-2.5',
    )}
    data-approval-id={a.id}
  >
    <span className="w-[34px] flex-none font-mono text-[11px] font-semibold text-warn">{a.method}</span>
    <span
      className={cn('min-w-0 flex-1 cursor-pointer truncate font-mono text-[12px]', done ? 'text-fg-subtle' : 'text-fg')}
      title={`${a.origin}${a.pathAndQuery} · open in the queue`}
      onClick={() => links.queueItem('ap:' + a.id)}
    >
      {host(a.origin)}<span className="text-fg-subtle">{a.pathAndQuery}</span>
    </span>
    {d ? <>
      <span className="flex flex-none items-center gap-[5px] text-[11.5px] text-fg-subtle">
        <Icon name={ACTIONS[d.act].icon} />{ACTIONS[d.act].label}{d.state === 'pending' ? ' · sending' : ''}
      </span>
      {d.state !== 'sent' && <button type="button" className={runIconBtn({ size: 'sm' })} title="Undo" aria-label="Undo" onClick={() => q.reopen('ap:' + a.id)}><Icon name="undo" /></button>}
    </> : a.status !== 'pending'
      ? <span className="flex flex-none items-center gap-[5px] text-[11.5px] text-fg-subtle"><StatusGlyph status={a.status} />{cap(a.status)}</span>
      : <span className="flex flex-none gap-0.5">
        <button type="button" className={runIconBtn({ size: 'sm', tone: 'danger' })} title={`Deny ${a.method} ${host(a.origin)}${a.pathAndQuery}`} aria-label="Deny" onClick={() => decide(a.id, 'deny')}><Icon name="x" /></button>
        <button type="button" className={runIconBtn({ size: 'sm', tone: 'ok' })} title={`Approve ${a.method} ${host(a.origin)}${a.pathAndQuery}`} aria-label="Approve" onClick={() => decide(a.id, 'approve')}><Icon name="check" /></button>
      </span>}
  </div>
}

function ApprovalsCard() {
  const model = useRunModel()
  const q = useDecisions()
  const nav = useNav()
  const pending = model.detail.approvals.filter(a => a.status === 'pending').sort((a, b) => a.createdAt - b.createdAt)
  if (!pending.length) return null
  const open = pending.filter(a => !q.get('ap:' + a.id))
  const settled = (id: string) => q.get('ap:' + id)?.state === 'sent'
  const shown = pending.slice().sort((a, b) => Number(settled(a.id)) - Number(settled(b.id))).slice(0, 3)
  return <div className="relative z-[2] flex-none border-b border-line bg-panel" data-testid="board-approvals" aria-label="Pending state-change approvals">
    <div className="overflow-hidden">
      <div className="flex h-8 items-center gap-2 border-b border-line bg-[color-mix(in_srgb,var(--sunk)_60%,transparent)] pl-4 pr-2.5 text-[12px] font-medium text-fg">
        <StatusGlyph status={open.length ? 'paused' : 'complete'} />
        <span title="State-changing requests requiring operator approval">{open.length ? 'Pending approvals' : 'Approvals decided'}</span>
        <span className="num font-normal text-fg-subtle">{open.length} of {pending.length} open</span>
        <button
          type="button"
          className={cn(runBtn({ variant: 'ghost', size: 'sm' }), 'ml-auto')}
          onClick={() => {
            const first = q.sections.decide[0]
            if (first) nav.open('queue', { kind: 'queue', id: first.key }, { push: false })
            else nav.setView('queue')
          }}
        >
          Review in queue<Icon name="arrowR" />
        </button>
      </div>
      <div>
        {shown.map(a => <ApprovalRow key={a.id} a={a} />)}
        {pending.length > 3 && <div className="flex h-[34px] items-center justify-center border-t border-line pl-4 pr-2.5 text-[12px] text-fg-subtle">
          <button type="button" className={runBtn({ variant: 'link', size: 'none' })} onClick={() => nav.setView('queue')}>+{pending.length - 3} more in the queue</button>
        </div>}
      </div>
    </div>
  </div>
}

// ---------------------------------------------------------------- agents dropdown (merged into compact filter bar)

function AgentsDropdown({ members, filter, setFilter }: { members: BoardMember[]; filter: Filter; setFilter: (f: Filter) => void }) {
  const links = useLinks()
  const activeAgent = members.find(m => m.handle === filter)
  const workingCount = members.filter(m => m.state === 'working').length
  return <Dropdown
    menuClassName="top-7 max-h-[280px] w-[236px] overflow-auto p-[5px]"
    btnClassName={cn(
      'inline-flex h-6 flex-none cursor-pointer items-center gap-[5px] whitespace-nowrap rounded-control border-0 px-2 font-sans text-[12px] font-normal shadow-none transition-[background-color,color] duration-[var(--d1)]',
      activeAgent ? 'bg-press text-fg hover:bg-press' : 'bg-transparent text-fg-subtle hover:bg-hover hover:text-fg',
    )}
    title="Filter by agent or jump to an active worker"
    label={<>
      {workingCount > 0 && <i className="inline-block size-[7px] flex-none animate-pulse rounded-full bg-ok motion-reduce:animate-none" aria-hidden="true" />}
      <span>{activeAgent ? '@' + activeAgent.handle : `Agents (${members.length})`}</span>
    </>}
  >
    {close => <div data-testid="board-roster" aria-label="Board roster">
      {activeAgent && <button type="button" className={runDdItem()} onClick={() => { setFilter('all'); close() }}>
        <span>All agents</span>
      </button>}
      {members.map(m => {
        const meta = boardStateMeta[m.state as keyof typeof boardStateMeta] ?? boardStateMeta.waiting
        const on = filter === m.handle
        const profile = m.specialistProfile ?? specialistProfileByHandle[m.handle]
        return <div key={m.id} className={cn('flex items-center gap-0.5', m.state === 'retired' && 'opacity-65')} data-handle={m.handle} data-state={m.state}>
          <button
            type="button"
            className={cn(runDdItem({ active: on }), 'h-7 min-w-0 flex-1 px-2')}
            aria-pressed={on}
            title={`${profile ?? boardRoleLabels[m.role] ?? m.role} · ${meta.label}`}
            onClick={() => { setFilter(on ? 'all' : m.handle); close() }}
          >
            <i className={cn('inline-block size-[7px] flex-none rounded-full', memberDotClass(m.state))} aria-hidden="true" />
            <span className="truncate">@{m.handle}</span>
            <span className="ml-auto text-fg-subtle">{meta.label}</span>
          </button>
          {m.activeAssignmentId && m.state !== 'retired' && <button
            type="button"
            className={cn(runIconBtn(), 'h-[26px] min-w-[26px] flex-none px-1')}
            aria-label={`Inspect @${m.handle}`}
            title={`Open @${m.handle}'s worker in Workflow`}
            onClick={() => { close(); links.worker(m.activeAssignmentId!) }}
          >
            <Icon name="ext" size={12} />
          </button>}
        </div>
      })}
    </div>}
  </Dropdown>
}

// ---------------------------------------------------------------- timeline items

function MessageBody({ text, muted, tainted }: { text: string; muted?: boolean; tainted?: boolean }) {
  const long = text.length > 320
  const [open, setOpen] = useState(false)
  return <>
    <div className={cn(
      'mt-0.5 whitespace-pre-wrap break-words text-[12.5px] leading-[19px]',
      tainted ? 'text-fg-subtle line-through decoration-fg-faint' : muted ? 'text-fg-subtle' : 'text-fg-muted',
      long && !open && 'line-clamp-4',
    )}>
      {text}
    </div>
    {long && <button type="button" className={cn(runBtn({ variant: 'link', size: 'none' }), 'mt-0.5')} onClick={() => setOpen(!open)}>{open ? 'Show less' : 'Show more'}</button>}
  </>
}

/** Inline detail for a referenced fact / exchange / finding / step, with a cross-link. */
function RefDetail({ kind, id }: { kind: RefKind; id: string }) {
  const model = useRunModel()
  const links = useLinks()
  const nav = useNav()
  const linkClass = cn(runBtn({ variant: 'link', size: 'none' }), 'mt-1 flex items-start justify-start gap-1.5 text-left')
  let body: ReactNode
  if (kind === 'fact') {
    const f = model.factById.get(id)
    const w = f ? model.workerById.get(f.assignmentId) : undefined
    body = f ? <>
      <b className="font-medium text-fg">{f.kind} · <span className="font-mono text-[12px]">{host(f.origin)}</span></b>
      <p className="m-0 mt-0.5 text-fg-muted">{f.summary}{f.tainted ? ' (tainted by scope revocation)' : ''}</p>
      {w && <button type="button" className={linkClass} onClick={() => links.worker(w.id)}><Icon name="workflow" />Recorded by {w.title}</button>}
    </> : <p className="m-0 text-fg-subtle">Fact {short(id)} is not loaded in this run.</p>
  } else if (kind === 'exchange') {
    const x = model.exchangeById.get(id)
    body = <>
      {x ? <><b className="font-mono text-[12px] font-medium text-fg">{x.method} {host(x.origin)}{x.pathAndQuery}</b><p className="m-0 mt-0.5 text-fg-muted">HTTP {x.status} · {x.mediaType || 'unknown type'} · {x.personaHandle ?? 'anonymous'}</p></>
        : <p className="m-0 text-fg-subtle">Exchange {short(id)} is outside the loaded window; it opens by id.</p>}
      <button type="button" className={linkClass} onClick={() => links.exchange(id)}><Icon name="exchanges" />Open in Exchanges</button>
    </>
  } else if (kind === 'finding') {
    const f = model.findingById.get(id)
    body = f ? <>
      <b className="font-medium text-fg">{f.title}</b>
      <p className="m-0 mt-0.5 text-fg-muted">{stLabel(f.status)} · {f.severity}{f.category ? ' · ' + f.category : ''}</p>
      <button type="button" className={linkClass} onClick={() => links.finding(f.id)}><Icon name="findings" />Open finding</button>
    </> : <p className="m-0 text-fg-subtle">Finding {short(id)} is not loaded.</p>
  } else {
    const s = model.stepById.get(id)
    body = s ? <>
      <b className="font-medium text-fg">Step #{s.seq} · {s.title}</b>
      <p className="m-0 mt-0.5 text-fg-muted">{stLabel(s.status)} · {s.hypothesis}</p>
      <button type="button" className={linkClass} onClick={() => s.assignedWorkerId ? links.worker(s.assignedWorkerId) : nav.open('workflow', { kind: 'step', id: s.id })}>
        <Icon name="workflow" />Open in Workflow
      </button>
    </> : <p className="m-0 text-fg-subtle">Chain step {short(id)} is not loaded.</p>
  }
  return <div className="mt-1.5 rounded-[7px] bg-sunk px-2.5 py-2 text-[12px] leading-[18px] shadow-[inset_0_0_0_1px_var(--line)] [overflow-wrap:anywhere]" data-testid="board-ref-detail">{body}</div>
}

function InlineApproval({ a }: { a: Approval }) {
  return <div className="mt-1.5 border-y border-line" data-testid="board-approval-inline">
    <div className="flex items-center gap-1.5 pb-0.5 pt-1.5 text-[11.5px] font-medium text-warn" title="State-changing request requiring operator approval">
      <Icon name="shield" /><span>Approval request</span><span className="font-normal text-fg-subtle">· {cap(a.status)}</span>
    </div>
    <ApprovalRow a={a} inset />
  </div>
}

function Avatar({ role, children }: { role: 'op' | 'co' | ''; children: ReactNode }) {
  return <span className={cn(
    'flex size-[22px] items-center justify-center rounded-full text-[10.5px] font-semibold',
    role === 'op'
      ? 'bg-fg text-panel'
      : role === 'co'
        ? 'bg-panel text-fg shadow-[inset_0_0_0_1px_var(--line-strong)]'
        : 'bg-sunk text-fg-muted shadow-[inset_0_0_0_1px_var(--line-2)]',
  )}>
    {children}
  </span>
}

const chipBtnClass = (on: boolean, mono = false) => cn(
  'inline-flex h-5 max-w-full cursor-pointer items-center gap-1 truncate whitespace-nowrap rounded-[5px] border-0 px-[7px] font-normal shadow-none transition-[background-color,color] duration-[var(--d1)]',
  mono ? 'font-mono text-[11px]' : 'font-sans text-[11.5px]',
  on
    ? 'bg-sel text-fg shadow-[inset_0_0_0_1px_var(--sel-line)] hover:bg-sel'
    : 'bg-transparent text-fg-muted shadow-[inset_0_0_0_1px_var(--line-2)] hover:bg-hover hover:text-fg',
)

function BoardPost({ m, filter, setFilter }: { m: BoardMessage; filter: Filter; setFilter: (f: Filter) => void }) {
  const model = useRunModel()
  const [open, setOpen] = useState<{ kind: RefKind; id: string } | null>(null)
  const op = m.authorRole === 'operator'
  const approval = m.refApprovalId ? model.approvalById.get(m.refApprovalId) : undefined
  const mentions = m.mentions.filter(h => h !== 'coordinator' || !op)
  const chip = (kind: RefKind, id: string, label: string, tip: string) => {
    const on = open?.kind === kind && open.id === id
    return <button key={kind + ':' + id} type="button" className={chipBtnClass(on, true)} data-ref-kind={kind} data-ref-id={id} aria-pressed={on} title={tip}
      onClick={() => setOpen(on ? null : { kind, id })}>
      <Icon name={kind === 'exchange' ? 'exchanges' : kind === 'finding' ? 'findings' : kind === 'step' ? 'workflow' : 'fact'} size={12} />{label}
    </button>
  }
  const refLabel = (kind: RefKind, id: string) => {
    if (kind === 'fact') {
      const f = model.factById.get(id)
      return f ? cap(f.kind) + ' · ' + host(f.origin) : 'Recorded fact'
    }
    if (kind === 'exchange') {
      const ex = model.exchangeById.get(id)
      return ex ? ex.method + ' ' + ex.pathAndQuery : 'HTTP exchange'
    }
    if (kind === 'finding') return model.findingById.get(id)?.title ?? 'Finding'
    const step = model.stepById.get(id)
    return step ? 'Step #' + step.seq : 'Plan step'
  }
  const refs: [RefKind, string][] = [...m.refFactIds.map(id => ['fact', id] as [RefKind, string]), ...m.refExchangeIds.map(id => ['exchange', id] as [RefKind, string]),
    ...m.refFindingIds.map(id => ['finding', id] as [RefKind, string]), ...(m.refStepId ? [['step', m.refStepId] as [RefKind, string]] : [])]
  const role: 'op' | 'co' | '' = m.authorRole === 'coordinator' ? 'co' : op ? 'op' : ''
  return <div className="grid grid-cols-[22px_minmax(0,1fr)] gap-2.5" data-role={m.authorRole} data-kind={m.kind} data-tainted={m.tainted} data-seq={m.seq}>
    <Avatar role={role}>{op ? 'Y' : m.authorHandle.charAt(0).toUpperCase()}</Avatar>
    <div className="min-w-0">
      <div className="flex items-baseline gap-2 text-[12.5px] font-medium leading-[18px] text-fg">
        <span>{op ? 'You' : '@' + m.authorHandle}</span>
        <span className={cn('text-[11.5px] font-medium', kindColorClass(m.kind))}>{QUIET_KIND_LABELS[m.kind as BoardMessageKind] ?? cap(m.kind)}</span>
        {m.tainted && <span className="text-[11.5px] font-medium italic text-fg-subtle" title="Scope revoked: excluded from future specialist wakes">Outdated</span>}
        <span className="num ml-auto text-[11.5px] font-normal text-fg-subtle">{fmtTime(m.createdAt)}</span>
      </div>
      <MessageBody text={m.body} tainted={m.tainted} />
      {(mentions.length > 0 || m.replyToSeq) && <div className="mt-[5px] flex flex-wrap gap-1">
        {m.replyToSeq && <span className="num text-[11.5px] text-fg-subtle" data-testid="board-reply">↳ #{m.replyToSeq}</span>}
        {mentions.map(h => <button key={h} type="button" className={chipBtnClass(filter === h)} onClick={() => setFilter(filter === h ? 'all' : h)}>@{h}</button>)}
      </div>}
      {refs.length > 0 && <div className="mt-[5px] flex flex-wrap gap-1" aria-label="Evidence references">{refs.map(([k, id]) => chip(k, id, refLabel(k, id), `${cap(k)} · ID ${id}`))}</div>}
      {open && <RefDetail kind={open.kind} id={open.id} />}
      {approval && <InlineApproval a={approval} />}
    </div>
  </div>
}

const APPROVAL_RE = /^Tier 3 approval required:\s*(\w+)\s+(\S+)/

/** A coordinator-thread message (coordinator / system replies, worker reports, pre-board operator messages). */
function ThreadMessage({ m }: { m: Message }) {
  const model = useRunModel()
  const q = useDecisions()
  const links = useLinks()
  const am = m.role === 'guardian' ? m.content.match(APPROVAL_RE) : null
  if (am) {
    const ap = model.detail.approvals.find(a => a.origin + a.pathAndQuery === am[2] || (a.method === am[1] && am[2].startsWith(a.origin)))
    const d = ap ? q.get('ap:' + ap.id) : undefined
    const st = d ? (d.act === 'approve' ? 'confirmed' : 'dismissed') : ap && ap.status !== 'pending' ? (ap.status === 'approved' ? 'confirmed' : 'dismissed') : 'paused'
    return <div className="grid grid-cols-[22px_minmax(0,1fr)] gap-2.5" data-source="thread" data-role={m.role}>
      <span className="flex size-[22px] items-center justify-center"><StatusGlyph status={st} /></span>
      <div className="min-w-0">
        <div className="flex items-baseline gap-2 text-[12.5px] font-normal leading-[18px] text-fg-muted">
          <span>Approval requested</span>
          <span className="num text-[11.5px] text-fg-subtle">{fmtTime(m.createdAt)}</span>
          {(d || (ap && ap.status !== 'pending')) && <span className="text-[11.5px] text-fg-subtle">· {(d ? ACTIONS[d.act].label : ap!.status).toLowerCase()}</span>}
        </div>
        <div
          className={cn('mt-0.5 truncate whitespace-nowrap font-mono text-[11.5px] leading-[19px] text-fg-subtle', ap && 'cursor-pointer hover:text-fg')}
          onClick={ap ? () => links.queueItem('ap:' + ap.id) : undefined}
        >
          {am[1]} {host(am[2])}
        </div>
      </div>
    </div>
  }
  const who: [string, 'op' | 'co' | '', string] = m.role === 'operator'
    ? ['You', 'op', 'Y']
    : m.role === 'coordinator'
      ? ['Coordinator', 'co', 'C']
      : m.role === 'worker'
        ? [model.workerById.get(m.threadId)?.title ?? 'Worker', '', 'W']
        : ['Kovo Hunter', '', 'K']
  const evidence = (m.evidenceIds ?? []).map(id => model.evidenceById.get(id)).filter(e => !!e)
  return <div className="grid grid-cols-[22px_minmax(0,1fr)] gap-2.5" data-source="thread" data-role={m.role}>
    <Avatar role={who[1]}>
      {who[1] === 'co' ? <svg className="block flex-none" viewBox="0 0 14 14" width="12" height="12" aria-hidden="true"><circle cx="7" cy="7" r="2.5" fill="currentColor" /></svg> : who[2]}
    </Avatar>
    <div className="min-w-0">
      <div className="flex items-baseline gap-2 text-[12.5px] font-medium leading-[18px] text-fg">
        <span className="max-w-[240px] truncate">{who[0]}</span>
        <span className="num text-[11.5px] font-normal text-fg-subtle">{fmtTime(m.createdAt)}</span>
      </div>
      <MessageBody text={m.content} muted={m.role === 'guardian'} />
      {evidence.map(ev => <button key={ev.id} type="button" className={cn(runBtn({ variant: 'link', size: 'none' }), 'mt-1 flex')} onClick={() => links.evidence(ev.id)}><Icon name="fact" />{ev.title}</button>)}
    </div>
  </div>
}

// ---------------------------------------------------------------- pane

export function BoardPane() {
  const { detail, send, pending: inFlight } = useRun()
  const model = useRunModel()
  const nav = useNav()
  const q = useDecisions()
  const toast = useToast()
  const r = detail.run
  const [filter, setFilter] = useState<Filter>('all')
  const [workerMsgs, setWorkerMsgs] = useState(false)
  const [draft, setDraft] = useState('')
  const [outbox, setOutbox] = useState<{ id: string; content: string; at: number; ctx?: string }[]>([])
  const [mention, setMention] = useState<{ query: string; start: number } | null>(null)
  const [hi, setHi] = useState(0)
  const scroller = useRef<HTMLDivElement>(null)
  const composer = useRef<HTMLTextAreaElement>(null)
  const board = detail.boardMessages
  const latestSeq = board.reduce((n, m) => Math.max(n, m.seq), 0)
  useEffect(() => { markSeen(r.id, latestSeq) }, [r.id, latestSeq])

  const members = useMemo(() => {
    const list = detail.boardMembers.slice()
    if (!list.some(m => m.handle === 'coordinator')) {
      list.unshift({
        id: 'coordinator-implicit', runId: r.id, handle: 'coordinator', role: 'coordinator', specialistProfile: null, sessionId: r.coordinatorId,
        activeAssignmentId: null, state: 'waiting', roleAffinity: null, lastReadSeq: 0, turnsUsed: 0, postsCount: 0, peerHopsUsed: 0,
        scopeRevision: r.scopeRevision, goalRevision: r.goalRevision, sourceOrigins: [], createdAt: r.createdAt, updatedAt: r.createdAt,
      } as BoardMember)
    }
    const order = new Map<string, number>(canonicalBoardHandles.map((h, i) => [h, i]))
    return list.sort((a, b) => (order.get(a.handle) ?? 99) - (order.get(b.handle) ?? 99) || a.handle.localeCompare(b.handle))
  }, [detail.boardMembers, r])
  const handles = useMemo(() => [...new Set([...canonicalBoardHandles, ...members.filter(m => m.state !== 'retired').map(m => m.handle), 'all'])], [members])
  const options = mention ? handles.filter(h => h.startsWith(mention.query)).slice(0, 10) : []

  const boardStart = board.length ? Math.min(...board.map(m => m.createdAt)) : Infinity
  const items = useMemo(() => {
    const thread: Message[] = (workerMsgs ? model.coordinatorMessages.concat(model.workerMessages) : model.coordinatorMessages)
      .filter(m => !(m.role === 'operator' && m.createdAt >= boardStart - 1000))
    const showThread = (m: Message) => filter === 'all' || (filter === 'coordinator' && m.role === 'coordinator')
    const out: ({ t: number; s: number; board: BoardMessage } | { t: number; s: number; thread: Message })[] = [
      ...board.filter(m => matches(m, filter)).map(m => ({ t: m.createdAt, s: m.seq, board: m })),
      ...thread.filter(showThread).map(m => ({ t: m.createdAt, s: 0, thread: m })),
    ]
    return out.sort((a, b) => a.t - b.t || a.s - b.s)
  }, [board, model, workerMsgs, filter, boardStart])

  useEffect(() => {
    setOutbox(o => o.filter(x => !board.some(m => m.authorRole === 'operator' && m.createdAt >= x.at - 60_000 && x.content.startsWith(m.body.slice(0, 200)))
      && !model.coordinatorMessages.some(m => m.role === 'operator' && m.content === x.content && m.createdAt >= x.at - 60_000)))
  }, [board, model.coordinatorMessages])
  const total = items.length + outbox.length

  useLayoutEffect(() => {
    const el = scroller.current
    if (el) el.scrollTop = el.scrollHeight
  }, [total, workerMsgs, filter])
  useEffect(() => { if (nav.chat) composer.current?.focus() }, [nav.chat, nav.chatContext])
  useEffect(() => { setHi(0) }, [mention?.query])

  const openApprovals = detail.approvals.filter(a => a.status === 'pending' && !q.get('ap:' + a.id))
  const ctx = nav.chatContext

  const updateDraft = (value: string) => {
    setDraft(value)
    const caret = composer.current?.selectionStart ?? value.length
    const m = /(^|\s)@([a-z0-9_-]*)$/i.exec(value.slice(0, caret))
    setMention(m ? { query: m[2].toLowerCase(), start: caret - m[2].length - 1 } : null)
  }
  const pick = (handle: string) => {
    if (!mention) return
    const caret = composer.current?.selectionStart ?? draft.length
    const before = draft.slice(0, mention.start)
    const after = draft.slice(caret).replace(/^\s+/, '')
    setDraft(`${before}@${handle} ${after}`)
    setMention(null)
    requestAnimationFrame(() => {
      const el = composer.current
      if (!el) return
      el.focus()
      const at = before.length + handle.length + 2
      el.setSelectionRange(at, at)
    })
  }
  const submit = () => {
    const text = draft.trim()
    if (!text) return
    const content = ctx ? `[About: ${ctx.label}]\n${text}` : text
    const mentions = parseBoardMentions(text)
    const id = crypto.randomUUID()
    setOutbox(o => [...o, { id, content, at: Date.now(), ctx: ctx?.label }])
    setDraft('')
    setMention(null)
    const command = mentions.length
      ? { action: 'board_post' as const, body: content.slice(0, maxBoardBodyLength), mentions }
      : { action: 'message' as const, message: content }
    send(command).catch(() => {
      setOutbox(o => o.filter(m => m.id !== id))
      setDraft(text)
      toast.show('Message not sent', { tone: 'error', sub: 'Your draft is back in the composer.' })
    })
  }

  useShortcuts([
    { key: 'mod+enter', allowInInput: true, when: () => document.activeElement === composer.current, run: () => { submit() } },
    { key: 'Escape', allowInInput: true, when: () => document.activeElement === composer.current && !draft.trim() && nav.chat, run: () => { composer.current?.blur(); nav.closeChat() } },
  ], { priority: 20 })

  const placeholder = ctx ? 'Ask about this item…'
    : r.status === 'waiting' ? 'Refine the goal before consenting…' : 'Message the coordinator · @ directs a specialist'

  let lastDay = ''
  const daySep = (t: number) => {
    const day = new Date(t).toDateString()
    if (day === lastDay) return null
    lastDay = day
    return <div className="num mb-3 flex items-center gap-2.5 text-[11.5px] text-fg-subtle before:h-px before:flex-1 before:bg-line before:content-[''] after:h-px after:flex-1 after:bg-line after:content-['']">
      {fmtDay(t)} · {fmtTime(t)}
    </div>
  }

  const statusNote = r.status === 'waiting'
    ? `Waiting for ${r.phase === 'review' ? 'scope approval' : 'consent'} before planning. Review the ${plural(model.surface.origins.length, 'proposed host')} in the main view.`
    : r.status === 'paused' || r.status === 'budget_paused'
      ? `Run paused in ${(PHASE_LABEL[r.phase] ?? r.phase).toLowerCase()}, round ${r.roundNo}.` + (openApprovals.length ? ' ' + capF(words(openApprovals.length)) + ' approval request' + (openApprovals.length > 1 ? 's are' : ' is') + ' waiting on you.' : '')
      : null
  return <div className="flex min-h-0 min-w-0 flex-1 flex-col" data-testid="board-pane">
    <div className="flex h-11 flex-none items-center gap-1.5 border-b border-line pl-4 pr-2.5">
      <div className="flex min-w-0 flex-1 gap-0.5" role="group" aria-label="Pane">
        <button
          type="button"
          className="inline-flex h-[26px] cursor-pointer items-center gap-1.5 whitespace-nowrap rounded-control border-0 bg-press px-[9px] font-sans text-[13px] font-medium text-fg shadow-none hover:bg-press"
          aria-pressed="true"
          title="Swarm board and coordinator thread"
        >
          Board<span className="num text-[12px] font-normal text-fg-subtle">{plural(board.length + model.coordinatorMessages.length, 'message')}</span>
        </button>
        {nav.sel && <button
          type="button"
          className="inline-flex h-[26px] cursor-pointer items-center gap-1.5 whitespace-nowrap rounded-control border-0 bg-transparent px-[9px] font-sans text-[13px] font-medium text-fg-subtle shadow-none hover:bg-hover hover:text-fg"
          aria-pressed="false"
          onClick={() => nav.closeChat()}
          title="Back to the selected item (Esc)"
        >
          Inspector
        </button>}
      </div>
      <span className="inline-flex items-center gap-1.5 text-[11.5px] text-fg-subtle">
        <StatusGlyph status={r.status === 'complete' ? 'complete' : r.status} />
        <span>{runStatusLabel(r.status)}</span>
      </span>
    </div>
    <ApprovalsCard />
    <div className="flex flex-none items-center gap-1 border-b border-line py-1.5 pl-3 pr-2.5" role="group" aria-label="Board filters">
      <div className="inline-flex min-w-0 items-center gap-0.5">
        {FILTERS.map(([k, l]) => {
          const on = filter === k
          return <button
            key={k}
            type="button"
            className={cn(
              'inline-flex h-6 flex-none cursor-pointer items-center gap-[5px] whitespace-nowrap rounded-control border-0 px-2 font-sans text-[12px] font-normal shadow-none transition-[background-color,color] duration-[var(--d1)]',
              on ? 'bg-press text-fg hover:bg-press' : 'bg-transparent text-fg-subtle hover:bg-hover hover:text-fg',
            )}
            aria-pressed={on}
            onClick={() => setFilter(k)}
          >
            {l}
          </button>
        })}
      </div>
      <span className="min-w-2 flex-1" />
      <AgentsDropdown members={members} filter={filter} setFilter={setFilter} />
    </div>
    <div className="relative flex min-h-0 flex-1 flex-col before:pointer-events-none before:absolute before:left-0 before:right-2.5 before:top-0 before:z-[1] before:h-[18px] before:bg-gradient-to-b before:from-panel before:to-transparent before:content-['']">
      <div className="min-h-0 flex-1 overflow-auto" ref={scroller}>
        {model.workerMessages.length > 0 && filter === 'all' && <button
          type="button"
          className="flex h-auto w-full cursor-pointer items-center gap-2 rounded-none border-0 border-b border-line bg-transparent px-4 py-2 text-left font-sans text-[12px] font-normal text-fg-subtle shadow-none hover:bg-hover hover:text-fg"
          onClick={() => setWorkerMsgs(v => !v)}
          aria-pressed={workerMsgs}
        >
          <span className={cn(
            'relative h-3.5 w-6 flex-none rounded-lg transition-colors duration-[var(--d2)] after:absolute after:left-0.5 after:top-0.5 after:size-2.5 after:rounded-full after:bg-white after:transition-transform after:duration-[var(--d2)] after:ease-spring after:content-[""]',
            workerMsgs ? 'bg-accent after:translate-x-2.5' : 'bg-line-strong',
          )} />
          <span>Include worker reports</span>
          <span className="num ml-auto">{model.workerMessages.length}</span>
        </button>}
        <div className="flex flex-col gap-3.5 px-4 pb-2 pt-3.5" data-testid="board-timeline" aria-label="Board timeline">
          {!items.length && <p className="mx-0.5 my-2 text-[12.5px] text-fg-subtle">{filter === 'all' ? 'Nothing on the board yet. Briefs, handoffs and verdicts land here as the run progresses.' : 'No board traffic for this filter yet.'}</p>}
          {items.map(it => <div key={'board' in it ? 'b' + it.board.id : 't' + it.thread.id}>
            {daySep(it.t)}
            {'board' in it ? <BoardPost m={it.board} filter={filter} setFilter={setFilter} /> : <ThreadMessage m={it.thread} />}
          </div>)}
          {outbox.map(m => <div key={m.id} className="grid grid-cols-[22px_minmax(0,1fr)] gap-2.5" data-role="pending">
            <Avatar role="op">Y</Avatar>
            <div className="min-w-0">
              <div className="flex items-baseline gap-2 text-[12.5px] font-medium leading-[18px] text-fg">
                <span>You</span>
                <span className="num text-[11.5px] font-normal text-fg-subtle">{fmtTime(m.at)}</span>
                <span className="text-[11.5px] font-normal text-fg-subtle">· {inFlight ? 'sending' : 'sent'}</span>
              </div>
              <div className="mt-0.5 whitespace-pre-wrap break-words text-[12.5px] leading-[19px] text-fg-subtle">
                {m.ctx ? m.content.replace(/^\[About: [^\]]*\]\n/, '') : m.content}
              </div>
              {m.ctx && <span className="mt-1 inline-flex h-5 max-w-full items-center gap-1.5 rounded-[5px] bg-sunk px-[7px] text-[11.5px] text-fg-muted shadow-[inset_0_0_0_1px_var(--line-2)]">
                <span className="min-w-0 truncate">{m.ctx}</span>
              </span>}
            </div>
          </div>)}
          {statusNote && filter === 'all' && <div className="grid grid-cols-[22px_minmax(0,1fr)] gap-2.5">
            <Avatar role="">K</Avatar>
            <div className="min-w-0">
              <div className="flex items-baseline gap-2 text-[12.5px] font-medium leading-[18px] text-fg">
                Kovo Hunter<span className="text-[11.5px] font-normal text-fg-subtle">now</span>
              </div>
              <div className="mt-0.5 whitespace-pre-wrap break-words text-[12.5px] leading-[19px] text-fg-subtle">{statusNote}</div>
            </div>
          </div>}
        </div>
      </div>
    </div>
    <div className="relative flex-none border-t border-line px-3 pb-3 pt-2.5" data-testid="board-composer">
      {mention && options.length > 0 && <div className="absolute bottom-[calc(100%-4px)] left-3 right-3 z-20 max-h-60 overflow-auto rounded-card bg-raise p-1 shadow-popover" role="listbox" aria-label="Mention roster">
        {options.map((h, i) => <button
          key={h}
          type="button"
          role="option"
          aria-selected={i === hi}
          className={cn(
            'flex h-9 w-full cursor-pointer items-center gap-2.5 rounded-[7px] border-0 px-2.5 text-left font-sans text-[13px] font-normal shadow-none',
            i === hi ? 'bg-press text-fg hover:bg-press' : 'bg-transparent text-fg-muted hover:bg-hover hover:text-fg',
          )}
          onMouseDown={e => { e.preventDefault(); pick(h) }}
          onMouseMove={() => setHi(i)}
        >
          <span className="min-w-0 flex-1 truncate text-fg">@{h}</span>
          <span className="max-w-[200px] truncate whitespace-nowrap text-[11.5px] text-fg-subtle">{specialistProfileByHandle[h] ?? (h === 'all' ? 'broadcast' : 'system')}</span>
        </button>)}
      </div>}
      <div className="rounded-lg bg-raise px-2.5 pb-1.5 pt-2 shadow-hairline transition-shadow duration-[var(--d1)] focus-within:shadow-[0_0_0_1px_var(--accent-line),0_0_0_3px_var(--accent-soft)]">
        {ctx && <span className="mb-1.5 inline-flex h-5 max-w-full items-center gap-1.5 rounded-[5px] bg-sunk pl-[7px] pr-1 text-[11.5px] text-fg-muted shadow-[inset_0_0_0_1px_var(--line-2)]">
          <span className="min-w-0 truncate">{ctx.label}</span>
          <button
            type="button"
            className="inline-flex h-auto cursor-pointer items-center border-0 bg-transparent p-0 text-fg-subtle shadow-none hover:bg-transparent hover:text-fg"
            title="Remove context"
            aria-label="Remove context"
            onClick={() => nav.openChat(null)}
          >
            <Icon name="close" size={12} />
          </button>
        </span>}
        <textarea
          ref={composer}
          className="h-[38px]! w-full resize-none! rounded-none! border-0! bg-transparent! p-0! text-[12.5px] leading-[19px] text-fg shadow-none! outline-none! placeholder:text-fg-subtle focus:shadow-none!"
          value={draft}
          rows={2}
          maxLength={8000}
          aria-label="Message board"
          placeholder={placeholder}
          onChange={e => updateDraft(e.target.value)}
          onKeyDown={e => {
            if (mention && options.length) {
              if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); e.stopPropagation(); setHi(i => (i + (e.key === 'ArrowDown' ? 1 : -1) + options.length) % options.length); return }
              if (e.key === 'Enter' || e.key === 'Tab') { e.preventDefault(); e.stopPropagation(); pick(options[hi] ?? options[0]); return }
              if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); setMention(null); return }
            }
            if (e.key === 'Enter' && !e.shiftKey && !e.metaKey && !e.ctrlKey && !e.nativeEvent.isComposing) { e.preventDefault(); e.stopPropagation(); submit() }
          }}
        />
        <div className="flex items-center gap-2 text-[11.5px] text-fg-subtle">
          <span>{model.needsModel || !detail.hasModel ? 'Replies wait for a connected model' : '@ directs a specialist'}</span>
          <span className="flex-1" />
          <Kbd>↵</Kbd>
          <button
            type="button"
            className={cn(runIconBtn({ size: 'xs' }), 'text-fg-muted')}
            title="Send (↵ · ⇧↵ for a new line)"
            aria-label="Send message"
            disabled={!draft.trim()}
            onClick={submit}
          >
            <Icon name="arrowUp" />
          </button>
        </div>
      </div>
    </div>
  </div>
}
