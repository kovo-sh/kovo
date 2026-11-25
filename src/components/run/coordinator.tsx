// Board pane (v5 swarm message board) in F's coordinator pane: the right pane when
// nothing is selected, on chat-first views, or after C / "Board".
//
// - Roster strip: board members with live state (working / waiting / paused / retired);
//   a member pill filters the timeline, ↗ opens its active worker in Workflow.
// - Pending Tier 3 approvals pinned on top (shared decision store: stamp now, send
//   `decide_approval` when the 6 s undo window closes).
// - Timeline: board posts (kind pill, mentions, reply, fact / exchange / finding / step
//   chips with an inline detail and a cross-link, inline approval cards) merged with the
//   coordinator thread (coordinator and Guardian replies are not posted to the board).
//   Operator messages are mirrored onto the board by the server, so thread copies made
//   after the board started are hidden.
// - Composer: plain text sends `message` (lands on the board as a NOTE to @coordinator);
//   text with @mentions sends `board_post`. @ opens roster autocomplete. ↵ sends, ⇧↵ adds a line.
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
  // First sight of a run counts everything already there as read.
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
function ApprovalRow({ a }: { a: Approval }) {
  const q = useDecisions()
  const links = useLinks()
  const decide = useApprovalDecide()
  const d = q.get('ap:' + a.id)
  return <div className={'ap' + (d || a.status !== 'pending' ? ' done' : '')} data-approval-id={a.id}>
    <span className="m mono">{a.method}</span>
    <span className="u mono" title={`${a.origin}${a.pathAndQuery} · open in the queue`} onClick={() => links.queueItem('ap:' + a.id)}>
      {host(a.origin)}<span>{a.pathAndQuery}</span>
    </span>
    {d ? <>
      <span className="verdict"><Icon name={ACTIONS[d.act].icon} />{ACTIONS[d.act].label}{d.state === 'pending' ? ' · sending' : ''}</span>
      {d.state !== 'sent' && <button type="button" className="icon-btn" title="Undo" aria-label="Undo" style={{ height: 24, minWidth: 24 }} onClick={() => q.reopen('ap:' + a.id)}><Icon name="undo" /></button>}
    </> : a.status !== 'pending'
      ? <span className="verdict"><StatusGlyph status={a.status} />{cap(a.status)}</span>
      : <span className="acts">
        <button type="button" className="icon-btn no" title={`Deny ${a.method} ${host(a.origin)}${a.pathAndQuery}`} aria-label="Deny" onClick={() => decide(a.id, 'deny')}><Icon name="x" /></button>
        <button type="button" className="icon-btn ok" title={`Approve ${a.method} ${host(a.origin)}${a.pathAndQuery}`} aria-label="Approve" onClick={() => decide(a.id, 'approve')}><Icon name="check" /></button>
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
  return <div className="approvals" data-testid="board-approvals" aria-label="Pending state-change approvals">
    <div className="ap-card">
      <div className="ap-h">
        <StatusGlyph status={open.length ? 'paused' : 'complete'} />
        <span title="State-changing requests requiring approval (Tier 3)">{open.length ? 'Pending approvals' : 'Approvals decided'}</span>
        <span className="muted num">{open.length} of {pending.length} open</span>
        <button type="button" className="btn ghost go" style={{ height: 24 }} onClick={() => {
          const first = q.sections.decide[0]
          if (first) nav.open('queue', { kind: 'queue', id: first.key }, { push: false })
          else nav.setView('queue')
        }}>Review in queue<Icon name="arrowR" /></button>
      </div>
      {shown.map(a => <ApprovalRow key={a.id} a={a} />)}
      {pending.length > 3 && <div className="ap" style={{ justifyContent: 'center', color: 'var(--fg-3)' }}>
        <button type="button" className="linkbtn" style={{ margin: 0 }} onClick={() => nav.setView('queue')}>+{pending.length - 3} more in the queue</button>
      </div>}
    </div>
  </div>
}

// ---------------------------------------------------------------- agents dropdown (merged into compact filter bar)

function AgentsDropdown({ members, filter, setFilter }: { members: BoardMember[]; filter: Filter; setFilter: (f: Filter) => void }) {
  const links = useLinks()
  const activeAgent = members.find(m => m.handle === filter)
  const workingCount = members.filter(m => m.state === 'working').length
  return <Dropdown
    className="b-agents-dd"
    menuClassName="b-agents-menu"
    btnClassName={'b-f b-agents-btn' + (activeAgent ? ' on' : '')}
    title="Filter by agent or jump to an active worker"
    label={<>
      {workingCount > 0 && <i className="b-dot working" aria-hidden="true" />}
      <span>{activeAgent ? '@' + activeAgent.handle : `Agents (${members.length})`}</span>
    </>}
  >
    {close => <div data-testid="board-roster" aria-label="Board roster">
      {activeAgent && <button type="button" className="dd-item" onClick={() => { setFilter('all'); close() }}>
        <span>All agents</span>
      </button>}
      {members.map(m => {
        const meta = boardStateMeta[m.state as keyof typeof boardStateMeta] ?? boardStateMeta.waiting
        const on = filter === m.handle
        const profile = m.specialistProfile ?? specialistProfileByHandle[m.handle]
        return <div key={m.id} className={'b-ag-row st-' + m.state + (on ? ' on' : '')} data-handle={m.handle} data-state={m.state}>
          <button type="button" className="dd-item b-ag-pick" aria-pressed={on}
            title={`${profile ?? boardRoleLabels[m.role] ?? m.role} · ${meta.label}`}
            onClick={() => { setFilter(on ? 'all' : m.handle); close() }}>
            <i className="b-dot" aria-hidden="true" />
            <span className="b-ag-h">@{m.handle}</span>
            <span className="ct">{meta.label}</span>
          </button>
          {m.activeAssignmentId && m.state !== 'retired' && <button type="button" className="icon-btn b-ag-go"
            aria-label={`Inspect @${m.handle}`} title={`Open @${m.handle}'s worker in Workflow`}
            onClick={() => { close(); links.worker(m.activeAssignmentId!) }}><Icon name="ext" size={12} /></button>}
        </div>
      })}
    </div>}
  </Dropdown>
}

// ---------------------------------------------------------------- timeline items

function MessageBody({ text }: { text: string }) {
  const long = text.length > 320
  const [open, setOpen] = useState(false)
  return <>
    <div className={'body' + (long && !open ? ' clamp' : '')}>{text}</div>
    {long && <button type="button" className="more" onClick={() => setOpen(!open)}>{open ? 'Show less' : 'Show more'}</button>}
  </>
}

/** Inline detail for a referenced fact / exchange / finding / step, with a cross-link. */
function RefDetail({ kind, id }: { kind: RefKind; id: string }) {
  const model = useRunModel()
  const links = useLinks()
  const nav = useNav()
  let body: ReactNode
  if (kind === 'fact') {
    const f = model.factById.get(id)
    const w = f ? model.workerById.get(f.assignmentId) : undefined
    body = f ? <>
      <b>{f.kind} · <span className="mono">{host(f.origin)}</span></b>
      <p>{f.summary}{f.tainted ? ' (tainted by scope revocation)' : ''}</p>
      {w && <button type="button" className="linkbtn" onClick={() => links.worker(w.id)}><Icon name="workflow" />Recorded by {w.title}</button>}
    </> : <p className="muted">Fact {short(id)} is not loaded in this run.</p>
  } else if (kind === 'exchange') {
    const x = model.exchangeById.get(id)
    body = <>
      {x ? <><b className="mono">{x.method} {host(x.origin)}{x.pathAndQuery}</b><p>HTTP {x.status} · {x.mediaType || 'unknown type'} · {x.personaHandle ?? 'anonymous'}</p></>
        : <p className="muted">Exchange {short(id)} is outside the loaded window; it opens by id.</p>}
      <button type="button" className="linkbtn" onClick={() => links.exchange(id)}><Icon name="exchanges" />Open in Exchanges</button>
    </>
  } else if (kind === 'finding') {
    const f = model.findingById.get(id)
    body = f ? <>
      <b>{f.title}</b><p>{stLabel(f.status)} · {f.severity}{f.category ? ' · ' + f.category : ''}</p>
      <button type="button" className="linkbtn" onClick={() => links.finding(f.id)}><Icon name="findings" />Open finding</button>
    </> : <p className="muted">Finding {short(id)} is not loaded.</p>
  } else {
    const s = model.stepById.get(id)
    body = s ? <>
      <b>Step #{s.seq} · {s.title}</b><p>{stLabel(s.status)} · {s.hypothesis}</p>
      <button type="button" className="linkbtn" onClick={() => s.assignedWorkerId ? links.worker(s.assignedWorkerId) : nav.open('workflow', { kind: 'step', id: s.id })}>
        <Icon name="workflow" />Open in Workflow</button>
    </> : <p className="muted">Chain step {short(id)} is not loaded.</p>
  }
  return <div className="b-ref-d" data-testid="board-ref-detail">{body}</div>
}

function InlineApproval({ a }: { a: Approval }) {
  return <div className="b-apin" data-testid="board-approval-inline">
    <div className="b-apin-h" title="State-changing request (Tier 3)"><Icon name="shield" /><span>Approval request</span><span className="muted">· {cap(a.status)}</span></div>
    <ApprovalRow a={a} />
  </div>
}

function BoardPost({ m, filter, setFilter }: { m: BoardMessage; filter: Filter; setFilter: (f: Filter) => void }) {
  const model = useRunModel()
  const [open, setOpen] = useState<{ kind: RefKind; id: string } | null>(null)
  const op = m.authorRole === 'operator'
  const approval = m.refApprovalId ? model.approvalById.get(m.refApprovalId) : undefined
  const mentions = m.mentions.filter(h => h !== 'coordinator' || !op)
  const chip = (kind: RefKind, id: string, label: string, tip: string) => {
    const on = open?.kind === kind && open.id === id
    return <button key={kind + ':' + id} type="button" className={'b-ref' + (on ? ' on' : '')} data-ref-kind={kind} data-ref-id={id} aria-pressed={on} title={tip}
      onClick={() => setOpen(on ? null : { kind, id })}><Icon name={kind === 'exchange' ? 'exchanges' : kind === 'finding' ? 'findings' : kind === 'step' ? 'workflow' : 'fact'} size={12} />{label}</button>
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
  const role = m.authorRole === 'coordinator' ? 'co' : op ? 'op' : ''
  return <div className={'msg b-msg' + (op ? ' mine' : '') + (m.tainted ? ' tainted' : '')} data-role={m.authorRole} data-kind={m.kind} data-tainted={m.tainted} data-seq={m.seq}>
    <span className={'av ' + role}>{op ? 'Y' : m.authorHandle.charAt(0).toUpperCase()}</span>
    <div style={{ minWidth: 0 }}>
      <div className="who">
        <span>{op ? 'You' : '@' + m.authorHandle}</span>
        <span className={'b-kind k-' + m.kind}>{QUIET_KIND_LABELS[m.kind as BoardMessageKind] ?? cap(m.kind)}</span>
        {m.tainted && <span className="b-kind k-outdated" title="Scope revoked: excluded from future specialist wakes">Outdated</span>}
        <span className="muted num" style={{ marginLeft: 'auto' }}>{fmtTime(m.createdAt)}</span>
      </div>
      <MessageBody text={m.body} />
      {(mentions.length > 0 || m.replyToSeq) && <div className="b-meta">
        {m.replyToSeq && <span className="muted num" data-testid="board-reply">↳ #{m.replyToSeq}</span>}
        {mentions.map(h => <button key={h} type="button" className={'b-men' + (filter === h ? ' on' : '')} onClick={() => setFilter(filter === h ? 'all' : h)}>@{h}</button>)}
      </div>}
      {refs.length > 0 && <div className="b-meta" aria-label="Evidence references">{refs.map(([k, id]) => chip(k, id, refLabel(k, id), `${cap(k)} · ID ${id}`))}</div>}
      {open && <RefDetail kind={open.kind} id={open.id} />}
      {approval && <InlineApproval a={approval} />}
    </div>
  </div>
}

const APPROVAL_RE = /^Tier 3 approval required:\s*(\w+)\s+(\S+)/

/** A coordinator-thread message (coordinator / Guardian replies, worker reports, pre-board operator messages). */
function ThreadMessage({ m }: { m: Message }) {
  const model = useRunModel()
  const q = useDecisions()
  const links = useLinks()
  const am = m.role === 'guardian' ? m.content.match(APPROVAL_RE) : null
  if (am) {
    const ap = model.detail.approvals.find(a => a.origin + a.pathAndQuery === am[2] || (a.method === am[1] && am[2].startsWith(a.origin)))
    const d = ap ? q.get('ap:' + ap.id) : undefined
    const st = d ? (d.act === 'approve' ? 'confirmed' : 'dismissed') : ap && ap.status !== 'pending' ? (ap.status === 'approved' ? 'confirmed' : 'dismissed') : 'paused'
    return <div className="msg sys" data-source="thread" data-role={m.role}>
      <span className="av" style={{ background: 'none', boxShadow: 'none' }}><StatusGlyph status={st} /></span>
      <div style={{ minWidth: 0 }}>
        <div className="who" style={{ fontWeight: 400, color: 'var(--fg-2)' }}><span>Approval requested</span><span className="muted num">{fmtTime(m.createdAt)}</span>
          {(d || (ap && ap.status !== 'pending')) && <span className="muted">· {(d ? ACTIONS[d.act].label : ap!.status).toLowerCase()}</span>}</div>
        <div className="body mono" style={{ fontSize: 11.5, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', cursor: ap ? 'pointer' : undefined }}
          onClick={ap ? () => links.queueItem('ap:' + ap.id) : undefined}>{am[1]} {host(am[2])}</div>
      </div>
    </div>
  }
  const who = m.role === 'operator' ? ['You', 'op', 'Y'] : m.role === 'coordinator' ? ['Coordinator', 'co', 'C'] : m.role === 'worker' ? [model.workerById.get(m.threadId)?.title ?? 'Worker', '', 'W'] : ['Kovo Hunter', '', 'K']
  const evidence = (m.evidenceIds ?? []).map(id => model.evidenceById.get(id)).filter(e => !!e)
  return <div className={'msg' + (m.role === 'guardian' ? ' sys' : '')} data-source="thread" data-role={m.role}>
    <span className={'av ' + who[1]}>{who[1] === 'co' ? <svg viewBox="0 0 14 14" width="12" height="12" aria-hidden="true"><circle cx="7" cy="7" r="2.5" fill="currentColor" /></svg> : who[2]}</span>
    <div style={{ minWidth: 0 }}>
      <div className="who"><span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 240 }}>{who[0]}</span><span className="muted num">{fmtTime(m.createdAt)}</span></div>
      <MessageBody text={m.content} />
      {evidence.map(ev => <button key={ev.id} type="button" className="linkbtn" style={{ display: 'flex' }} onClick={() => links.evidence(ev.id)}><Icon name="fact" />{ev.title}</button>)}
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

  // Roster: the coordinator is always present, even before the server backfills it.
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

  // Timeline: board posts + the coordinator thread, oldest first.
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

  // Drop optimistic messages once the server echoes them (on the board or in the thread).
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
    // The composer takes focus when chat opens; Esc in an empty composer continues the Esc stack
    // (chat → Back → close) instead of only blurring. With a draft, Esc just leaves the box.
    { key: 'Escape', allowInInput: true, when: () => document.activeElement === composer.current && !draft.trim() && nav.chat, run: () => { composer.current?.blur(); nav.closeChat() } },
  ], { priority: 20 })

  const placeholder = ctx ? 'Ask about this item…'
    : r.status === 'waiting' ? 'Refine the goal before consenting…' : 'Message the coordinator · @ directs a specialist'

  let lastDay = ''
  const daySep = (t: number) => {
    const day = new Date(t).toDateString()
    if (day === lastDay) return null
    lastDay = day
    return <div className="daysep num">{fmtDay(t)} · {fmtTime(t)}</div>
  }

  const statusNote = r.status === 'waiting'
    ? `Waiting for ${r.phase === 'review' ? 'scope approval' : 'consent'} before planning. Review the ${plural(model.surface.origins.length, 'proposed host')} in the main view.`
    : r.status === 'paused' || r.status === 'budget_paused'
      ? `Run paused in ${(PHASE_LABEL[r.phase] ?? r.phase).toLowerCase()}, round ${r.roundNo}.` + (openApprovals.length ? ' ' + capF(words(openApprovals.length)) + ' approval request' + (openApprovals.length > 1 ? 's are' : ' is') + ' waiting on you.' : '')
      : null
  return <div className="board" data-testid="board-pane">
    <div className="pane-h">
      <div className="ptabs" role="group" aria-label="Pane">
        <button type="button" className="ptab on" aria-pressed="true" title="Swarm board and coordinator thread">Board<span className="ct num">{plural(board.length + model.coordinatorMessages.length, 'message')}</span></button>
        {nav.sel && <button type="button" className="ptab" aria-pressed="false" onClick={() => nav.closeChat()} title="Back to the selected item (Esc)">Inspector</button>}
      </div>
      <span className="hint"><StatusGlyph status={r.status === 'complete' ? 'complete' : r.status} /><span>{runStatusLabel(r.status)}</span></span>
    </div>
    <ApprovalsCard />
    <div className="b-bar" role="group" aria-label="Board filters">
      <div className="b-bar-tabs">
        {FILTERS.map(([k, l]) => <button key={k} type="button" className={'b-f' + (filter === k ? ' on' : '')} aria-pressed={filter === k} onClick={() => setFilter(k)}>{l}</button>)}
      </div>
      <span className="tb-sp" />
      <AgentsDropdown members={members} filter={filter} setFilter={setFilter} />
    </div>
    <div className="chat-wrap">
      <div className="pane-body" ref={scroller}>
        {model.workerMessages.length > 0 && filter === 'all' && <button type="button" className="toggle-line" style={{ width: '100%' }} onClick={() => setWorkerMsgs(v => !v)} aria-pressed={workerMsgs}>
          <span className={'switch' + (workerMsgs ? ' on' : '')} /><span>Include worker reports</span><span className="num" style={{ marginLeft: 'auto' }}>{model.workerMessages.length}</span>
        </button>}
        <div className="chat" data-testid="board-timeline" aria-label="Board timeline">
          {!items.length && <p className="b-empty">{filter === 'all' ? 'Nothing on the board yet. Briefs, handoffs and verdicts land here as the run progresses.' : 'No board traffic for this filter yet.'}</p>}
          {items.map(it => <div key={'board' in it ? 'b' + it.board.id : 't' + it.thread.id}>
            {daySep(it.t)}
            {'board' in it ? <BoardPost m={it.board} filter={filter} setFilter={setFilter} /> : <ThreadMessage m={it.thread} />}
          </div>)}
          {outbox.map(m => <div key={m.id} className="msg pend new" data-role="pending">
            <span className="av op">Y</span>
            <div style={{ minWidth: 0 }}>
              <div className="who"><span>You</span><span className="muted num">{fmtTime(m.at)}</span><span className="muted">· {inFlight ? 'sending' : 'sent'}</span></div>
              <div className="body">{m.ctx ? m.content.replace(/^\[About: [^\]]*\]\n/, '') : m.content}</div>
              {m.ctx && <span className="ctxchip" style={{ margin: '4px 0 0', animation: 'none' }}><span>{m.ctx}</span></span>}
            </div>
          </div>)}
          {statusNote && filter === 'all' && <div className="msg sys"><span className="av">K</span><div><div className="who">Kovo Hunter<span className="muted">now</span></div><div className="body">{statusNote}</div></div></div>}
        </div>
      </div>
    </div>
    <div className="composer" data-testid="board-composer">
      {mention && options.length > 0 && <div className="b-mention" role="listbox" aria-label="Mention roster">
        {options.map((h, i) => <button key={h} type="button" role="option" aria-selected={i === hi} className={'pi' + (i === hi ? ' on' : '')}
          onMouseDown={e => { e.preventDefault(); pick(h) }} onMouseMove={() => setHi(i)}>
          <span className="l">@{h}</span><span className="r">{specialistProfileByHandle[h] ?? (h === 'all' ? 'broadcast' : 'system')}</span>
        </button>)}
      </div>}
      <div className="cbox">
        {ctx && <span className="ctxchip"><span>{ctx.label}</span><button type="button" title="Remove context" aria-label="Remove context" onClick={() => nav.openChat(null)}><Icon name="close" /></button></span>}
        <textarea ref={composer} value={draft} rows={2} maxLength={8000} aria-label="Message board" placeholder={placeholder}
          onChange={e => updateDraft(e.target.value)}
          onKeyDown={e => {
            if (mention && options.length) {
              if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); e.stopPropagation(); setHi(i => (i + (e.key === 'ArrowDown' ? 1 : -1) + options.length) % options.length); return }
              if (e.key === 'Enter' || e.key === 'Tab') { e.preventDefault(); e.stopPropagation(); pick(options[hi] ?? options[0]); return }
              if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); setMention(null); return }
            }
            if (e.key === 'Enter' && !e.shiftKey && !e.metaKey && !e.ctrlKey && !e.nativeEvent.isComposing) { e.preventDefault(); e.stopPropagation(); submit() }
          }} />
        <div className="cbox-f">
          <span>{model.needsModel || !detail.hasModel ? 'Replies wait for a connected model' : '@ directs a specialist'}</span>
          <span className="sp" />
          <span className="kbd-group"><Kbd>↵</Kbd></span>
          <button type="button" className="icon-btn" title="Send (↵ · ⇧↵ for a new line)" aria-label="Send message" disabled={!draft.trim()} onClick={submit} style={{ height: 22, minWidth: 22, padding: '0 4px', color: 'var(--fg-2)' }}><Icon name="arrowUp" /></button>
        </div>
      </div>
    </div>
  </div>
}
