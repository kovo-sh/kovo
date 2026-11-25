// Queue view (E's triage inside F's frame), owned by Agent Q.
//
// Decide / Review / Follow up / Done, identical baseline checks bundled
// (model.queue + the shared decision store). The reading view lives in the
// right pane (`queue` inspector) with a sticky action bar.
//
// Decisions: A / D / F on the current item (or the inline buttons). The row
// and the action bar stamp, the row collapses its own height (rows above do
// not move), the next open item slides into the inspector, and an undo toast
// springs up. Approvals are real (`decide_approval` / `approve_similar_endpoint`,
// sent when the 6 s undo window closes); follow-ups send `inject_hint` while
// the run is live; finding triage is local (no server API), persisted per run.
import { useEffect, useLayoutEffect, useMemo, useRef, useSyncExternalStore } from 'react'
import type { ReactNode } from 'react'
import { capabilityTierMeta } from '../../run-state.ts'
import { useRunModel } from '../data.tsx'
import { ACTIONS, actionsFor, approvalCommand, useDecisions } from '../decisions.tsx'
import type { DecisionAct, DecisionsApi } from '../decisions.tsx'
import type { Command } from '../data.tsx'
import { EmptyState, Kbd } from '../display.tsx'
import { cap, fmtTime, fmtTimeS, fmtUsd, host, plural } from '../format.ts'
import { StatusGlyph } from '../glyphs.tsx'
import { Icon } from '../icons.tsx'
import type { IconName } from '../icons.tsx'
import { useShortcuts } from '../keyboard.tsx'
import { normFStatus, prettyCat } from '../meta.ts'
import { QSEC } from '../model.ts'
import type { QueueItem, QueueSection, RunModel } from '../model.ts'
import { AnimatedNumber, T } from '../motion.tsx'
import { useListNav, useNav, useViewState } from '../nav.tsx'
import type { NavApi } from '../nav.tsx'
import { PaneBody, PaneHeader } from '../pane.tsx'
import type { InspectorMap, InspectorProps } from '../pane.tsx'
import { usePaletteCommands } from '../palette.tsx'
import { useToast } from '../toast.tsx'
import type { ToastApi } from '../toast.tsx'
import { QGlyph, ReadApproval, ReadConsent, ReadFinding, ReadFollow, VState } from './queue-read.tsx'

// ---------------------------------------------------------------- decision motion store
// One tiny external store so the list row and the inspector's action bar
// stamp together, whichever of them started the decision.

interface Motion { key: string | null; act: DecisionAct | null; phase: 'idle' | 'stamp' | 'leave'; enter: string | null }
let motion: Motion = { key: null, act: null, phase: 'idle', enter: null }
const subs = new Set<() => void>()
const setMotion = (m: Partial<Motion>) => { motion = { ...motion, ...m }; subs.forEach(f => f()) }
const subscribe = (f: () => void) => { subs.add(f); return () => { subs.delete(f) } }
const useMotion = () => useSyncExternalStore(subscribe, () => motion, () => motion)
/** Keys of open rows in display order, published by the list (falls back to the sections). */
let visibleOrder: string[] = []

const STAMP_MS = 340
const COLLAPSE_MS = 240

function openKeys(q: DecisionsApi) {
  return [...q.sections.decide, ...q.sections.review, ...q.sections.follow].map(i => i.key)
}

/** Real command for a decision, if there is one. */
function commandFor(it: QueueItem, act: DecisionAct, model: RunModel, similar?: boolean): Command | undefined {
  if (it.kind === 'approval' && (act === 'approve' || act === 'deny')) {
    if (similar && act === 'approve') return { action: 'approve_similar_endpoint', approvalId: it.ap.id }
    return approvalCommand(it.ap.id, act)
  }
  if (it.kind === 'follow' && act === 'queue' && followIsLive(model)) {
    const x = it.cov
    const asset = model.run.candidates.find(c => c.origin === x.origin && model.run.approved.includes(c.id))
    return {
      action: 'inject_hint',
      hint: `Follow up on ${host(x.origin)} · ${prettyCat(x.category)}: ${x.summary}`.slice(0, 2000),
      ...(asset ? { targetAssetId: asset.id } : {}),
    }
  }
  return undefined
}
/** Finding triage (accept / dismiss / false positive) has no server API; follow-ups on finished runs can't be sent either. */
const localOnly = (it: QueueItem, m: RunModel) => it.kind === 'finding' || (it.kind === 'follow' && !followIsLive(m))
/** Follow-ups can only be scheduled while the run can still plan. */
export const followIsLive = (m: RunModel) => m.run.phase !== 'complete' && !['complete', 'stopped', 'failed'].includes(m.run.status)

function decisionMessage(it: QueueItem, act: DecisionAct, similar?: boolean): string {
  const A = ACTIONS[act]
  if (it.kind === 'approval') return `${similar ? 'Approved similar endpoints for' : A.label} ${it.ap.method} ${host(it.ap.origin)}${it.ap.pathAndQuery}`
  return A.label
}

interface ActDeps { q: DecisionsApi; nav: NavApi; model: RunModel; toast: ToastApi }

/** decide → stamp → collapse → advance. Returns false when the action does not apply. */
function runDecision(deps: ActDeps, key: string, act: DecisionAct, opts: { similar?: boolean } = {}) {
  const { q, nav, model } = deps
  const it = model.queueItem.get(key)
  if (!it || motion.phase !== 'idle') return false
  if (it.kind === 'consent') { nav.setView('overview'); return true }
  if (!q.canAct(key, act)) return false
  const order = visibleOrder.length ? visibleOrder : openKeys(q)
  const idx = order.indexOf(key)
  const open = new Set(openKeys(q))
  const nextKey = order.slice(idx + 1).find(k => open.has(k) && k !== key) ?? order.slice(0, Math.max(0, idx)).reverse().find(k => open.has(k)) ?? null
  const commit = () => {
    const command = commandFor(it, act, model, opts.similar)
    q.decide(key, act, {
      command,
      message: decisionMessage(it, act, opts.similar),
      sub: command ? 'Sends when this closes' : it.kind === 'finding' || it.kind === 'follow' ? 'Saved in this browser only · ' + it.title : it.title,
      onUndo: () => {
        setMotion({ enter: key })
        setTimeout(() => { if (motion.enter === key) setMotion({ enter: null }) }, 600)
        if (nav.view === 'queue') nav.select({ kind: 'queue', id: key })
        setTimeout(() => deps.toast.show('Restored to the queue', { icon: 'undo' }), T(60))
      },
    })
    setMotion({ key: null, act: null, phase: 'idle' })
    if (nav.view === 'queue' && nav.sel?.kind === 'queue' && nav.sel.id === key) {
      if (nextKey) nav.select({ kind: 'queue', id: nextKey }, { anim: 'left' })
      else nav.close()
    }
  }
  const stampMs = T(STAMP_MS)
  if (!stampMs) { commit(); return true }
  setMotion({ key, act, phase: 'stamp', enter: null })
  setTimeout(() => setMotion({ phase: 'leave' }), stampMs)
  setTimeout(commit, stampMs + COLLAPSE_MS)
  return true
}

function useDecide() {
  const q = useDecisions()
  const nav = useNav()
  const model = useRunModel()
  const toast = useToast()
  const deps = useRef<ActDeps>({ q, nav, model, toast })
  deps.current = { q, nav, model, toast }
  return (key: string, act: DecisionAct, opts?: { similar?: boolean }) => runDecision(deps.current, key, act, opts)
}

/** Ask the coordinator about an item: chat in the pane with a context chip ("Back to item"). */
function useAsk() {
  const nav = useNav()
  const model = useRunModel()
  return (key: string) => {
    const it = model.queueItem.get(key)
    if (!it) return
    nav.openChat({ label: it.title, sel: { kind: 'queue', id: key } })
  }
}

/** Keyboard: A / D / F on the selected item, C to ask about it. */
function useQueueKeys(priority: number) {
  const nav = useNav()
  const model = useRunModel()
  const decide = useDecide()
  const ask = useAsk()
  const cur = () => (nav.sel?.kind === 'queue' ? nav.sel.id : null)
  const letter = (l: string) => () => {
    const key = cur()
    if (!key || nav.chat) return false
    const a = actionsFor(model.queueItem.get(key)).find(x => x[2] === l)
    if (!a) return false
    return decide(key, a[0]) ? undefined : false
  }
  useShortcuts([
    { key: 'a', run: letter('a') },
    { key: 'd', run: letter('d') },
    { key: 'f', run: letter('f') },
    { key: 'c', run: () => { const key = cur(); if (!key || nav.chat) return false; ask(key) } },
  ], { priority })
}

// ---------------------------------------------------------------- list

const EMPTY: Record<QueueSection, string> = {
  decide: 'Nothing is waiting on you.',
  review: 'Every finding is verified or decided.',
  follow: 'No coverage flagged for follow-up.',
  done: 'Nothing here yet.',
}

export function QueueView() {
  const model = useRunModel()
  const q = useDecisions()
  const nav = useNav()
  const m = useMotion()
  const decide = useDecide()
  const ask = useAsk()
  const [collapsed, setCollapsed] = useViewState<Partial<Record<QueueSection, boolean>>>('queue.collapsed', {})
  const listRef = useRef<HTMLDivElement>(null)
  const isCol = (k: QueueSection) => collapsed[k] ?? k === 'done'
  const flat = useMemo(() => QSEC.flatMap(([k]) => (isCol(k) ? [] : q.sections[k].map(i => i.key))),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [q.sections, collapsed])
  visibleOrder = flat
  const selKey = nav.sel?.kind === 'queue' ? nav.sel.id : null

  // Land on the first open item; drop selections that no longer exist.
  useEffect(() => {
    if (nav.chat) return
    if (selKey && model.queueItem.has(selKey)) return
    if (nav.sel && nav.sel.kind !== 'queue') return
    const first = openKeys(q)[0]
    if (first) nav.select({ kind: 'queue', id: first })
    else if (selKey) nav.close()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selKey, model])

  useListNav({ ids: flat, kind: 'queue', anim: 'left' })
  useQueueKeys(10)
  usePaletteCommands([
    ...(['decide', 'review', 'follow', 'done'] as const).map(k => ({
      id: 'q.toggle.' + k, section: 'Actions', label: (isCol(k) ? 'Expand' : 'Collapse') + ' the ' + QSEC.find(s => s[0] === k)![1] + ' section', icon: 'queue' as IconName,
      run: () => setCollapsed(c => ({ ...c, [k]: !isCol(k) })),
    })),
  ])

  // Keep the current row in view (j/k, advance).
  useEffect(() => {
    if (!selKey) return
    const el = listRef.current?.querySelector<HTMLElement>(`.row[data-id="${CSS.escape(selKey)}"]`)
    el?.scrollIntoView({ block: 'nearest' })
  }, [selKey])

  const initial = q.initialCount
  const handled = q.handledCount
  const pct = initial ? handled / initial : 0
  const hero = <div className="qhero num">
    <span><b><AnimatedNumber id="q.open" value={q.openCount} /> open</b><span style={{ color: 'var(--fg-3)' }}> · {handled} decided by you this session</span></span>
    <span className="prog" title={`${handled} of ${initial} handled`}>{Array.from({ length: 12 }, (_, i) => <i key={i} className={i < Math.ceil(pct * 12) ? 'on' : ''} />)}</span>
    <span className="tb-sp" />
    <span className="hint qkeys"><Kbd>A</Kbd>accept<Kbd>D</Kbd>deny<Kbd>F</Kbd>false positive<Kbd>Z</Kbd>undo</span>
  </div>
  if (!initial && !q.sections.done.length) {
    return <>{hero}<EmptyState icon="queue" title="Queue is empty">Approvals, unverified findings and flagged coverage collect here as the run progresses.</EmptyState></>
  }
  return <>
    {hero}
    <div className="list" ref={listRef} tabIndex={-1}>
      {QSEC.map(([k, label, sub]) => {
        const items = q.sections[k]
        const col = isCol(k)
        return <div key={k} className="qsec" data-sec={k}>
          <div className={'ghead' + (col ? ' collapsed' : '')} role="button" tabIndex={0} aria-expanded={!col}
            onClick={() => setCollapsed(c => ({ ...c, [k]: !col }))}
            onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setCollapsed(c => ({ ...c, [k]: !col })) } }}>
            <Icon name="chev" /><span>{label}</span><span className="ct num"><AnimatedNumber id={'q.sec.' + k} value={items.length} /></span><span className="sub">{sub}</span>
          </div>
          {!col && (!items.length
            ? <div className="qempty">{EMPTY[k]}</div>
            : k === 'done' ? <DoneRows items={items} selKey={selKey} />
              : items.map(it => <QRow key={it.key} it={it} sec={k} cur={it.key === selKey} motion={m}
                onSelect={() => nav.select({ kind: 'queue', id: it.key })} onAct={act => decide(it.key, act)} onAsk={() => ask(it.key)} />))}
        </div>
      })}
    </div>
  </>
}

function QTitle({ it }: { it: QueueItem }) {
  if (it.kind === 'approval') {
    const a = it.ap
    return <span className="title mono qurl"><span className="m">{a.method}</span>{host(a.origin)}<span className="pq">{a.pathAndQuery}</span></span>
  }
  return <span className="title">{it.title}</span>
}

function QMeta({ it, model }: { it: QueueItem; model: RunModel }): ReactNode[] {
  if (it.kind === 'approval') return ['Approval request', it.ap.status === 'pending' ? 'Expires ' + fmtTime(it.ap.expiresAt) : cap(it.ap.status)]
  if (it.kind === 'consent') return [plural(model.detail.project.seeds.length, 'seed host'), capabilityTierMeta[model.run.capabilityTier].short, fmtUsd(model.run.budgetUsd)]
  if (it.kind === 'follow') return [<span key="h" className="mono">{host(it.cov.origin)}</span>, prettyCat(it.cov.category)]
  return [
    it.bundle ? <span key="o" className="tag num">{it.origins.length} origins</span> : <span key="h" className="mono">{host(it.origins[0])}</span>,
    it.finding.findingKind === 'multi_step_chain' ? 'Chain' : 'Baseline',
    <VState key="v" status={it.status} />,
  ]
}

function QRow({ it, sec, cur, motion: m, onSelect, onAct, onAsk }: {
  it: QueueItem
  sec: QueueSection
  cur: boolean
  motion: Motion
  onSelect: () => void
  onAct: (act: DecisionAct) => void
  onAsk: () => void
}) {
  const model = useRunModel()
  const ref = useRef<HTMLDivElement>(null)
  const stamping = m.key === it.key && m.phase !== 'idle'
  const leaving = stamping && m.phase === 'leave'
  const A = stamping && m.act ? ACTIONS[m.act] : null
  // Collapse our own height so the reflow that follows lands on the same layout.
  useLayoutEffect(() => {
    const el = ref.current
    if (!el || !leaving) return
    el.style.height = el.offsetHeight + 'px'
    void el.offsetHeight
    el.classList.add('leaving')
    el.style.height = '0px'
    return () => { el.classList.remove('leaving'); el.style.height = '' }
  }, [leaving])
  const meta = QMeta({ it, model })
  const acts = it.kind === 'consent' ? [['scope', 'Review scope', 'a', true] as const] : actionsFor(it)
  return <div ref={ref} className={'row qrow' + (cur ? ' cur' : '') + (stamping ? ' stamp' : '') + (m.enter === it.key ? ' entering' : '')} data-id={it.key}
    onClick={onSelect} aria-selected={cur}>
    <QGlyph it={it} />
    <span className="qt"><QTitle it={it} /></span>
    <span className="meta">{meta.map((x, i) => <span key={i} className="qm">{i > 0 && <span className="qdot">·</span>}{x}</span>)}</span>
    {sec !== 'done' && <span className="acts">
      {acts.map(([a, l, k, p]) => <button key={a} type="button" className={'qbtn' + (p ? ' pri' : '')} title={`${l} (${k.toUpperCase()})${localOnly(it, model) ? ' · local triage, saved in this browser only' : ''}`} onClick={e => { e.stopPropagation(); onAct(a) }}>
        {l}<Kbd>{k.toUpperCase()}</Kbd>
      </button>)}
      <button type="button" className="qbtn icon" title="Ask coordinator (C)" aria-label="Ask coordinator" onClick={e => { e.stopPropagation(); onAsk() }}><Icon name="chat" /></button>
    </span>}
    {A && <span className={'stampl ' + A.tone}><Icon name={A.icon} />{A.label}</span>}
  </div>
}

/** Done: your decisions first, then verified / dismissed findings, then the approval audit log. */
function DoneRows({ items, selKey }: { items: QueueItem[]; selKey: string | null }) {
  const q = useDecisions()
  const nav = useNav()
  const m = useMotion()
  const auto = (it: QueueItem) => it.kind === 'approval' && !q.get(it.key) && (it.ap.decidedBy ?? '').startsWith('auto')
  const main = items.filter(it => !auto(it))
  const log = items.filter(auto)
  const row = (it: QueueItem) => {
    const dec = q.get(it.key)
    let right: ReactNode = null
    if (dec) {
      const A = ACTIONS[dec.act]
      right = <span className={'dec ' + A.tone}><Icon name={A.icon} />{A.label}{dec.state === 'pending' ? ' · sending' : dec.state === 'local' ? ' · local' : ''}</span>
    } else if (it.kind === 'finding') right = <VState status={it.status} />
    else if (it.kind === 'approval') right = <span className="dec"><StatusGlyph status={it.ap.status} />{cap(it.ap.status)}{it.ap.decidedBy ? ' · ' + it.ap.decidedBy : ''}</span>
    return <div key={it.key} className={'row qrow done' + (it.key === selKey ? ' cur' : '') + (m.enter === it.key ? ' entering' : '')} data-id={it.key}
      onClick={() => nav.select({ kind: 'queue', id: it.key })}>
      <QGlyph it={it} />
      <span className="qt"><QTitle it={it} /></span>
      <span className="meta">{right}</span>
    </div>
  }
  return <>
    {main.map(row)}
    {log.length > 0 && <>
      <div className="qsub"><Icon name="shield" /><span>Auto-approved by policy</span><span className="ct num">{log.length}</span><span className="sub">Audit log of active test requests the policy approved automatically</span></div>
      {log.map(row)}
    </>}
  </>
}

// ---------------------------------------------------------------- inspector

function QueueInspector({ sel }: InspectorProps) {
  const model = useRunModel()
  const q = useDecisions()
  const nav = useNav()
  const m = useMotion()
  const decide = useDecide()
  const ask = useAsk()
  const it = model.queueItem.get(sel.id)
  if (!it) {
    return <>
      <PaneHeader title="Queue" />
      <PaneBody><EmptyState icon="queue" title="Item not found">It may have been decided or superseded since the run refreshed.</EmptyState></PaneBody>
    </>
  }
  const sec = q.sectionOf(it.key) ?? 'done'
  const inSec = q.sections[sec]
  const pos = inSec.findIndex(i => i.key === it.key)
  const secName = QSEC.find(s => s[0] === sec)?.[1] ?? ''
  const dec = q.get(it.key)
  const order = visibleOrder.length ? visibleOrder : openKeys(q)
  const step = (d: number) => {
    const i = order.indexOf(it.key)
    const k = order[i < 0 ? 0 : Math.max(0, Math.min(order.length - 1, i + d))]
    if (k && k !== it.key) nav.select({ kind: 'queue', id: k }, { anim: d > 0 ? 'left' : 'up' })
  }
  const stamped = m.key === it.key && m.phase !== 'idle' && m.act ? ACTIONS[m.act] : null
  const acts = sec !== 'done' ? (it.kind === 'consent' ? [['scope', 'Review scope', 'a', true] as const] : actionsFor(it)) : []
  const icon = (a: DecisionAct): IconName => a === 'fp' ? 'slash' : a === 'dismiss' || a === 'close' ? 'archive' : a === 'deny' ? 'x' : a === 'queue' ? 'follow' : 'check'
  let banner: ReactNode = null
  if (dec) {
    banner = <div className="banner"><Icon name={ACTIONS[dec.act].icon} />
      <span>{ACTIONS[dec.act].label} by you · {fmtTimeS(dec.at)}{dec.state === 'pending' ? ' · sending when the undo window closes' : dec.state === 'sent' ? ' · sent to Kovo Hunter' : dec.state === 'local' ? ' · saved in this browser only, not sent to Kovo Hunter' : ''}</span>
      {dec.state !== 'sent' && <button type="button" className="btn ghost" onClick={() => q.reopen(it.key)}><Icon name="undo" />Move back</button>}
    </div>
  } else if (sec === 'done' && it.kind === 'finding') {
    banner = <div className="banner"><StatusGlyph status={normFStatus(it.status)} /><span>{it.status === 'dismissed' ? 'Dismissed by verification.' : 'Confirmed by automated replay. Nothing to decide.'}</span></div>
  } else if (sec === 'done' && it.kind === 'approval') {
    banner = <div className="banner"><StatusGlyph status={it.ap.status} /><span>{cap(it.ap.status)}{it.ap.decidedBy ? ' by ' + it.ap.decidedBy : ''}{it.ap.decidedAt ? ' · ' + fmtTimeS(it.ap.decidedAt) : ''}.</span></div>
  }
  const local = it.kind === 'follow' && !followIsLive(model)
  return <>
    <PaneHeader title={secName} sub={pos >= 0 ? <span className="num">{pos + 1} of {inSec.length}</span> : undefined}
      extra={<>
        <button type="button" className="icon-btn" onClick={() => step(-1)} title="Previous (K)" aria-label="Previous item"><Icon name="chevU" /></button>
        <button type="button" className="icon-btn" onClick={() => step(1)} title="Next (J)" aria-label="Next item"><Icon name="chevD" /></button>
      </>} />
    <div className="read">
      <PaneBody><div className="d">
        {banner}
        {it.kind === 'finding' ? <ReadFinding it={it} />
          : it.kind === 'approval' ? <ReadApproval it={it} />
            : it.kind === 'follow' ? <ReadFollow it={it} local={local} />
              : <ReadConsent />}
      </div></PaneBody>
      <div className={'abar' + (stamped ? ' stamped' : '')}>
        {acts.map(([a, l, k, p]) => <button key={a} type="button" className={'btn' + (p ? ' ink' : '')} onClick={() => decide(it.key, a)}
          title={localOnly(it, model) ? 'Local triage: saved in this browser only, not sent to Kovo Hunter' : undefined}>
          <Icon name={icon(a)} />{l}<Kbd>{k.toUpperCase()}</Kbd>
        </button>)}
        {it.kind === 'approval' && sec !== 'done' && <button type="button" className="btn ghost" title="Approve this request and future requests to the same endpoint pattern"
          onClick={() => decide(it.key, 'approve', { similar: true })}><Icon name="check" />Approve similar</button>}
        {acts.length <= 2 && <button type="button" className="btn ghost" title="Ask the coordinator about this item (C)" aria-label="Ask the coordinator" onClick={() => ask(it.key)}>
          <Icon name="chat" />{sec === 'done' || it.kind === 'approval' ? null : <>Ask<Kbd>C</Kbd></>}
        </button>}
        <span className="sp" />
        <span className={'rstamp stampl ' + (stamped?.tone ?? '')}>{stamped && <><Icon name={stamped.icon} />{stamped.label} <span className="rstamp-sub">· next item</span></>}</span>
      </div>
    </div>
  </>
}

/** Inspectors this view owns, keyed by selection kind ('queue'). */
export const queueInspectors: InspectorMap = {
  queue: QueueInspector,
}
