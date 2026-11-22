// Coordinator pane: the real coordinator thread, real send (`message`), and
// pinned pending Tier 3 approvals with inline ✓ / ✕ (real `decide_approval`
// through the shared decision store, with a 6 s undo window).
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { useRun, useRunModel } from './data.tsx'
import { ACTIONS, approvalCommand, useDecisions } from './decisions.tsx'
import { Kbd } from './display.tsx'
import { capF, fmtDay, fmtTime, host, plural, words } from './format.ts'
import { StatusGlyph } from './glyphs.tsx'
import { Icon } from './icons.tsx'
import { useShortcuts } from './keyboard.tsx'
import { PHASE_LABEL, runStatusLabel } from './meta.ts'
import type { Message } from './model.ts'
import { useLinks, useNav } from './nav.tsx'
import { useToast } from './toast.tsx'

function ApprovalsCard() {
  const model = useRunModel()
  const q = useDecisions()
  const links = useLinks()
  const nav = useNav()
  const pending = model.detail.approvals.filter(a => a.status === 'pending').sort((a, b) => a.createdAt - b.createdAt)
  if (!pending.length) return null
  const open = pending.filter(a => !q.get('ap:' + a.id))
  const settled = (id: string) => q.get('ap:' + id)?.state === 'sent'
  const shown = pending.slice().sort((a, b) => Number(settled(a.id)) - Number(settled(b.id))).slice(0, 3)
  const decide = (id: string, act: 'approve' | 'deny') => {
    const a = model.approvalById.get(id)
    q.decide('ap:' + id, act, { command: approvalCommand(id, act), message: `${ACTIONS[act].label} ${a?.method ?? ''} ${host(a?.origin)}${a?.pathAndQuery ?? ''}` })
  }
  return <div className="approvals">
    <div className="ap-card">
      <div className="ap-h">
        <StatusGlyph status={open.length ? 'paused' : 'complete'} />
        <span>{open.length ? 'Pending approvals' : 'Approvals decided'}</span>
        <span className="muted num">{open.length} of {pending.length} · Tier 3</span>
        <button type="button" className="btn ghost go" style={{ height: 24 }} onClick={() => {
          const first = q.sections.decide[0]
          if (first) nav.open('queue', { kind: 'queue', id: first.key }, { push: false })
          else nav.setView('queue')
        }}>Review in queue<Icon name="arrowR" /></button>
      </div>
      {shown.map(a => {
        const d = q.get('ap:' + a.id)
        return <div key={a.id} className={'ap' + (d ? ' done' : '')}>
          <span className="m mono">{a.method}</span>
          <span className="u mono" title={`${a.origin}${a.pathAndQuery} — open in queue`} onClick={() => links.queueItem('ap:' + a.id)}>
            {host(a.origin)}<span>{a.pathAndQuery}</span>
          </span>
          {d ? <>
            <span className="verdict"><Icon name={ACTIONS[d.act].icon} />{ACTIONS[d.act].label}{d.state === 'pending' ? ' · sending' : ''}</span>
            {d.state !== 'sent' && <button type="button" className="icon-btn" title="Undo" style={{ height: 24, minWidth: 24 }} onClick={() => q.reopen('ap:' + a.id)}><Icon name="undo" /></button>}
          </> : <span className="acts">
            <button type="button" className="icon-btn no" title="Deny" aria-label={`Deny ${a.method} ${host(a.origin)}${a.pathAndQuery}`} onClick={() => decide(a.id, 'deny')}><Icon name="x" /></button>
            <button type="button" className="icon-btn ok" title="Approve" aria-label={`Approve ${a.method} ${host(a.origin)}${a.pathAndQuery}`} onClick={() => decide(a.id, 'approve')}><Icon name="check" /></button>
          </span>}
        </div>
      })}
      {pending.length > 3 && <div className="ap" style={{ justifyContent: 'center', color: 'var(--fg-3)' }}>
        <button type="button" className="linkbtn" style={{ margin: 0 }} onClick={() => nav.setView('queue')}>+{pending.length - 3} more in the queue</button>
      </div>}
    </div>
  </div>
}

function MessageBody({ text }: { text: string }) {
  const long = text.length > 320
  const [open, setOpen] = useState(false)
  return <>
    <div className={'body' + (long && !open ? ' clamp' : '')}>{text}</div>
    {long && <button type="button" className="more" onClick={() => setOpen(!open)}>{open ? 'Show less' : 'Show more'}</button>}
  </>
}

const APPROVAL_RE = /^Tier 3 approval required:\s*(\w+)\s+(\S+)/

export function CoordinatorPane() {
  const { detail, send, pending: inFlight } = useRun()
  const model = useRunModel()
  const nav = useNav()
  const q = useDecisions()
  const links = useLinks()
  const toast = useToast()
  const r = detail.run
  const [workerMsgs, setWorkerMsgs] = useState(false)
  const [draft, setDraft] = useState('')
  const [outbox, setOutbox] = useState<{ id: string; content: string; at: number; ctx?: string }[]>([])
  const scroller = useRef<HTMLDivElement>(null)
  const composer = useRef<HTMLTextAreaElement>(null)

  const messages = useMemo(() => {
    const list: Message[] = workerMsgs ? model.coordinatorMessages.concat(model.workerMessages) : model.coordinatorMessages
    return list.slice().sort((a, b) => a.createdAt - b.createdAt)
  }, [model, workerMsgs])
  // drop optimistic messages once the server echoes them
  useEffect(() => {
    setOutbox(o => o.filter(m => !model.coordinatorMessages.some(x => x.role === 'operator' && x.content === m.content && x.createdAt >= m.at - 60_000)))
  }, [model.coordinatorMessages])
  const total = messages.length + outbox.length

  useLayoutEffect(() => {
    const el = scroller.current
    if (el) el.scrollTop = el.scrollHeight
  }, [total, workerMsgs])

  useEffect(() => { if (nav.chat) composer.current?.focus() }, [nav.chat, nav.chatContext])

  const openApprovals = detail.approvals.filter(a => a.status === 'pending' && !q.get('ap:' + a.id))
  const ctx = nav.chatContext

  const submit = () => {
    const text = draft.trim()
    if (!text) return
    const content = ctx ? `[About: ${ctx.label}]\n${text}` : text
    const id = crypto.randomUUID()
    setOutbox(o => [...o, { id, content, at: Date.now(), ctx: ctx?.label }])
    setDraft('')
    send({ action: 'message', message: content }).catch(() => {
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
    : r.status === 'complete' ? 'Ask about the report or findings…'
      : r.status === 'waiting' ? 'Refine the goal before consenting…' : 'Message the coordinator…'

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
      ? `Run paused in ${(PHASE_LABEL[r.phase] ?? r.phase).toLowerCase()}, round ${r.roundNo}.` + (openApprovals.length ? ' ' + capF(words(openApprovals.length)) + ' Tier 3 request' + (openApprovals.length > 1 ? 's are' : ' is') + ' waiting on you.' : '')
      : null

  return <>
    <div className="pane-h">
      <span className="t">Coordinator <span className="muted num">· {plural(total, 'message')}</span></span>
      {nav.chat && nav.sel
        ? <button type="button" className="btn ghost" style={{ height: 24 }} onClick={() => nav.closeChat()}><Icon name="undo" />Back to item</button>
        : <span className="hint"><StatusGlyph status={r.status === 'complete' ? 'complete' : r.status} /><span>{runStatusLabel(r.status)}</span></span>}
    </div>
    <ApprovalsCard />
    <div className="chat-wrap">
      <div className="pane-body" ref={scroller}>
        {model.workerMessages.length > 0 && <button type="button" className="toggle-line" style={{ width: '100%' }} onClick={() => setWorkerMsgs(v => !v)} aria-pressed={workerMsgs}>
          <span className={'switch' + (workerMsgs ? ' on' : '')} /><span>Include worker reports</span><span className="num" style={{ marginLeft: 'auto' }}>{model.workerMessages.length}</span>
        </button>}
        <div className="chat">
          {messages.map(m => {
            const sep = daySep(m.createdAt)
            const am = m.role === 'guardian' ? m.content.match(APPROVAL_RE) : null
            if (am) {
              const ap = detail.approvals.find(a => a.origin + a.pathAndQuery === am[2] || (a.method === am[1] && am[2].startsWith(a.origin)))
              const d = ap ? q.get('ap:' + ap.id) : undefined
              const st = d ? (d.act === 'approve' ? 'confirmed' : 'dismissed') : ap && ap.status !== 'pending' ? (ap.status === 'approved' ? 'confirmed' : 'dismissed') : 'paused'
              return <div key={m.id}>{sep}<div className="msg sys">
                <span className="av" style={{ background: 'none', boxShadow: 'none' }}><StatusGlyph status={st} /></span>
                <div style={{ minWidth: 0 }}>
                  <div className="who" style={{ fontWeight: 400, color: 'var(--fg-2)' }}><span>Approval requested</span><span className="muted num">{fmtTime(m.createdAt)}</span>
                    {(d || (ap && ap.status !== 'pending')) && <span className="muted">· {(d ? ACTIONS[d.act].label : ap!.status).toLowerCase()}</span>}</div>
                  <div className="body mono" style={{ fontSize: 11.5, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', cursor: ap ? 'pointer' : undefined }}
                    onClick={ap ? () => links.queueItem('ap:' + ap.id) : undefined}>{am[1]} {host(am[2])}</div>
                </div>
              </div></div>
            }
            const who = m.role === 'operator' ? ['You', 'op', 'Y'] : m.role === 'coordinator' ? ['Coordinator', 'co', 'C'] : m.role === 'worker' ? [model.workerById.get(m.threadId)?.title ?? 'Worker', '', 'W'] : ['Guardian', '', 'G']
            const evidence = (m.evidenceIds ?? []).map(id => model.evidenceById.get(id)).filter(e => !!e)
            return <div key={m.id}>{sep}<div className={'msg' + (m.role === 'guardian' ? ' sys' : '')}>
              <span className={'av ' + who[1]}>{who[1] === 'co' ? <svg viewBox="0 0 14 14" width="12" height="12" aria-hidden="true"><circle cx="7" cy="7" r="2.5" fill="currentColor" /></svg> : who[2]}</span>
              <div style={{ minWidth: 0 }}>
                <div className="who"><span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 240 }}>{who[0]}</span><span className="muted num">{fmtTime(m.createdAt)}</span></div>
                <MessageBody text={m.content} />
                {evidence.map(ev => <button key={ev.id} type="button" className="linkbtn" style={{ display: 'flex' }} onClick={() => links.evidence(ev.id)}><Icon name="fact" />{ev.title}</button>)}
              </div>
            </div></div>
          })}
          {outbox.map(m => <div key={m.id} className="msg pend new">
            <span className="av op">Y</span>
            <div style={{ minWidth: 0 }}>
              <div className="who"><span>You</span><span className="muted num">{fmtTime(m.at)}</span><span className="muted">· {inFlight ? 'sending' : 'sent'}</span></div>
              <div className="body">{m.ctx ? m.content.replace(/^\[About: [^\]]*\]\n/, '') : m.content}</div>
              {m.ctx && <span className="ctxchip" style={{ margin: '4px 0 0', animation: 'none' }}><span>{m.ctx}</span></span>}
            </div>
          </div>)}
          {statusNote && <div className="msg sys"><span className="av">G</span><div><div className="who">Guardian<span className="muted">now</span></div><div className="body">{statusNote}</div></div></div>}
        </div>
      </div>
    </div>
    <div className="composer">
      <div className="cbox">
        {ctx && <span className="ctxchip"><span>{ctx.label}</span><button type="button" title="Remove context" aria-label="Remove context" onClick={() => nav.openChat(null)}><Icon name="close" /></button></span>}
        <textarea ref={composer} value={draft} onChange={e => setDraft(e.target.value)} placeholder={placeholder} rows={2} maxLength={8000} aria-label="Message the coordinator" />
        <div className="cbox-f">
          <span>{model.needsModel || !detail.hasModel ? 'Replies wait for a connected model' : 'Sent to the run coordinator'}</span>
          <span className="sp" />
          <span className="kbd-group"><Kbd>mod</Kbd><Kbd>↵</Kbd></span>
          <button type="button" className="icon-btn" title="Send" aria-label="Send message" disabled={!draft.trim()} onClick={submit} style={{ height: 22, minWidth: 22, padding: '0 4px', color: 'var(--fg-2)' }}><Icon name="arrowUp" /></button>
        </div>
      </div>
    </div>
  </>
}
