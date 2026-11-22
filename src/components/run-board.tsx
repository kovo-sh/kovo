import { useEffect, useMemo, useRef, useState } from 'react'
import {
  canonicalBoardHandles, parseBoardMentions, specialistProfileByHandle,
} from '../domain.ts'
import type { BoardMessageKind } from '../domain.ts'
import { timeText } from './common.tsx'
import type { Command } from './run-overview.tsx'
import { boardKindLabels, boardRoleLabels, boardStateMeta } from './run-state.ts'
import type { RunDetail } from './run-state.ts'
import { Button } from './ui/button.tsx'
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupTextarea } from './ui/input-group.tsx'
import {
  Bubble, BubbleContent, Message, MessageContent, MessageHeader, MessageScroller, MessageScrollerButton,
  MessageScrollerContent, MessageScrollerItem, MessageScrollerProvider, MessageScrollerViewport,
} from './ui/message.tsx'

type BoardFilter = 'all' | 'handoffs' | 'blockers' | 'approvals' | string

interface OpenRef {
  messageId: string
  kind: 'fact' | 'exchange' | 'finding' | 'step'
  id: string
}

const filterPresets = [
  { id: 'all', label: 'All' },
  { id: 'handoffs', label: 'Handoffs & Verdicts' },
  { id: 'blockers', label: 'Blockers' },
  { id: 'approvals', label: 'Approvals' },
] as const

function messageMatchesFilter(message: RunDetail['boardMessages'][number], filter: BoardFilter) {
  if (filter === 'all') return true
  if (filter === 'handoffs') return message.kind === 'handoff' || message.kind === 'verdict'
  if (filter === 'blockers') return message.kind === 'blocker'
  if (filter === 'approvals') return message.kind === 'approval' || Boolean(message.refApprovalId)
  return message.authorHandle === filter || message.mentions.includes(filter)
}

function ApprovalActions({ approval, pending, execute }: {
  approval: RunDetail['approvals'][number]
  pending: boolean
  execute: (command: Command) => void
}) {
  if (approval.status !== 'pending') return null
  return <div className="approval-actions">
    <Button className="btn-danger" disabled={pending} onClick={() => {
      execute({ action: 'decide_approval', approvalId: approval.id, decision: 'denied' })
    }}>Deny</Button>
    <Button variant="ghost" disabled={pending} onClick={() => {
      execute({ action: 'approve_similar_endpoint', approvalId: approval.id })
    }}>Approve similar</Button>
    <Button variant="default" disabled={pending} onClick={() => {
      execute({ action: 'decide_approval', approvalId: approval.id, decision: 'approved' })
    }}>Approve</Button>
  </div>
}

function ApprovalCard({ approval, pending, execute, inline = false }: {
  approval: RunDetail['approvals'][number]
  pending: boolean
  execute: (command: Command) => void
  inline?: boolean
}) {
  return <div className={`approval-card${inline ? ' approval-card-compact board-approval-inline' : ' approval-card-compact'}`}
    data-testid={inline ? 'board-approval-inline' : 'board-approval-card'} data-approval-id={approval.id}>
    <div className="inline-badges">
      <strong>Tier 3 approval</strong>
      <span className="badge badge-attention">{approval.method}</span>
      <span className={`badge ${approval.status === 'pending' ? 'badge-attention' : 'badge-complete'}`}>{approval.status}</span>
    </div>
    <p className="approval-target"><code>{approval.origin}{approval.pathAndQuery}</code></p>
    <p className="muted">{approval.rationale}</p>
    <ApprovalActions approval={approval} pending={pending} execute={execute} />
  </div>
}

export function RunBoard({ detail, pending, execute, inspectWorker, openEvidence }: {
  detail: RunDetail
  pending: boolean
  execute: (command: Command, onSuccess?: () => void) => void
  inspectWorker: (workerId: string) => void
  openEvidence: (artifactId: string) => void
}) {
  const [filter, setFilter] = useState<BoardFilter>('all')
  const [draft, setDraft] = useState('')
  const [openRef, setOpenRef] = useState<OpenRef>()
  const [mention, setMention] = useState<{ query: string; start: number }>()
  const [highlight, setHighlight] = useState(0)
  const textarea = useRef<HTMLTextAreaElement>(null)
  const { run, boardMessages, boardMembers, approvals } = detail

  const members = useMemo(() => {
    const roster = [...boardMembers]
    if (!roster.some(member => member.handle === 'coordinator')) {
      roster.unshift({
        id: 'coordinator-implicit',
        runId: run.id,
        handle: 'coordinator',
        role: 'coordinator',
        specialistProfile: null,
        sessionId: run.coordinatorId,
        activeAssignmentId: null,
        state: 'waiting',
        roleAffinity: null,
        lastReadSeq: 0,
        turnsUsed: 0,
        postsCount: boardMessages.filter(message => message.authorHandle === 'coordinator').length,
        peerHopsUsed: 0,
        scopeRevision: run.scopeRevision,
        goalRevision: run.goalRevision,
        sourceOrigins: [],
        createdAt: run.createdAt,
        updatedAt: run.createdAt,
      })
    }
    return roster
  }, [boardMembers, boardMessages, run])

  const handleOrder = useMemo(() => {
    const order = new Map<string, number>(canonicalBoardHandles.map((handle, index) => [handle, index]))
    return [...new Set([
      ...canonicalBoardHandles,
      ...members.filter(member => member.state !== 'retired').map(member => member.handle),
    ])].sort((a, b) => (order.get(a) ?? 99) - (order.get(b) ?? 99) || a.localeCompare(b))
  }, [members])

  const mentionCandidates = useMemo(() => {
    const active = members.filter(member => member.state !== 'retired').map(member => member.handle)
    return [...new Set([...handleOrder, ...active, 'all'])]
  }, [handleOrder, members])
  const visibleMentions = mentionCandidates.filter(handle => mention && handle.startsWith(mention.query)).slice(0, 10)

  const visibleMessages = boardMessages.filter(message => messageMatchesFilter(message, filter))
  const pendingApprovals = approvals.filter(item => item.status === 'pending')
  const approvalById = useMemo(() => new Map(approvals.map(item => [item.id, item])), [approvals])
  const factById = useMemo(() => new Map(detail.facts.map(fact => [fact.id, fact])), [detail.facts])
  const exchangeById = useMemo(() => new Map(detail.exchangesSummary.map(item => [item.id, item])), [detail.exchangesSummary])
  const findingById = useMemo(() => new Map(detail.findings.map(item => [item.id, item])), [detail.findings])
  const stepById = useMemo(() => new Map(detail.chainSteps.map(item => [item.id, item])), [detail.chainSteps])

  useEffect(() => {
    if (!mention) return
    setHighlight(0)
  }, [mention?.query])

  function updateDraft(value: string) {
    setDraft(value)
    const caret = textarea.current?.selectionStart ?? value.length
    const upto = value.slice(0, caret)
    const match = /(^|\s)@([a-z0-9_-]*)$/i.exec(upto)
    setMention(match ? { query: match[2].toLowerCase(), start: caret - match[2].length - 1 } : undefined)
  }

  function pickMention(handle: string) {
    if (!mention) return
    const caret = textarea.current?.selectionStart ?? draft.length
    const before = draft.slice(0, mention.start)
    const after = draft.slice(caret).replace(/^\s+/, '')
    const next = `${before}@${handle}${after ? ' ' + after : ' '}`
    setDraft(next)
    setMention(undefined)
    requestAnimationFrame(() => {
      const element = textarea.current
      if (!element) return
      element.focus()
      const position = before.length + handle.length + 2
      element.setSelectionRange(position, position)
    })
  }

  function submit() {
    const body = draft.trim()
    if (!body) return
    const mentions = parseBoardMentions(body)
    if (mentions.length) {
      execute({ action: 'board_post', body: body.slice(0, 1200), mentions }, () => setDraft(''))
    } else {
      execute({ action: 'message', message: body }, () => setDraft(''))
    }
  }

  function refChip(message: RunDetail['boardMessages'][number], kind: OpenRef['kind'], id: string, label: string) {
    const active = openRef?.messageId === message.id && openRef.kind === kind && openRef.id === id
    return <button
      key={`${kind}:${id}`}
      type="button"
      className={`board-ref-chip${active ? ' active' : ''}`}
      data-ref-kind={kind}
      data-ref-id={id}
      aria-pressed={active}
      onClick={() => setOpenRef(active ? undefined : { messageId: message.id, kind, id })}
    >{label}</button>
  }

  function refDetail(ref: OpenRef) {
    if (ref.kind === 'fact') {
      const fact = factById.get(ref.id)
      if (!fact) return <p className="muted xs">Fact {ref.id} is not loaded in this run detail.</p>
      return <>
        <strong>{fact.kind} · {fact.origin}</strong>
        <p>{fact.summary}{fact.tainted ? ' (tainted by scope revocation)' : ''}</p>
      </>
    }
    if (ref.kind === 'exchange') {
      const exchange = exchangeById.get(ref.id)
      if (!exchange) return <p className="muted xs">Exchange {ref.id} is outside the loaded window.</p>
      return <>
        <strong>{exchange.method} {exchange.origin}{exchange.pathAndQuery}</strong>
        <p>HTTP {exchange.status ?? '—'} · {exchange.mediaType ?? 'unknown type'} · {exchange.personaHandle ?? 'anonymous'}</p>
        {exchange.bodyArtifactId && <Button variant="ghost" className="evidence-row" onClick={() => openEvidence(exchange.bodyArtifactId!)}>
          Open redacted exchange evidence ↗
        </Button>}
      </>
    }
    if (ref.kind === 'finding') {
      const finding = findingById.get(ref.id)
      if (!finding) return <p className="muted xs">Finding {ref.id} is not loaded.</p>
      return <>
        <strong>{finding.title}</strong>
        <p>{finding.status} · {finding.severity} · {finding.category}</p>
      </>
    }
    const step = stepById.get(ref.id)
    if (!step) return <p className="muted xs">Chain step {ref.id} is not loaded.</p>
    return <>
      <strong>Step #{step.seq} · {step.title}</strong>
      <p>{step.status} · {step.hypothesis}</p>
    </>
  }

  return <div className="board-pane" data-testid="board-pane">
    <div className="board-roster" data-testid="board-roster" aria-label="Board roster">
      {members.map(member => {
        const meta = boardStateMeta[member.state]
        const profile = member.specialistProfile ?? specialistProfileByHandle[member.handle]
        const active = filter === member.handle
        return <div key={member.id} className={`board-member ${meta.className}${active ? ' active' : ''}`}
          data-handle={member.handle} data-state={member.state}>
          <button
            type="button"
            className="board-member-pill"
            title={`${profile ?? member.role} · ${member.state} · filter board by @${member.handle}`}
            aria-pressed={active}
            onClick={() => setFilter(active ? 'all' : member.handle)}
          >
            <span aria-hidden="true" className="board-state-symbol">{meta.symbol}</span>
            <span>@{member.handle}</span>
            <span className="board-member-state">{meta.label}</span>
          </button>
          {member.activeAssignmentId && member.state !== 'retired' && <button
            type="button"
            className="board-member-inspect"
            aria-label={`Inspect @${member.handle}`}
            title={`Inspect @${member.handle} worker transcript`}
            onClick={() => inspectWorker(member.activeAssignmentId!)}
          >↗</button>}
        </div>
      })}
    </div>

    {pendingApprovals.length > 0 && <div className="board-approvals" aria-label="Pending Tier 3 approvals" data-testid="board-approvals">
      <div className="board-section-label">Pending approvals · {pendingApprovals.length}</div>
      {pendingApprovals.map(item => <ApprovalCard key={item.id} approval={item} pending={pending} execute={execute} />)}
    </div>}

    <div className="board-filters" role="group" aria-label="Board filters">
      {filterPresets.map(preset => <button
        key={preset.id}
        type="button"
        className={`board-filter-chip${filter === preset.id ? ' active' : ''}`}
        aria-pressed={filter === preset.id}
        onClick={() => setFilter(preset.id)}
      >{preset.label}</button>)}
      {handleOrder.filter(handle => handle !== 'coordinator').map(handle => <button
        key={handle}
        type="button"
        className={`board-filter-chip${filter === handle ? ' active' : ''}`}
        aria-pressed={filter === handle}
        onClick={() => setFilter(filter === handle ? 'all' : handle)}
      >@{handle}</button>)}
    </div>

    <div className="board-timeline" data-testid="board-timeline">
      <MessageScrollerProvider autoScroll defaultScrollPosition="end">
        <MessageScroller>
          <MessageScrollerViewport aria-label="Board timeline">
            <MessageScrollerContent>
              {!visibleMessages.length && <p className="muted board-empty">
                No board traffic for this filter yet. System posters land here as the run progresses.
              </p>}
              {visibleMessages.map(message => {
                const fromOperator = message.authorRole === 'operator'
                const approval = message.refApprovalId ? approvalById.get(message.refApprovalId) : undefined
                const mentions = message.mentions.filter(handle => handle !== 'coordinator' || message.authorRole !== 'operator')
                return <MessageScrollerItem key={message.id} messageId={message.id} scrollAnchor={fromOperator}>
                  <Message align={fromOperator ? 'end' : 'start'} data-role={message.authorRole}
                    data-kind={message.kind} data-tainted={message.tainted} data-seq={message.seq}>
                    <MessageContent>
                      <MessageHeader>
                        <span className="board-author">@{message.authorHandle}</span>
                        <span className={`board-kind board-kind-${message.kind}`}>{boardKindLabels[message.kind as BoardMessageKind] ?? message.kind.toUpperCase()}</span>
                        <span className="muted xs">{boardRoleLabels[message.authorRole] ?? message.authorRole}</span>
                        {message.tainted && <span className="badge badge-attention" title="Scope revoked: excluded from future specialist wakes">TAINTED</span>}
                        <time dateTime={new Date(message.createdAt).toISOString()}>{timeText(message.createdAt)}</time>
                      </MessageHeader>
                      <Bubble variant={fromOperator ? 'muted' : 'ghost'}>
                        <BubbleContent>{message.body}</BubbleContent>
                      </Bubble>
                      {(mentions.length > 0 || message.replyToSeq) && <div className="board-meta-row">
                        {message.replyToSeq && <span className="board-reply" data-testid="board-reply">↳ #{message.replyToSeq}</span>}
                        {mentions.map(handle => <button
                          key={handle}
                          type="button"
                          className={`board-mention-chip${filter === handle ? ' active' : ''}`}
                          onClick={() => setFilter(filter === handle ? 'all' : handle)}
                        >@{handle}</button>)}
                      </div>}
                      {(message.refFactIds.length > 0 || message.refExchangeIds.length > 0 || message.refFindingIds.length > 0 || message.refStepId) &&
                        <div className="board-refs" aria-label="Evidence references">
                          {message.refFactIds.map(id => refChip(message, 'fact', id, id))}
                          {message.refExchangeIds.map(id => refChip(message, 'exchange', id, id))}
                          {message.refFindingIds.map(id => refChip(message, 'finding', id, id))}
                          {message.refStepId && refChip(message, 'step', message.refStepId, `step:${stepById.get(message.refStepId)?.seq ?? message.refStepId}`)}
                        </div>}
                      {openRef?.messageId === message.id && <div className="board-ref-detail" data-testid="board-ref-detail">
                        {refDetail(openRef)}
                      </div>}
                      {approval && <ApprovalCard approval={approval} pending={pending} execute={execute} inline />}
                    </MessageContent>
                  </Message>
                </MessageScrollerItem>
              })}
            </MessageScrollerContent>
          </MessageScrollerViewport>
          <MessageScrollerButton aria-label="Jump to latest board message" render={<Button size="icon" />}>
            <span aria-hidden="true">↓</span>
          </MessageScrollerButton>
        </MessageScroller>
      </MessageScrollerProvider>
    </div>

    <form className="composer board-composer" data-testid="board-composer" onSubmit={event => {
      event.preventDefault()
      submit()
    }}>
      {mention && visibleMentions.length > 0 && <div className="board-mention-popover" role="listbox" aria-label="Mention roster">
        {visibleMentions.map((handle, index) => <button
          key={handle}
          type="button"
          role="option"
          aria-selected={index === highlight}
          className={`board-mention-option${index === highlight ? ' active' : ''}`}
          onMouseDown={event => { event.preventDefault(); pickMention(handle) }}
        >
          <span>@{handle}</span>
          <span className="muted xs">{specialistProfileByHandle[handle] ?? (handle === 'all' ? 'broadcast' : 'system')}</span>
        </button>)}
      </div>}
      <InputGroup>
        <InputGroupTextarea
          ref={textarea}
          rows={1}
          value={draft}
          onChange={event => updateDraft(event.target.value)}
          onKeyDown={event => {
            if (mention && visibleMentions.length) {
              if (event.key === 'ArrowDown') {
                event.preventDefault()
                setHighlight(index => (index + 1) % visibleMentions.length)
                return
              }
              if (event.key === 'ArrowUp') {
                event.preventDefault()
                setHighlight(index => (index - 1 + visibleMentions.length) % visibleMentions.length)
                return
              }
              if (event.key === 'Enter' || event.key === 'Tab') {
                event.preventDefault()
                pickMention(visibleMentions[highlight] ?? visibleMentions[0])
                return
              }
              if (event.key === 'Escape') {
                event.preventDefault()
                setMention(undefined)
                return
              }
            }
            if (event.key !== 'Enter' || event.shiftKey || event.nativeEvent.isComposing) return
            event.preventDefault()
            event.currentTarget.form?.requestSubmit()
          }}
          aria-label="Message board"
          placeholder="Message the board — plain text goes to @coordinator. Type @ to direct a specialist…"
        />
        <InputGroupAddon><InputGroupButton type="submit" variant="default" aria-label="Send board message"
          disabled={pending || !draft.trim()}>↑</InputGroupButton></InputGroupAddon>
      </InputGroup>
    </form>
  </div>
}
