import { timeText } from './common.tsx'
import type { RunDetail, Worker } from './run-state.ts'
import { Button } from './ui/button.tsx'
import {
  Bubble, BubbleContent, Message, MessageContent, MessageHeader, MessageScroller, MessageScrollerButton,
  MessageScrollerContent, MessageScrollerItem, MessageScrollerProvider, MessageScrollerViewport,
} from './ui/message.tsx'
import { Trace, TraceCollapsible, TraceCollapsibleContent, TraceCollapsibleTrigger, TraceIcon, TraceLine, TraceTitle } from './ui/trace.tsx'

const roleNames = { operator: 'You', coordinator: 'Coordinator', worker: 'Worker', guardian: 'Guardian' } as const

function EvidenceRows({ items, label, openEvidence }: {
  items: RunDetail['evidence']
  label: string
  openEvidence: (id: string) => void
}) {
  if (!items.length) return null
  return <Trace role="group" aria-label={label}>
    {items.map(item => <Button key={item.id} variant="ghost" className="evidence-row" onClick={() => openEvidence(item.id)}>
      <TraceLine><TraceIcon>↳</TraceIcon><TraceTitle>{item.title}</TraceTitle></TraceLine>
      <span aria-hidden="true">↗</span>
    </Button>)}
  </Trace>
}

export function ThreadTranscript({ messages, worker, workerFacts, attachments, openEvidence }: {
  messages: RunDetail['messages']
  worker?: Worker
  workerFacts?: RunDetail['facts']
  attachments: RunDetail['evidence']
  openEvidence: (id: string) => void
}) {
  const evidenceById = new Map(attachments.map(item => [item.id, item]))
  const linked = new Set(messages.flatMap(message => message.evidenceIds ?? []))
  const assignment = attachments.find(item => item.operationId === 'assignment')
  const supporting = attachments.filter(item => item.id !== assignment?.id && !linked.has(item.id))

  return <MessageScrollerProvider autoScroll={!worker} defaultScrollPosition={worker ? 'start' : 'end'}>
    <MessageScroller>
      <MessageScrollerViewport aria-label={worker ? 'Worker transcript' : 'Coordinator transcript'}>
        <MessageScrollerContent>
          {worker && <Trace aria-label="Assignment activity">
            <TraceCollapsible defaultOpen>
              <TraceCollapsibleTrigger>
                <TraceLine><TraceIcon>◎</TraceIcon><TraceTitle>Assignment</TraceTitle></TraceLine>
              </TraceCollapsibleTrigger>
              <TraceCollapsibleContent>
                <p>{worker.objective}</p>
                {assignment && <EvidenceRows items={[assignment]} label="Assignment file" openEvidence={openEvidence} />}
              </TraceCollapsibleContent>
            </TraceCollapsible>
          </Trace>}
          {worker && workerFacts && workerFacts.length > 0 && <Trace aria-label="Recorded facts">
            <TraceCollapsible>
              <TraceCollapsibleTrigger>
                <TraceLine><TraceIcon>◆</TraceIcon><TraceTitle>{workerFacts.length} recorded {workerFacts.length === 1 ? 'fact' : 'facts'}</TraceTitle></TraceLine>
              </TraceCollapsibleTrigger>
              <TraceCollapsibleContent>
                {workerFacts.map(fact => <p key={fact.id}>
                  <strong>[{fact.kind}]</strong> {fact.summary}{fact.tainted ? ' (tainted)' : ''}
                </p>)}
              </TraceCollapsibleContent>
            </TraceCollapsible>
          </Trace>}
          {messages.map(message => {
            const fromOperator = message.role === 'operator'
            const evidence = (message.evidenceIds ?? []).flatMap(id => {
              const item = evidenceById.get(id)
              return item ? [item] : []
            })
            return <MessageScrollerItem key={message.id} messageId={message.id} scrollAnchor={fromOperator}>
              <Message align={fromOperator ? 'end' : 'start'} data-role={message.role}>
                <MessageContent>
                  <MessageHeader>{roleNames[message.role]}
                    <time dateTime={new Date(message.createdAt).toISOString()}>{timeText(message.createdAt)}</time>
                  </MessageHeader>
                  <Bubble variant={fromOperator ? 'muted' : 'ghost'}>
                    <BubbleContent>{message.content}</BubbleContent>
                  </Bubble>
                  <EvidenceRows items={evidence} label="Turn evidence" openEvidence={openEvidence} />
                </MessageContent>
              </Message>
            </MessageScrollerItem>
          })}
          <EvidenceRows items={supporting} label="Supporting evidence" openEvidence={openEvidence} />
        </MessageScrollerContent>
      </MessageScrollerViewport>
      <MessageScrollerButton aria-label="Jump to latest message" render={<Button size="icon" />}>
        <span aria-hidden="true">↓</span>
      </MessageScrollerButton>
    </MessageScroller>
  </MessageScrollerProvider>
}
