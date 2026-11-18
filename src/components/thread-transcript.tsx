import { timeText } from './common.tsx'
import type { RunDetail, Worker } from './run-state.ts'
import { Button } from './ui/button.tsx'
import {
  Bubble, BubbleContent, Message, MessageContent, MessageHeader, MessageScroller, MessageScrollerButton,
  MessageScrollerContent, MessageScrollerItem, MessageScrollerProvider, MessageScrollerViewport,
} from './ui/message.tsx'
import { Trace, TraceCollapsible, TraceCollapsibleContent, TraceCollapsibleTrigger, TraceIcon, TraceLine, TraceTitle } from './ui/trace.tsx'

const roleNames = { operator: 'You', coordinator: 'Coordinator', worker: 'Worker', guardian: 'Guardian' } as const

export function ThreadTranscript({ messages, worker, attachments, openEvidence }: {
  messages: RunDetail['messages']
  worker?: Worker
  attachments: RunDetail['evidence']
  openEvidence: (id: string) => void
}) {
  return <MessageScrollerProvider autoScroll={!worker} defaultScrollPosition={worker ? 'start' : 'end'}>
    <MessageScroller>
      <MessageScrollerViewport aria-label={worker ? 'Worker transcript' : 'Coordinator transcript'}>
        <MessageScrollerContent>
          {worker && <Trace aria-label="Assignment activity">
            <TraceCollapsible defaultOpen>
              <TraceCollapsibleTrigger>
                <TraceLine><TraceIcon>◎</TraceIcon><TraceTitle>Assignment</TraceTitle></TraceLine>
              </TraceCollapsibleTrigger>
              <TraceCollapsibleContent>{worker.objective}</TraceCollapsibleContent>
            </TraceCollapsible>
          </Trace>}
          {messages.map(message => {
            const fromOperator = message.role === 'operator'
            return <MessageScrollerItem key={message.id} messageId={message.id} scrollAnchor={fromOperator}>
              <Message align={fromOperator ? 'end' : 'start'} data-role={message.role}>
                <MessageContent>
                  <MessageHeader>{roleNames[message.role]}
                    <time dateTime={new Date(message.createdAt).toISOString()}>{timeText(message.createdAt)}</time>
                  </MessageHeader>
                  <Bubble variant={fromOperator ? 'muted' : 'ghost'}>
                    <BubbleContent>{message.content}</BubbleContent>
                  </Bubble>
                </MessageContent>
              </Message>
            </MessageScrollerItem>
          })}
          {attachments.length > 0 && <Trace aria-label="Supporting evidence">
            {attachments.map(item => <Button key={item.id} variant="ghost" className="evidence-row" onClick={() => openEvidence(item.id)}>
              <TraceLine><TraceIcon>↳</TraceIcon><TraceTitle>{item.title}</TraceTitle></TraceLine>
              <span aria-hidden="true">↗</span>
            </Button>)}
          </Trace>}
        </MessageScrollerContent>
      </MessageScrollerViewport>
      <MessageScrollerButton aria-label="Jump to latest message" render={<Button size="icon" />}>
        <span aria-hidden="true">↓</span>
      </MessageScrollerButton>
    </MessageScroller>
  </MessageScrollerProvider>
}
