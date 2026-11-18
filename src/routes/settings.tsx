import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import { modelData, saveModel, testModel } from '../actions.ts'
import { FormError, useAction } from '../components/common.tsx'
import { Button } from '../components/ui/button.tsx'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '../components/ui/collapsible.tsx'
import { Input, NativeSelect } from '../components/ui/input.tsx'
import { DEFAULT_PROVIDER, id } from '../domain.ts'

export const Route = createFileRoute('/settings')({
  validateSearch: (search): { runId?: string } => ({ runId: id.safeParse(search.runId).data }),
  loader: () => modelData(),
  component: ModelPage,
})

function ModelPage() {
  const config = Route.useLoaderData()
  const { runId } = Route.useSearch()
  const navigate = useNavigate()
  const action = useAction()
  const [feedback, setFeedback] = useState('')
  return <main className="workspace-page">
    {runId ? <Link to="/runs/$runId" params={{ runId }} className="back-link">← Back to run</Link>
      : <Link to="/" className="back-link">← Projects</Link>}
    <div className="page-title"><h1>Model settings</h1></div>
    <form className="form-card" onInput={() => setFeedback('')} onSubmit={event => {
      event.preventDefault()
      setFeedback('')
      const form = new FormData(event.currentTarget)
      const command = (event.nativeEvent as SubmitEvent).submitter?.getAttribute('value')
      const data = {
        endpoint: String(form.get('endpoint')), model: String(form.get('model')),
        protocol: form.get('protocol') === 'messages' ? 'messages' as const : 'responses' as const,
        key: String(form.get('key')),
      }
      const element = event.currentTarget
      void action.submit(() => command === 'test' ? testModel({ data }) : saveModel({ data }), async () => {
        setFeedback(command === 'test' ? 'Connection verified. The model streamed a valid tool call.' : 'Model saved for this workspace.')
        if (command !== 'test') {
          const input = element.elements.namedItem('key') as HTMLInputElement | null
          if (input) input.value = ''
          if (runId) await navigate({ to: '/runs/$runId', params: { runId } })
        }
      })
    }}>
      <h2>{config ? 'Workspace model' : 'Connect OpenRouter'}</h2>
      {config && <p className="muted">Active model <strong>{config.model}</strong></p>}
      <label>API key<Input name="key" type="password" required minLength={8} maxLength={512} autoComplete="off"
        placeholder={config ? 'Enter a replacement key' : 'Enter your provider key'} /></label>
      <Collapsible className="provider-advanced">
        <CollapsibleTrigger render={<Button variant="ghost" />}>Advanced provider settings</CollapsibleTrigger>
        <CollapsibleContent keepMounted>
          <label>Model ID<Input name="model" required defaultValue={(config ?? DEFAULT_PROVIDER).model} /></label>
          <label>Base URL<Input name="endpoint" type="url" required defaultValue={(config ?? DEFAULT_PROVIDER).endpoint} /></label>
          <label>Protocol<NativeSelect name="protocol" defaultValue={(config ?? DEFAULT_PROVIDER).protocol}>
            <option value="responses">OpenAI Responses</option>
            <option value="messages">Anthropic Messages</option>
          </NativeSelect></label>
        </CollapsibleContent>
      </Collapsible>
      <p className="muted">The provider receives sanitized context and selected evidence excerpts. The connection test uses synthetic input.</p>
      <FormError error={action.error} />
      {feedback && <p role="status">{feedback}</p>}
      <div className="form-actions">
        <Button type="submit" value="test" disabled={action.pending}>Test connection</Button>
        <Button type="submit" value="save" variant="default" disabled={action.pending}>Save model</Button>
      </div>
    </form>
  </main>
}
