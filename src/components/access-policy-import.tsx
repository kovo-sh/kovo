import { useState } from 'react'
import type { FormEvent } from 'react'
import { accessPolicySnapshot, maxAccessPolicyBytes } from '../access-policy.ts'
import type { AccessPolicySnapshot } from '../access-policy.ts'
import { importProjectAccessPolicy } from '../actions.ts'
import type { Candidate } from '../domain.ts'
import { FormError, timeText, useAction } from './common.tsx'
import { Button } from './ui/button.tsx'
import { Input } from './ui/input.tsx'

export function AccessPolicyImport({ projectId, assets, cancel, imported }: {
  projectId: string
  assets: Pick<Candidate, 'origin' | 'accessPolicy'>[]
  cancel: () => void
  imported: (result: { origin: string; cases: number }) => void
}) {
  const [preview, setPreview] = useState<{ snapshot: AccessPolicySnapshot; requestId: string }>()
  const [reading, setReading] = useState(false)
  const [error, setError] = useState('')
  const action = useAction()

  async function review(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const file = new FormData(event.currentTarget).get('records')
    if (!(file instanceof File) || !file.size || file.size > maxAccessPolicyBytes) {
      setError('Choose a JSON file of at most 64 KiB.')
      return
    }
    setReading(true)
    setError('')
    try {
      const input: unknown = JSON.parse(await file.text())
      const parsed = accessPolicySnapshot.safeParse(input)
      if (!parsed.success) {
        const issue = parsed.error.issues[0]
        setError(issue.path.length ? issue.message + ' (' + issue.path.join('.') + ')' : issue.message)
      } else if (!assets.some(asset => asset.origin === parsed.data.origin)) {
        setError('Select a file for an existing project host.')
      } else {
        setPreview({ snapshot: parsed.data, requestId: crypto.randomUUID() })
      }
    } catch {
      setError('Choose a readable JSON file with access policy records.')
    } finally {
      setReading(false)
    }
  }

  if (preview) {
    const { snapshot, requestId } = preview
    const replacement = assets.some(asset => asset.origin === snapshot.origin && asset.accessPolicy)
    const ratedCases = snapshot.expected.filter(item => item.impactIfAllowed).length
    return <section className="form-card" aria-label="Access policy import preview">
      <h3>{new URL(snapshot.origin).hostname}</h3>
      <p>{snapshot.expected.length} expected cases · {snapshot.observed.length} recorded decisions</p>
      {ratedCases > 0 && <p className="muted">Policy impact supplied for {ratedCases} {ratedCases === 1 ? 'case' : 'cases'}.</p>}
      <p className="muted">Recorded {timeText(Date.parse(snapshot.recordedAt))}. Available at the next discovery.</p>
      <FormError error={action.error} />
      <div className="form-actions">
        <Button onClick={() => setPreview(undefined)} disabled={action.pending}>Choose another file</Button>
        <Button variant="default" disabled={action.pending} onClick={() => {
          void action.submit(() => importProjectAccessPolicy({ data: { projectId, requestId, snapshot } }), imported)
        }}>{replacement ? 'Replace access records' : 'Import records'}</Button>
      </div>
    </section>
  }

  return <form className="form-card" onSubmit={event => { void review(event) }}>
    <h3>Import access policy records</h3>
    <p className="muted">Load expected policy cases and decisions from your authorization tests.</p>
    <label>Access policy JSON<Input name="records" type="file" accept=".json,application/json" required /></label>
    <FormError error={error} />
    <div className="form-actions">
      <Button onClick={cancel}>Cancel</Button>
      <Button type="submit" variant="default" disabled={reading}>Review records</Button>
    </div>
  </form>
}
