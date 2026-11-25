import { useState } from 'react'
import type { FormEvent } from 'react'
import { accessPolicySnapshot, maxAccessPolicyBytes } from '../access-policy.ts'
import type { AccessPolicySnapshot } from '../access-policy.ts'
import { importProjectAccessPolicy } from '../actions.ts'
import type { Candidate } from '../domain.ts'
import { formatHumanTime, FormError, useAction } from './common.tsx'

function safeHostname(origin: string): string {
  try {
    return new URL(origin).hostname
  } catch {
    return origin
  }
}

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
      setError('Choose a JSON file up to 64 KiB.')
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
        setError('Select a file for a host that is already in this project.')
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
    const recorded = formatHumanTime(snapshot.recordedAt)
    return <section className="pw-sheet" aria-label="Access policy import preview">
      <div className="pw-sheet-h">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <span>Review access records</span>
          <span className="pw-tag accent mono">{safeHostname(snapshot.origin)}</span>
        </div>
        <button type="button" className="pw-btn ghost" disabled={action.pending} onClick={cancel}>Close</button>
      </div>
      <div className="pw-sheet-b">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <span className="pw-tag solid num">{snapshot.expected.length} expected {snapshot.expected.length === 1 ? 'case' : 'cases'}</span>
          <span className="pw-tag solid num">{snapshot.observed.length} recorded {snapshot.observed.length === 1 ? 'decision' : 'decisions'}</span>
          {ratedCases > 0 && (
            <span className="pw-tag solid num">{ratedCases} with impact rating</span>
          )}
        </div>
        <p className="muted" style={{ margin: 0, fontSize: 12 }}>
          Recorded{' '}
          <span className="num" title={recorded.full || undefined}>{recorded.label || snapshot.recordedAt}</span>.
          {' '}Available during the next discovery pass.
        </p>
        <FormError error={action.error} />
      </div>
      <div className="pw-sheet-f">
        <button type="button" className="pw-btn ghost" onClick={() => setPreview(undefined)} disabled={action.pending}>
          Choose another file
        </button>
        <button
          type="button"
          className="pw-btn primary"
          disabled={action.pending}
          onClick={() => {
            void action.submit(() => importProjectAccessPolicy({ data: { projectId, requestId, snapshot } }), imported)
          }}
        >
          {action.pending ? 'Importing…' : replacement ? 'Replace access records' : 'Import records'}
        </button>
      </div>
    </section>
  }

  return <form className="pw-sheet" onSubmit={event => { void review(event) }}>
    <div className="pw-sheet-h">
      <span>Import access policy records</span>
      <button type="button" className="pw-btn ghost" onClick={cancel}>Close</button>
    </div>
    <div className="pw-sheet-b">
      <p className="muted" style={{ margin: 0, fontSize: 12 }}>
        Upload expected access rules and test decisions from your authorization test suite.
      </p>
      <label className="pw-fld">Access policy JSON
        <input className="pw-in" style={{ paddingTop: 3 }} name="records" type="file" accept=".json,application/json" required />
      </label>
      <FormError error={error} />
    </div>
    <div className="pw-sheet-f">
      <button type="button" className="pw-btn ghost" onClick={cancel}>Cancel</button>
      <button type="submit" className="pw-btn primary" disabled={reading}>
        {reading ? 'Reading…' : 'Review records'}
      </button>
    </div>
  </form>
}
