import { useState } from 'react'
import type { FormEvent } from 'react'
import { accessPolicySnapshot, maxAccessPolicyBytes } from '../access-policy.ts'
import type { AccessPolicySnapshot } from '../access-policy.ts'
import { importProjectAccessPolicy } from '../actions.ts'
import type { Candidate } from '../domain.ts'
import { formatHumanTime, FormError, useAction } from './common.tsx'
import { Badge } from './ui/badge.tsx'
import { Button } from './ui/button.tsx'
import { Card, CardBody, CardFooter, CardHeader } from './ui/card.tsx'
import { Input } from './ui/input.tsx'

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
    return (
      <Card className="overflow-hidden border-line" aria-label="Access policy import preview">
        <CardHeader className="items-center py-2.5">
          <div className="flex flex-wrap items-center gap-2 text-[13px] font-semibold text-fg">
            <span>Review access records</span>
            <Badge variant="accent" className="font-mono">{safeHostname(snapshot.origin)}</Badge>
          </div>
          <Button type="button" variant="ghost" disabled={action.pending} onClick={cancel}>
            Close
          </Button>
        </CardHeader>
        <CardBody className="grid gap-3 py-3.5">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="neutral" className="bg-sunk tabular-nums">
              {snapshot.expected.length} expected {snapshot.expected.length === 1 ? 'case' : 'cases'}
            </Badge>
            <Badge variant="neutral" className="bg-sunk tabular-nums">
              {snapshot.observed.length} recorded {snapshot.observed.length === 1 ? 'decision' : 'decisions'}
            </Badge>
            {ratedCases > 0 && (
              <Badge variant="neutral" className="bg-sunk tabular-nums">
                {ratedCases} with impact rating
              </Badge>
            )}
          </div>
          <p className="m-0 text-[12px] text-fg-subtle">
            Recorded{' '}
            <span className="tabular-nums" title={recorded.full || undefined}>
              {recorded.label || snapshot.recordedAt}
            </span>.
            {' '}Available during the next discovery pass.
          </p>
          <FormError error={action.error} />
        </CardBody>
        <CardFooter className="py-2.5">
          <Button type="button" variant="ghost" onClick={() => setPreview(undefined)} disabled={action.pending}>
            Choose another file
          </Button>
          <Button
            type="button"
            variant="default"
            disabled={action.pending}
            onClick={() => {
              void action.submit(() => importProjectAccessPolicy({ data: { projectId, requestId, snapshot } }), imported)
            }}
          >
            {action.pending ? 'Importing…' : replacement ? 'Replace access records' : 'Import records'}
          </Button>
        </CardFooter>
      </Card>
    )
  }

  return (
    <Card className="overflow-hidden border-line">
      <form onSubmit={event => { void review(event) }}>
        <CardHeader className="items-center py-2.5">
          <span className="text-[13px] font-semibold text-fg">Import access policy records</span>
          <Button type="button" variant="ghost" onClick={cancel}>Close</Button>
        </CardHeader>
        <CardBody className="grid gap-3 py-3.5">
          <p className="m-0 text-[12px] text-fg-subtle">
            Upload expected access rules and test decisions from your authorization test suite.
          </p>
          <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
            Access policy JSON
            <Input className="w-full pt-[3px]!" name="records" type="file" accept=".json,application/json" required />
          </label>
          <FormError error={error} />
        </CardBody>
        <CardFooter className="py-2.5">
          <Button type="button" variant="ghost" onClick={cancel}>Cancel</Button>
          <Button type="submit" variant="default" disabled={reading}>
            {reading ? 'Reading…' : 'Review records'}
          </Button>
        </CardFooter>
      </form>
    </Card>
  )
}
