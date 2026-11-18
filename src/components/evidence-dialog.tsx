import { useEffect, useState } from 'react'
import { Link } from '@tanstack/react-router'
import { readArtifact } from '../actions.ts'
import { Button } from './ui/button.tsx'
import { Dialog, DialogClose, DialogContent, DialogTitle } from './ui/dialog.tsx'

export function EvidenceDialog({ runId, artifactId, historyLabel, close }: {
  runId: string
  artifactId: string
  historyLabel?: string
  close: () => void
}) {
  const [artifact, setArtifact] = useState<Awaited<ReturnType<typeof readArtifact>>>()
  const [error, setError] = useState('')
  useEffect(() => {
    let active = true
    readArtifact({ data: { runId, artifactId } }).then(value => {
      if (active) setArtifact(value)
    }, () => {
      if (active) setError('This evidence is unavailable.')
    })
    return () => { active = false }
  }, [runId, artifactId])

  return <Dialog open onOpenChange={open => { if (!open) close() }}>
    <DialogContent className="artifact-dialog">
      <div className="section-heading"><DialogTitle>{artifact?.title ?? 'Evidence'}</DialogTitle>
        <DialogClose render={<Button />}>Close</DialogClose>
      </div>
      {error ? <p role="alert">{error}</p> : !artifact ? <p role="status">Loading evidence…</p> : <>
        <p className="muted">Scope revision {artifact.scopeRevision}{historyLabel && ` · ${historyLabel}`}</p>
        <pre>{artifact.content}</pre>
        <Link className="text-button" to="/runs/$runId/workers/$workerId"
          params={{ runId, workerId: artifact.assignmentId }} search={{ view: 'trace' }} onClick={close}>Open worker thread ↗</Link>
      </>}
    </DialogContent>
  </Dialog>
}
