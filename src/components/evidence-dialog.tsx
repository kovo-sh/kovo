import { useEffect, useRef, useState } from 'react'
import { readArtifact } from '../actions.ts'

export function EvidenceDialog({ runId, artifactId, close }: {
  runId: string
  artifactId: string
  close: () => void
}) {
  const dialog = useRef<HTMLDialogElement>(null)
  const [artifact, setArtifact] = useState<Awaited<ReturnType<typeof readArtifact>>>()
  const [error, setError] = useState('')
  useEffect(() => {
    dialog.current?.showModal()
    let active = true
    readArtifact({ data: { runId, artifactId } }).then(value => {
      if (active) setArtifact(value)
    }, () => {
      if (active) setError('This evidence is unavailable.')
    })
    return () => { active = false }
  }, [runId, artifactId])

  return <dialog ref={dialog} className="artifact-dialog" aria-labelledby="artifact-title" onClose={close}>
    <div className="section-heading"><h2 id="artifact-title">{artifact?.title ?? 'Evidence'}</h2>
      <button onClick={() => dialog.current?.close()}>Close</button>
    </div>
    {error ? <p role="alert">{error}</p> : !artifact ? <p role="status">Loading evidence…</p> : <>
      <p className="muted">Scope revision {artifact.scopeRevision}</p>
      <pre>{artifact.content}</pre>
    </>}
  </dialog>
}
