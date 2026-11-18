import { useState } from 'react'
import type { FormEvent } from 'react'
import { importProjectDns } from '../actions.ts'
import { maxDnsExportBytes } from '../domain.ts'
import { parseDnsInventory } from '../passive-dns.ts'
import { FormError, useAction } from './common.tsx'
import { Button } from './ui/button.tsx'
import { Input } from './ui/input.tsx'

export function DnsInventoryImport({ projectId, defaultZone, cancel, imported }: {
  projectId: string
  defaultZone: string
  cancel: () => void
  imported: (result: { added: number; existing: number }) => void
}) {
  const [preview, setPreview] = useState<(ReturnType<typeof parseDnsInventory> & { document: string; requestId: string })>()
  const [reading, setReading] = useState(false)
  const [error, setError] = useState('')
  const action = useAction()

  async function review(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const fields = new FormData(event.currentTarget)
    const file = fields.get('export')
    const zone = String(fields.get('zone') ?? '')
    if (!(file instanceof File) || !file.size || file.size > maxDnsExportBytes) {
      setError('Choose a DNS export of at most 128 KiB.')
      return
    }
    setReading(true)
    setError('')
    try {
      const document = await file.text()
      setPreview({ ...parseDnsInventory(zone, document), document, requestId: crypto.randomUUID() })
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'The DNS export could not be read.')
    } finally {
      setReading(false)
    }
  }

  if (preview) return <section className="form-card" aria-label="DNS import preview">
    <h3>Review DNS inventory</h3>
    <p className="muted">{preview.candidates.length} {preview.candidates.length === 1 ? 'host' : 'hosts'} in {preview.zone}. Choose hosts during the next run’s scope review.</p>
    <ul className="project-list dns-import-preview">{preview.candidates.map(host => <li key={host.origin}>
      <div className="list-row">
        <span><strong>{new URL(host.origin).hostname}</strong><small>{host.dnsSource.recordTypes.join(', ')}</small></span>
        {host.thirdParty && <small>Third-party alias · {host.dnsSource.externalAliases.join(', ')}</small>}
      </div>
    </li>)}</ul>
    <FormError error={action.error} />
    <div className="form-actions">
      <Button onClick={() => setPreview(undefined)} disabled={action.pending}>Choose another file</Button>
      <Button variant="default" disabled={action.pending} onClick={() => {
        void action.submit(() => importProjectDns({ data: {
          projectId, requestId: preview.requestId, zone: preview.zone, document: preview.document,
        } }), imported)
      }}>Import hosts</Button>
    </div>
  </section>

  return <form className="form-card" onSubmit={event => { void review(event) }}>
    <h3>Import a DNS zone</h3>
    <p className="muted">Load host candidates from a self-contained DNS zone file.</p>
    <label>Zone domain<Input name="zone" defaultValue={defaultZone} required /></label>
    <label>DNS export<Input name="export" type="file" accept=".zone,.dns,.db,.txt,text/plain" required /></label>
    <FormError error={error} />
    <div className="form-actions">
      <Button onClick={cancel}>Cancel</Button>
      <Button type="submit" variant="default" disabled={reading}>Review import</Button>
    </div>
  </form>
}
