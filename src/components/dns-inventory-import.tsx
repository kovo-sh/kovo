import { useState } from 'react'
import type { FormEvent } from 'react'
import { importProjectDns } from '../actions.ts'
import { maxDnsExportBytes } from '../domain.ts'
import { parseDnsInventory } from '../passive-dns.ts'
import { FormError, useAction } from './common.tsx'

function safeHostname(origin: string): string {
  try {
    return new URL(origin).hostname
  } catch {
    return origin
  }
}

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
    const zone = String(fields.get('zone') ?? '').trim()
    if (!(file instanceof File) || !file.size || file.size > maxDnsExportBytes) {
      setError('Choose a DNS export file up to 128 KiB.')
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

  if (preview) {
    return <section className="pw-sheet" aria-label="DNS import preview">
      <div className="pw-sheet-h">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <span>Review DNS inventory</span>
          <span className="pw-tag solid num">
            {preview.candidates.length} {preview.candidates.length === 1 ? 'host' : 'hosts'}
          </span>
        </div>
        <button type="button" className="pw-btn ghost" disabled={action.pending} onClick={cancel}>Close</button>
      </div>
      <div className="pw-sheet-b">
        <p className="muted" style={{ margin: 0, fontSize: 12 }}>
          Found {preview.candidates.length} {preview.candidates.length === 1 ? 'host' : 'hosts'} in <code className="mono">{preview.zone}</code>. You can choose which hosts to include before starting a scan.
        </p>
        <div className="pw-table-wrap" style={{ maxHeight: 240, overflowY: 'auto' }}>
          {preview.candidates.map(host => <div key={host.origin} className="pw-row">
            <div className="pw-row-main">
              <div className="pw-row-title">
                <strong className="mono">{safeHostname(host.origin)}</strong>
                <span className="pw-tag solid mono">{host.dnsSource.recordTypes.join(', ')}</span>
                {host.thirdParty && (
                  <span className="pw-tag warn">
                    Third-party alias{host.dnsSource.externalAliases.length > 0 ? ` · ${host.dnsSource.externalAliases.join(', ')}` : ''}
                  </span>
                )}
              </div>
            </div>
          </div>)}
        </div>
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
            void action.submit(() => importProjectDns({ data: {
              projectId, requestId: preview.requestId, zone: preview.zone, document: preview.document,
            } }), imported)
          }}
        >
          {action.pending ? 'Importing…' : 'Import hosts'}
        </button>
      </div>
    </section>
  }

  return <form className="pw-sheet" onSubmit={event => { void review(event) }}>
    <div className="pw-sheet-h">
      <span>Import DNS zone</span>
      <button type="button" className="pw-btn ghost" onClick={cancel}>Close</button>
    </div>
    <div className="pw-sheet-b">
      <p className="muted" style={{ margin: 0, fontSize: 12 }}>
        Upload a DNS zone export to preview host candidates before adding them to this project.
      </p>
      <div className="pw-grid-2">
        <label className="pw-fld">Zone domain
          <input className="pw-in mono" name="zone" defaultValue={defaultZone} placeholder="example.com" required />
        </label>
        <label className="pw-fld">DNS export file
          <input className="pw-in" style={{ paddingTop: 3 }} name="export" type="file" accept=".zone,.dns,.db,.txt,text/plain" required />
        </label>
      </div>
      <FormError error={error} />
    </div>
    <div className="pw-sheet-f">
      <button type="button" className="pw-btn ghost" onClick={cancel}>Cancel</button>
      <button type="submit" className="pw-btn primary" disabled={reading}>
        {reading ? 'Reading…' : 'Review import'}
      </button>
    </div>
  </form>
}
