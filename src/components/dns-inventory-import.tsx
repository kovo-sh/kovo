import { useState } from 'react'
import type { FormEvent } from 'react'
import { importProjectDns } from '../actions.ts'
import { maxDnsExportBytes } from '../domain.ts'
import { parseDnsInventory } from '../passive-dns.ts'
import { FormError, useAction } from './common.tsx'
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

const maxDnsExportMiB = Math.round(maxDnsExportBytes / (1024 * 1024))

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
      setError(`Choose a DNS export file up to ${maxDnsExportMiB} MiB.`)
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
    return (
      <Card className="overflow-hidden border-line" aria-label="DNS import preview">
        <CardHeader className="items-center py-2.5">
          <div className="flex flex-wrap items-center gap-2 text-[13px] font-semibold text-fg">
            <span>Review DNS inventory</span>
            <Badge variant="neutral" className="bg-sunk tabular-nums">
              {preview.candidates.length} {preview.candidates.length === 1 ? 'host' : 'hosts'}
            </Badge>
          </div>
          <Button type="button" variant="ghost" disabled={action.pending} onClick={cancel}>
            Close
          </Button>
        </CardHeader>
        <CardBody className="grid gap-3 py-3.5">
          <p className="m-0 text-[12px] text-fg-subtle">
            Found {preview.candidates.length} {preview.candidates.length === 1 ? 'host' : 'hosts'} in{' '}
            <code className="font-mono text-[12px]">{preview.zone}</code>. Importing adds all listed hosts into{' '}
            <strong className="font-medium text-fg">Needs approval</strong> — review and approve which hosts to include before starting a scan.
          </p>
          <div className="max-h-[240px] overflow-y-auto border-t border-line">
            {preview.candidates.map(host => (
              <div
                key={host.origin}
                className="flex min-h-[44px] items-center justify-between gap-3 border-b border-line px-1 py-2 transition-colors hover:bg-hover"
              >
                <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                  <div className="flex min-w-0 flex-wrap items-center gap-1.5 font-medium text-fg">
                    <strong className="font-mono text-[12px] font-semibold">{safeHostname(host.origin)}</strong>
                    <Badge variant="neutral" className="bg-sunk font-mono">
                      {host.dnsSource.recordTypes.join(', ')}
                    </Badge>
                    {host.thirdParty && (
                      <Badge variant="warn">
                        Third-party alias{host.dnsSource.externalAliases.length > 0 ? ` · ${host.dnsSource.externalAliases.join(', ')}` : ''}
                      </Badge>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
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
              void action.submit(() => importProjectDns({ data: {
                projectId, requestId: preview.requestId, zone: preview.zone, document: preview.document,
              } }), imported)
            }}
          >
            {action.pending
              ? 'Importing…'
              : `Import all ${preview.candidates.length} ${preview.candidates.length === 1 ? 'host' : 'hosts'}`}
          </Button>
        </CardFooter>
      </Card>
    )
  }

  return (
    <Card className="overflow-hidden border-line">
      <form onSubmit={event => { void review(event) }}>
        <CardHeader className="items-center py-2.5">
          <span className="text-[13px] font-semibold text-fg">Import DNS zone</span>
          <Button type="button" variant="ghost" onClick={cancel}>Close</Button>
        </CardHeader>
        <CardBody className="grid gap-3 py-3.5">
          <p className="m-0 text-[12px] text-fg-subtle">
            Upload a DNS zone export to preview host candidates before adding them to this project.
          </p>
          <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-2">
            <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
              Zone domain
              <Input className="w-full font-mono text-[12px]" name="zone" defaultValue={defaultZone} placeholder="example.com" required />
            </label>
            <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
              DNS export file
              <Input className="w-full pt-[3px]!" name="export" type="file" accept=".zone,.dns,.db,.txt,text/plain" required />
            </label>
          </div>
          <FormError error={error} />
        </CardBody>
        <CardFooter className="py-2.5">
          <Button type="button" variant="ghost" onClick={cancel}>Cancel</Button>
          <Button type="submit" variant="default" disabled={reading}>
            {reading ? 'Reading…' : 'Review import'}
          </Button>
        </CardFooter>
      </form>
    </Card>
  )
}
