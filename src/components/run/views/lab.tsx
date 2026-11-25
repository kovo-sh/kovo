// Local lab runner panel (local-lab projects only), shown on the Overview and
// on the consent sheet: stack state, runtime telemetry, services, seed command,
// loopback origin; Start / Stop, Health check and Refresh.
import { useState } from 'react'
import type { ReactNode } from 'react'
import { checkRunLabHealthAction, startRunLabAction, stopRunLabAction } from '../../../actions.ts'
import { useRun } from '../data.tsx'
import { Props, Tag } from '../display.tsx'
import { fmtN } from '../format.ts'
import { Icon } from '../icons.tsx'
import { cn, runBtn } from '../tw.ts'

export function LabPanel({ className }: { className?: string }) {
  const { detail, refresh } = useRun()
  const [busy, setBusy] = useState(false)
  const [note, setNote] = useState<{ text: string; error?: boolean } | null>(null)
  if (detail.project.environment !== 'local-lab') return null
  const cfg = detail.project.labConfig
  const target = detail.labTarget
  const runId = detail.run.id
  const act = async (fn: () => Promise<unknown>, done: (res: unknown) => string) => {
    setBusy(true)
    setNote(null)
    try {
      const res = await fn()
      setNote({ text: done(res) })
      await refresh()
    } catch (e) {
      setNote({ text: e instanceof Error ? e.message : 'The lab action failed.', error: true })
    } finally {
      setBusy(false)
    }
  }
  const state = target ? 'Running' : cfg?.enabled ? 'Ready' : 'Disabled'
  const traces = detail.labTelemetry?.length ?? 0
  return <section className={cn('pt-4', className)} aria-label="Local lab runner">
    <h4 className="m-0 mb-1.5 flex items-center gap-2 text-[12px] font-medium text-fg-muted">Local lab runner</h4>
    <div className="mb-2 mt-0.5 flex flex-wrap gap-1.5">
      <Tag tone={target ? 'accent' : undefined} icon="node">{state}</Tag>
      <Tag icon="activity">{cfg?.iastEnabled ? 'Runtime telemetry on' : 'Runtime telemetry off'}</Tag>
      {!detail.localLabEnvEnabled && <Tag tone="warn" icon="alert" title="Local lab containers are disabled in this environment">Local lab disabled in environment</Tag>}
    </div>
    <Props
      wrap
      className="mb-2.5"
      rows={[
        ['Stack', <span>Isolated Docker <span className="font-mono text-[12px]">--internal</span> · port <span className="num">{cfg?.internalPort ?? 8080}</span> · health <span className="font-mono text-[12px]">{cfg?.healthPath ?? '/health'}</span></span>],
        ...(cfg?.dockerComposeFile ? [['Compose', <span className="font-mono text-[12px]">{cfg.dockerComposeFile}</span>] as [string, ReactNode]] : []),
        ...(cfg?.services?.length ? [['Services', <span className="font-mono text-[12px]">{cfg.services.map(s => s.name + (s.internalPort ? ':' + s.internalPort : '')).join(' · ')}</span>] as [string, ReactNode]] : []),
        ...(cfg?.seedCommand ? [['Seed command', <span className="font-mono text-[12px]">{cfg.seedCommand}</span>] as [string, ReactNode]] : []),
        ...(target ? [['Loopback origin', <span className="font-mono text-[12px]">{target.origin}</span>] as [string, ReactNode]] : []),
        ...(traces ? [['Runtime telemetry', <span className="num">{fmtN(traces)} traces recorded</span>] as [string, ReactNode]] : []),
      ]}
    />
    <div className="flex flex-wrap gap-1.5">
      {target
        ? <button type="button" className={runBtn()} disabled={busy} onClick={() => void act(() => stopRunLabAction({ data: { runId } }), () => 'Lab stack stopped.')}><Icon name="stop" />Stop lab</button>
        : <button
          type="button"
          className={runBtn()}
          disabled={busy || !detail.localLabEnvEnabled || !cfg?.enabled}
          title={!cfg?.enabled ? 'Enable the lab on the project page first' : undefined}
          onClick={() => void act(() => startRunLabAction({ data: { runId } }), res => {
            const t = (res as { target?: { origin?: string } } | null)?.target
            return t?.origin ? 'Lab running at ' + t.origin : 'Lab started.'
          })}
        >
          <Icon name="play" />Start lab
        </button>}
      <button type="button" className={runBtn({ variant: 'ghost' })} disabled={busy} onClick={() => void act(() => checkRunLabHealthAction({ data: { runId } }), res => (res as { message?: string } | null)?.message ?? 'Health checked.')}><Icon name="activity" />Health check</button>
      <button type="button" className={runBtn({ variant: 'ghost' })} disabled={busy} onClick={() => void act(() => refresh(), () => 'Refreshed.')}><Icon name="replay" />Refresh</button>
    </div>
    {note && <p role="status" className={cn('m-0 mt-2 text-[12px]', note.error ? 'text-danger' : 'text-fg-subtle')}>{note.text}</p>}
  </section>
}
