// Local lab runner panel (local-lab projects only), shown on the Overview and
// on the consent sheet. It keeps the old run page's lab status and controls:
// stack state, IAST, services, seed command, loopback origin; Start / Stop,
// Health check and Refresh. The header "…" menu offers the same actions.
import { useState } from 'react'
import { checkRunLabHealthAction, startRunLabAction, stopRunLabAction } from '../../../actions.ts'
import { useRun } from '../data.tsx'
import { Props, Tag } from '../display.tsx'
import { fmtN } from '../format.ts'
import { Icon } from '../icons.tsx'

export function LabPanel() {
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
  return <section className="ov-sec lab" aria-label="Local lab runner">
    <h4>Local lab runner</h4>
    <div className="d-meta">
      <Tag tone={target ? 'accent' : undefined} icon="node">{state}</Tag>
      <Tag icon="activity">{cfg?.iastEnabled ? 'IAST enabled' : 'IAST off'}</Tag>
      {!detail.localLabEnvEnabled && <Tag tone="warn" icon="alert" title="Set GUARDIAN_ALLOW_LOCAL_LAB=1 to enable local lab containers">Local lab disabled in environment</Tag>}
    </div>
    <Props rows={[
      ['Stack', <span>Isolated Docker <span className="mono">--internal</span> · port <span className="num">{cfg?.internalPort ?? 8080}</span> · health <span className="mono">{cfg?.healthPath ?? '/health'}</span></span>],
      ...(cfg?.dockerComposeFile ? [['Compose', <span className="mono">{cfg.dockerComposeFile}</span>] as [string, React.ReactNode]] : []),
      ...(cfg?.services?.length ? [['Services', <span className="mono">{cfg.services.map(s => s.name + (s.internalPort ? ':' + s.internalPort : '')).join(' · ')}</span>] as [string, React.ReactNode]] : []),
      ...(cfg?.seedCommand ? [['Seed command', <span className="mono">{cfg.seedCommand}</span>] as [string, React.ReactNode]] : []),
      ...(target ? [['Loopback origin', <span className="mono">{target.origin}</span>] as [string, React.ReactNode]] : []),
      ...(traces ? [['IAST telemetry', <span className="num">{fmtN(traces)} traces recorded</span>] as [string, React.ReactNode]] : []),
    ]} />
    <div className="lab-acts">
      {target
        ? <button type="button" className="btn" disabled={busy} onClick={() => void act(() => stopRunLabAction({ data: { runId } }), () => 'Lab stack stopped.')}><Icon name="stop" />Stop lab</button>
        : <button type="button" className="btn" disabled={busy || !detail.localLabEnvEnabled || !cfg?.enabled}
          title={!cfg?.enabled ? 'Enable the lab on the project page first' : undefined}
          onClick={() => void act(() => startRunLabAction({ data: { runId } }), res => {
            const t = (res as { target?: { origin?: string } } | null)?.target
            return t?.origin ? 'Lab running at ' + t.origin : 'Lab started.'
          })}><Icon name="play" />Start lab</button>}
      <button type="button" className="btn ghost" disabled={busy} onClick={() => void act(() => checkRunLabHealthAction({ data: { runId } }), res => (res as { message?: string } | null)?.message ?? 'Health checked.')}><Icon name="activity" />Health check</button>
      <button type="button" className="btn ghost" disabled={busy} onClick={() => void act(() => refresh(), () => 'Refreshed.')}><Icon name="replay" />Refresh</button>
    </div>
    {note && <p role="status" className={'lab-note' + (note.error ? ' err' : '')}>{note.text}</p>}
  </section>
}
