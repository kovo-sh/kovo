import { useState } from 'react'
import {
  updateProjectLabConfigAction,
  updateProjectSandboxAllowlistAction,
} from '../../actions.ts'
import type { IastRuntime, LabServiceConfig } from '../../domain.ts'
import { iastRuntimes } from '../../domain.ts'
import { FormError, useAction } from '../common.tsx'
import type { ProjectLoaderData } from './types.ts'

interface Props {
  data: ProjectLoaderData
}

export function ProjectGuardrailsTab({ data }: Props) {
  const { project, localLabEnvEnabled } = data
  const labAllowed = project.environment === 'local-lab' && localLabEnvEnabled

  const [allowOrigin, setAllowOrigin] = useState(() => project.seeds[0] ?? '')
  const [allowMethod, setAllowMethod] = useState('POST')
  const [allowPath, setAllowPath] = useState('')
  const [allowNotice, setAllowNotice] = useState('')

  const [labEnabled, setLabEnabled] = useState(() => Boolean(project.labConfig?.enabled))
  const [labComposeFile, setLabComposeFile] = useState(() => project.labConfig?.dockerComposeFile ?? '')
  const [labServicesJson, setLabServicesJson] = useState(() =>
    project.labConfig?.services?.length ? JSON.stringify(project.labConfig.services) : '',
  )
  const [labSeedCommand, setLabSeedCommand] = useState(() => project.labConfig?.seedCommand ?? '')
  const [labIastEnabled, setLabIastEnabled] = useState(() => Boolean(project.labConfig?.iastEnabled))
  const [labIastRuntime, setLabIastRuntime] = useState<IastRuntime>(() => project.labConfig?.iastRuntime ?? 'node')
  const [labHealthPath, setLabHealthPath] = useState(() => project.labConfig?.healthPath ?? '/health')
  const [labInternalPort, setLabInternalPort] = useState(() =>
    project.labConfig?.internalPort ? String(project.labConfig.internalPort) : '8080',
  )
  const [labNotice, setLabNotice] = useState('')

  const allowlistAction = useAction()
  const labAction = useAction()
  const rules = project.sandboxWriteAllowlist ?? []

  const labRunnerForm = <form
    className="pw-sheet"
    onSubmit={event => {
      event.preventDefault()
      setLabNotice('')
      let parsedServices: LabServiceConfig[] | undefined
      const servicesTrimmed = labServicesJson.trim()
      if (servicesTrimmed) {
        try {
          const raw = JSON.parse(servicesTrimmed) as unknown
          if (!Array.isArray(raw)) throw new Error('Services must be a JSON array.')
          parsedServices = raw as LabServiceConfig[]
        } catch (err) {
          void labAction.submit(async () => {
            throw new Error(err instanceof Error ? err.message : 'Services must be valid JSON.')
          })
          return
        }
      }
      const parsedPort = labInternalPort.trim() ? Number(labInternalPort.trim()) : undefined
      void labAction.submit(() => updateProjectLabConfigAction({
        data: {
          requestId: crypto.randomUUID(),
          projectId: project.id,
          labConfig: {
            enabled: labEnabled,
            ...(labComposeFile.trim() ? { dockerComposeFile: labComposeFile.trim() } : {}),
            ...(parsedServices ? { services: parsedServices } : {}),
            ...(labSeedCommand.trim() ? { seedCommand: labSeedCommand.trim() } : {}),
            iastEnabled: labIastEnabled,
            iastRuntime: labIastRuntime,
            healthPath: labHealthPath.trim() || '/health',
            ...(parsedPort !== undefined && Number.isFinite(parsedPort) ? { internalPort: parsedPort } : {}),
          },
        },
      }), () => setLabNotice('Lab runner settings saved.'))
    }}
  >
    <div className="pw-sheet-h">
      <span>Local lab runner</span>
      <span className={`pw-tag ${labAllowed ? (labEnabled ? 'ok' : 'accent') : 'solid'}`}>
        {labAllowed ? (labEnabled ? 'Lab enabled' : 'Lab ready') : 'Disabled (fail-closed)'}
      </span>
    </div>
    <div className="pw-sheet-b">
      <p className="muted" style={{ margin: 0, fontSize: 12 }}>
        Isolated multi-container Docker <code>--internal</code> target stack with optional test account seeding and opt-in IAST telemetry.
        {!labAllowed && ' Requires a Local Lab project and server-side GUARDIAN_ALLOW_LOCAL_LAB=1.'}
      </p>
      {labNotice && <p role="status" className="notice" style={{ margin: 0 }}>{labNotice}</p>}
      <label className="pw-chk">
        <input type="checkbox" checked={labEnabled} disabled={!labAllowed || labAction.pending}
          onChange={e => setLabEnabled(e.target.checked)} />
        <span>Enable local lab</span>
      </label>
      <div className="pw-grid-2">
        <label className="pw-fld">Docker Compose file
          <input className="pw-in mono" name="dockerComposeFile" value={labComposeFile}
            disabled={!labAllowed || labAction.pending} onChange={e => setLabComposeFile(e.target.value)}
            placeholder="docker-compose.lab.yml" />
        </label>
        <label className="pw-fld">Seed command
          <input className="pw-in mono" name="seedCommand" value={labSeedCommand}
            disabled={!labAllowed || labAction.pending} onChange={e => setLabSeedCommand(e.target.value)}
            placeholder="node scripts/seed-personas.mjs" />
        </label>
      </div>
      <label className="pw-fld">Services (JSON)
        <textarea className="pw-textarea mono" name="services" rows={3} value={labServicesJson}
          disabled={!labAllowed || labAction.pending} onChange={e => setLabServicesJson(e.target.value)}
          placeholder='[{"name":"app","internalPort":8080},{"name":"postgres"}]' />
      </label>
      <div className="pw-grid-3">
        <label className="pw-fld">Health path
          <input className="pw-in mono" name="healthPath" value={labHealthPath}
            disabled={!labAllowed || labAction.pending} onChange={e => setLabHealthPath(e.target.value)} placeholder="/health" />
        </label>
        <label className="pw-fld">Internal port
          <input className="pw-in num" name="internalPort" type="number" min={1} max={65535} value={labInternalPort}
            disabled={!labAllowed || labAction.pending} onChange={e => setLabInternalPort(e.target.value)} />
        </label>
        <label className="pw-fld">Target runtime
          <select className="pw-select" name="iastRuntime" value={labIastRuntime}
            disabled={!labAllowed || labAction.pending} onChange={e => setLabIastRuntime(e.target.value as IastRuntime)}>
            {iastRuntimes.map(rt => <option key={rt} value={rt}>{rt}</option>)}
          </select>
        </label>
      </div>
      <label className="pw-chk">
        <input type="checkbox" checked={labIastEnabled} disabled={!labAllowed || labAction.pending}
          onChange={e => setLabIastEnabled(e.target.checked)} />
        <span>Enable IAST telemetry (redacted local-lab sink &amp; coverage side-channel)</span>
      </label>
      <FormError error={labAction.error} />
    </div>
    <div className="pw-sheet-f">
      <button type="submit" className="pw-btn primary" disabled={!labAllowed || labAction.pending}>
        Save lab settings
      </button>
    </div>
  </form>

  return <div>
    <section aria-label="Sandbox write allowlist">
      <div className="pw-sec-head">
        <div>
          <h2>Tier-2 sandbox write allowlist <span className="muted num">({rules.length})</span></h2>
          <p>Explicitly allow non-destructive Tier-2 POST probes on approved staging or test-account endpoints. Defaults to fail-closed empty list on public projects.</p>
        </div>
      </div>

      {allowNotice && <p role="status" className="notice">{allowNotice}</p>}

      <form
        className="pw-sheet"
        style={{ marginBottom: 14 }}
        onSubmit={event => {
          event.preventDefault()
          setAllowNotice('')
          const nextEntry = {
            origin: allowOrigin.trim(),
            method: allowMethod.trim().toUpperCase(),
            pathPattern: allowPath.trim(),
          }
          const updated = [...rules, nextEntry]
          void allowlistAction.submit(() => updateProjectSandboxAllowlistAction({
            data: {
              requestId: crypto.randomUUID(),
              projectId: project.id,
              sandboxWriteAllowlist: updated,
            },
          }), () => {
            setAllowPath('')
            setAllowNotice('Sandbox write allowlist updated.')
          })
        }}
      >
        <div className="pw-sheet-b">
          <div className="pw-grid-3">
            <label className="pw-fld">Allowlist origin
              <input className="pw-in mono" name="allowOrigin" required value={allowOrigin}
                onChange={e => setAllowOrigin(e.target.value)} placeholder={project.seeds[0] ?? 'https://example.com'} />
            </label>
            <label className="pw-fld">Method
              <select className="pw-select" name="allowMethod" value={allowMethod} onChange={e => setAllowMethod(e.target.value)}>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="PATCH">PATCH</option>
                <option value="GET">GET</option>
              </select>
            </label>
            <label className="pw-fld">Path pattern
              <input className="pw-in mono" name="allowPathPattern" required value={allowPath}
                onChange={e => setAllowPath(e.target.value)} placeholder="/api/search" />
            </label>
          </div>
          <FormError error={allowlistAction.error} />
        </div>
        <div className="pw-sheet-f">
          <button type="submit" className="pw-btn primary" disabled={allowlistAction.pending || !allowOrigin.trim() || !allowPath.trim()}>
            Add allowlist rule
          </button>
        </div>
      </form>

      {rules.length > 0 ? (
        <div className="pw-table-wrap">
          {rules.map((rule, idx) => (
            <div key={`${rule.origin}:${rule.method}:${rule.pathPattern}:${idx}`} className="pw-row">
              <div className="pw-row-title">
                <span className="pw-tag accent">{rule.method}</span>
                <strong className="mono">{rule.origin}</strong>
                <code className="mono muted">{rule.pathPattern}</code>
              </div>
              <button
                type="button"
                className="pw-btn ghost danger"
                disabled={allowlistAction.pending}
                onClick={() => {
                  const updated = rules.filter((_, i) => i !== idx)
                  void allowlistAction.submit(() => updateProjectSandboxAllowlistAction({
                    data: {
                      requestId: crypto.randomUUID(),
                      projectId: project.id,
                      sandboxWriteAllowlist: updated,
                    },
                  }), () => setAllowNotice('Removed allowlist rule.'))
                }}
              >
                Remove
              </button>
            </div>
          ))}
        </div>
      ) : (
        <div className="pw-empty">
          <p>No sandbox write allowlist rules configured (default fail-closed empty list).</p>
        </div>
      )}
    </section>

    <section className="pw-sec" aria-label="Local lab runner">
      {project.environment === 'local-lab' ? (
        labRunnerForm
      ) : (
        <details className="pw-disclosure">
          <summary>Local lab runner (disabled on Public HTTPS projects)</summary>
          <div className="pw-disclosure-body">{labRunnerForm}</div>
        </details>
      )}
    </section>
  </div>
}
