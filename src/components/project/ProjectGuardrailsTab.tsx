import { useState } from 'react'
import {
  updateProjectLabConfigAction,
  updateProjectSandboxAllowlistAction,
} from '../../actions.ts'
import type { IastRuntime, LabServiceConfig } from '../../domain.ts'
import { iastRuntimes } from '../../domain.ts'
import { FormError, useAction } from '../common.tsx'
import { Checkbox } from '../ui/checkbox.tsx'
import type { ProjectLoaderData } from './types.ts'

interface Props {
  data: ProjectLoaderData
}

function GuardrailsEmptyIllustration() {
  return (
    <svg
      width="180"
      height="88"
      viewBox="0 0 180 88"
      fill="none"
      aria-hidden="true"
      style={{ display: 'block', color: 'var(--pw-fg)' }}
    >
      <rect x="6" y="8" width="168" height="72" rx="10" fill="var(--pw-sunk)" stroke="var(--pw-line-2)" strokeWidth="1.2" />
      <path d="M24 44h38" stroke="var(--pw-line-strong)" strokeWidth="1.4" strokeLinecap="round" strokeDasharray="3 3" />
      <path d="M118 44h38" stroke="var(--pw-line-strong)" strokeWidth="1.4" strokeLinecap="round" />
      <rect x="20" y="34" width="26" height="20" rx="5" fill="var(--pw-panel)" stroke="var(--pw-line-strong)" strokeWidth="1.2" />
      <path d="M27 44h12" stroke="var(--pw-fg-3)" strokeWidth="1.5" strokeLinecap="round" />
      <path
        d="M90 19 112 27v16.5c0 12.2-8.7 21.6-22 26-13.3-4.4-22-13.8-22-26V27l22-8Z"
        fill="var(--pw-panel)"
        stroke="var(--pw-accent)"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <rect x="83" y="42" width="14" height="11" rx="2.5" fill="var(--pw-accent-soft)" stroke="var(--pw-accent)" strokeWidth="1.4" />
      <path d="M86.5 42v-3.2a3.5 3.5 0 0 1 7 0V42" stroke="var(--pw-accent)" strokeWidth="1.4" strokeLinecap="round" />
      <circle cx="90" cy="47.5" r="1.4" fill="var(--pw-accent)" />
      <rect x="134" y="34" width="26" height="20" rx="5" fill="var(--pw-panel)" stroke="var(--pw-line-strong)" strokeWidth="1.2" />
      <path d="M142 40l8 8M150 40l-8 8" stroke="var(--pw-fg-3)" strokeWidth="1.4" strokeLinecap="round" />
    </svg>
  )
}

export function ProjectGuardrailsTab({ data }: Props) {
  const { project, localLabEnvEnabled } = data
  const labAllowed = project.environment === 'local-lab' && localLabEnvEnabled

  const [addRuleOpen, setAddRuleOpen] = useState(false)
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
      <span
        className={`pw-tag ${labAllowed ? (labEnabled ? 'ok' : 'accent') : 'solid'}`}
        title={labAllowed ? undefined : 'Requires a Local Lab project with the local lab runner enabled on this server'}
      >
        {labAllowed ? (labEnabled ? 'Lab enabled' : 'Lab ready') : 'Unavailable on this server'}
      </span>
    </div>
    <div className="pw-sheet-b">
      <p className="muted" style={{ margin: 0, fontSize: 12 }}>
        Isolated local Docker target stack with optional test-account seeding and runtime code telemetry.
        {!labAllowed && (
          <span>Available only on Local Lab projects when enabled on this server.</span>
        )}
      </p>
      {labNotice && <p role="status" className="notice" style={{ margin: 0 }}>{labNotice}</p>}
      <label className="pw-chk">
        <Checkbox
          checked={labEnabled}
          disabled={!labAllowed || labAction.pending}
          aria-label="Enable local lab"
          onCheckedChange={checked => setLabEnabled(Boolean(checked))}
        />
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
        <Checkbox
          checked={labIastEnabled}
          disabled={!labAllowed || labAction.pending}
          aria-label="Enable runtime telemetry (IAST)"
          onCheckedChange={checked => setLabIastEnabled(Boolean(checked))}
        />
        <span title="Redacted local-lab IAST sink and coverage side-channel">
          Enable runtime telemetry (capture redacted code coverage and sink traces in the local lab)
        </span>
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
    <section aria-label="Approved write rules">
      <div className="pw-sec-head">
        <div>
          <h2>Approved write rules <span className="muted num">({rules.length})</span></h2>
          <p title="Write requests stay blocked until you approve a specific endpoint">
            Allow non-destructive POST checks on specific staging or test-account endpoints. Write requests are blocked by default on public projects.
          </p>
        </div>
        {(rules.length > 0 || addRuleOpen) && (
          <div className="pw-sec-actions">
            <button
              type="button"
              className={addRuleOpen ? 'pw-btn ghost' : 'pw-btn primary'}
              aria-expanded={addRuleOpen}
              onClick={() => {
                setAddRuleOpen(v => !v)
                setAllowNotice('')
              }}
            >
              {addRuleOpen ? 'Close' : 'Add rule'}
            </button>
          </div>
        )}
      </div>

      {allowNotice && <p role="status" className="notice">{allowNotice}</p>}

      {addRuleOpen && <form
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
            setAddRuleOpen(false)
            setAllowNotice('Approved write rules updated.')
          })
        }}
      >
        <div className="pw-sheet-h">
          <span>Add rule</span>
          <button type="button" className="pw-btn ghost" onClick={() => setAddRuleOpen(false)}>Close</button>
        </div>
        <div className="pw-sheet-b">
          <div className="pw-grid-3">
            <label className="pw-fld">Endpoint origin
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
          <button type="button" className="pw-btn ghost" onClick={() => setAddRuleOpen(false)}>Cancel</button>
          <button type="submit" className="pw-btn primary" disabled={allowlistAction.pending || !allowOrigin.trim() || !allowPath.trim()}>
            {allowlistAction.pending ? 'Saving…' : 'Save rule'}
          </button>
        </div>
      </form>}

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
                  }), () => setAllowNotice('Removed write rule.'))
                }}
              >
                Remove
              </button>
            </div>
          ))}
        </div>
      ) : (
        <div className="pw-empty-card">
          <GuardrailsEmptyIllustration />
          <h3>Write requests are blocked by default</h3>
          <p>
            Kovo Hunter will not send state-changing requests unless you explicitly approve a staging or test-account endpoint here.
          </p>
          {!addRuleOpen && (
            <button
              type="button"
              className="pw-btn primary"
              onClick={() => {
                setAddRuleOpen(true)
                setAllowNotice('')
              }}
            >
              Add rule
            </button>
          )}
        </div>
      )}
    </section>

    <section className="pw-sec" aria-label="Local lab runner">
      {project.environment === 'local-lab' ? (
        labRunnerForm
      ) : (
        <p className="pw-footnote">
          Local Docker lab settings are only available on Local Lab projects.
        </p>
      )}
    </section>
  </div>
}
