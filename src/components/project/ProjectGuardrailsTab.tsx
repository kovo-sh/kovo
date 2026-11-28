import { useState } from 'react'
import {
  updateProjectLabConfigAction,
  updateProjectSandboxAllowlistAction,
} from '../../actions.ts'
import type { IastRuntime, LabServiceConfig } from '../../domain.ts'
import { iastRuntimes } from '../../domain.ts'
import { FormError, useAction } from '../common.tsx'
import { Badge } from '../ui/badge.tsx'
import { Button } from '../ui/button.tsx'
import { Card, CardBody, CardFooter, CardHeader } from '../ui/card.tsx'
import { Checkbox } from '../ui/checkbox.tsx'
import { Disclosure, DisclosureContent, DisclosureTrigger } from '../ui/disclosure.tsx'
import { EmptyState } from '../ui/empty-state.tsx'
import { Input, NativeSelect, Textarea } from '../ui/input.tsx'
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
      className="block text-fg"
    >
      <rect x="6" y="8" width="168" height="72" rx="10" fill="var(--sunk)" stroke="var(--line-2)" strokeWidth="1.2" />
      <path d="M24 44h38" stroke="var(--line-strong)" strokeWidth="1.4" strokeLinecap="round" strokeDasharray="3 3" />
      <path d="M118 44h38" stroke="var(--line-strong)" strokeWidth="1.4" strokeLinecap="round" />
      <rect x="20" y="34" width="26" height="20" rx="5" fill="var(--panel)" stroke="var(--line-strong)" strokeWidth="1.2" />
      <path d="M27 44h12" stroke="var(--fg-3)" strokeWidth="1.5" strokeLinecap="round" />
      <path
        d="M90 19 112 27v16.5c0 12.2-8.7 21.6-22 26-13.3-4.4-22-13.8-22-26V27l22-8Z"
        fill="var(--panel)"
        stroke="var(--accent)"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <rect x="83" y="42" width="14" height="11" rx="2.5" fill="var(--accent-soft)" stroke="var(--accent)" strokeWidth="1.4" />
      <path d="M86.5 42v-3.2a3.5 3.5 0 0 1 7 0V42" stroke="var(--accent)" strokeWidth="1.4" strokeLinecap="round" />
      <circle cx="90" cy="47.5" r="1.4" fill="var(--accent)" />
      <rect x="134" y="34" width="26" height="20" rx="5" fill="var(--panel)" stroke="var(--line-strong)" strokeWidth="1.2" />
      <path d="M142 40l8 8M150 40l-8 8" stroke="var(--fg-3)" strokeWidth="1.4" strokeLinecap="round" />
    </svg>
  )
}

const LAB_ENV_KEY_RE = /^[A-Z_][A-Z0-9_]{0,63}$/

export function formatLabEnv(env: Record<string, string> | undefined): string {
  if (!env) return ''
  return Object.entries(env).map(([k, v]) => `${k}=${v}`).join('\n')
}

export function parseLabEnv(raw: string): Record<string, string> | undefined {
  const trimmed = raw.trim()
  if (!trimmed) return undefined
  if (trimmed.startsWith('{')) {
    const parsed = JSON.parse(trimmed) as unknown
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('Environment variables JSON must be an object of KEY: value strings.')
    }
    const out: Record<string, string> = {}
    for (const [key, val] of Object.entries(parsed)) {
      if (!LAB_ENV_KEY_RE.test(key)) {
        throw new Error(`Invalid environment variable key "${key}". Use uppercase letters, digits, and underscores.`)
      }
      if (typeof val !== 'string' || val.length > 1024) {
        throw new Error(`Environment variable "${key}" value must be a string up to 1024 characters.`)
      }
      out[key] = val
    }
    return Object.keys(out).length > 0 ? out : undefined
  }
  const out: Record<string, string> = {}
  for (const rawLine of trimmed.split(/\r?\n/)) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#')) continue
    const eq = line.indexOf('=')
    if (eq <= 0) {
      throw new Error(`Invalid environment line "${line}". Expected KEY=VALUE or JSON object.`)
    }
    const key = line.slice(0, eq).trim()
    const val = line.slice(eq + 1)
    if (!LAB_ENV_KEY_RE.test(key)) {
      throw new Error(`Invalid environment variable key "${key}". Use uppercase letters, digits, and underscores.`)
    }
    if (val.length > 1024) {
      throw new Error(`Environment variable "${key}" value exceeds 1024 characters.`)
    }
    out[key] = val
  }
  return Object.keys(out).length > 0 ? out : undefined
}

export function ProjectGuardrailsTab({ data }: Props) {
  const { project, localLabEnvEnabled } = data
  const labAllowed = project.environment === 'local-lab' && localLabEnvEnabled

  const [addRuleOpen, setAddRuleOpen] = useState(false)
  const [allowOrigin, setAllowOrigin] = useState(() => project.seeds[0] ?? '')
  const [allowMethod, setAllowMethod] = useState('POST')
  const [allowPath, setAllowPath] = useState('')
  const [allowNotice, setAllowNotice] = useState('')
  const [editingRuleIdx, setEditingRuleIdx] = useState<number | null>(null)
  const [editOrigin, setEditOrigin] = useState('')
  const [editMethod, setEditMethod] = useState('POST')
  const [editPath, setEditPath] = useState('')

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
  const [labRepo, setLabRepo] = useState(() => project.labConfig?.repo ?? '')
  const [labStartCommand, setLabStartCommand] = useState(() => project.labConfig?.startCommand ?? '')
  const [labDockerfile, setLabDockerfile] = useState(() => project.labConfig?.dockerfile ?? '')
  const [labImage, setLabImage] = useState(() => project.labConfig?.image ?? '')
  const [labEnvText, setLabEnvText] = useState(() => formatLabEnv(project.labConfig?.env))
  const [labMemoryLimit, setLabMemoryLimit] = useState(() => project.labConfig?.memoryLimit ?? '')
  const [labCpus, setLabCpus] = useState(() => project.labConfig?.cpus ?? '')
  const [labPidsLimit, setLabPidsLimit] = useState(() =>
    project.labConfig?.pidsLimit ? String(project.labConfig.pidsLimit) : '',
  )
  const [labNotice, setLabNotice] = useState('')

  const allowlistAction = useAction()
  const labAction = useAction()
  const rules = project.sandboxWriteAllowlist ?? []

  function resetLabFields() {
    setLabEnabled(false)
    setLabComposeFile('')
    setLabServicesJson('')
    setLabSeedCommand('')
    setLabIastEnabled(false)
    setLabIastRuntime('node')
    setLabHealthPath('/health')
    setLabInternalPort('8080')
    setLabRepo('')
    setLabStartCommand('')
    setLabDockerfile('')
    setLabImage('')
    setLabEnvText('')
    setLabMemoryLimit('')
    setLabCpus('')
    setLabPidsLimit('')
  }

  const labRunnerForm = (
    <Card className="overflow-hidden border-line">
      <form
        onSubmit={event => {
          event.preventDefault()
          setLabNotice('')
          let parsedServices: LabServiceConfig[] | undefined
          let parsedEnv: Record<string, string> | undefined
          let parsedPids: number | undefined
          try {
            const servicesTrimmed = labServicesJson.trim()
            if (servicesTrimmed) {
              const raw = JSON.parse(servicesTrimmed) as unknown
              if (!Array.isArray(raw)) throw new Error('Services must be a JSON array.')
              parsedServices = raw as LabServiceConfig[]
            }
            parsedEnv = parseLabEnv(labEnvText)
            if (labPidsLimit.trim()) {
              const n = Number(labPidsLimit.trim())
              if (!Number.isInteger(n) || n < 16 || n > 1024) {
                throw new Error('PIDs limit must be an integer between 16 and 1024.')
              }
              parsedPids = n
            }
          } catch (err) {
            void labAction.submit(async () => {
              throw new Error(err instanceof Error ? err.message : 'Invalid lab configuration.')
            })
            return
          }
          const parsedPort = labInternalPort.trim() ? Number(labInternalPort.trim()) : undefined
          void labAction.submit(() => updateProjectLabConfigAction({
            data: {
              requestId: crypto.randomUUID(),
              projectId: project.id,
              labConfig: {
                enabled: labEnabled,
                ...(labRepo.trim() ? { repo: labRepo.trim() } : {}),
                ...(labStartCommand.trim() ? { startCommand: labStartCommand.trim() } : {}),
                ...(labDockerfile.trim() ? { dockerfile: labDockerfile.trim() } : {}),
                ...(labComposeFile.trim() ? { dockerComposeFile: labComposeFile.trim() } : {}),
                ...(labImage.trim() ? { image: labImage.trim() } : {}),
                ...(parsedEnv ? { env: parsedEnv } : {}),
                ...(labMemoryLimit.trim() ? { memoryLimit: labMemoryLimit.trim() } : {}),
                ...(labCpus.trim() ? { cpus: labCpus.trim() } : {}),
                ...(parsedPids !== undefined ? { pidsLimit: parsedPids } : {}),
                ...(parsedServices ? { services: parsedServices } : {}),
                ...(labSeedCommand.trim() ? { seedCommand: labSeedCommand.trim() } : {}),
                ...(project.labConfig?.buildTimeoutMs !== undefined
                  ? { buildTimeoutMs: project.labConfig.buildTimeoutMs }
                  : {}),
                ...(project.labConfig?.healthTimeoutMs !== undefined
                  ? { healthTimeoutMs: project.labConfig.healthTimeoutMs }
                  : {}),
                iastEnabled: labIastEnabled,
                iastRuntime: labIastRuntime,
                healthPath: labHealthPath.trim() || '/health',
                ...(parsedPort !== undefined && Number.isFinite(parsedPort) ? { internalPort: parsedPort } : {}),
              },
            },
          }), () => setLabNotice('Lab runner settings saved.'))
        }}
      >
        <CardHeader className="items-center py-2.5">
          <span className="text-[13px] font-semibold text-fg">Local lab runner</span>
          <Badge
            variant={labAllowed ? (labEnabled ? 'ok' : 'accent') : 'neutral'}
            className={!labAllowed ? 'bg-sunk' : undefined}
            title={labAllowed ? undefined : 'Requires a Local Lab project with the local lab runner enabled on this server'}
          >
            {labAllowed ? (labEnabled ? 'Lab enabled' : 'Lab ready') : 'Unavailable on this server'}
          </Badge>
        </CardHeader>
        <CardBody className="grid gap-3 py-3.5">
          <p className="m-0 text-[12px] text-fg-subtle">
            Isolated local Docker target stack with optional test-account seeding and runtime code telemetry.
            {!labAllowed && (
              <span> Available only on Local Lab projects when enabled on this server.</span>
            )}
          </p>
          {labNotice && (
            <p
              role="status"
              className="m-0 flex items-center gap-2 rounded-[7px] border border-line bg-sunk px-3 py-[7px] text-[12.5px] text-fg-muted"
            >
              {labNotice}
            </p>
          )}
          <label className="inline-flex cursor-pointer select-none items-center gap-[7px] text-[12.5px] font-normal text-fg-muted">
            <Checkbox
              checked={labEnabled}
              disabled={!labAllowed || labAction.pending}
              aria-label="Enable local lab"
              onCheckedChange={checked => setLabEnabled(Boolean(checked))}
            />
            <span>Enable local lab</span>
          </label>
          <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-2">
            <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
              Docker Compose file
              <Input
                className="w-full font-mono text-[12px]"
                name="dockerComposeFile"
                value={labComposeFile}
                disabled={!labAllowed || labAction.pending}
                onChange={e => setLabComposeFile(e.target.value)}
                placeholder="docker-compose.lab.yml"
              />
            </label>
            <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
              Seed command
              <Input
                className="w-full font-mono text-[12px]"
                name="seedCommand"
                value={labSeedCommand}
                disabled={!labAllowed || labAction.pending}
                onChange={e => setLabSeedCommand(e.target.value)}
                placeholder="node scripts/seed-personas.mjs"
              />
            </label>
          </div>
          <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
            Services (JSON)
            <Textarea
              className="w-full font-mono text-[12px]"
              name="services"
              rows={3}
              value={labServicesJson}
              disabled={!labAllowed || labAction.pending}
              onChange={e => setLabServicesJson(e.target.value)}
              placeholder='[{"name":"app","internalPort":8080},{"name":"postgres"}]'
            />
          </label>
          <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-3">
            <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
              Health path
              <Input
                className="w-full font-mono text-[12px]"
                name="healthPath"
                value={labHealthPath}
                disabled={!labAllowed || labAction.pending}
                onChange={e => setLabHealthPath(e.target.value)}
                placeholder="/health"
              />
            </label>
            <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
              Internal port
              <Input
                className="w-full tabular-nums"
                name="internalPort"
                type="number"
                min={1}
                max={65535}
                value={labInternalPort}
                disabled={!labAllowed || labAction.pending}
                onChange={e => setLabInternalPort(e.target.value)}
              />
            </label>
            <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
              Target runtime
              <NativeSelect
                className="w-full"
                name="iastRuntime"
                value={labIastRuntime}
                disabled={!labAllowed || labAction.pending}
                onChange={e => setLabIastRuntime(e.target.value as IastRuntime)}
              >
                {iastRuntimes.map(rt => <option key={rt} value={rt}>{rt}</option>)}
              </NativeSelect>
            </label>
          </div>
          <label className="inline-flex cursor-pointer select-none items-center gap-[7px] text-[12.5px] font-normal text-fg-muted">
            <Checkbox
              checked={labIastEnabled}
              disabled={!labAllowed || labAction.pending}
              aria-label="Enable runtime telemetry"
              onCheckedChange={checked => setLabIastEnabled(Boolean(checked))}
            />
            <span title="Redacted local-lab runtime telemetry sink and coverage side-channel">
              Enable runtime telemetry (capture redacted code coverage and sink traces in the local lab)
            </span>
          </label>
          <Disclosure className="border-t border-line pt-2.5">
            <DisclosureTrigger className="px-0 py-0.5 text-[12px] font-medium text-fg-muted hover:bg-transparent hover:text-fg">
              <span>Advanced lab settings</span>
            </DisclosureTrigger>
            <DisclosureContent className="grid gap-3 pt-2.5">
              <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-2">
                <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                  Repository
                  <Input
                    className="w-full font-mono text-[12px]"
                    name="repo"
                    value={labRepo}
                    disabled={!labAllowed || labAction.pending}
                    onChange={e => setLabRepo(e.target.value)}
                    placeholder="owner/repo"
                    maxLength={200}
                  />
                </label>
                <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                  Start command
                  <Input
                    className="w-full font-mono text-[12px]"
                    name="startCommand"
                    value={labStartCommand}
                    disabled={!labAllowed || labAction.pending}
                    onChange={e => setLabStartCommand(e.target.value)}
                    placeholder="npm start"
                    maxLength={500}
                  />
                </label>
              </div>
              <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-2">
                <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                  Dockerfile
                  <Input
                    className="w-full font-mono text-[12px]"
                    name="dockerfile"
                    value={labDockerfile}
                    disabled={!labAllowed || labAction.pending}
                    onChange={e => setLabDockerfile(e.target.value)}
                    placeholder="Dockerfile"
                    maxLength={300}
                  />
                </label>
                <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                  Base image
                  <Input
                    className="w-full font-mono text-[12px]"
                    name="image"
                    value={labImage}
                    disabled={!labAllowed || labAction.pending}
                    onChange={e => setLabImage(e.target.value)}
                    placeholder="node:24-bookworm-slim"
                    maxLength={300}
                  />
                </label>
              </div>
              <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                Environment variables (KEY=VALUE or JSON)
                <Textarea
                  className="w-full font-mono text-[12px]"
                  name="env"
                  rows={3}
                  value={labEnvText}
                  disabled={!labAllowed || labAction.pending}
                  onChange={e => setLabEnvText(e.target.value)}
                  placeholder={'NODE_ENV=test\nPORT=8080'}
                />
              </label>
              <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-3">
                <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                  Memory limit
                  <Input
                    className="w-full font-mono text-[12px]"
                    name="memoryLimit"
                    value={labMemoryLimit}
                    disabled={!labAllowed || labAction.pending}
                    onChange={e => setLabMemoryLimit(e.target.value)}
                    placeholder="512m"
                    maxLength={32}
                  />
                </label>
                <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                  CPUs
                  <Input
                    className="w-full font-mono text-[12px]"
                    name="cpus"
                    value={labCpus}
                    disabled={!labAllowed || labAction.pending}
                    onChange={e => setLabCpus(e.target.value)}
                    placeholder="1.0"
                    maxLength={16}
                  />
                </label>
                <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                  PIDs limit
                  <Input
                    className="w-full tabular-nums"
                    name="pidsLimit"
                    type="number"
                    min={16}
                    max={1024}
                    value={labPidsLimit}
                    disabled={!labAllowed || labAction.pending}
                    onChange={e => setLabPidsLimit(e.target.value)}
                    placeholder="256"
                  />
                </label>
              </div>
            </DisclosureContent>
          </Disclosure>
          <FormError error={labAction.error} />
        </CardBody>
        <CardFooter className="justify-between py-2.5">
          <Button
            type="button"
            variant="ghost"
            className="data-[slot=button]:text-danger data-[slot=button]:hover:bg-danger-soft data-[slot=button]:hover:text-danger"
            disabled={!labAllowed || labAction.pending || !project.labConfig}
            onClick={() => {
              setLabNotice('')
              void labAction.submit(() => updateProjectLabConfigAction({
                data: {
                  requestId: crypto.randomUUID(),
                  projectId: project.id,
                  labConfig: null,
                },
              }), () => {
                resetLabFields()
                setLabNotice('Lab configuration cleared.')
              })
            }}
          >
            Reset / Clear lab config
          </Button>
          <Button type="submit" variant="default" disabled={!labAllowed || labAction.pending}>
            Save lab settings
          </Button>
        </CardFooter>
      </form>
    </Card>
  )

  return (
    <div>
      <section aria-label="Approved write rules">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="m-0 text-[13px] font-semibold text-fg">
              Approved write rules <span className="font-normal tabular-nums text-fg-subtle">({rules.length})</span>
            </h2>
            <p
              className="mt-0.5 text-[12px] text-fg-subtle"
              title="Write requests stay blocked until you approve a specific endpoint"
            >
              Allow non-destructive POST checks on specific staging or test-account endpoints. Write requests are blocked by default on public projects.
            </p>
          </div>
          {(rules.length > 0 || addRuleOpen) && (
            <div className="flex flex-wrap items-center gap-1.5">
              <Button
                type="button"
                variant={addRuleOpen ? 'ghost' : 'outline'}
                aria-expanded={addRuleOpen}
                onClick={() => {
                  setAddRuleOpen(v => !v)
                  setAllowNotice('')
                }}
              >
                {addRuleOpen ? 'Close' : 'Add rule'}
              </Button>
            </div>
          )}
        </div>

        {allowNotice && (
          <p
            role="status"
            className="mb-3.5 flex items-center gap-2 rounded-[7px] border border-line bg-sunk px-3 py-[7px] text-[12.5px] text-fg-muted"
          >
            {allowNotice}
          </p>
        )}

        {addRuleOpen && (
          <Card className="mb-3.5 overflow-hidden border-line">
            <form
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
              <CardHeader className="items-center py-2.5">
                <span className="text-[13px] font-semibold text-fg">Add rule</span>
                <Button type="button" variant="ghost" onClick={() => setAddRuleOpen(false)}>Close</Button>
              </CardHeader>
              <CardBody className="grid gap-3 py-3.5">
                <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-3">
                  <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                    Endpoint origin
                    <Input
                      className="w-full font-mono text-[12px]"
                      name="allowOrigin"
                      required
                      value={allowOrigin}
                      onChange={e => setAllowOrigin(e.target.value)}
                      placeholder={project.seeds[0] ?? 'https://example.com'}
                    />
                  </label>
                  <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                    Method
                    <NativeSelect
                      className="w-full"
                      name="allowMethod"
                      value={allowMethod}
                      onChange={e => setAllowMethod(e.target.value)}
                    >
                      <option value="POST">POST</option>
                      <option value="PUT">PUT</option>
                      <option value="PATCH">PATCH</option>
                    </NativeSelect>
                  </label>
                  <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                    Path pattern
                    <Input
                      className="w-full font-mono text-[12px]"
                      name="allowPathPattern"
                      required
                      value={allowPath}
                      onChange={e => setAllowPath(e.target.value)}
                      placeholder="/api/search"
                    />
                  </label>
                </div>
                <FormError error={allowlistAction.error} />
              </CardBody>
              <CardFooter className="py-2.5">
                <Button type="button" variant="ghost" onClick={() => setAddRuleOpen(false)}>Cancel</Button>
                <Button
                  type="submit"
                  variant="default"
                  disabled={allowlistAction.pending || !allowOrigin.trim() || !allowPath.trim()}
                >
                  {allowlistAction.pending ? 'Saving…' : 'Save rule'}
                </Button>
              </CardFooter>
            </form>
          </Card>
        )}

        {rules.length > 0 ? (
          <div className="border-t border-line">
            {rules.map((rule, idx) => (
              editingRuleIdx === idx ? (
                <form
                  key={`${rule.origin}:${rule.method}:${rule.pathPattern}:${idx}:edit`}
                  className="grid gap-2.5 border-b border-line bg-sunk px-2.5 py-2.5"
                  onSubmit={event => {
                    event.preventDefault()
                    setAllowNotice('')
                    const updated = rules.map((entry, i) => (
                      i === idx
                        ? {
                          ...entry,
                          origin: editOrigin.trim(),
                          method: editMethod.trim().toUpperCase(),
                          pathPattern: editPath.trim(),
                        }
                        : entry
                    ))
                    void allowlistAction.submit(() => updateProjectSandboxAllowlistAction({
                      data: {
                        requestId: crypto.randomUUID(),
                        projectId: project.id,
                        sandboxWriteAllowlist: updated,
                      },
                    }), () => {
                      setEditingRuleIdx(null)
                      setAllowNotice('Updated write rule.')
                    })
                  }}
                >
                  <div className="grid grid-cols-1 items-center gap-2 sm:grid-cols-[minmax(0,1.2fr)_110px_minmax(0,1fr)_auto]">
                    <Input
                      className="w-full font-mono text-[12px]"
                      name="editAllowOrigin"
                      aria-label="Edit endpoint origin"
                      required
                      value={editOrigin}
                      disabled={allowlistAction.pending}
                      onChange={e => setEditOrigin(e.target.value)}
                    />
                    <NativeSelect
                      className="w-full"
                      name="editAllowMethod"
                      aria-label="Edit HTTP method"
                      value={editMethod}
                      disabled={allowlistAction.pending}
                      onChange={e => setEditMethod(e.target.value)}
                    >
                      <option value="POST">POST</option>
                      <option value="PUT">PUT</option>
                      <option value="PATCH">PATCH</option>
                    </NativeSelect>
                    <Input
                      className="w-full font-mono text-[12px]"
                      name="editAllowPathPattern"
                      aria-label="Edit path pattern"
                      required
                      value={editPath}
                      disabled={allowlistAction.pending}
                      onChange={e => setEditPath(e.target.value)}
                    />
                    <div className="flex items-center justify-end gap-1.5">
                      <Button
                        type="button"
                        variant="ghost"
                        disabled={allowlistAction.pending}
                        onClick={() => setEditingRuleIdx(null)}
                      >
                        Cancel
                      </Button>
                      <Button
                        type="submit"
                        variant="default"
                        disabled={allowlistAction.pending || !editOrigin.trim() || !editPath.trim()}
                      >
                        {allowlistAction.pending ? 'Saving…' : 'Save'}
                      </Button>
                    </div>
                  </div>
                  <FormError error={allowlistAction.error} />
                </form>
              ) : (
                <div
                  key={`${rule.origin}:${rule.method}:${rule.pathPattern}:${idx}`}
                  className="flex min-h-[44px] items-center justify-between gap-3 border-b border-line px-1 py-2 transition-colors hover:bg-hover"
                >
                  <div className="flex min-w-0 flex-wrap items-center gap-1.5 font-medium text-fg">
                    <Badge variant="accent">{rule.method}</Badge>
                    <strong className="font-mono text-[12px] font-semibold">{rule.origin}</strong>
                    <code className="font-mono text-[12px] text-fg-subtle">{rule.pathPattern}</code>
                  </div>
                  <div className="flex flex-none items-center gap-1">
                    <Button
                      type="button"
                      variant="ghost"
                      disabled={allowlistAction.pending}
                      aria-label={`Edit rule ${rule.method} ${rule.origin}${rule.pathPattern}`}
                      onClick={() => {
                        setAllowNotice('')
                        setEditingRuleIdx(idx)
                        setEditOrigin(rule.origin)
                        setEditMethod(rule.method)
                        setEditPath(rule.pathPattern)
                      }}
                    >
                      Edit
                    </Button>
                    <Button
                      type="button"
                      variant="ghost"
                      className="data-[slot=button]:text-danger data-[slot=button]:hover:bg-danger-soft data-[slot=button]:hover:text-danger"
                      disabled={allowlistAction.pending}
                      onClick={() => {
                        const updated = rules.filter((_, i) => i !== idx)
                        void allowlistAction.submit(() => updateProjectSandboxAllowlistAction({
                          data: {
                            requestId: crypto.randomUUID(),
                            projectId: project.id,
                            sandboxWriteAllowlist: updated,
                          },
                        }), () => {
                          if (editingRuleIdx === idx) setEditingRuleIdx(null)
                          setAllowNotice('Removed write rule.')
                        })
                      }}
                    >
                      Remove
                    </Button>
                  </div>
                </div>
              )
            ))}
          </div>
        ) : (
          <div className="mt-3.5 rounded-card border border-line bg-sunk">
            <EmptyState
              icon={<GuardrailsEmptyIllustration />}
              title="Write requests are blocked by default"
              description="Kovo will not send state-changing requests unless you explicitly approve a staging or test-account endpoint here."
              className="max-w-[440px] py-9 [&_[data-slot=empty-state-icon]]:size-auto [&_[data-slot=empty-state-icon]>svg]:h-[88px] [&_[data-slot=empty-state-icon]>svg]:w-[180px]"
              action={
                !addRuleOpen ? (
                  <Button
                    type="button"
                    variant="default"
                    onClick={() => {
                      setAddRuleOpen(true)
                      setAllowNotice('')
                    }}
                  >
                    Add rule
                  </Button>
                ) : undefined
              }
            />
          </div>
        )}
      </section>

      <section className="mt-[22px]" aria-label="Local lab runner">
        {project.environment === 'local-lab' ? (
          labRunnerForm
        ) : (
          <p className="mt-3.5 border-t border-line px-3 py-2.5 text-[12px] leading-[18px] text-fg-subtle">
            Local Docker lab settings are only available on Local Lab projects.
          </p>
        )}
      </section>
    </div>
  )
}
