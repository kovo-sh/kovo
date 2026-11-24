import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import {
  addProjectAsset,
  clearGithubToken,
  createRun,
  importSpec,
  listGithubRepositories,
  projectData,
  registerPersona,
  removePersona,
  removeProjectSpec,
  saveGithubToken,
  syncGithubRepositories,
  testPersonaAuthAction,
  updateProjectLabConfigAction,
  updateProjectSandboxAllowlistAction,
} from '../actions.ts'
import { AccessPolicyImport } from '../components/access-policy-import.tsx'
import { FormError, Status, timeText, useAction } from '../components/common.tsx'
import { parseCurlOrHeader } from '../components/curl-parser.ts'
import { DnsInventoryImport } from '../components/dns-inventory-import.tsx'
import { approvalPolicyMeta, capabilityTierMeta, formatUsd, phaseNames } from '../components/run-state.ts'
import { Button } from '../components/ui/button.tsx'
import { Checkbox } from '../components/ui/checkbox.tsx'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '../components/ui/collapsible.tsx'
import { Input, NativeSelect, Textarea } from '../components/ui/input.tsx'
import {
  approvalPolicies,
  defaultBudgetRequests,
  defaultBudgetUsd,
  defaultMaxRpsPerOrigin,
  defaultWorkerConcurrency,
  defaultWorkerMaxTurns,
  iastRuntimes,
  maxBudgetRequests,
  maxRpsPerOriginCeiling,
  maxSpecBytes,
  maxWorkerConcurrency,
  maxWorkerMaxTurns,
} from '../domain.ts'
import type { ApprovalPolicy, CapabilityTier, IastRuntime, LabServiceConfig, PersonaAuthKind, PersonaLoginAdapter, PublicPersona } from '../domain.ts'

export const Route = createFileRoute('/projects/$projectId')({
  loader: ({ params }) => projectData({ data: { projectId: params.projectId } }),
  component: ProjectPage,
})

interface MissionPreset {
  id: string
  name: string
  tierLabel: string
  tier: CapabilityTier
  summary: string
  goal: string
  usdCap: number
  rps: number
  concurrency: number
  maxTurns: number
}

const MISSION_PRESETS: MissionPreset[] = [
  {
    id: 'passive-recon',
    name: 'Passive Recon',
    tierLabel: 'Tier 1 · Read-Only',
    tier: 1,
    summary: 'Map hosts, JS bundles, routes, headers, auth boundaries, and crown-jewel assets with zero mutations.',
    goal: 'Enumerate public attack surfaces, classify crown-jewel APIs vs static origins, inspect JS bundles and headers, and verify reachable read-only issues without state-changing requests.',
    usdCap: 10,
    rps: 3,
    concurrency: 4,
    maxTurns: 40,
  },
  {
    id: 'bola-idor',
    name: 'Authenticated BOLA / IDOR',
    tierLabel: 'Tier 2 · Multi-Persona',
    tier: 2,
    summary: 'Cross-user authorization matrix probing with User A vs User B sessions across APIs and Server Actions.',
    goal: 'Verify tenant and user isolation across all authenticated API routes and Server Actions using paired personas. Capture control vs probe HTTP proofs for every cross-user boundary.',
    usdCap: 15,
    rps: 4,
    concurrency: 6,
    maxTurns: 80,
  },
  {
    id: 'greybox-deep',
    name: 'Full Grey-Box Deep Pentest',
    tierLabel: 'Tier 2 · Code + Live',
    tier: 2,
    summary: 'Combine static repo/spec auditing with live multi-persona runtime probes and independent replay verification.',
    goal: 'Audit synced specs and source handlers alongside live authenticated endpoints. Trace Server Actions, middleware auth guards, business-logic workflows, and verify all findings via replay.',
    usdCap: 25,
    rps: 5,
    concurrency: 6,
    maxTurns: 150,
  },
  {
    id: 'active-hitl',
    name: 'Approval-Gated Active',
    tierLabel: 'Tier 3 · HITL',
    tier: 3,
    summary: 'Controlled state-changing verification with mandatory operator approval before every risky probe.',
    goal: 'Validate high-impact state transitions, race conditions, and business-logic bypasses with mandatory human-in-the-loop approval gates prior to any mutating verification probe.',
    usdCap: 30,
    rps: 3,
    concurrency: 4,
    maxTurns: 120,
  },
  {
    id: 'offline-audit',
    name: 'Offline Repo / Spec Audit',
    tierLabel: 'Tier 0 · Offline',
    tier: 0,
    summary: 'Zero live network traffic. Analyze synced repositories, OpenAPI/GraphQL specs, lockfiles, and prepared metadata.',
    goal: 'Perform an offline source-first and specification security audit across imported specs, lockfiles, DNS exports, and access policy records with zero outbound target traffic.',
    usdCap: 10,
    rps: 1,
    concurrency: 4,
    maxTurns: 60,
  },
]

interface PersonaTestState {
  status: 'testing' | 'ok' | 'warn' | 'error'
  message: string
}

function safeHost(origin: string) {
  try {
    const u = new URL(origin)
    return u.port ? `${u.hostname}:${u.port}` : u.hostname
  } catch {
    return origin
  }
}

const LOGIN_URL_PLACEHOLDERS: Record<PersonaLoginAdapter, string> = {
  auto: 'Optional — auto-detected for Clerk',
  clerk: 'Optional — auto-detected for Clerk',
  json: 'https://app.example.com/api/auth/sign-in/email',
  supabase: 'Optional — defaults to <origin>/auth/v1/token?grant_type=password',
  form: 'Optional — defaults to <origin>/login',
}

function formatPersonaAuthBadge(persona: PublicPersona): string {
  if (persona.authKind === 'login') {
    const email = persona.loginConfig?.email
    const adapter = persona.loginConfig?.adapter ?? 'auto'
    return email ? `${email} · login (${adapter})` : `login (${adapter})`
  }
  return persona.headerName ? `${persona.authKind} · ${persona.headerName}` : persona.authKind
}

interface DiscoveredGithubRepo {
  fullName: string
  private: boolean
  defaultBranch: string
  updatedAt: string | null
  description: string | null
}

function formatGithubPatBadge(status: { configured: boolean; source: 'vault' | 'fixture' | null; tokenKind: 'fine_grained' | 'classic' | 'unknown' | null }): string {
  if (!status.configured) return 'Optional · Not connected'
  const kindLabel = status.tokenKind === 'fine_grained'
    ? 'Fine-grained PAT'
    : status.tokenKind === 'classic'
      ? 'Classic PAT'
      : 'GitHub PAT'
  return status.source === 'fixture' ? `${kindLabel} · fixture` : `${kindLabel} saved`
}

function formatIsoDay(iso: string | null): string | null {
  if (!iso) return null
  const ms = Date.parse(iso)
  if (!Number.isFinite(ms)) return null
  return new Date(ms).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
}

function ProjectPage() {
  const { project, assets, personas, specs, runs, githubPatStatus, localLabEnvEnabled } = Route.useLoaderData()
  const navigate = useNavigate()
  const labAllowed = project.environment === 'local-lab' && localLabEnvEnabled
  const [panel, setPanel] = useState<'candidate' | 'dns' | 'access'>()
  const [addingPersona, setAddingPersona] = useState(false)
  const [inlinePersonaOpen, setInlinePersonaOpen] = useState(false)
  const [starting, setStarting] = useState(runs.length === 0)

  // Source repositories (GitHub PAT + auto-discovery checklist) state
  const [githubTokenInput, setGithubTokenInput] = useState('')
  const [editingGithubToken, setEditingGithubToken] = useState(false)
  const [repoPickerOpen, setRepoPickerOpen] = useState(false)
  const [discoveredRepos, setDiscoveredRepos] = useState<DiscoveredGithubRepo[]>([])
  const [reposLoaded, setReposLoaded] = useState(false)
  const [reposTruncated, setReposTruncated] = useState(false)
  const [repoSearch, setRepoSearch] = useState('')
  const [selectedRepos, setSelectedRepos] = useState<string[]>([])
  const [githubNotice, setGithubNotice] = useState('')

  // New Run state (Mission presets + smart defaults)
  const [selectedPreset, setSelectedPreset] = useState<string>('')
  const [goal, setGoal] = useState('')
  const [tier, setTier] = useState<CapabilityTier>(1)
  const [approvalPolicy, setApprovalPolicy] = useState<ApprovalPolicy>('auto_review')
  const [budgetUsd, setBudgetUsd] = useState<number>(defaultBudgetUsd)
  const [maxRps, setMaxRps] = useState<number>(defaultMaxRpsPerOrigin)
  const [unlimitedReqs, setUnlimitedReqs] = useState<boolean>(defaultBudgetRequests === 0)
  const [budgetReqs, setBudgetReqs] = useState<number>(defaultBudgetRequests === 0 ? 2500 : defaultBudgetRequests)
  const [concurrency, setConcurrency] = useState<number>(defaultWorkerConcurrency)
  const [maxTurns, setMaxTurns] = useState<number>(defaultWorkerMaxTurns)
  const [selectedPersonaIds, setSelectedPersonaIds] = useState<string[]>(() => personas.map(p => p.id))

  // Persona creation form state (Email + Password default, plus Paste cURL for static tokens)
  const [authKind, setAuthKind] = useState<PersonaAuthKind>('login')
  const [loginAdapter, setLoginAdapter] = useState<PersonaLoginAdapter>('auto')
  const [loginEmail, setLoginEmail] = useState('')
  const [loginUrl, setLoginUrl] = useState('')
  const [personaHandle, setPersonaHandle] = useState('')
  const [personaRole, setPersonaRole] = useState('')
  const [personaHeaderName, setPersonaHeaderName] = useState('')
  const [personaOrigins, setPersonaOrigins] = useState(() => project.seeds.join('\n'))
  const [personaSecret, setPersonaSecret] = useState('')
  const [personaCanaries, setPersonaCanaries] = useState('')
  const [curlPaste, setCurlPaste] = useState('')
  const [curlNote, setCurlNote] = useState('')
  const [personaTests, setPersonaTests] = useState<Record<string, PersonaTestState>>({})

  const [notice, setNotice] = useState('')
  const [personaNotice, setPersonaNotice] = useState('')
  const [specNotice, setSpecNotice] = useState('')
  const [specName, setSpecName] = useState('')
  const [specContent, setSpecContent] = useState('')

  // LabRunner v4 configuration state
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

  // Tier-2 Sandbox Write Allowlist state
  const [allowOrigin, setAllowOrigin] = useState(() => project.seeds[0] ?? '')
  const [allowMethod, setAllowMethod] = useState('POST')
  const [allowPath, setAllowPath] = useState('')
  const [allowNotice, setAllowNotice] = useState('')

  const action = useAction()
  const inventoryAction = useAction()
  const personaAction = useAction()
  const githubAction = useAction()
  const specAction = useAction()
  const labAction = useAction()
  const allowlistAction = useAction()

  function applyPreset(preset: MissionPreset) {
    setSelectedPreset(preset.id)
    setGoal(preset.goal)
    setTier(preset.tier)
    setBudgetUsd(preset.usdCap)
    setMaxRps(preset.rps)
    setUnlimitedReqs(true)
    setConcurrency(preset.concurrency)
    setMaxTurns(preset.maxTurns)
    if (preset.tier >= 2 && personas.length > 0 && selectedPersonaIds.length === 0) {
      setSelectedPersonaIds(personas.map(p => p.id))
    }
  }

  function applyCurlParse(rawText: string) {
    const parsed = parseCurlOrHeader(rawText)
    if (!parsed) {
      setCurlNote('Could not detect a Cookie:, Authorization: Bearer, or custom auth header.')
      return
    }
    setAuthKind(parsed.authKind)
    if (parsed.headerName) setPersonaHeaderName(parsed.headerName)
    if (parsed.origin && !personaOrigins.includes(parsed.origin)) {
      setPersonaOrigins(prev => prev.trim() ? `${prev.trim()}\n${parsed.origin}` : parsed.origin!)
    }
    setPersonaSecret(parsed.secret)
    setCurlPaste('')
    setCurlNote(parsed.summary)
  }

  function prefillPersonaPair(which: 'user_a' | 'user_b') {
    setPersonaHandle(which)
    setPersonaRole(which === 'user_a' ? 'User A (Control / Owner)' : 'User B (Cross-User Probe)')
    setAuthKind('login')
    setLoginAdapter('auto')
    setPersonaOrigins(project.seeds.join('\n'))
    setPersonaSecret('')
    setCurlNote('')
  }

  async function handleTestPersonaAuth(persona: PublicPersona) {
    setPersonaTests(prev => ({
      ...prev,
      [persona.id]: {
        status: 'testing',
        message: persona.authKind === 'login' ? 'Logging in & testing GET…' : 'Testing safe GET…',
      },
    }))
    try {
      const res = await testPersonaAuthAction({
        data: { projectId: project.id, personaId: persona.id },
      })
      setPersonaTests(prev => ({
        ...prev,
        [persona.id]: {
          status: res.ok ? 'ok' : 'warn',
          message: `HTTP ${res.status} (${res.durationMs}ms) · ${res.authHint}`,
        },
      }))
    } catch (err) {
      setPersonaTests(prev => ({
        ...prev,
        [persona.id]: {
          status: 'error',
          message: err instanceof Error ? err.message : 'Auth check failed.',
        },
      }))
    }
  }

  function toggleInventory(next: typeof panel) {
    setPanel(current => current === next ? undefined : next)
    setNotice('')
  }

  function loadGithubRepos() {
    setGithubNotice('')
    void githubAction.submit(() => listGithubRepositories(), result => {
      setDiscoveredRepos(result.repos)
      setSelectedRepos(result.defaultSelected)
      setReposTruncated(result.truncated)
      setReposLoaded(true)
      setRepoPickerOpen(true)
      setEditingGithubToken(false)
    })
  }

  function openRepoPicker() {
    setEditingGithubToken(false)
    setGithubNotice('')
    if (repoPickerOpen && reposLoaded) {
      setRepoPickerOpen(false)
      return
    }
    setRepoPickerOpen(true)
    if (!reposLoaded) {
      loadGithubRepos()
    }
  }

  function toggleSelectedRepo(fullName: string, checked: boolean) {
    setSelectedRepos(prev =>
      checked
        ? (prev.includes(fullName) ? prev : [...prev, fullName])
        : prev.filter(name => name !== fullName),
    )
  }

  async function onSpecFileSelected(file: File | undefined) {
    if (!file) return
    if (file.size > maxSpecBytes) {
      setSpecNotice(`File exceeds the ${Math.round(maxSpecBytes / (1024 * 1024))} MiB spec limit.`)
      return
    }
    const text = await file.text()
    setSpecName(current => current || file.name.slice(0, 160))
    setSpecContent(text)
  }

  function resetPersonaForm() {
    setPersonaHandle('')
    setPersonaRole('')
    setPersonaHeaderName('')
    setLoginAdapter('auto')
    setLoginEmail('')
    setLoginUrl('')
    setPersonaOrigins(project.seeds.join('\n'))
    setPersonaSecret('')
    setPersonaCanaries('')
    setCurlPaste('')
    setCurlNote('')
  }

  function submitPersona(onDone: (created: { id: string; handle: string }) => void) {
    const allowlist = personaOrigins.split(/[\s,]+/).filter(Boolean)
    const canaryMarkers = personaCanaries.split(',').map(s => s.trim()).filter(Boolean)
    const headerNameRaw = personaHeaderName.trim()
    const loginUrlRaw = loginUrl.trim()
    void personaAction.submit(() => registerPersona({ data: {
      requestId: crypto.randomUUID(),
      projectId: project.id,
      handle: personaHandle.trim(),
      roleLabel: personaRole.trim(),
      originAllowlist: allowlist,
      authKind,
      ...(authKind === 'header' && headerNameRaw ? { headerName: headerNameRaw } : {}),
      ...(authKind === 'login' ? {
        loginConfig: {
          adapter: loginAdapter,
          email: loginEmail.trim(),
          ...(loginUrlRaw ? { loginUrl: loginUrlRaw } : {}),
        },
      } : {}),
      secret: personaSecret,
      canaryMarkers,
    } }), created => {
      resetPersonaForm()
      setPersonaNotice(`Saved persona "${created.handle}". Secret stored in local 0600 vault.`)
      setSelectedPersonaIds(prev => prev.includes(created.id) ? prev : [...prev, created.id])
      onDone(created)
    })
  }

  return <main className="workspace-page">
    <Link className="back-link" to="/">← Projects</Link>
    <div className="page-title">
      <div className="page-title-main">
        <div className="inline-badges">
          <h1>{project.name}</h1>
          {project.environment === 'local-lab'
            ? <span className="badge badge-attention">Local lab</span>
            : <span className="badge">Public HTTPS</span>}
        </div>
        <p className="muted mono-inline">{project.seeds.map(safeHost).join(', ')}</p>
      </div>
      {!starting && <Button variant="default" className="btn-nowrap" onClick={() => setStarting(true)}>New run</Button>}
    </div>

    {starting && <form className="form-card start-run-card" onSubmit={event => {
      event.preventDefault()
      const sourceMode = tier === 0 ? 'prepared' as const : 'public' as const
      const effectiveReqs = tier === 0 || unlimitedReqs ? 0 : Math.max(0, Math.min(maxBudgetRequests, Math.round(budgetReqs)))
      void action.submit(() => createRun({ data: {
        requestId: crypto.randomUUID(),
        projectId: project.id,
        goal,
        sourceMode,
        capabilityTier: tier,
        approvalPolicy,
        approvedPersonaIds: tier >= 2 ? selectedPersonaIds : [],
        budgetUsd,
        budgetRequests: effectiveReqs,
        maxRpsPerOrigin: maxRps,
        workerConcurrency: concurrency,
        workerMaxTurns: maxTurns,
      } }), async result => { await navigate({ to: '/runs/$runId', params: { runId: result.id } }) })
    }}>
      <div className="section-heading">
        <div>
          <h2>Start a run</h2>
          <p className="muted">Choose a mission preset to pre-fill goal, tier, and guardrails — customize freely below.</p>
        </div>
        {runs.length > 0 && <Button variant="ghost" onClick={() => setStarting(false)}>Cancel</Button>}
      </div>

      <div className="mission-presets" role="group" aria-label="Mission presets">
        {MISSION_PRESETS.map(preset => <button
          key={preset.id}
          type="button"
          className={`preset-card${selectedPreset === preset.id ? ' active' : ''}`}
          onClick={() => applyPreset(preset)}
        >
          <div className="preset-card-top">
            <span className={`badge ${preset.tier === 3 ? 'badge-attention' : preset.tier === 2 ? 'badge-trace' : ''}`}>
              {preset.tierLabel}
            </span>
            <span className="mono muted preset-meta">${preset.usdCap} · {preset.rps} rps</span>
          </div>
          <strong className="preset-name">{preset.name}</strong>
          <span className="preset-desc">{preset.summary}</span>
        </button>)}
      </div>

      <label>Run goal
        <Textarea
          name="goal"
          rows={3}
          maxLength={8000}
          required
          value={goal}
          onChange={e => setGoal(e.target.value)}
          placeholder="Assess authentication, API authorization, client-side exposure, and reachable CVEs across approved hosts."
        />
      </label>

      <div className="field-grid-2">
        <label>Capability tier
          <NativeSelect name="capabilityTier" value={tier} onChange={event => setTier(Number(event.target.value) as CapabilityTier)}>
            <option value={0}>{capabilityTierMeta[0].name}</option>
            <option value={1}>{capabilityTierMeta[1].name}</option>
            <option value={2}>{capabilityTierMeta[2].name}</option>
            <option value={3}>{capabilityTierMeta[3].name}</option>
          </NativeSelect>
          <span className="muted">{capabilityTierMeta[tier].summary}</span>
        </label>
        <div className="field-grid-2">
          <label>USD Spend Cap
            <Input name="budgetUsd" type="number" min={0.1} max={500} step="any" required
              value={budgetUsd} onChange={e => setBudgetUsd(Number(e.target.value))} />
          </label>
          <label>Rate Limit (RPS / origin)
            <Input name="maxRpsPerOrigin" type="number" min={1} max={maxRpsPerOriginCeiling} step={1} required
              value={maxRps} onChange={e => setMaxRps(Number(e.target.value))} />
          </label>
        </div>
      </div>

      {/* Tier 3 Approval Policy selector */}
      {tier === 3 && <div className="policy-selector-box" role="radiogroup" aria-label="Tier 3 Approval Policy">
        <div className="section-heading">
          <div>
            <strong>Tier 3 Approval Policy</strong>
            <p className="muted">Choose how state-changing probes are gated. You can switch policy live mid-run.</p>
          </div>
        </div>
        <div className="policy-option-grid">
          {approvalPolicies.map(policy => {
            const meta = approvalPolicyMeta[policy]
            const active = approvalPolicy === policy
            return <button
              key={policy}
              type="button"
              role="radio"
              aria-checked={active}
              className={`policy-option${active ? ' active' : ''}`}
              onClick={() => setApprovalPolicy(policy)}
            >
              <div className="policy-option-head">
                <strong>{meta.optionLabel}</strong>
                {policy === 'yolo' && <span className="badge badge-attention">Autonomous</span>}
                {policy === 'auto_review' && <span className="badge badge-complete">Default</span>}
                {policy === 'strict' && <span className="badge">Manual</span>}
              </div>
              <span className="muted xs">{meta.summary}</span>
            </button>
          })}
        </div>
      </div>}

      {/* Integrated Personas for Tier 2/3 */}
      {tier >= 2 && <div className="inline-personas-box">
        <div className="section-heading">
          <div>
            <strong>Authenticated Personas (User A / User B)</strong>
            <p className="muted">Select vault personas to bind to this run. Secrets stay in local 0600 files and never enter LLM prompts.</p>
          </div>
          <Button type="button" variant="ghost" onClick={() => setInlinePersonaOpen(v => !v)}>
            {inlinePersonaOpen ? 'Hide quick add' : '+ Add Persona / Pair User A & B'}
          </Button>
        </div>

        {personas.length > 0 ? <div className="inline-persona-list">
          {personas.map(persona => {
            const test = personaTests[persona.id]
            return <div key={persona.id} className="inline-persona-row">
              <label className="checkbox">
                <Checkbox
                  checked={selectedPersonaIds.includes(persona.id)}
                  aria-label={`Select persona ${persona.handle} for run`}
                  onCheckedChange={checked => setSelectedPersonaIds(prev =>
                    checked ? (prev.includes(persona.id) ? prev : [...prev, persona.id]) : prev.filter(id => id !== persona.id),
                  )}
                />
                <span className="inline-badges">
                  <strong>{persona.handle}</strong>
                  <span className="badge badge-trace">{persona.roleLabel}</span>
                  <span className="badge">{formatPersonaAuthBadge(persona)}</span>
                </span>
              </label>
              <div className="inline-badges">
                {test && <span className={`badge ${test.status === 'ok' ? 'badge-complete' : test.status === 'warn' ? 'badge-attention' : test.status === 'error' ? 'badge-danger' : ''}`}>
                  {test.message}
                </span>}
                <Button type="button" variant="ghost" disabled={test?.status === 'testing'} onClick={() => void handleTestPersonaAuth(persona)}>
                  {test?.status === 'testing' ? 'Testing…' : test?.status === 'ok' ? 'Test Auth ✓' : 'Test Auth'}
                </Button>
              </div>
            </div>
          })}
        </div> : <p className="muted">No personas saved yet. Add User A &amp; User B below for cross-user BOLA/IDOR checks.</p>}

        {inlinePersonaOpen && <div className="inline-persona-creator">
          <div className="section-heading">
            <strong>Quick-add vault persona</strong>
            <div className="inline-badges">
              <Button type="button" variant="ghost" onClick={() => prefillPersonaPair('user_a')}>Preset User A</Button>
              <Button type="button" variant="ghost" onClick={() => prefillPersonaPair('user_b')}>Preset User B</Button>
            </div>
          </div>
          {authKind !== 'login' && <>
            <div className="curl-parse-row">
              <Input
                value={curlPaste}
                onChange={e => setCurlPaste(e.target.value)}
                onPaste={e => {
                  const pasted = e.clipboardData.getData('text')
                  if (pasted) {
                    e.preventDefault()
                    applyCurlParse(pasted)
                  }
                }}
                placeholder="Paste cURL command or Cookie:/Authorization: header (auto-parses & masks secret)"
              />
              <Button type="button" onClick={() => applyCurlParse(curlPaste)} disabled={!curlPaste.trim()}>Parse cURL</Button>
            </div>
            {curlNote && <p className="muted small-note">{curlNote}</p>}
          </>}
          <div className="field-grid-2">
            <label>Handle
              <Input value={personaHandle} onChange={e => setPersonaHandle(e.target.value)} placeholder="user_a" />
            </label>
            <label>Role label
              <Input value={personaRole} onChange={e => setPersonaRole(e.target.value)} placeholder="Standard user" />
            </label>
          </div>
          <label>Auth kind
            <NativeSelect value={authKind} onChange={e => setAuthKind(e.target.value as PersonaAuthKind)}>
              <option value="login">Email + Password (auto-login &amp; refresh)</option>
              <option value="cookie">Session cookie (Cookie: …)</option>
              <option value="bearer">Bearer token (Authorization: Bearer …)</option>
              <option value="header">Custom request header</option>
            </NativeSelect>
          </label>
          {authKind === 'login' ? <>
            <div className="field-grid-2">
              <label>Email
                <Input
                  type="email"
                  value={loginEmail}
                  onChange={e => setLoginEmail(e.target.value)}
                  placeholder="guardian-a@dyad.sh"
                  autoComplete="off"
                />
              </label>
              <label>Password
                <Input
                  type="password"
                  value={personaSecret}
                  onChange={e => setPersonaSecret(e.target.value)}
                  placeholder="Account password (stored in local 0600 vault)"
                  autoComplete="off"
                />
              </label>
            </div>
            <div className="field-grid-2">
              <label>Auth method
                <NativeSelect value={loginAdapter} onChange={e => setLoginAdapter(e.target.value as PersonaLoginAdapter)}>
                  <option value="auto">Auto-detect</option>
                  <option value="clerk">Clerk (auto-refresh 60s JWT)</option>
                  <option value="json">JSON API / Better Auth</option>
                  <option value="supabase">Supabase Auth</option>
                  <option value="form">Login Form (Browser)</option>
                </NativeSelect>
              </label>
              <label>Login URL (optional)
                <Input
                  type="url"
                  value={loginUrl}
                  onChange={e => setLoginUrl(e.target.value)}
                  placeholder={LOGIN_URL_PLACEHOLDERS[loginAdapter]}
                  autoComplete="off"
                />
              </label>
            </div>
          </> : <div className="field-grid-2">
            {authKind === 'header' && <label>Header name
              <Input value={personaHeaderName} onChange={e => setPersonaHeaderName(e.target.value)} placeholder="X-Api-Key" />
            </label>}
            <label>Secret (masked)
              <Input type="password" value={personaSecret} onChange={e => setPersonaSecret(e.target.value)} autoComplete="off" placeholder="Never echoed after save" />
            </label>
          </div>}
          <FormError error={personaAction.error} />
          <div className="form-actions">
            <Button type="button" variant="ghost" onClick={() => setInlinePersonaOpen(false)}>Close</Button>
            <Button
              type="button"
              variant="default"
              disabled={
                personaAction.pending ||
                !personaHandle.trim() ||
                !personaRole.trim() ||
                !personaSecret ||
                (authKind === 'login' ? !loginEmail.trim() : !personaSecret.trim())
              }
              onClick={() => submitPersona(() => setInlinePersonaOpen(false))}
            >
              Save to vault &amp; select
            </Button>
          </div>
        </div>}
      </div>}

      <Collapsible className="provider-advanced">
        <CollapsibleTrigger render={<Button type="button" variant="ghost" className="collapsible-trigger" />}>
          Advanced limits <span className="muted">(Requests: {unlimitedReqs || tier === 0 ? '∞ Unlimited' : budgetReqs} · {concurrency} workers · {maxTurns} turns)</span>
        </CollapsibleTrigger>
        <CollapsibleContent keepMounted>
          <div className="advanced-limits-grid">
            <div className="field-grid">
              <label className="checkbox">
                <Checkbox
                  checked={unlimitedReqs}
                  aria-label="Unlimited max requests"
                  onCheckedChange={checked => setUnlimitedReqs(Boolean(checked))}
                />
                <span>Unlimited max requests (<code>∞</code>, recommended)</span>
              </label>
              {!unlimitedReqs && <label>Max brokered requests
                <Input name="budgetRequests" type="number" min={1} max={maxBudgetRequests} step={1}
                  value={budgetReqs} onChange={e => setBudgetReqs(Number(e.target.value))} />
              </label>}
            </div>
            <div className="field-grid-2">
              <label>Worker concurrency
                <Input name="workerConcurrency" type="number" min={1} max={maxWorkerConcurrency} step={1} required
                  value={concurrency} onChange={e => setConcurrency(Number(e.target.value))} />
              </label>
              <label>Worker max turns
                <Input name="workerMaxTurns" type="number" min={1} max={maxWorkerMaxTurns} step={1} required
                  value={maxTurns} onChange={e => setMaxTurns(Number(e.target.value))} />
              </label>
            </div>
          </div>
        </CollapsibleContent>
      </Collapsible>

      <FormError error={action.error} />
      <div className="form-actions">
        <span className="muted mono-inline run-summary-hint">
          {capabilityTierMeta[tier].short} · ${budgetUsd} cap · {maxRps} rps · Reqs {unlimitedReqs || tier === 0 ? '∞' : budgetReqs}
        </span>
        <Button type="submit" variant="default" className="btn-nowrap" disabled={action.pending}>Create run</Button>
      </div>
    </form>}

    {runs.length > 0 && <section aria-label="Run history" className="stacked-section">
      <h2>Run history</h2>
      <ul className="project-list">{runs.map(run => <li key={run.id}>
        <Link to="/runs/$runId" params={{ runId: run.id }} className="run-history-link">
          <span className="run-history-main">
            <strong className="run-history-goal">{run.goal}</strong>
            <small>
              {timeText(run.createdAt)} · {capabilityTierMeta[run.capabilityTier].short} · {phaseNames[run.phase]} · {run.turnsUsed} turns · {run.spentRequests} reqs · {formatUsd(run.spentUsd)}
            </small>
          </span>
          <Status status={run.status} />
        </Link>
      </li>)}</ul>
    </section>}

    <section className="stacked-section" aria-label="Project inventory">
      <div className="section-heading"><h2>Project inventory</h2>
        <div className="toolbar inventory-toolbar">
          <Button onClick={() => toggleInventory('candidate')} aria-expanded={panel === 'candidate'}>Add candidate</Button>
          <Button onClick={() => toggleInventory('dns')} aria-expanded={panel === 'dns'}>Import DNS export</Button>
          <Button onClick={() => toggleInventory('access')} aria-expanded={panel === 'access'}>Import access records</Button>
        </div>
      </div>
      {notice && <p role="status" className="muted">{notice}</p>}
      {panel === 'dns' && <DnsInventoryImport projectId={project.id} defaultZone={new URL(project.seeds[0]).hostname}
        cancel={() => setPanel(undefined)} imported={({ added, existing }) => {
          setPanel(undefined)
          setNotice(`Added ${added} ${added === 1 ? 'host' : 'hosts'}. Skipped ${existing} existing.`)
        }} />}
      {panel === 'access' && <AccessPolicyImport projectId={project.id} assets={assets}
        cancel={() => setPanel(undefined)} imported={({ origin, cases }) => {
          setPanel(undefined)
          setNotice(`Imported ${cases} access ${cases === 1 ? 'case' : 'cases'} for ${new URL(origin).hostname}.`)
        }} />}
      {panel === 'candidate' && <form className="form-card" onSubmit={event => {
        event.preventDefault()
        const form = new FormData(event.currentTarget)
        let prepared: unknown
        const supplied = String(form.get('prepared') ?? '').trim()
        if (supplied) {
          try {
            prepared = JSON.parse(supplied)
          } catch {
            void inventoryAction.submit(async () => { throw new Error('Prepared evidence must be valid JSON.') })
            return
          }
        }
        void inventoryAction.submit(() => addProjectAsset({ data: {
          requestId: crypto.randomUUID(), projectId: project.id,
          origin: String(form.get('origin')), source: String(form.get('source')), thirdParty: form.has('thirdParty'),
          prepared: prepared as Parameters<typeof addProjectAsset>[0]['data']['prepared'],
        } }), () => setPanel(undefined))
      }}>
        <label>Host<Input name="origin" placeholder="docs.example.com" required /></label>
        <label>Source<Input name="source" placeholder="Service ownership inventory" required maxLength={160} /></label>
        <label className="checkbox"><Checkbox name="thirdParty" aria-label="Third-party service" /> Third-party service</label>
        <Collapsible className="provider-advanced">
          <CollapsibleTrigger render={<Button variant="ghost" className="collapsible-trigger" />}>Supply prepared evidence</CollapsibleTrigger>
          <CollapsibleContent keepMounted>
            <label>Prepared response metadata
              <Textarea name="prepared" rows={4} placeholder={'{"status":200,"mediaType":"text/html","transportMaxAge":31536000,"includeSubDomains":false,"contentTypeOptions":"nosniff","referrerPolicy":"strict-origin-when-cross-origin"}'} />
            </label>
          </CollapsibleContent>
        </Collapsible>
        <FormError error={inventoryAction.error} />
        <div className="form-actions"><Button type="submit" variant="default" disabled={inventoryAction.pending}>Add to project</Button></div>
      </form>}
      <ul className="project-list">{assets.map(asset => <li key={asset.id}>
        <div className="list-row"><span><strong>{safeHost(asset.origin)}</strong>
          <small>{asset.source}{asset.dnsSource ? ` · ${asset.dnsSource.zone}` : ''}{asset.accessPolicy ? ' · Access policy records' : ''}</small></span>
          <span className="muted btn-nowrap">{asset.thirdParty ? 'Third party' : project.defaultScope.includes(asset.origin) ? 'Project default' : 'Candidate'}</span>
        </div>
      </li>)}</ul>
    </section>

    <section className="stacked-section" aria-label="Persona vault">
      <div className="section-heading">
        <div>
          <h2>Persona vault</h2>
          <p className="muted">Opaque test accounts for Tier 2/3 validation. Secrets are stored locally at 0600 and injected only on allowlisted origins.</p>
        </div>
        <Button className="btn-nowrap" onClick={() => { setAddingPersona(v => !v); setPersonaNotice('') }} aria-expanded={addingPersona}>
          {addingPersona ? 'Close' : 'Add persona'}
        </Button>
      </div>
      {personaNotice && <p role="status" className="muted">{personaNotice}</p>}
      {addingPersona && <form className="form-card" onSubmit={event => {
        event.preventDefault()
        submitPersona(() => setAddingPersona(false))
      }}>
        <div className="section-heading">
          <h3>Add test persona</h3>
          <div className="inline-badges">
            <Button type="button" variant="ghost" onClick={() => prefillPersonaPair('user_a')}>Prefill User A</Button>
            <Button type="button" variant="ghost" onClick={() => prefillPersonaPair('user_b')}>Prefill User B</Button>
          </div>
        </div>
        {authKind !== 'login' && <>
          <div className="curl-parse-row">
            <Input
              value={curlPaste}
              onChange={e => setCurlPaste(e.target.value)}
              onPaste={e => {
                const pasted = e.clipboardData.getData('text')
                if (pasted) {
                  e.preventDefault()
                  applyCurlParse(pasted)
                }
              }}
              placeholder="Paste cURL or Cookie / Authorization header to auto-extract credentials…"
            />
            <Button type="button" onClick={() => applyCurlParse(curlPaste)} disabled={!curlPaste.trim()}>Parse cURL</Button>
          </div>
          {curlNote && <p className="muted small-note">{curlNote}</p>}
        </>}
        <div className="field-grid-2">
          <label>Handle (lowercase, opaque to workers)
            <Input name="handle" required pattern="[a-z0-9][a-z0-9_-]{0,47}" placeholder="tenant_a"
              value={personaHandle} onChange={e => setPersonaHandle(e.target.value)} />
          </label>
          <label>Role label
            <Input name="roleLabel" required maxLength={160} placeholder="Standard tenant member"
              value={personaRole} onChange={e => setPersonaRole(e.target.value)} />
          </label>
        </div>
        <label>Origin allowlist (one per line or comma-separated)
          <Textarea name="originAllowlist" rows={2} required value={personaOrigins} onChange={e => setPersonaOrigins(e.target.value)} />
        </label>
        <div className="field-grid-2">
          <label>Authentication kind
            <NativeSelect name="authKind" value={authKind} onChange={event => setAuthKind(event.target.value as PersonaAuthKind)}>
              <option value="login">Email + Password (auto-login &amp; refresh)</option>
              <option value="cookie">Session cookie (Cookie: …)</option>
              <option value="bearer">Bearer token (Authorization: Bearer …)</option>
              <option value="header">Custom request header</option>
            </NativeSelect>
          </label>
          {authKind === 'header' && <label>Header name
            <Input name="headerName" required pattern="[A-Za-z0-9-]{1,64}" placeholder="X-Api-Key"
              value={personaHeaderName} onChange={e => setPersonaHeaderName(e.target.value)} />
          </label>}
        </div>
        {authKind === 'login' ? <>
          <div className="field-grid-2">
            <label>Email
              <Input name="loginEmail" type="email" required maxLength={320} autoComplete="off"
                value={loginEmail} onChange={e => setLoginEmail(e.target.value)}
                placeholder="guardian-a@dyad.sh" />
            </label>
            <label>Password
              <Input name="secret" type="password" required maxLength={4096} autoComplete="off"
                value={personaSecret} onChange={e => setPersonaSecret(e.target.value)}
                placeholder="Account password (stored in local 0600 vault)" />
            </label>
          </div>
          <div className="field-grid-2">
            <label>Auth method
              <NativeSelect name="loginAdapter" value={loginAdapter} onChange={event => setLoginAdapter(event.target.value as PersonaLoginAdapter)}>
                <option value="auto">Auto-detect</option>
                <option value="clerk">Clerk (auto-refresh 60s JWT)</option>
                <option value="json">JSON API / Better Auth</option>
                <option value="supabase">Supabase Auth</option>
                <option value="form">Login Form (Browser)</option>
              </NativeSelect>
            </label>
            <label>Login URL (optional)
              <Input name="loginUrl" type="url" maxLength={500} autoComplete="off"
                value={loginUrl} onChange={e => setLoginUrl(e.target.value)}
                placeholder={LOGIN_URL_PLACEHOLDERS[loginAdapter]} />
            </label>
          </div>
        </> : <label>Credential secret
          <Input name="secret" type="password" required maxLength={4096} autoComplete="off"
            value={personaSecret} onChange={e => setPersonaSecret(e.target.value)}
            placeholder="Never displayed back after saving" />
        </label>}
        <label>Canary markers (optional, comma-separated)
          <Input name="canaryMarkers" value={personaCanaries} onChange={e => setPersonaCanaries(e.target.value)}
            placeholder="tenant-a-canary@example.test, org_alpha_001" />
          <span className="muted">Strings that indicate cross-tenant data leakage if seen by another persona.</span>
        </label>
        <FormError error={personaAction.error} />
        <div className="form-actions">
          <Button type="button" onClick={() => setAddingPersona(false)}>Cancel</Button>
          <Button type="submit" variant="default" disabled={personaAction.pending}>Save persona</Button>
        </div>
      </form>}
      {personas.length > 0 ? <ul className="project-list">{personas.map(persona => {
        const test = personaTests[persona.id]
        return <li key={persona.id}>
          <div className="list-row">
            <span>
              <span className="inline-badges">
                <strong>{persona.handle}</strong>
                <span className="badge badge-trace">{persona.roleLabel}</span>
                <span className="badge">{formatPersonaAuthBadge(persona)}</span>
                {test && <span className={`badge ${test.status === 'ok' ? 'badge-complete' : test.status === 'warn' ? 'badge-attention' : test.status === 'error' ? 'badge-danger' : ''}`}>
                  {test.message}
                </span>}
              </span>
              <small>Allowlist: {persona.originAllowlist.map(safeHost).join(', ')}
                {persona.canaryMarkers.length > 0 && ` · ${persona.canaryMarkers.length} canary ${persona.canaryMarkers.length === 1 ? 'marker' : 'markers'}`}</small>
            </span>
            <div className="toolbar">
              <Button type="button" variant="ghost" disabled={test?.status === 'testing'} onClick={() => void handleTestPersonaAuth(persona)}>
                {test?.status === 'testing' ? 'Testing…' : test?.status === 'ok' ? 'Test Auth ✓' : 'Test Auth'}
              </Button>
              <Button variant="ghost" className="btn-danger" disabled={personaAction.pending} onClick={() => {
                void personaAction.submit(() => removePersona({ data: {
                  requestId: crypto.randomUUID(), projectId: project.id, personaId: persona.id,
                } }), () => setPersonaNotice(`Removed persona "${persona.handle}".`))
              }}>Delete</Button>
            </div>
          </div>
        </li>
      })}</ul> : <p className="muted" style={{ marginTop: 8 }}>No personas configured yet.</p>}
    </section>

    <section className="stacked-section" aria-label="Source repositories">
      <div className="section-heading">
        <div>
          <div className="inline-badges">
            <h2>Source repositories (read-only)</h2>
            <span className={githubPatStatus.configured ? 'badge badge-complete' : 'badge'}>
              {formatGithubPatBadge(githubPatStatus)}
            </span>
          </div>
          <p className="muted">Optional read-only GitHub sync for grey-box code, schema, and CVE context. Tokens are saved in your local 0600 vault and never echoed back.</p>
        </div>
        {githubPatStatus.configured && <div className="toolbar inventory-toolbar">
          <Button
            type="button"
            variant="default"
            disabled={githubAction.pending}
            onClick={openRepoPicker}
            aria-expanded={repoPickerOpen}
          >
            {repoPickerOpen ? 'Hide repos' : 'Discover & sync repos'}
          </Button>
          <Button
            type="button"
            variant="ghost"
            disabled={githubAction.pending}
            onClick={() => { setEditingGithubToken(v => !v); setGithubNotice('') }}
            aria-expanded={editingGithubToken}
          >
            {editingGithubToken ? 'Cancel' : 'Update token'}
          </Button>
        </div>}
      </div>

      {githubNotice && <p role="status" className="muted" style={{ marginTop: 8 }}>{githubNotice}</p>}
      {specNotice && <p role="status" className="muted" style={{ marginTop: 8 }}>{specNotice}</p>}

      {(!githubPatStatus.configured || editingGithubToken) && <form
        className="form-card github-pat-card"
        style={{ marginTop: 10 }}
        onSubmit={event => {
          event.preventDefault()
          const token = githubTokenInput.trim()
          if (!token) return
          setGithubNotice('')
          void githubAction.submit(() => saveGithubToken({ data: { token } }), result => {
            setGithubTokenInput('')
            setEditingGithubToken(false)
            setDiscoveredRepos(result.repos)
            setSelectedRepos(result.defaultSelected)
            setReposTruncated(result.truncated)
            setReposLoaded(true)
            setRepoPickerOpen(true)
            setRepoSearch('')
            setGithubNotice(`Token saved to local 0600 vault. Found ${result.repos.length} accessible ${result.repos.length === 1 ? 'repository' : 'repositories'}.`)
          })
        }}
      >
        <div className="section-heading">
          <h3>{githubPatStatus.configured ? 'Update GitHub personal access token' : 'Connect GitHub with a Fine-Grained PAT'}</h3>
          <a
            className="action-link"
            href="https://github.com/settings/personal-access-tokens/new"
            target="_blank"
            rel="noopener noreferrer"
          >
            Create Fine-Grained PAT on GitHub ↗
          </a>
        </div>
        <ol className="github-pat-steps">
          <li>Under <strong>Repository access</strong>, choose <strong>Only select repositories</strong> and pick the repos you want Guardian to inspect.</li>
          <li>Under <strong>Repository permissions</strong>, set <strong>Contents: Read-only</strong>.</li>
          <li>Click <strong>Generate token</strong> and paste it below — Guardian stores it in your local <code>0600</code> vault and auto-discovers accessible repos.</li>
        </ol>
        <label>GitHub Personal Access Token
          <Input
            name="githubPat"
            type="password"
            required
            minLength={10}
            maxLength={512}
            autoComplete="off"
            value={githubTokenInput}
            onChange={e => setGithubTokenInput(e.target.value)}
            placeholder="github_pat_…"
          />
        </label>
        <FormError error={githubAction.error} />
        <div className="form-actions">
          {githubPatStatus.configured && <Button type="button" variant="ghost" onClick={() => {
            setEditingGithubToken(false)
            setGithubTokenInput('')
          }}>Cancel</Button>}
          <Button type="submit" variant="default" disabled={githubAction.pending || githubTokenInput.trim().length < 10}>
            {githubAction.pending ? 'Saving & discovering…' : 'Save token & discover repos'}
          </Button>
        </div>
      </form>}

      {githubPatStatus.configured && !editingGithubToken && repoPickerOpen && (() => {
        const needle = repoSearch.trim().toLowerCase()
        const filteredRepos = needle
          ? discoveredRepos.filter(r =>
            r.fullName.toLowerCase().includes(needle) ||
            (r.description?.toLowerCase().includes(needle) ?? false) ||
            r.defaultBranch.toLowerCase().includes(needle),
          )
          : discoveredRepos
        const maxSyncBatch = 20
        const showBroadNote = discoveredRepos.length > 10 || githubPatStatus.tokenKind === 'classic'
        return <div className="form-card github-picker-card" style={{ marginTop: 10 }}>
          <div className="section-heading">
            <div>
              <h3>Select repositories to sync</h3>
              <p className="muted">
                Read-only shallow clone + automatic OpenAPI, GraphQL, route, and lockfile extraction.
                {reposTruncated && ' Showing the 200 most recently updated repositories.'}
              </p>
            </div>
            <div className="toolbar">
              <Button type="button" variant="ghost" disabled={githubAction.pending} onClick={loadGithubRepos}>
                {githubAction.pending && !reposLoaded ? 'Loading…' : 'Refresh'}
              </Button>
              {githubPatStatus.source === 'vault' && <Button
                type="button"
                variant="ghost"
                className="btn-danger"
                disabled={githubAction.pending}
                onClick={() => {
                  setGithubNotice('')
                  void githubAction.submit(() => clearGithubToken(), result => {
                    setDiscoveredRepos([])
                    setSelectedRepos([])
                    setReposLoaded(false)
                    setRepoPickerOpen(false)
                    setRepoSearch('')
                    setGithubNotice(result.status.configured
                      ? 'Removed saved vault token (fallback fixture PAT is still present).'
                      : 'Removed saved GitHub token from local vault.')
                  })
                }}
              >
                Remove saved token
              </Button>}
            </div>
          </div>

          {githubPatStatus.source === 'fixture' && <p className="muted small-note">
            Using fallback fixture PAT from <code>~/.config/guardian-fixtures/github.pat</code>. Click <strong>Update token</strong> above to store a project-vault token instead.
          </p>}

          {showBroadNote && discoveredRepos.length > 0 && <div className="github-broad-note">
            <span className="muted">
              {githubPatStatus.tokenKind === 'classic'
                ? `Classic PAT detected (${discoveredRepos.length} accessible repos).`
                : `Found ${discoveredRepos.length} accessible repos.`}{' '}
              {discoveredRepos.length > 10
                ? 'Nothing was pre-selected so you do not accidentally clone everything.'
                : 'Consider scoping a Fine-Grained PAT to only the target repositories.'}
            </span>
            <Button
              type="button"
              variant="ghost"
              disabled={githubAction.pending || filteredRepos.length === 0}
              onClick={() => setSelectedRepos(filteredRepos.slice(0, maxSyncBatch).map(r => r.fullName))}
            >
              Select all{filteredRepos.length > maxSyncBatch ? ` (first ${maxSyncBatch})` : ` (${filteredRepos.length})`}
            </Button>
          </div>}

          <div className="github-picker-toolbar">
            <Input
              type="search"
              value={repoSearch}
              onChange={e => setRepoSearch(e.target.value)}
              placeholder="Filter repositories by name, branch, or description…"
              aria-label="Filter GitHub repositories"
            />
            <div className="toolbar">
              <Button
                type="button"
                variant="ghost"
                disabled={githubAction.pending || filteredRepos.length === 0}
                onClick={() => setSelectedRepos(filteredRepos.slice(0, maxSyncBatch).map(r => r.fullName))}
              >
                Select all
              </Button>
              <Button
                type="button"
                variant="ghost"
                disabled={githubAction.pending || selectedRepos.length === 0}
                onClick={() => setSelectedRepos([])}
              >
                Clear
              </Button>
            </div>
          </div>

          {githubAction.pending && !reposLoaded ? (
            <p className="muted">Discovering accessible repositories…</p>
          ) : filteredRepos.length > 0 ? (
            <ul className="github-repo-list" aria-label="Accessible GitHub repositories">
              {filteredRepos.map(repo => {
                const checked = selectedRepos.includes(repo.fullName)
                const updatedLabel = formatIsoDay(repo.updatedAt)
                return <li key={repo.fullName} className="github-repo-row">
                  <label className="checkbox github-repo-label">
                    <Checkbox
                      checked={checked}
                      aria-label={`Select repository ${repo.fullName}`}
                      onCheckedChange={next => toggleSelectedRepo(repo.fullName, Boolean(next))}
                    />
                    <span className="github-repo-meta">
                      <span className="inline-badges">
                        <strong className="mono">{repo.fullName}</strong>
                        <span className="badge">{repo.private ? 'private' : 'public'}</span>
                        <span className="badge badge-trace">{repo.defaultBranch}</span>
                        {updatedLabel && <span className="muted xs">Updated {updatedLabel}</span>}
                      </span>
                      {repo.description && <small className="muted truncate">{repo.description}</small>}
                    </span>
                  </label>
                </li>
              })}
            </ul>
          ) : (
            <p className="muted">
              {discoveredRepos.length === 0
                ? 'No repositories were returned for this token. Verify the token grants Repository permissions → Contents: Read-only on at least one repository.'
                : `No repositories match "${repoSearch.trim()}".`}
            </p>
          )}

          {selectedRepos.length > maxSyncBatch && (
            <p role="alert" className="form-error">Select at most {maxSyncBatch} repositories per sync batch.</p>
          )}
          <FormError error={githubAction.error} />
          <div className="form-actions">
            <span className="muted run-summary-hint">
              {selectedRepos.length} of {discoveredRepos.length} selected
            </span>
            <Button type="button" variant="ghost" onClick={() => setRepoPickerOpen(false)}>Close</Button>
            <Button
              type="button"
              variant="default"
              disabled={githubAction.pending || selectedRepos.length === 0 || selectedRepos.length > maxSyncBatch}
              onClick={() => {
                setGithubNotice('')
                void githubAction.submit(
                  () => syncGithubRepositories({ data: { projectId: project.id, repos: selectedRepos } }),
                  result => {
                    setRepoPickerOpen(false)
                    const warnText = result.warnings.length ? ` Warnings: ${result.warnings.join('; ')}` : ''
                    setGithubNotice(`Synced ${result.repos.length} ${result.repos.length === 1 ? 'repo' : 'repos'}: ${result.specsImported} specs imported, ${result.dependenciesExtracted} dependencies extracted.${warnText}`)
                  },
                )
              }}
            >
              {githubAction.pending ? 'Syncing…' : `Sync selected (${selectedRepos.length})`}
            </Button>
          </div>
        </div>
      })()}

      {specs.length > 0 ? <ul className="project-list">{specs.map(spec => <li key={spec.id}>
        <div className="list-row">
          <span>
            <span className="inline-badges">
              <strong>{spec.name}</strong>
              <span className="badge">{spec.kind}</span>
              {spec.origin && <span className="badge badge-trace">{safeHost(spec.origin)}</span>}
            </span>
            <small>{Math.max(1, Math.round(spec.bytes / 1024))} KiB · Imported {timeText(spec.createdAt)}</small>
          </span>
          <Button variant="ghost" className="btn-danger" disabled={specAction.pending} onClick={() => {
            void specAction.submit(() => removeProjectSpec({ data: {
              requestId: crypto.randomUUID(), projectId: project.id, specId: spec.id,
            } }), () => setSpecNotice(`Removed spec "${spec.name}".`))
          }}>Delete</Button>
        </div>
      </li>)}</ul> : <p className="muted" style={{ marginTop: 8 }}>No repositories or specs synced yet.</p>}

      <details className="advanced-schema-disclosure">
        <summary className="collapsible-trigger">
          Advanced: upload schemas or lockfiles manually
        </summary>
        <div className="advanced-schema-body">
          <p className="muted small-note">
            Guardian automatically discovers runtime schemas and extracts OpenAPI, GraphQL, and lockfile specs from synced repositories. Use manual upload only when you need to supply an extra schema or lockfile directly.
          </p>
          <form className="form-card" onSubmit={event => {
            event.preventDefault()
            const form = new FormData(event.currentTarget)
            const originVal = String(form.get('origin') ?? '').trim()
            const kindRaw = String(form.get('kind') ?? 'openapi')
            const kind = (['openapi', 'graphql', 'routes', 'notes'] as const).includes(kindRaw as 'openapi')
              ? kindRaw as 'openapi' | 'graphql' | 'routes' | 'notes' : 'notes'
            void specAction.submit(() => importSpec({ data: {
              requestId: crypto.randomUUID(),
              projectId: project.id,
              name: specName.trim() || String(form.get('name') ?? '').trim(),
              kind,
              ...(originVal ? { origin: originVal } : {}),
              content: specContent,
            } }), saved => {
              setSpecName('')
              setSpecContent('')
              setSpecNotice(`Imported spec "${saved.name}" (${saved.kind}).`)
            })
          }}>
            <h3>Upload OpenAPI, GraphQL, or lockfile</h3>
            <div className="field-grid-2">
              <label>Name
                <Input name="name" required maxLength={160} value={specName} onChange={e => setSpecName(e.target.value)}
                  placeholder="openapi.yaml or package-lock.json" />
              </label>
              <label>Kind
                <NativeSelect name="kind" defaultValue="openapi">
                  <option value="openapi">OpenAPI / Swagger</option>
                  <option value="graphql">GraphQL schema</option>
                  <option value="routes">Route map / Server handlers</option>
                  <option value="notes">Lockfile / Dependencies / Notes</option>
                </NativeSelect>
              </label>
            </div>
            <label>Target origin (optional)
              <Input name="origin" placeholder={project.seeds[0] ?? 'https://api.example.com'} />
            </label>
            <label>Load from file (optional, up to 2 MiB)
              <Input type="file" accept=".json,.yaml,.yml,.graphql,.gql,.txt,.md,.lock" onChange={e => {
                void onSpecFileSelected(e.target.files?.[0])
              }} />
            </label>
            <label>Content
              <Textarea name="content" rows={6} required value={specContent} onChange={e => setSpecContent(e.target.value)}
                placeholder="Paste OpenAPI, GraphQL SDL, lockfile JSON, or route notes…" />
            </label>
            <FormError error={specAction.error} />
            <div className="form-actions">
              <Button type="submit" variant="default" disabled={specAction.pending || !specContent.trim()}>Import spec</Button>
            </div>
          </form>
        </div>
      </details>
    </section>

    <section className="stacked-section" aria-label="Local lab runner">
      <div className="section-heading">
        <div>
          <h2>Local lab runner</h2>
          <p className="muted">
            Isolated multi-container Docker <code>--internal</code> target stack with optional persona seeding and opt-in IAST telemetry.
            {!labAllowed && ' Requires a Local Lab project and server-side GUARDIAN_ALLOW_LOCAL_LAB=1.'}
          </p>
        </div>
        <span className={`badge ${labAllowed ? (labEnabled ? 'badge-complete' : 'badge-trace') : ''}`}>
          {labAllowed ? (labEnabled ? 'Lab enabled' : 'Lab ready') : 'Disabled (fail-closed)'}
        </span>
      </div>
      {labNotice && <p role="status" className="muted">{labNotice}</p>}
      <form className="form-card" onSubmit={event => {
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
        }), () => {
          setLabNotice('Lab runner settings saved.')
        })
      }}>
        <label className="checkbox">
          <input
            type="checkbox"
            className="native-checkbox"
            checked={labEnabled}
            disabled={!labAllowed || labAction.pending}
            onChange={e => setLabEnabled(e.target.checked)}
          />
          Enable local lab
        </label>
        <div className="field-grid-2">
          <label>Docker Compose file
            <Input
              name="dockerComposeFile"
              value={labComposeFile}
              disabled={!labAllowed || labAction.pending}
              onChange={e => setLabComposeFile(e.target.value)}
              placeholder="docker-compose.lab.yml"
            />
          </label>
          <label>Seed command
            <Input
              name="seedCommand"
              value={labSeedCommand}
              disabled={!labAllowed || labAction.pending}
              onChange={e => setLabSeedCommand(e.target.value)}
              placeholder="node scripts/seed-personas.mjs"
            />
          </label>
        </div>
        <label>Services (JSON)
          <Textarea
            name="services"
            rows={3}
            value={labServicesJson}
            disabled={!labAllowed || labAction.pending}
            onChange={e => setLabServicesJson(e.target.value)}
            placeholder='[{"name":"app","internalPort":8080},{"name":"postgres"}]'
          />
        </label>
        <div className="field-grid-3">
          <label>Health path
            <Input
              name="healthPath"
              value={labHealthPath}
              disabled={!labAllowed || labAction.pending}
              onChange={e => setLabHealthPath(e.target.value)}
              placeholder="/health"
            />
          </label>
          <label>Internal port
            <Input
              name="internalPort"
              type="number"
              min={1}
              max={65535}
              value={labInternalPort}
              disabled={!labAllowed || labAction.pending}
              onChange={e => setLabInternalPort(e.target.value)}
            />
          </label>
          <label>Target runtime
            <NativeSelect
              name="iastRuntime"
              value={labIastRuntime}
              disabled={!labAllowed || labAction.pending}
              onChange={e => setLabIastRuntime(e.target.value as IastRuntime)}
            >
              {iastRuntimes.map(rt => <option key={rt} value={rt}>{rt}</option>)}
            </NativeSelect>
          </label>
        </div>
        <label className="checkbox">
          <input
            type="checkbox"
            className="native-checkbox"
            checked={labIastEnabled}
            disabled={!labAllowed || labAction.pending}
            onChange={e => setLabIastEnabled(e.target.checked)}
          />
          Enable IAST telemetry (redacted local-lab sink &amp; coverage side-channel)
        </label>
        <FormError error={labAction.error} />
        <div className="form-actions">
          <Button type="submit" variant="default" disabled={!labAllowed || labAction.pending}>
            Save lab settings
          </Button>
        </div>
      </form>
    </section>

    <section className="stacked-section" aria-label="Sandbox write allowlist">
      <div className="section-heading">
        <div>
          <h2>Tier-2 sandbox write allowlist</h2>
          <p className="muted">Explicitly allow non-destructive Tier-2 POST probes on approved staging or test-account endpoints. Defaults to empty on public projects.</p>
        </div>
        <span className="badge">{(project.sandboxWriteAllowlist ?? []).length} rules</span>
      </div>
      {allowNotice && <p role="status" className="muted">{allowNotice}</p>}
      <form className="form-card" onSubmit={event => {
        event.preventDefault()
        setAllowNotice('')
        const nextEntry = {
          origin: allowOrigin.trim(),
          method: allowMethod.trim().toUpperCase(),
          pathPattern: allowPath.trim(),
        }
        const existing = project.sandboxWriteAllowlist ?? []
        const updated = [...existing, nextEntry]
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
      }}>
        <div className="field-grid-3">
          <label>Allowlist origin
            <Input
              name="allowOrigin"
              required
              value={allowOrigin}
              onChange={e => setAllowOrigin(e.target.value)}
              placeholder={project.seeds[0] ?? 'https://example.com'}
            />
          </label>
          <label>Allowlist method
            <NativeSelect name="allowMethod" value={allowMethod} onChange={e => setAllowMethod(e.target.value)}>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="PATCH">PATCH</option>
              <option value="GET">GET</option>
            </NativeSelect>
          </label>
          <label>Path pattern
            <Input
              name="allowPathPattern"
              required
              value={allowPath}
              onChange={e => setAllowPath(e.target.value)}
              placeholder="/api/search"
            />
          </label>
        </div>
        <FormError error={allowlistAction.error} />
        <div className="form-actions">
          <Button type="submit" variant="default" disabled={allowlistAction.pending || !allowOrigin.trim() || !allowPath.trim()}>
            Add allowlist rule
          </Button>
        </div>
      </form>
      {(project.sandboxWriteAllowlist ?? []).length > 0 ? <ul className="project-list">
        {(project.sandboxWriteAllowlist ?? []).map((rule, idx) => <li key={`${rule.origin}:${rule.method}:${rule.pathPattern}:${idx}`}>
          <div className="list-row">
            <span className="inline-badges">
              <span className="badge badge-trace">{rule.method}</span>
              <strong className="mono">{rule.origin}</strong>
              <code className="mono">{rule.pathPattern}</code>
            </span>
            <Button variant="ghost" className="btn-danger" disabled={allowlistAction.pending} onClick={() => {
              const updated = (project.sandboxWriteAllowlist ?? []).filter((_, i) => i !== idx)
              void allowlistAction.submit(() => updateProjectSandboxAllowlistAction({
                data: {
                  requestId: crypto.randomUUID(),
                  projectId: project.id,
                  sandboxWriteAllowlist: updated,
                },
              }), () => setAllowNotice('Removed allowlist rule.'))
            }}>Remove</Button>
          </div>
        </li>)}
      </ul> : <p className="muted" style={{ marginTop: 8 }}>No sandbox write allowlist rules configured (default fail-closed empty list).</p>}
    </section>
  </main>
}
