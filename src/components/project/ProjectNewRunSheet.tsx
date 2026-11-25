import { useNavigate } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import { createRun, registerPersona } from '../../actions.ts'
import type {
  ApprovalPolicy,
  CapabilityTier,
  PersonaAuthKind,
  PersonaLoginAdapter,
  PublicPersona,
} from '../../domain.ts'
import {
  approvalPolicies,
  defaultBudgetRequests,
  defaultBudgetUsd,
  defaultMaxRpsPerOrigin,
  defaultWorkerConcurrency,
  defaultWorkerMaxTurns,
  maxBudgetRequests,
  maxRpsPerOriginCeiling,
  maxWorkerConcurrency,
  maxWorkerMaxTurns,
} from '../../domain.ts'
import { FormError, useAction } from '../common.tsx'
import { parseCurlOrHeader } from '../curl-parser.ts'
import { approvalPolicyMeta, capabilityTierMeta } from '../run-state.ts'
import { Checkbox } from '../ui/checkbox.tsx'
import type { MissionPreset, PersonaTestState, ProjectLoaderData } from './types.ts'
import {
  formatPersonaAuthBadge,
  LOGIN_URL_PLACEHOLDERS,
  MISSION_PRESETS,
} from './types.ts'

interface Props {
  open: boolean
  onClose: () => void
  data: ProjectLoaderData
  selectedPersonaIds: string[]
  setSelectedPersonaIds: React.Dispatch<React.SetStateAction<string[]>>
  personaTests: Record<string, PersonaTestState>
  onTestPersona: (persona: PublicPersona) => void
}

export function ProjectNewRunSheet({
  open,
  onClose,
  data,
  selectedPersonaIds,
  setSelectedPersonaIds,
  personaTests,
  onTestPersona,
}: Props) {
  const { project, personas } = data
  const navigate = useNavigate()
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

  // Quick-add persona inside Tier >= 2 runs
  const [inlinePersonaOpen, setInlinePersonaOpen] = useState(false)
  const [authKind, setAuthKind] = useState<PersonaAuthKind>('login')
  const [loginAdapter, setLoginAdapter] = useState<PersonaLoginAdapter>('auto')
  const [loginEmail, setLoginEmail] = useState('')
  const [loginUrl, setLoginUrl] = useState('')
  const [personaHandle, setPersonaHandle] = useState('')
  const [personaRole, setPersonaRole] = useState('')
  const [personaHeaderName, setPersonaHeaderName] = useState('')
  const [personaOrigins, setPersonaOrigins] = useState(() => project.seeds.join('\n'))
  const [personaSecret, setPersonaSecret] = useState('')
  const [curlPaste, setCurlPaste] = useState('')
  const [curlNote, setCurlNote] = useState('')

  const runAction = useAction()
  const personaAction = useAction()

  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!open) return null

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

  function prefillPair(which: 'user_a' | 'user_b') {
    setPersonaHandle(which)
    setPersonaRole(which === 'user_a' ? 'User A (Control / Owner)' : 'User B (Cross-User Probe)')
    setAuthKind('login')
    setLoginAdapter('auto')
    setPersonaOrigins(project.seeds.join('\n'))
    setPersonaSecret('')
    setCurlNote('')
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

  function saveInlinePersona() {
    const allowlist = personaOrigins.split(/[\s,]+/).filter(Boolean)
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
      canaryMarkers: [],
    } }), created => {
      setPersonaHandle('')
      setPersonaRole('')
      setLoginEmail('')
      setLoginUrl('')
      setPersonaSecret('')
      setCurlPaste('')
      setCurlNote('')
      setInlinePersonaOpen(false)
      setSelectedPersonaIds(prev => prev.includes(created.id) ? prev : [...prev, created.id])
    })
  }

  return <div
    className="pw-overlay"
    role="dialog"
    aria-modal="true"
    aria-label="Start a run"
    onMouseDown={e => { if (e.target === e.currentTarget) onClose() }}
  >
    <form
      className="pw-modal"
      onSubmit={event => {
        event.preventDefault()
        const sourceMode = tier === 0 ? 'prepared' as const : 'public' as const
        const effectiveReqs = tier === 0 || unlimitedReqs ? 0 : Math.max(0, Math.min(maxBudgetRequests, Math.round(budgetReqs)))
        void runAction.submit(() => createRun({ data: {
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
        } }), async result => {
          onClose()
          await navigate({ to: '/runs/$runId', params: { runId: result.id } })
        })
      }}
    >
      <div className="pw-sheet-h">
        <span>Start a run · {project.name}</span>
        <button type="button" className="pw-btn ghost" onClick={onClose}>Close</button>
      </div>

      <div className="pw-sheet-b">
        <div>
          <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--pw-fg-2)', marginBottom: 6 }}>
            Mission preset <span className="muted">(1-click prefill)</span>
          </div>
          <div className="pw-opt-grid" role="group" aria-label="Mission presets">
            {MISSION_PRESETS.map(preset => (
              <button
                key={preset.id}
                type="button"
                className={`pw-opt${selectedPreset === preset.id ? ' on' : ''}`}
                onClick={() => applyPreset(preset)}
              >
                <span className="pw-opt-top">
                  <span className={`pw-tag ${preset.tier === 3 ? 'warn' : preset.tier === 2 ? 'accent' : 'solid'}`}>
                    {preset.tierLabel}
                  </span>
                  <span className="mono muted num" style={{ fontSize: 11 }}>${preset.usdCap}</span>
                </span>
                <b>{preset.name}</b>
                <small>{preset.summary}</small>
              </button>
            ))}
          </div>
        </div>

        <label className="pw-fld">Run goal
          <textarea
            className="pw-textarea"
            name="goal"
            rows={3}
            maxLength={8000}
            required
            value={goal}
            onChange={e => setGoal(e.target.value)}
            placeholder="Assess authentication, API authorization, client-side exposure, and reachable CVEs across approved hosts."
          />
        </label>

        <div className="pw-grid-2">
          <label className="pw-fld">Capability tier
            <select
              className="pw-select"
              name="capabilityTier"
              value={tier}
              onChange={e => setTier(Number(e.target.value) as CapabilityTier)}
            >
              <option value={0}>{capabilityTierMeta[0].name}</option>
              <option value={1}>{capabilityTierMeta[1].name}</option>
              <option value={2}>{capabilityTierMeta[2].name}</option>
              <option value={3}>{capabilityTierMeta[3].name}</option>
            </select>
            <small>{capabilityTierMeta[tier].summary}</small>
          </label>
          <label className="pw-fld">USD Spend Cap
            <input
              className="pw-in num"
              name="budgetUsd"
              type="number"
              min={0.1}
              max={500}
              step="any"
              required
              value={budgetUsd}
              onChange={e => setBudgetUsd(Number(e.target.value))}
            />
            <small>Hard stop when spend reaches cap.</small>
          </label>
        </div>

        {tier === 3 && <div className="pw-sheet" role="radiogroup" aria-label="Tier 3 Approval Policy">
          <div className="pw-sheet-h">
            <span>Tier 3 Approval Policy</span>
            <span className="muted" style={{ fontWeight: 400, fontSize: 12 }}>Switchable live mid-run</span>
          </div>
          <div className="pw-sheet-b">
            <div className="pw-opt-grid">
              {approvalPolicies.map(policy => {
                const meta = approvalPolicyMeta[policy]
                const active = approvalPolicy === policy
                return <button
                  key={policy}
                  type="button"
                  role="radio"
                  aria-checked={active}
                  className={`pw-opt${active ? ' on' : ''}`}
                  onClick={() => setApprovalPolicy(policy)}
                >
                  <span className="pw-opt-top">
                    <b>{meta.optionLabel}</b>
                    {policy === 'yolo' && <span className="pw-tag warn">Autonomous</span>}
                    {policy === 'auto_review' && <span className="pw-tag ok">Default</span>}
                    {policy === 'strict' && <span className="pw-tag solid">Manual</span>}
                  </span>
                  <small>{meta.summary}</small>
                </button>
              })}
            </div>
          </div>
        </div>}

        {tier >= 2 && <div className="pw-sheet">
          <div className="pw-sheet-h">
            <span>Authenticated Personas (User A / User B)</span>
            <button type="button" className="pw-btn ghost" onClick={() => setInlinePersonaOpen(v => !v)}>
              {inlinePersonaOpen ? 'Hide quick add' : '+ Quick add persona'}
            </button>
          </div>
          <div className="pw-sheet-b">
            {personas.length > 0 ? (
              <div className="pw-table-wrap">
                {personas.map(persona => {
                  const test = personaTests[persona.id]
                  return <div key={persona.id} className="pw-row">
                    <label className="pw-chk">
                      <Checkbox
                        checked={selectedPersonaIds.includes(persona.id)}
                        aria-label={`Select persona ${persona.handle} for run`}
                        onCheckedChange={checked => setSelectedPersonaIds(prev =>
                          checked ? (prev.includes(persona.id) ? prev : [...prev, persona.id]) : prev.filter(id => id !== persona.id),
                        )}
                      />
                      <span className="pw-row-title">
                        <strong className="mono">{persona.handle}</strong>
                        <span className="pw-tag accent">{persona.roleLabel}</span>
                        <span className="pw-tag solid">{formatPersonaAuthBadge(persona)}</span>
                      </span>
                    </label>
                    <div className="pw-row-right">
                      {test && (
                        <span className={`pw-tag ${test.status === 'ok' ? 'ok' : test.status === 'warn' ? 'warn' : test.status === 'error' ? 'bad' : 'solid'}`}>
                          {test.message}
                        </span>
                      )}
                      <button type="button" className="pw-btn ghost" disabled={test?.status === 'testing'} onClick={() => onTestPersona(persona)}>
                        {test?.status === 'testing' ? 'Testing…' : test?.status === 'ok' ? 'Test Auth ✓' : 'Test Auth'}
                      </button>
                    </div>
                  </div>
                })}
              </div>
            ) : (
              <p className="muted" style={{ margin: 0, fontSize: 12 }}>
                No personas saved yet. Quick-add User A &amp; User B below for cross-user BOLA/IDOR checks.
              </p>
            )}

            {inlinePersonaOpen && <div style={{ borderTop: '1px solid var(--pw-line)', paddingTop: 10, display: 'grid', gap: 10 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                <strong style={{ fontSize: 12.5 }}>Quick-add vault persona</strong>
                <div className="pw-sec-actions">
                  <button type="button" className="pw-btn ghost" onClick={() => prefillPair('user_a')}>Preset User A</button>
                  <button type="button" className="pw-btn ghost" onClick={() => prefillPair('user_b')}>Preset User B</button>
                </div>
              </div>
              {authKind !== 'login' && <div style={{ display: 'grid', gap: 4 }}>
                <div style={{ display: 'flex', gap: 6 }}>
                  <input
                    className="pw-in mono"
                    value={curlPaste}
                    onChange={e => setCurlPaste(e.target.value)}
                    onPaste={e => {
                      const pasted = e.clipboardData.getData('text')
                      if (pasted) { e.preventDefault(); applyCurlParse(pasted) }
                    }}
                    placeholder="Paste cURL or Cookie:/Authorization: header"
                  />
                  <button type="button" className="pw-btn" onClick={() => applyCurlParse(curlPaste)} disabled={!curlPaste.trim()}>Parse cURL</button>
                </div>
                {curlNote && <span className="muted" style={{ fontSize: 11.5 }}>{curlNote}</span>}
              </div>}
              <div className="pw-grid-2">
                <label className="pw-fld">Handle
                  <input className="pw-in mono" value={personaHandle} onChange={e => setPersonaHandle(e.target.value)} placeholder="user_a" />
                </label>
                <label className="pw-fld">Role label
                  <input className="pw-in" value={personaRole} onChange={e => setPersonaRole(e.target.value)} placeholder="Standard user" />
                </label>
              </div>
              <label className="pw-fld">Auth kind
                <select className="pw-select" value={authKind} onChange={e => setAuthKind(e.target.value as PersonaAuthKind)}>
                  <option value="login">Email + Password (auto-login &amp; refresh)</option>
                  <option value="cookie">Session cookie (Cookie: …)</option>
                  <option value="bearer">Bearer token (Authorization: Bearer …)</option>
                  <option value="header">Custom request header</option>
                </select>
              </label>
              {authKind === 'login' ? <>
                <div className="pw-grid-2">
                  <label className="pw-fld">Email
                    <input className="pw-in" type="email" value={loginEmail} onChange={e => setLoginEmail(e.target.value)} placeholder="guardian-a@example.com" autoComplete="off" />
                  </label>
                  <label className="pw-fld">Password
                    <input className="pw-in" type="password" value={personaSecret} onChange={e => setPersonaSecret(e.target.value)} placeholder="Stored in local 0600 vault" autoComplete="off" />
                  </label>
                </div>
                <div className="pw-grid-2">
                  <label className="pw-fld">Auth method
                    <select className="pw-select" value={loginAdapter} onChange={e => setLoginAdapter(e.target.value as PersonaLoginAdapter)}>
                      <option value="auto">Auto-detect</option>
                      <option value="clerk">Clerk (auto-refresh 60s JWT)</option>
                      <option value="json">JSON API / Better Auth</option>
                      <option value="supabase">Supabase Auth</option>
                      <option value="form">Login Form (Browser)</option>
                    </select>
                  </label>
                  <label className="pw-fld">Login URL (optional)
                    <input className="pw-in" type="url" value={loginUrl} onChange={e => setLoginUrl(e.target.value)} placeholder={LOGIN_URL_PLACEHOLDERS[loginAdapter]} autoComplete="off" />
                  </label>
                </div>
              </> : <div className="pw-grid-2">
                {authKind === 'header' && <label className="pw-fld">Header name
                  <input className="pw-in mono" value={personaHeaderName} onChange={e => setPersonaHeaderName(e.target.value)} placeholder="X-Api-Key" />
                </label>}
                <label className="pw-fld">Secret (masked)
                  <input className="pw-in" type="password" value={personaSecret} onChange={e => setPersonaSecret(e.target.value)} autoComplete="off" placeholder="Never echoed after save" />
                </label>
              </div>}
              <FormError error={personaAction.error} />
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6 }}>
                <button type="button" className="pw-btn ghost" onClick={() => setInlinePersonaOpen(false)}>Close</button>
                <button
                  type="button"
                  className="pw-btn primary"
                  disabled={
                    personaAction.pending ||
                    !personaHandle.trim() ||
                    !personaRole.trim() ||
                    !personaSecret ||
                    (authKind === 'login' ? !loginEmail.trim() : !personaSecret.trim())
                  }
                  onClick={saveInlinePersona}
                >
                  Save to vault &amp; select
                </button>
              </div>
            </div>}
          </div>
        </div>}

        <details className="pw-disclosure" style={{ marginTop: 2 }}>
          <summary>
            Advanced execution controls <span className="muted num">({maxRps} rps · {unlimitedReqs || tier === 0 ? '∞ reqs' : `${budgetReqs} reqs`} · {concurrency} workers · {maxTurns} turns)</span>
          </summary>
          <div className="pw-disclosure-body">
            <label className="pw-chk">
              <Checkbox
                checked={unlimitedReqs}
                aria-label="Unlimited max requests"
                onCheckedChange={checked => setUnlimitedReqs(Boolean(checked))}
              />
              <span>Unlimited max requests (<code>∞</code>, recommended)</span>
            </label>
            <div className="pw-grid-3">
              <label className="pw-fld">Rate Limit (RPS / origin)
                <input className="pw-in num" name="maxRpsPerOrigin" type="number" min={1} max={maxRpsPerOriginCeiling} step={1} required
                  value={maxRps} onChange={e => setMaxRps(Number(e.target.value))} />
              </label>
              <label className="pw-fld">Worker concurrency
                <input className="pw-in num" name="workerConcurrency" type="number" min={1} max={maxWorkerConcurrency} step={1} required
                  value={concurrency} onChange={e => setConcurrency(Number(e.target.value))} />
              </label>
              <label className="pw-fld">Worker max turns
                <input className="pw-in num" name="workerMaxTurns" type="number" min={1} max={maxWorkerMaxTurns} step={1} required
                  value={maxTurns} onChange={e => setMaxTurns(Number(e.target.value))} />
              </label>
            </div>
            {!unlimitedReqs && <label className="pw-fld">Max brokered requests
              <input className="pw-in num" name="budgetRequests" type="number" min={1} max={maxBudgetRequests} step={1}
                value={budgetReqs} onChange={e => setBudgetReqs(Number(e.target.value))} />
            </label>}
          </div>
        </details>

        <FormError error={runAction.error} />
      </div>

      <div className="pw-sheet-f">
        <span className="hint mono num">
          {capabilityTierMeta[tier].short} · ${budgetUsd} cap · {maxRps} rps · {unlimitedReqs || tier === 0 ? '∞ reqs' : `${budgetReqs} reqs`}
        </span>
        <button type="button" className="pw-btn ghost" onClick={onClose}>Cancel</button>
        <button type="submit" className="pw-btn primary" disabled={runAction.pending}>
          {runAction.pending ? 'Creating…' : 'Create run'}
        </button>
      </div>
    </form>
  </div>
}
