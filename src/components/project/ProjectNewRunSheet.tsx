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
  maxBudgetRequests,
  maxRpsPerOriginCeiling,
  maxWorkerConcurrency,
  maxWorkerMaxTurns,
} from '../../domain.ts'
import { FormError, useAction } from '../common.tsx'
import { parseCurlOrHeader } from '../curl-parser.ts'
import { approvalPolicyMeta, capabilityTierMeta } from '../run-state.ts'
import { Checkbox } from '../ui/checkbox.tsx'
import type { PersonaTestState, ProjectLoaderData } from './types.ts'
import { formatPersonaAuthBadge, LOGIN_URL_PLACEHOLDERS } from './types.ts'

interface Props {
  open: boolean
  onClose: () => void
  data: ProjectLoaderData
  selectedPersonaIds: string[]
  setSelectedPersonaIds: React.Dispatch<React.SetStateAction<string[]>>
  personaTests: Record<string, PersonaTestState>
  onTestPersona: (persona: PublicPersona) => void
}

type ModeKey = 'tier1' | 'tier2' | 'tier3'

interface ModePreset {
  key: ModeKey
  tier: CapabilityTier
  usdCap: number
  rps: number
  concurrency: number
  maxTurns: number
  goal: string
  label: string
  badge: string
  desc: string
  badgeTone: 'solid' | 'accent' | 'warn'
}

const MODES: Record<ModeKey, ModePreset> = {
  tier1: {
    key: 'tier1',
    tier: 1,
    usdCap: 10,
    rps: 3,
    concurrency: 4,
    maxTurns: 40,
    goal: 'Enumerate public attack surfaces, map API routes and JS bundles, and verify read-only exposures without state-changing requests.',
    label: 'Safe Audit',
    badge: 'Read-only',
    desc: 'Surface map & passive checks. Zero writes.',
    badgeTone: 'solid',
  },
  tier2: {
    key: 'tier2',
    tier: 2,
    usdCap: 25,
    rps: 5,
    concurrency: 6,
    maxTurns: 150,
    goal: 'Verify authentication, cross-user BOLA/IDOR authorization boundaries, and business logic across approved hosts using paired personas.',
    label: 'Core Pentest',
    badge: 'Recommended',
    desc: 'Auth, BOLA & logic tests with personas.',
    badgeTone: 'accent',
  },
  tier3: {
    key: 'tier3',
    tier: 3,
    usdCap: 30,
    rps: 3,
    concurrency: 4,
    maxTurns: 120,
    goal: 'Validate high-impact state transitions, race conditions, and active proofs with human-in-the-loop approval gates.',
    label: 'Active Pentest',
    badge: 'Approval-gated',
    desc: 'Full active proofs with human approval.',
    badgeTone: 'warn',
  },
}

const BUDGET_CHIPS = [10, 25, 50] as const

function RadarAuditSvg() {
  return (
    <svg className="pw-vcard-art" viewBox="0 0 64 40" fill="none" aria-hidden="true">
      <rect x="1.5" y="1.5" width="61" height="37" rx="7" fill="var(--pw-sunk)" stroke="var(--pw-line-2)" strokeWidth="1.2" />
      <circle cx="32" cy="20" r="12.5" stroke="var(--pw-line-strong)" strokeWidth="1.2" />
      <circle cx="32" cy="20" r="7" stroke="var(--pw-line-strong)" strokeWidth="1.2" strokeDasharray="2.5 2.5" />
      <path d="M32 20L41 12" stroke="var(--pw-accent)" strokeWidth="1.6" strokeLinecap="round" />
      <circle cx="32" cy="20" r="2.25" fill="var(--pw-panel)" stroke="currentColor" strokeWidth="1.4" />
      <circle cx="41" cy="12" r="2.6" fill="var(--pw-accent)" />
      <circle cx="24" cy="25" r="1.9" fill="var(--pw-fg-3)" />
    </svg>
  )
}

function CorePentestSvg() {
  return (
    <svg className="pw-vcard-art" viewBox="0 0 64 40" fill="none" aria-hidden="true">
      <rect x="1.5" y="1.5" width="61" height="37" rx="7" fill="var(--pw-sunk)" stroke="var(--pw-line-2)" strokeWidth="1.2" />
      <circle cx="15" cy="14" r="3" fill="var(--pw-panel)" stroke="currentColor" strokeWidth="1.4" />
      <circle cx="15" cy="26" r="3" fill="var(--pw-accent)" />
      <path d="M18.5 14h10c3 0 4 6 7.5 6h5.5" stroke="var(--pw-fg-3)" strokeWidth="1.3" strokeLinecap="round" />
      <path d="M18.5 26h10c3 0 4-6 7.5-6h5.5" stroke="var(--pw-accent)" strokeWidth="1.6" strokeLinecap="round" />
      <path d="M47 10.5 53 13v5.2c0 3.7-2.4 6.5-6 7.8-3.6-1.3-6-4.1-6-7.8V13l6-2.5Z" fill="var(--pw-panel)" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
      <path d="M44.6 18.2 46.3 20l3.3-3.5" stroke="var(--pw-accent)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function ActiveGateSvg() {
  return (
    <svg className="pw-vcard-art" viewBox="0 0 64 40" fill="none" aria-hidden="true">
      <rect x="1.5" y="1.5" width="61" height="37" rx="7" fill="var(--pw-sunk)" stroke="var(--pw-line-2)" strokeWidth="1.2" />
      <path d="M10 20h14M40 20h14" stroke="var(--pw-line-strong)" strokeWidth="1.4" strokeLinecap="round" />
      <path d="M14 14l4 6-4 6" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
      <rect x="24.5" y="11" width="15" height="18" rx="4" fill="var(--pw-panel)" stroke="var(--pw-accent)" strokeWidth="1.5" />
      <path d="M29 20.2 31.2 22.4 35.4 17.8" stroke="var(--pw-accent)" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M49 16l4.5 4-4.5 4" stroke="var(--pw-accent)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function ModeIllustration({ mode }: { mode: ModeKey }) {
  if (mode === 'tier1') return <RadarAuditSvg />
  if (mode === 'tier2') return <CorePentestSvg />
  return <ActiveGateSvg />
}

export function ProjectNewRunSheet({
  open,
  onClose,
  data,
  selectedPersonaIds,
  setSelectedPersonaIds,
  personaTests,
}: Props) {
  const { project, personas } = data
  const navigate = useNavigate()

  const [mode, setMode] = useState<ModeKey>('tier2')
  const [goal, setGoal] = useState('')
  const [tier, setTier] = useState<CapabilityTier>(2)
  const [approvalPolicy, setApprovalPolicy] = useState<ApprovalPolicy>('auto_review')
  const [budgetUsd, setBudgetUsd] = useState<number>(MODES.tier2.usdCap)
  const [maxRps, setMaxRps] = useState<number>(MODES.tier2.rps)
  const [unlimitedReqs, setUnlimitedReqs] = useState<boolean>(defaultBudgetRequests === 0)
  const [budgetReqs, setBudgetReqs] = useState<number>(defaultBudgetRequests === 0 ? 2500 : defaultBudgetRequests)
  const [concurrency, setConcurrency] = useState<number>(MODES.tier2.concurrency)
  const [maxTurns, setMaxTurns] = useState<number>(MODES.tier2.maxTurns)

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

  function applyMode(next: ModeKey) {
    const preset = MODES[next]
    setMode(next)
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

  function togglePersona(id: string) {
    setSelectedPersonaIds(prev => (prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]))
  }

  function prefillPair(which: 'user_a' | 'user_b') {
    setPersonaHandle(which)
    setPersonaRole(which === 'user_a' ? 'User A (Owner)' : 'User B (Cross-User)')
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

  function handleSubmit(event: React.FormEvent) {
    event.preventDefault()
    const effectiveGoal = goal.trim() || MODES[mode].goal
    const sourceMode = tier === 0 ? 'prepared' as const : 'public' as const
    const effectiveReqs = tier === 0 || unlimitedReqs ? 0 : Math.max(0, Math.min(maxBudgetRequests, Math.round(budgetReqs)))
    void runAction.submit(() => createRun({ data: {
      requestId: crypto.randomUUID(),
      projectId: project.id,
      goal: effectiveGoal,
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
  }

  const footerSummary = [
    capabilityTierMeta[tier].short,
    `$${budgetUsd} cap`,
    ...(tier >= 2 ? [`${selectedPersonaIds.length} ${selectedPersonaIds.length === 1 ? 'persona' : 'personas'}`] : []),
  ].join(' · ')

  return (
    <div
      className="pw-overlay"
      role="dialog"
      aria-modal="true"
      aria-label="Start a run"
      onMouseDown={e => { if (e.target === e.currentTarget) onClose() }}
    >
      <form className="pw-modal" onSubmit={handleSubmit}>
        <div className="pw-modal-hdr">
          <span>New run · {project.name}</span>
          <button type="button" className="pw-btn ghost" onClick={onClose} aria-label="Close">✕</button>
        </div>

        <div className="pw-modal-body">
          <div className="pw-vcard-grid-3" role="radiogroup" aria-label="Assessment mode">
            {(['tier1', 'tier2', 'tier3'] as const).map(k => {
              const m = MODES[k]
              const active = mode === k
              return (
                <button
                  key={k}
                  type="button"
                  role="radio"
                  aria-checked={active}
                  className={`pw-vcard${active ? ' on' : ''}`}
                  onClick={() => applyMode(k)}
                >
                  <div className="pw-vcard-top">
                    <ModeIllustration mode={k} />
                    <span className={`pw-tag ${m.badgeTone}`}>{m.badge}</span>
                  </div>
                  <div className="pw-vcard-copy">
                    <strong>{m.label}</strong>
                    <span>{m.desc}</span>
                  </div>
                </button>
              )
            })}
          </div>

          {tier >= 2 && (
            <div className="pw-section-box">
              <div className="pw-section-box-h">
                <span className="pw-section-label">
                  Personas
                  <span className="pw-tag solid num">{selectedPersonaIds.length}/{personas.length}</span>
                </span>
                <button type="button" className="pw-btn ghost" onClick={() => setInlinePersonaOpen(v => !v)}>
                  {inlinePersonaOpen ? 'Hide form' : '+ Quick add'}
                </button>
              </div>
              {personas.length > 0 ? (
                <div className="pw-pill-wrap" role="group" aria-label="Select personas for run">
                  {personas.map(persona => {
                    const selected = selectedPersonaIds.includes(persona.id)
                    const test = personaTests[persona.id]
                    return (
                      <button
                        key={persona.id}
                        type="button"
                        aria-pressed={selected}
                        className={`pw-persona-pill${selected ? ' on' : ''}`}
                        onClick={() => togglePersona(persona.id)}
                        title={`${persona.handle} · ${persona.roleLabel} (${formatPersonaAuthBadge(persona)})${test ? ` — ${test.message}` : ''}`}
                      >
                        <span className="pcheck" aria-hidden="true">✓</span>
                        <span className="mono">{persona.handle}</span>
                        <span className="muted" style={{ fontWeight: 400 }}>{persona.roleLabel}</span>
                      </button>
                    )
                  })}
                </div>
              ) : (
                <span className="muted" style={{ fontSize: 12 }}>
                  No personas configured yet — add User A &amp; User B to test cross-user isolation.
                </span>
              )}

              {inlinePersonaOpen && (
                <div style={{ borderTop: '1px solid var(--pw-line)', paddingTop: 10, display: 'grid', gap: 9 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                    <strong style={{ fontSize: 12 }}>Quick-add persona</strong>
                    <div className="pw-sec-actions">
                      <button type="button" className="pw-btn ghost" onClick={() => prefillPair('user_a')}>Preset User A</button>
                      <button type="button" className="pw-btn ghost" onClick={() => prefillPair('user_b')}>Preset User B</button>
                    </div>
                  </div>
                  {authKind !== 'login' && (
                    <div style={{ display: 'grid', gap: 4 }}>
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
                        <button type="button" className="pw-btn" onClick={() => applyCurlParse(curlPaste)} disabled={!curlPaste.trim()}>Parse</button>
                      </div>
                      {curlNote && <span className="muted" style={{ fontSize: 11.5 }}>{curlNote}</span>}
                    </div>
                  )}
                  <div className="pw-grid-2">
                    <label className="pw-fld">Handle
                      <input className="pw-in mono" value={personaHandle} onChange={e => setPersonaHandle(e.target.value)} placeholder="user_a" />
                    </label>
                    <label className="pw-fld">Role
                      <input className="pw-in" value={personaRole} onChange={e => setPersonaRole(e.target.value)} placeholder="Standard user" />
                    </label>
                  </div>
                  <label className="pw-fld">Auth kind
                    <select className="pw-select" value={authKind} onChange={e => setAuthKind(e.target.value as PersonaAuthKind)}>
                      <option value="login">Email + Password (auto-login &amp; refresh)</option>
                      <option value="cookie">Session cookie</option>
                      <option value="bearer">Bearer token</option>
                      <option value="header">Custom header</option>
                    </select>
                  </label>
                  {authKind === 'login' ? (
                    <>
                      <div className="pw-grid-2">
                        <label className="pw-fld">Email
                          <input className="pw-in" type="email" value={loginEmail} onChange={e => setLoginEmail(e.target.value)} placeholder="guardian-a@example.com" autoComplete="off" />
                        </label>
                        <label className="pw-fld">Password
                          <input className="pw-in" type="password" value={personaSecret} onChange={e => setPersonaSecret(e.target.value)} placeholder="Stored in 0600 vault" autoComplete="off" />
                        </label>
                      </div>
                      <div className="pw-grid-2">
                        <label className="pw-fld">Auth method
                          <select className="pw-select" value={loginAdapter} onChange={e => setLoginAdapter(e.target.value as PersonaLoginAdapter)}>
                            <option value="auto">Auto-detect</option>
                            <option value="clerk">Clerk (auto-refresh)</option>
                            <option value="json">JSON API / Better Auth</option>
                            <option value="supabase">Supabase Auth</option>
                            <option value="form">Login Form (Browser)</option>
                          </select>
                        </label>
                        <label className="pw-fld">Login URL (optional)
                          <input className="pw-in" type="url" value={loginUrl} onChange={e => setLoginUrl(e.target.value)} placeholder={LOGIN_URL_PLACEHOLDERS[loginAdapter]} autoComplete="off" />
                        </label>
                      </div>
                    </>
                  ) : (
                    <div className="pw-grid-2">
                      {authKind === 'header' && (
                        <label className="pw-fld">Header name
                          <input className="pw-in mono" value={personaHeaderName} onChange={e => setPersonaHeaderName(e.target.value)} placeholder="X-Api-Key" />
                        </label>
                      )}
                      <label className="pw-fld">Secret (masked)
                        <input className="pw-in" type="password" value={personaSecret} onChange={e => setPersonaSecret(e.target.value)} autoComplete="off" placeholder="Never echoed after save" />
                      </label>
                    </div>
                  )}
                  <FormError error={personaAction.error} />
                  <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6 }}>
                    <button type="button" className="pw-btn ghost" onClick={() => setInlinePersonaOpen(false)}>Cancel</button>
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
                      Save &amp; select
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {tier === 3 && (
            <div className="pw-section-box" role="radiogroup" aria-label="Tier 3 Approval Policy">
              <div className="pw-section-box-h">
                <span className="pw-section-label">Approval policy</span>
                <span className="muted" style={{ fontSize: 11.5 }}>Switchable mid-run</span>
              </div>
              <div className="pw-policy-grid">
                {approvalPolicies.map(policy => {
                  const meta = approvalPolicyMeta[policy]
                  const active = approvalPolicy === policy
                  return (
                    <button
                      key={policy}
                      type="button"
                      role="radio"
                      aria-checked={active}
                      className={`pw-opt${active ? ' on' : ''}`}
                      onClick={() => setApprovalPolicy(policy)}
                    >
                      <span className="pw-opt-top">
                        <b>{meta.short}</b>
                        {policy === 'auto_review' && <span className="pw-tag ok">Default</span>}
                        {policy === 'strict' && <span className="pw-tag solid">Manual</span>}
                        {policy === 'yolo' && <span className="pw-tag warn">Auto</span>}
                      </span>
                      <small>{meta.optionLabel}</small>
                    </button>
                  )
                })}
              </div>
            </div>
          )}

          <div className="pw-budget-row">
            <div>
              <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--pw-fg)' }}>Budget cap</div>
              <div className="muted" style={{ fontSize: 11.5 }}>Hard stop when spend reaches limit</div>
            </div>
            <div className="pw-budget-ctrl">
              {BUDGET_CHIPS.map(v => (
                <button
                  key={v}
                  type="button"
                  className={`pw-chip num${budgetUsd === v ? ' on' : ''}`}
                  onClick={() => setBudgetUsd(v)}
                >
                  ${v}
                </button>
              ))}
              <label style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 12, color: 'var(--pw-fg-2)' }}>
                <span>$</span>
                <input
                  className="pw-budget-in"
                  name="budgetUsd"
                  aria-label="USD Spend Cap"
                  type="number"
                  min={0.1}
                  max={500}
                  step="any"
                  required
                  value={budgetUsd}
                  onChange={e => setBudgetUsd(Number(e.target.value))}
                />
              </label>
            </div>
          </div>

          <details className="pw-disclosure" style={{ marginTop: 0 }}>
            <summary>
              Custom configuration <span className="muted num">({capabilityTierMeta[tier].short} · {maxRps} rps · {concurrency}w · {maxTurns}t)</span>
            </summary>
            <div className="pw-disclosure-body">
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
              </label>
              <label className="pw-fld">Run goal
                <textarea
                  className="pw-textarea"
                  name="goal"
                  rows={2}
                  maxLength={8000}
                  value={goal}
                  onChange={e => setGoal(e.target.value)}
                  placeholder={MODES[mode].goal}
                />
              </label>
              <div className="pw-grid-3">
                <label className="pw-fld">Rate (req/s)
                  <input
                    className="pw-in num"
                    name="maxRpsPerOrigin"
                    type="number"
                    min={1}
                    max={maxRpsPerOriginCeiling}
                    step={1}
                    required
                    value={maxRps}
                    onChange={e => setMaxRps(Number(e.target.value))}
                  />
                </label>
                <label className="pw-fld">Workers
                  <input
                    className="pw-in num"
                    name="workerConcurrency"
                    type="number"
                    min={1}
                    max={maxWorkerConcurrency}
                    step={1}
                    required
                    value={concurrency}
                    onChange={e => setConcurrency(Number(e.target.value))}
                  />
                </label>
                <label className="pw-fld">Max turns
                  <input
                    className="pw-in num"
                    name="workerMaxTurns"
                    type="number"
                    min={1}
                    max={maxWorkerMaxTurns}
                    step={1}
                    required
                    value={maxTurns}
                    onChange={e => setMaxTurns(Number(e.target.value))}
                  />
                </label>
              </div>
              <label className="pw-chk">
                <Checkbox
                  checked={unlimitedReqs}
                  aria-label="Unlimited max requests"
                  onCheckedChange={checked => setUnlimitedReqs(Boolean(checked))}
                />
                <span>Unlimited requests (recommended)</span>
              </label>
              {!unlimitedReqs && (
                <label className="pw-fld">Max brokered requests
                  <input
                    className="pw-in num"
                    name="budgetRequests"
                    type="number"
                    min={1}
                    max={maxBudgetRequests}
                    step={1}
                    value={budgetReqs}
                    onChange={e => setBudgetReqs(Number(e.target.value))}
                  />
                </label>
              )}
            </div>
          </details>

          <FormError error={runAction.error} />
        </div>

        <div className="pw-modal-ftr">
          <span className="hint mono num">{footerSummary}</span>
          <button type="button" className="pw-btn ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="pw-btn primary" disabled={runAction.pending}>
            {runAction.pending ? 'Starting…' : 'Start run'}
          </button>
        </div>
      </form>
    </div>
  )
}
