import { useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
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
import { cn } from '../../lib/cn.ts'
import { FormError, useAction } from '../common.tsx'
import { parseCurlOrHeader } from '../curl-parser.ts'
import { Icon } from '../run/icons.tsx'
import { approvalPolicyMeta } from '../run-state.ts'
import { Badge } from '../ui/badge.tsx'
import { Button } from '../ui/button.tsx'
import { Checkbox } from '../ui/checkbox.tsx'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/dialog.tsx'
import { Disclosure, DisclosureContent, DisclosureTrigger } from '../ui/disclosure.tsx'
import { Input, NativeSelect, Textarea } from '../ui/input.tsx'
import type { PersonaTestState, ProjectLoaderData } from './types.ts'
import { formatPersonaAuthBadge, LOGIN_URL_PLACEHOLDERS } from './types.ts'

const SCAN_DEPTH_LABELS: Record<CapabilityTier, { short: string; option: string }> = {
  0: { short: 'Offline Audit', option: 'Offline Audit — no live traffic (imported specs & files only)' },
  1: { short: 'Safe Audit', option: 'Safe Audit — read-only surface map & passive checks' },
  2: { short: 'Core Pentest', option: 'Core Pentest — authenticated multi-account checks' },
  3: { short: 'Active Pentest', option: 'Active Pentest — approval-gated active verification' },
}

const APPROVAL_POLICY_COPY: Record<ApprovalPolicy, { label: string; desc: string }> = {
  auto_review: {
    label: 'Smart Review',
    desc: 'Auto-approves safe checks and asks before risky actions.',
  },
  strict: {
    label: 'Ask Every Time',
    desc: 'Pauses for your approval before every state-changing action.',
  },
  yolo: {
    label: 'Autonomous',
    desc: 'Runs in-scope active checks automatically with full audit logs.',
  },
}

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
  badgeVariant: 'neutral' | 'accent' | 'warn'
}

const MODES: Record<ModeKey, ModePreset> = {
  tier1: {
    key: 'tier1',
    tier: 1,
    usdCap: 10,
    rps: 3,
    concurrency: 4,
    maxTurns: 40,
    goal: 'Map public endpoints, API routes, and client bundles, and verify read-only exposures without state-changing requests.',
    label: 'Safe Audit',
    badge: 'Read-only',
    desc: 'Surface map & passive checks. Zero writes.',
    badgeVariant: 'neutral',
  },
  tier2: {
    key: 'tier2',
    tier: 2,
    usdCap: 25,
    rps: 5,
    concurrency: 6,
    maxTurns: 150,
    goal: 'Check authentication, cross-account access controls, and business logic across approved hosts using paired test accounts.',
    label: 'Core Pentest',
    badge: 'Recommended',
    desc: 'Auth, access-control & logic checks with test accounts.',
    badgeVariant: 'accent',
  },
  tier3: {
    key: 'tier3',
    tier: 3,
    usdCap: 30,
    rps: 3,
    concurrency: 4,
    maxTurns: 120,
    goal: 'Verify high-impact state changes, race conditions, and active proofs with human approval before risky requests.',
    label: 'Active Pentest',
    badge: 'Approval-gated',
    desc: 'Full active proofs with human approval.',
    badgeVariant: 'warn',
  },
}

const BUDGET_CHIPS = [10, 25, 50] as const

function RadarAuditSvg() {
  return (
    <svg className="block h-[38px] w-[60px] flex-none text-fg" viewBox="0 0 64 40" fill="none" aria-hidden="true">
      <rect x="1.5" y="1.5" width="61" height="37" rx="7" fill="var(--sunk)" stroke="var(--line-2)" strokeWidth="1.2" />
      <circle cx="32" cy="20" r="12.5" stroke="var(--line-strong)" strokeWidth="1.2" />
      <circle cx="32" cy="20" r="7" stroke="var(--line-strong)" strokeWidth="1.2" strokeDasharray="2.5 2.5" />
      <path d="M32 20L41 12" stroke="var(--accent)" strokeWidth="1.6" strokeLinecap="round" />
      <circle cx="32" cy="20" r="2.25" fill="var(--panel)" stroke="currentColor" strokeWidth="1.4" />
      <circle cx="41" cy="12" r="2.6" fill="var(--accent)" />
      <circle cx="24" cy="25" r="1.9" fill="var(--fg-3)" />
    </svg>
  )
}

function CorePentestSvg() {
  return (
    <svg className="block h-[38px] w-[60px] flex-none text-fg" viewBox="0 0 64 40" fill="none" aria-hidden="true">
      <rect x="1.5" y="1.5" width="61" height="37" rx="7" fill="var(--sunk)" stroke="var(--line-2)" strokeWidth="1.2" />
      <circle cx="15" cy="14" r="3" fill="var(--panel)" stroke="currentColor" strokeWidth="1.4" />
      <circle cx="15" cy="26" r="3" fill="var(--accent)" />
      <path d="M18.5 14h10c3 0 4 6 7.5 6h5.5" stroke="var(--fg-3)" strokeWidth="1.3" strokeLinecap="round" />
      <path d="M18.5 26h10c3 0 4-6 7.5-6h5.5" stroke="var(--accent)" strokeWidth="1.6" strokeLinecap="round" />
      <path d="M47 10.5 53 13v5.2c0 3.7-2.4 6.5-6 7.8-3.6-1.3-6-4.1-6-7.8V13l6-2.5Z" fill="var(--panel)" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
      <path d="M44.6 18.2 46.3 20l3.3-3.5" stroke="var(--accent)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function ActiveGateSvg() {
  return (
    <svg className="block h-[38px] w-[60px] flex-none text-fg" viewBox="0 0 64 40" fill="none" aria-hidden="true">
      <rect x="1.5" y="1.5" width="61" height="37" rx="7" fill="var(--sunk)" stroke="var(--line-2)" strokeWidth="1.2" />
      <path d="M10 20h14M40 20h14" stroke="var(--line-strong)" strokeWidth="1.4" strokeLinecap="round" />
      <path d="M14 14l4 6-4 6" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
      <rect x="24.5" y="11" width="15" height="18" rx="4" fill="var(--panel)" stroke="var(--accent)" strokeWidth="1.5" />
      <path d="M29 20.2 31.2 22.4 35.4 17.8" stroke="var(--accent)" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M49 16l4.5 4-4.5 4" stroke="var(--accent)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
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
  const busy = runAction.pending || personaAction.pending

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
    SCAN_DEPTH_LABELS[tier].short,
    `$${budgetUsd} cap`,
    ...(tier >= 2 ? [`${selectedPersonaIds.length} ${selectedPersonaIds.length === 1 ? 'test account' : 'test accounts'}`] : []),
  ].join(' · ')

  return (
    <Dialog
      open={open}
      closeOnEscape={!busy}
      onOpenChange={nextOpen => {
        if (!nextOpen && !busy) onClose()
      }}
    >
      <DialogContent className="flex max-h-[calc(100vh-56px)] max-w-[680px] flex-col overflow-hidden p-0">
        <form className="flex min-h-0 flex-1 flex-col" onSubmit={handleSubmit}>
          <DialogHeader className="flex-row items-center justify-between gap-2.5 border-b border-line bg-raise px-4 py-2.5">
            <DialogTitle className="text-[13px] font-semibold text-fg">
              New run · {project.name}
            </DialogTitle>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="size-[26px]"
              onClick={onClose}
              disabled={busy}
              aria-label="Close"
            >
              <Icon name="close" size={14} />
            </Button>
          </DialogHeader>

          <DialogBody className="flex min-h-0 flex-1 flex-col gap-3.5 overflow-y-auto p-4">
            <div className="grid grid-cols-1 gap-[9px] sm:grid-cols-3" role="radiogroup" aria-label="Assessment mode">
              {(['tier1', 'tier2', 'tier3'] as const).map(k => {
                const m = MODES[k]
                const active = mode === k
                return (
                  <button
                    key={k}
                    type="button"
                    role="radio"
                    aria-checked={active}
                    className={cn(
                      'flex h-auto w-full cursor-pointer flex-col gap-[9px] whitespace-normal rounded-[9px] border px-[13px] py-3 text-left shadow-none transition-colors',
                      active
                        ? 'border-accent-line bg-accent-soft text-fg hover:bg-accent-soft'
                        : 'border-line-2 bg-panel text-fg hover:border-line-strong hover:bg-hover',
                    )}
                    onClick={() => applyMode(k)}
                  >
                    <div className="flex w-full items-start justify-between gap-2">
                      <ModeIllustration mode={k} />
                      <Badge
                        variant={m.badgeVariant}
                        className={m.badgeVariant === 'neutral' ? 'bg-sunk' : undefined}
                      >
                        {m.badge}
                      </Badge>
                    </div>
                    <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                      <strong className="text-[13px] font-semibold leading-[18px] text-fg">{m.label}</strong>
                      <span className="text-[11.5px] font-normal leading-4 text-fg-muted">{m.desc}</span>
                    </div>
                  </button>
                )
              })}
            </div>

            {tier >= 2 && (
              <div className="flex flex-col gap-2.5 border-t border-line pt-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="inline-flex items-center gap-1.5 text-[12px] font-semibold text-fg">
                    Test accounts
                    <Badge variant="neutral" className="bg-sunk tabular-nums">
                      {selectedPersonaIds.length}/{personas.length}
                    </Badge>
                  </span>
                  <Button type="button" variant="outline" onClick={() => setInlinePersonaOpen(v => !v)}>
                    {inlinePersonaOpen ? 'Hide form' : '+ Quick add account'}
                  </Button>
                </div>
                {personas.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5" role="group" aria-label="Select test accounts for run">
                    {personas.map(persona => {
                      const selected = selectedPersonaIds.includes(persona.id)
                      const test = personaTests[persona.id]
                      return (
                        <button
                          key={persona.id}
                          type="button"
                          aria-pressed={selected}
                          className={cn(
                            'inline-flex h-auto min-h-[28px] cursor-pointer items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 py-1 text-[12px] font-medium shadow-none transition-colors',
                            selected
                              ? 'border-accent-line bg-accent-soft text-fg hover:bg-accent-soft'
                              : 'border-line-2 bg-sunk text-fg-muted hover:bg-hover hover:text-fg',
                          )}
                          onClick={() => togglePersona(persona.id)}
                          title={`${persona.handle} · ${persona.roleLabel} (${formatPersonaAuthBadge(persona)})${test ? ` — ${test.message}` : ''}`}
                        >
                          <span
                            className={cn(
                              'inline-grid size-[13px] flex-none place-items-center rounded-full border text-[9px] font-bold',
                              selected
                                ? 'border-accent bg-accent text-accent-fg'
                                : 'border-line-strong text-transparent',
                            )}
                            aria-hidden="true"
                          >
                            ✓
                          </span>
                          <span className="font-mono text-[12px]">{persona.handle}</span>
                          <span className="font-normal text-fg-subtle">{persona.roleLabel}</span>
                        </button>
                      )
                    })}
                  </div>
                ) : (
                  <span className="text-[12px] text-fg-subtle">
                    No test accounts configured yet — add User A &amp; User B to test cross-user isolation.
                  </span>
                )}

                {inlinePersonaOpen && (
                  <div className="grid gap-[9px] border-t border-line pt-2.5">
                    <div className="flex items-center justify-between gap-2">
                      <strong className="text-[12px] font-semibold text-fg">Quick-add test account</strong>
                      <div className="flex flex-wrap items-center gap-1.5">
                        <Button type="button" variant="ghost" onClick={() => prefillPair('user_a')}>
                          Preset User A
                        </Button>
                        <Button type="button" variant="ghost" onClick={() => prefillPair('user_b')}>
                          Preset User B
                        </Button>
                      </div>
                    </div>
                    {authKind !== 'login' && (
                      <div className="grid gap-1">
                        <div className="flex items-center gap-1.5">
                          <Input
                            className="flex-1 font-mono text-[12px]"
                            value={curlPaste}
                            onChange={e => setCurlPaste(e.target.value)}
                            onPaste={e => {
                              const pasted = e.clipboardData.getData('text')
                              if (pasted) {
                                e.preventDefault()
                                applyCurlParse(pasted)
                              }
                            }}
                            placeholder="Paste cURL or Cookie:/Authorization: header"
                          />
                          <Button
                            type="button"
                            variant="outline"
                            onClick={() => applyCurlParse(curlPaste)}
                            disabled={!curlPaste.trim()}
                          >
                            Parse
                          </Button>
                        </div>
                        {curlNote && <span className="text-[11.5px] text-fg-subtle">{curlNote}</span>}
                      </div>
                    )}
                    <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-2">
                      <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                        Handle
                        <Input
                          className="w-full font-mono text-[12px]"
                          value={personaHandle}
                          onChange={e => setPersonaHandle(e.target.value)}
                          placeholder="user_a"
                        />
                      </label>
                      <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                        Role
                        <Input
                          className="w-full"
                          value={personaRole}
                          onChange={e => setPersonaRole(e.target.value)}
                          placeholder="Standard user"
                        />
                      </label>
                    </div>
                    <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                      Auth kind
                      <NativeSelect
                        className="w-full"
                        value={authKind}
                        onChange={e => setAuthKind(e.target.value as PersonaAuthKind)}
                      >
                        <option value="login">Email + Password (auto-login &amp; refresh)</option>
                        <option value="cookie">Session cookie</option>
                        <option value="bearer">Bearer token</option>
                        <option value="header">Custom header</option>
                      </NativeSelect>
                    </label>
                    {authKind === 'login' ? (
                      <>
                        <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-2">
                          <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                            Email
                            <Input
                              className="w-full"
                              type="email"
                              value={loginEmail}
                              onChange={e => setLoginEmail(e.target.value)}
                              placeholder="test-user-a@example.com"
                              autoComplete="off"
                            />
                          </label>
                          <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                            Password
                            <Input
                              className="w-full"
                              type="password"
                              value={personaSecret}
                              onChange={e => setPersonaSecret(e.target.value)}
                              placeholder="Stored privately on your machine"
                              autoComplete="off"
                            />
                          </label>
                        </div>
                        <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-2">
                          <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                            Auth method
                            <NativeSelect
                              className="w-full"
                              value={loginAdapter}
                              onChange={e => setLoginAdapter(e.target.value as PersonaLoginAdapter)}
                            >
                              <option value="auto">Auto-detect</option>
                              <option value="clerk">Clerk (auto-refresh)</option>
                              <option value="json">JSON API / Better Auth</option>
                              <option value="supabase">Supabase Auth</option>
                              <option value="form">Login Form (Browser)</option>
                            </NativeSelect>
                          </label>
                          <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                            Login URL (optional)
                            <Input
                              className="w-full"
                              type="url"
                              value={loginUrl}
                              onChange={e => setLoginUrl(e.target.value)}
                              placeholder={LOGIN_URL_PLACEHOLDERS[loginAdapter]}
                              autoComplete="off"
                            />
                          </label>
                        </div>
                      </>
                    ) : (
                      <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-2">
                        {authKind === 'header' && (
                          <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                            Header name
                            <Input
                              className="w-full font-mono text-[12px]"
                              value={personaHeaderName}
                              onChange={e => setPersonaHeaderName(e.target.value)}
                              placeholder="X-Api-Key"
                            />
                          </label>
                        )}
                        <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                          Secret (masked)
                          <Input
                            className="w-full"
                            type="password"
                            value={personaSecret}
                            onChange={e => setPersonaSecret(e.target.value)}
                            autoComplete="off"
                            placeholder="Never echoed after save"
                          />
                        </label>
                      </div>
                    )}
                    <FormError error={personaAction.error} />
                    <div className="flex justify-end gap-1.5">
                      <Button type="button" variant="ghost" onClick={() => setInlinePersonaOpen(false)}>
                        Cancel
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
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
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {tier === 3 && (
              <div className="flex flex-col gap-2.5 border-t border-line pt-3" role="radiogroup" aria-label="Approval policy">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="inline-flex items-center gap-1.5 text-[12px] font-semibold text-fg">
                    Approval policy
                  </span>
                  <span className="text-[11.5px] text-fg-subtle">Switchable mid-run</span>
                </div>
                <div className="grid grid-cols-1 gap-[7px] sm:grid-cols-3">
                  {approvalPolicies.map(policy => {
                    const meta = approvalPolicyMeta[policy]
                    const copy = APPROVAL_POLICY_COPY[policy]
                    const active = approvalPolicy === policy
                    return (
                      <button
                        key={policy}
                        type="button"
                        role="radio"
                        aria-checked={active}
                        className={cn(
                          'flex h-auto w-full cursor-pointer flex-col gap-[3px] whitespace-normal rounded-[7px] border px-2.5 py-2 text-left shadow-none transition-colors',
                          active
                            ? 'border-accent-line bg-accent-soft text-fg hover:bg-accent-soft'
                            : 'border-line bg-panel text-fg hover:bg-hover',
                        )}
                        onClick={() => setApprovalPolicy(policy)}
                        title={meta.summary}
                      >
                        <span className="flex w-full items-center justify-between gap-1.5">
                          <b className="text-[12.5px] font-semibold text-fg">{copy.label}</b>
                          {policy === 'auto_review' && <Badge variant="ok">Default</Badge>}
                          {policy === 'strict' && <Badge variant="neutral" className="bg-sunk">Manual</Badge>}
                          {policy === 'yolo' && <Badge variant="warn">Auto</Badge>}
                        </span>
                        <small className="text-[11.5px] font-normal leading-4 text-fg-subtle">{copy.desc}</small>
                      </button>
                    )
                  })}
                </div>
              </div>
            )}

            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line pt-2.5">
              <div>
                <div className="text-[12.5px] font-semibold text-fg">Budget cap</div>
                <div className="text-[11.5px] text-fg-subtle">Hard stop when spend reaches limit</div>
              </div>
              <div className="flex flex-wrap items-center gap-1.5">
                {BUDGET_CHIPS.map(v => {
                  const on = budgetUsd === v
                  return (
                    <button
                      key={v}
                      type="button"
                      className={cn(
                        'h-6 cursor-pointer rounded-[5px] border px-2 text-[11.5px] font-medium tabular-nums shadow-none transition-colors',
                        on
                          ? 'border-accent-line bg-accent-soft text-accent hover:bg-accent-soft'
                          : 'border-line-2 bg-panel text-fg-muted hover:bg-hover hover:text-fg',
                      )}
                      onClick={() => setBudgetUsd(v)}
                    >
                      ${v}
                    </button>
                  )
                })}
                <label className="inline-flex items-center gap-1 text-[12px] text-fg-muted">
                  <span>$</span>
                  <Input
                    className="h-[26px]! w-[84px] tabular-nums"
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

            <Disclosure className="border-t border-line pt-2.5">
              <DisclosureTrigger className="h-auto bg-transparent px-0 py-1 text-fg-muted shadow-none hover:bg-transparent hover:text-fg">
                <span>
                  Advanced configuration{' '}
                  <span className="font-normal tabular-nums text-fg-subtle">
                    ({SCAN_DEPTH_LABELS[tier].short} · {maxRps} req/s · {concurrency} workers · {maxTurns} turns)
                  </span>
                </span>
              </DisclosureTrigger>
              <DisclosureContent className="grid gap-2.5 pt-2.5">
                <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                  Scan depth
                  <NativeSelect
                    className="w-full"
                    name="capabilityTier"
                    value={tier}
                    onChange={e => setTier(Number(e.target.value) as CapabilityTier)}
                  >
                    <option value={0}>{SCAN_DEPTH_LABELS[0].option}</option>
                    <option value={1}>{SCAN_DEPTH_LABELS[1].option}</option>
                    <option value={2}>{SCAN_DEPTH_LABELS[2].option}</option>
                    <option value={3}>{SCAN_DEPTH_LABELS[3].option}</option>
                  </NativeSelect>
                </label>
                <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                  Run goal
                  <Textarea
                    className="w-full"
                    name="goal"
                    rows={2}
                    maxLength={8000}
                    value={goal}
                    onChange={e => setGoal(e.target.value)}
                    placeholder={MODES[mode].goal}
                  />
                </label>
                <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-3">
                  <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                    Rate (req/s)
                    <Input
                      className="w-full tabular-nums"
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
                  <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                    Workers
                    <Input
                      className="w-full tabular-nums"
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
                  <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                    Max turns
                    <Input
                      className="w-full tabular-nums"
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
                <label className="inline-flex cursor-pointer select-none items-center gap-[7px] text-[12.5px] font-normal text-fg-muted">
                  <Checkbox
                    checked={unlimitedReqs}
                    aria-label="Unlimited max requests"
                    onCheckedChange={checked => setUnlimitedReqs(Boolean(checked))}
                  />
                  <span>Unlimited requests (recommended)</span>
                </label>
                {!unlimitedReqs && (
                  <label
                    className="grid gap-1 text-[12px] font-medium text-fg-muted"
                    title="Maximum HTTP requests sent through the request guardrail"
                  >
                    Max requests
                    <Input
                      className="w-full tabular-nums"
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
              </DisclosureContent>
            </Disclosure>

            <FormError error={runAction.error} />
          </DialogBody>

          <DialogFooter className="flex-wrap">
            <span className="mr-auto font-mono text-[12px] tabular-nums text-fg-subtle">{footerSummary}</span>
            <Button type="button" variant="ghost" disabled={busy} onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" variant="default" disabled={runAction.pending}>
              {runAction.pending ? 'Starting…' : 'Start run'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
