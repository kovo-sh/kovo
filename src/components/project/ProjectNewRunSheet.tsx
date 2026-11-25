import { useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import { createRun } from '../../actions.ts'
import type { ApprovalPolicy, CapabilityTier, PublicPersona } from '../../domain.ts'
import {
  defaultBudgetRequests,
  maxBudgetRequests,
  maxRpsPerOriginCeiling,
} from '../../domain.ts'
import { cn } from '../../lib/cn.ts'
import { FormError, useAction } from '../common.tsx'
import { Icon } from '../run/icons.tsx'
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
import { Input, Textarea } from '../ui/input.tsx'
import { PersonaFormModal } from './PersonaFormModal.tsx'
import type { PersonaTestState, ProjectLoaderData } from './types.ts'
import { formatPersonaAuthBadge } from './types.ts'

interface Props {
  open: boolean
  onClose: () => void
  data: ProjectLoaderData
  selectedPersonaIds: string[]
  setSelectedPersonaIds: React.Dispatch<React.SetStateAction<string[]>>
  personaTests: Record<string, PersonaTestState>
  onTestPersona: (persona: PublicPersona) => void
}

type ScanMode = 'passive' | 'supervised' | 'autonomous'

interface ScanModePreset {
  key: ScanMode
  usdCap: number
  rps: number
  goal: string
  label: string
  badge: string
  desc: string
  badgeVariant: 'neutral' | 'accent' | 'warn'
  warning?: string
}

const SCAN_MODES: Record<ScanMode, ScanModePreset> = {
  passive: {
    key: 'passive',
    usdCap: 15,
    rps: 4,
    goal: 'Map endpoints, API routes, and client bundles, and verify read-only exposures and cross-account reads without state-changing requests.',
    label: 'Passive Scan',
    badge: 'Safest',
    desc: 'Read-only discovery and checks; never mutates state.',
    badgeVariant: 'neutral',
  },
  supervised: {
    key: 'supervised',
    usdCap: 25,
    rps: 5,
    goal: 'Run safe active checks, auth/access-control probes, and high-impact proofs while pausing for human approval before risky state-changing actions.',
    label: 'Supervised Scan',
    badge: 'Recommended',
    desc: 'Safe active checks automatically; pauses for approval before risky writes.',
    badgeVariant: 'accent',
  },
  autonomous: {
    key: 'autonomous',
    usdCap: 30,
    rps: 5,
    goal: 'Run all in-scope active probes, mutations, and race bursts automatically with full audit logs and no approval pauses.',
    label: 'Autonomous Scan',
    badge: 'Risky',
    desc: 'All in-scope active probes, mutations, and race bursts with no approval pauses.',
    badgeVariant: 'warn',
    warning: 'Not recommended for production environments',
  },
}

const SCAN_MODE_ORDER: readonly ScanMode[] = ['passive', 'supervised', 'autonomous']
const BUDGET_CHIPS = [10, 25, 50] as const

function PassiveScanSvg() {
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

function SupervisedScanSvg() {
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

function AutonomousScanSvg() {
  return (
    <svg className="block h-[38px] w-[60px] flex-none text-fg" viewBox="0 0 64 40" fill="none" aria-hidden="true">
      <rect x="1.5" y="1.5" width="61" height="37" rx="7" fill="var(--sunk)" stroke="var(--line-2)" strokeWidth="1.2" />
      <path d="M12 20h10M42 20h10" stroke="var(--line-strong)" strokeWidth="1.4" strokeLinecap="round" />
      <path d="M34 10 24 21h8l-2 9 10-11h-8l2-9Z" fill="var(--panel)" stroke="var(--warn)" strokeWidth="1.5" strokeLinejoin="round" />
      <circle cx="15" cy="20" r="2.2" fill="var(--fg-3)" />
      <circle cx="49" cy="20" r="2.2" fill="var(--warn)" />
    </svg>
  )
}

function ModeIllustration({ mode }: { mode: ScanMode }) {
  if (mode === 'passive') return <PassiveScanSvg />
  if (mode === 'supervised') return <SupervisedScanSvg />
  return <AutonomousScanSvg />
}

export function resolveRunSubmissionMode(
  scanMode: ScanMode,
  selectedPersonaCount: number,
  strictWrites: boolean,
): { capabilityTier: CapabilityTier; approvalPolicy: ApprovalPolicy } {
  if (scanMode === 'passive') {
    return {
      capabilityTier: selectedPersonaCount > 0 ? 2 : 1,
      approvalPolicy: 'auto_review',
    }
  }
  if (scanMode === 'supervised') {
    return {
      capabilityTier: 3,
      approvalPolicy: strictWrites ? 'strict' : 'auto_review',
    }
  }
  return {
    capabilityTier: 3,
    approvalPolicy: 'yolo',
  }
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

  const [scanMode, setScanMode] = useState<ScanMode>('supervised')
  const [strictWrites, setStrictWrites] = useState(false)
  const [goal, setGoal] = useState('')
  const [budgetUsd, setBudgetUsd] = useState<number>(SCAN_MODES.supervised.usdCap)
  const [maxRps, setMaxRps] = useState<number>(SCAN_MODES.supervised.rps)
  const [unlimitedReqs, setUnlimitedReqs] = useState<boolean>(defaultBudgetRequests === 0)
  const [budgetReqs, setBudgetReqs] = useState<number>(defaultBudgetRequests === 0 ? 2500 : defaultBudgetRequests)
  const [addPersonaOpen, setAddPersonaOpen] = useState(false)

  const runAction = useAction()
  const busy = runAction.pending

  function applyScanMode(nextMode: ScanMode) {
    const preset = SCAN_MODES[nextMode]
    setScanMode(nextMode)
    setBudgetUsd(preset.usdCap)
    setMaxRps(preset.rps)
  }

  function togglePersona(id: string) {
    setSelectedPersonaIds(prev => (prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]))
  }

  function handleSubmit(event: React.FormEvent) {
    event.preventDefault()
    const { capabilityTier, approvalPolicy } = resolveRunSubmissionMode(
      scanMode,
      selectedPersonaIds.length,
      strictWrites,
    )
    const effectiveGoal = goal.trim() || SCAN_MODES[scanMode].goal
    const effectiveReqs = unlimitedReqs ? 0 : Math.max(1, Math.min(maxBudgetRequests, Math.round(budgetReqs)))
    void runAction.submit(() => createRun({ data: {
      requestId: crypto.randomUUID(),
      projectId: project.id,
      goal: effectiveGoal,
      sourceMode: 'public',
      capabilityTier,
      approvalPolicy,
      approvedPersonaIds: selectedPersonaIds,
      budgetUsd,
      budgetRequests: effectiveReqs,
      maxRpsPerOrigin: maxRps,
    } }), async result => {
      onClose()
      await navigate({ to: '/runs/$runId', params: { runId: result.id } })
    })
  }

  const testedPersonas = personas.filter(p => Boolean(personaTests[p.id]))
  const footerSummary = [
    SCAN_MODES[scanMode].label,
    `$${budgetUsd} cap`,
    `${selectedPersonaIds.length} ${selectedPersonaIds.length === 1 ? 'test account' : 'test accounts'}`,
  ].join(' · ')

  return (
    <>
      <Dialog
        open={open}
        closeOnEscape={!busy && !addPersonaOpen}
        onOpenChange={nextOpen => {
          if (!nextOpen && !busy && !addPersonaOpen) onClose()
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
              <div className="flex flex-col gap-2">
                <div className="grid grid-cols-1 gap-[9px] sm:grid-cols-3" role="radiogroup" aria-label="Scan mode">
                  {SCAN_MODE_ORDER.map(modeKey => {
                    const m = SCAN_MODES[modeKey]
                    const active = scanMode === modeKey
                    const activeClasses = modeKey === 'autonomous'
                      ? 'border-warn-line bg-warn-soft text-fg hover:bg-warn-soft'
                      : 'border-accent-line bg-accent-soft text-fg hover:bg-accent-soft'
                    return (
                      <button
                        key={modeKey}
                        type="button"
                        role="radio"
                        aria-checked={active}
                        className={cn(
                          'flex h-auto w-full cursor-pointer flex-col gap-[9px] whitespace-normal rounded-[9px] border px-[13px] py-3 text-left shadow-none transition-colors',
                          active
                            ? activeClasses
                            : 'border-line-2 bg-panel text-fg hover:border-line-strong hover:bg-hover',
                        )}
                        onClick={() => applyScanMode(modeKey)}
                      >
                        <div className="flex w-full items-start justify-between gap-2">
                          <ModeIllustration mode={modeKey} />
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
                          {m.warning && (
                            <span className="mt-1 text-[11px] font-medium leading-3.5 text-warn">
                              {m.warning}
                            </span>
                          )}
                        </div>
                      </button>
                    )
                  })}
                </div>

                {scanMode === 'supervised' && (
                  <label className="inline-flex cursor-pointer select-none items-center gap-[7px] pt-0.5 text-[12px] font-normal text-fg-muted">
                    <Checkbox
                      checked={strictWrites}
                      aria-label="Ask before every write (strict)"
                      onCheckedChange={checked => setStrictWrites(Boolean(checked))}
                    />
                    <span>Ask before every write (strict)</span>
                  </label>
                )}

                {scanMode === 'autonomous' && (
                  <div
                    role="status"
                    className="flex items-start gap-2 rounded-[7px] border border-warn-line bg-warn-soft px-3 py-2 text-[12px] leading-[17px] text-fg"
                  >
                    <Icon name="alert" size={14} className="mt-0.5 flex-none text-warn" />
                    <span>
                      <strong className="font-semibold">Not recommended for production environments.</strong>{' '}
                      Autonomous Scan executes in-scope mutations and race bursts without pausing for approval.
                    </span>
                  </div>
                )}
              </div>

              <div className="flex flex-col gap-2.5 border-t border-line pt-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="inline-flex items-center gap-1.5 text-[12px] font-semibold text-fg">
                    Test accounts
                    <Badge variant="neutral" className="bg-sunk tabular-nums">
                      {selectedPersonaIds.length}/{personas.length}
                    </Badge>
                  </span>
                  <Button type="button" variant="outline" onClick={() => setAddPersonaOpen(true)}>
                    + Add test account
                  </Button>
                </div>
                {personas.length > 0 ? (
                  <>
                    <div className="flex flex-wrap gap-1.5" role="group" aria-label="Select test accounts for run">
                      {personas.map(persona => {
                        const selected = selectedPersonaIds.includes(persona.id)
                        const test = personaTests[persona.id]
                        const verifyLabel = test?.status === 'testing'
                          ? 'Verifying…'
                          : test?.status === 'ok'
                            ? 'Verified ✓'
                            : test?.status === 'warn'
                              ? 'Retry sign-in'
                              : test?.status === 'error'
                                ? 'Sign-in failed'
                                : 'Verify sign-in'
                        const verifyTone = test?.status === 'ok'
                          ? 'text-ok'
                          : test?.status === 'warn'
                            ? 'text-warn'
                            : test?.status === 'error'
                              ? 'text-danger'
                              : 'text-fg-subtle hover:text-fg'
                        return (
                          <div
                            key={persona.id}
                            className={cn(
                              'inline-flex min-h-[28px] items-center overflow-hidden rounded-full border transition-colors',
                              selected
                                ? 'border-accent-line bg-accent-soft text-fg'
                                : 'border-line-2 bg-sunk text-fg-muted',
                            )}
                          >
                            <button
                              type="button"
                              aria-pressed={selected}
                              className="inline-flex h-full cursor-pointer items-center gap-1.5 whitespace-nowrap border-0 bg-transparent py-1 pl-2.5 pr-2 text-[12px] font-medium text-inherit shadow-none transition-colors hover:bg-hover/60"
                              onClick={() => togglePersona(persona.id)}
                              title={`${persona.handle} · ${persona.roleLabel} (${formatPersonaAuthBadge(persona)})`}
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
                            <button
                              type="button"
                              disabled={test?.status === 'testing'}
                              className={cn(
                                'inline-flex h-full cursor-pointer items-center whitespace-nowrap border-0 border-l border-line/80 bg-transparent px-2 py-1 text-[11px] font-medium shadow-none transition-colors hover:bg-hover/80 disabled:cursor-default disabled:opacity-60',
                                verifyTone,
                              )}
                              aria-label={`Verify sign-in for ${persona.handle}`}
                              title={test?.message ?? `Verify sign-in for ${persona.handle}`}
                              onClick={() => onTestPersona(persona)}
                            >
                              {verifyLabel}
                            </button>
                          </div>
                        )
                      })}
                    </div>
                    {testedPersonas.length > 0 && (
                      <div className="grid gap-1" role="status">
                        {testedPersonas.map(persona => {
                          const test = personaTests[persona.id]!
                          const tone = test.status === 'ok'
                            ? 'text-ok'
                            : test.status === 'warn'
                              ? 'text-warn'
                              : test.status === 'error'
                                ? 'text-danger'
                                : 'text-fg-subtle'
                          return (
                            <div key={persona.id} className={cn('text-[11.5px]', tone)}>
                              <span className="font-mono font-medium">{persona.handle}</span>: {test.message}
                            </div>
                          )
                        })}
                      </div>
                    )}
                  </>
                ) : (
                  <span className="text-[12px] text-fg-subtle">
                    No test accounts configured yet — add User A &amp; User B to test signed-in views and cross-user isolation.
                  </span>
                )}
              </div>

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
                      ({maxRps} req/s · {unlimitedReqs ? 'unlimited reqs' : `${budgetReqs} max reqs`})
                    </span>
                  </span>
                </DisclosureTrigger>
                <DisclosureContent className="grid gap-2.5 pt-2.5">
                  <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                    Run goal
                    <Textarea
                      className="w-full"
                      name="goal"
                      rows={2}
                      maxLength={8000}
                      value={goal}
                      onChange={e => setGoal(e.target.value)}
                      placeholder={SCAN_MODES[scanMode].goal}
                    />
                  </label>
                  <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                    Rate (req/s)
                    <Input
                      className="w-full tabular-nums sm:max-w-[180px]"
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
                        className="w-full tabular-nums sm:max-w-[180px]"
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

      <PersonaFormModal
        open={addPersonaOpen}
        onClose={() => setAddPersonaOpen(false)}
        project={project}
        existingPersonas={personas}
        submitLabel="Save & select"
        onCreated={created => {
          setSelectedPersonaIds(prev => prev.includes(created.id) ? prev : [...prev, created.id])
        }}
      />
    </>
  )
}
