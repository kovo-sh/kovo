import { useEffect, useRef, useState } from 'react'
import { removePersona } from '../../actions.ts'
import type { PublicPersona } from '../../domain.ts'
import { useAction } from '../common.tsx'
import { Icon } from '../run/icons.tsx'
import { Badge } from '../ui/badge.tsx'
import { Button } from '../ui/button.tsx'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/dialog.tsx'
import { EmptyState } from '../ui/empty-state.tsx'
import { PersonaFormModal } from './PersonaFormModal.tsx'
import type { PersonaTestState, ProjectLoaderData } from './types.ts'
import { formatPersonaAuthBadge, safeHost } from './types.ts'

/**
 * Derive a concise 2–3 word status pill label from a persona auth error or warning message.
 * Keeps the row badge compact while the full error text renders in the inline callout below.
 */
export function classifyPersonaTestError(message: string): string {
  const text = message.trim()
  if (!text) return 'Auth failed'
  if (/mfa|second factor|two[- ]?factor|totp|needs_second_factor|multi[- ]?factor/i.test(text)) {
    return 'MFA required'
  }
  if (/captcha|turnstile|anti[- ]?bot|verify you are human|bot_detected/i.test(text)) {
    return 'CAPTCHA blocked'
  }
  if (/timed?\s*out|timeout|aborted/i.test(text) && !/authentication aborted/i.test(text)) {
    return 'Timed out'
  }
  if (/blocked|forbidden|rate[- ]?limit|waf|\bhttp\s*403\b|\bhttp\s*429\b/i.test(text)) {
    return 'Blocked'
  }
  if (/invalid|incorrect|wrong password|unauthorized|bad credentials|\bhttp\s*401\b/i.test(text)) {
    return 'Invalid login'
  }
  if (/network|econn|enotfound|dns|fetch failed|unreachable|connection/i.test(text)) {
    return 'Network error'
  }
  if (/\bhttp\s*5\d\d\b|server error/i.test(text)) {
    return 'Server error'
  }
  return 'Auth failed'
}

/** Format the concise status chip label for a persona verification state. */
export function formatPersonaTestStatusLabel(test: PersonaTestState): string {
  if (test.status === 'error' || test.status === 'warn') {
    return classifyPersonaTestError(test.message)
  }
  return test.message
}

interface Props {
  data: ProjectLoaderData
  assets?: ProjectLoaderData['assets']
  personaTests: Record<string, PersonaTestState>
  onTestPersona: (persona: PublicPersona) => void
  onPersonaCreated: (created: { id: string; handle: string }) => void
  onPersonaUpdated?: (updated: { id: string; handle: string }) => void
}

function CrossAccountEmptySvg() {
  return (
    <svg
      className="block"
      width="180"
      height="88"
      viewBox="0 0 180 88"
      fill="none"
      aria-hidden="true"
    >
      {/* Left card: User A */}
      <rect
        x="4"
        y="14"
        width="68"
        height="60"
        rx="8"
        fill="var(--panel)"
        stroke="var(--line-2)"
        strokeWidth="1.2"
      />
      <circle
        cx="19"
        cy="31"
        r="7.5"
        fill="var(--accent-soft)"
        stroke="var(--accent-line)"
        strokeWidth="1.1"
      />
      <circle cx="19" cy="29.3" r="2.1" stroke="var(--accent)" strokeWidth="1.2" />
      <path
        d="M15.4 35.1c.65-1.75 1.9-2.55 3.6-2.55s2.95.8 3.6 2.55"
        stroke="var(--accent)"
        strokeWidth="1.2"
        strokeLinecap="round"
      />
      <text
        x="31"
        y="34"
        fill="var(--fg)"
        fontSize="9.5"
        fontWeight="600"
        fontFamily="inherit"
      >
        User A
      </text>
      <rect x="13" y="47" width="46" height="4.5" rx="2.25" fill="var(--line-2)" />
      <rect x="13" y="56" width="31" height="4.5" rx="2.25" fill="var(--line)" />

      {/* Right card: User B */}
      <rect
        x="108"
        y="14"
        width="68"
        height="60"
        rx="8"
        fill="var(--panel)"
        stroke="var(--line-2)"
        strokeWidth="1.2"
      />
      <circle
        cx="123"
        cy="31"
        r="7.5"
        fill="var(--sunk)"
        stroke="var(--line-strong)"
        strokeWidth="1.1"
      />
      <circle cx="123" cy="29.3" r="2.1" stroke="var(--fg-2)" strokeWidth="1.2" />
      <path
        d="M119.4 35.1c.65-1.75 1.9-2.55 3.6-2.55s2.95.8 3.6 2.55"
        stroke="var(--fg-2)"
        strokeWidth="1.2"
        strokeLinecap="round"
      />
      <text
        x="135"
        y="34"
        fill="var(--fg)"
        fontSize="9.5"
        fontWeight="600"
        fontFamily="inherit"
      >
        User B
      </text>
      <rect x="117" y="47" width="46" height="4.5" rx="2.25" fill="var(--line-2)" />
      <rect x="117" y="56" width="34" height="4.5" rx="2.25" fill="var(--line)" />

      {/* Center vertical isolation boundary */}
      <line
        x1="90"
        y1="6"
        x2="90"
        y2="24"
        stroke="var(--line-strong)"
        strokeWidth="1.25"
        strokeDasharray="3 3"
        strokeLinecap="round"
      />
      <line
        x1="90"
        y1="64"
        x2="90"
        y2="82"
        stroke="var(--line-strong)"
        strokeWidth="1.25"
        strokeDasharray="3 3"
        strokeLinecap="round"
      />

      {/* Shield + lock emblem on the boundary */}
      <path
        d="M90 26L102 30.8V42.4C102 50.6 96.9 56.8 90 60.5C83.1 56.8 78 50.6 78 42.4V30.8L90 26Z"
        fill="var(--panel)"
        stroke="var(--accent)"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
      <path
        d="M90 28.6L99.5 32.4V42.2C99.5 48.9 95.4 54.1 90 57.3C84.6 54.1 80.5 48.9 80.5 42.2V32.4L90 28.6Z"
        fill="var(--accent-soft)"
      />
      <rect
        x="85.8"
        y="41.8"
        width="8.4"
        height="6.8"
        rx="1.6"
        fill="var(--accent)"
      />
      <path
        d="M87.4 41.8V39.6A2.6 2.6 0 0 1 92.6 39.6V41.8"
        stroke="var(--accent)"
        strokeWidth="1.4"
        strokeLinecap="round"
      />
      <circle cx="90" cy="45.1" r="1" fill="var(--panel)" />
    </svg>
  )
}

export function ProjectPersonasTab({ data, assets, personaTests, onTestPersona, onPersonaCreated, onPersonaUpdated }: Props) {
  const { project, personas } = data
  const resolvedAssets = assets ?? data.assets
  const [modalOpen, setModalOpen] = useState(false)
  const [editingPersona, setEditingPersona] = useState<PublicPersona | null>(null)
  const [personaToDelete, setPersonaToDelete] = useState<PublicPersona | null>(null)
  const [notice, setNotice] = useState('')
  const [dismissedErrorKeys, setDismissedErrorKeys] = useState<Record<string, string>>({})
  const [copiedPersonaId, setCopiedPersonaId] = useState<string | null>(null)
  const copyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const personaAction = useAction()

  useEffect(() => () => {
    if (copyTimerRef.current) clearTimeout(copyTimerRef.current)
  }, [])

  function openCreateModal() {
    setEditingPersona(null)
    setModalOpen(true)
    setNotice('')
  }

  function openEditModal(persona: PublicPersona) {
    setEditingPersona(persona)
    setModalOpen(true)
    setNotice('')
  }

  function handleRetryPersona(persona: PublicPersona) {
    setDismissedErrorKeys(prev => {
      if (!(persona.id in prev)) return prev
      const next = { ...prev }
      delete next[persona.id]
      return next
    })
    onTestPersona(persona)
  }

  async function handleCopyError(personaId: string, message: string) {
    try {
      await navigator.clipboard?.writeText(message)
      setCopiedPersonaId(personaId)
      if (copyTimerRef.current) clearTimeout(copyTimerRef.current)
      copyTimerRef.current = setTimeout(() => {
        setCopiedPersonaId(prev => (prev === personaId ? null : prev))
      }, 2000)
    } catch {
      // Clipboard API may be unavailable in non-secure contexts; ignore silently.
    }
  }

  return (
    <section aria-label="Test accounts">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="m-0 text-[13px] font-semibold text-fg">
            Test accounts <span className="font-normal tabular-nums text-fg-subtle">({personas.length})</span>
          </h2>
          <p className="mt-0.5 text-[12px] text-fg-subtle">
            Add test logins so Kovo can scan behind sign-in and check whether one user can reach another user&apos;s data. Credentials stay encrypted on your machine.
          </p>
        </div>
        {personas.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5">
            <Button
              type="button"
              variant="default"
              onClick={openCreateModal}
            >
              Add test account
            </Button>
          </div>
        )}
      </div>

      {notice && (
        <p
          role="status"
          className="mb-3.5 flex items-center gap-2 rounded-[7px] border border-line bg-sunk px-3 py-[7px] text-[12.5px] text-fg-muted"
        >
          {notice}
        </p>
      )}

      {personas.length > 0 ? (
        <div className="border-t border-line">
          {personas.map(persona => {
            const test = personaTests[persona.id]
            const testVariant = test?.status === 'ok'
              ? 'ok'
              : test?.status === 'warn'
                ? 'warn'
                : test?.status === 'error'
                  ? 'danger'
                  : 'neutral'
            const isFailure = test?.status === 'error' || test?.status === 'warn'
            const showCallout = Boolean(isFailure && test && dismissedErrorKeys[persona.id] !== test.message)
            const isCopied = copiedPersonaId === persona.id
            return (
              <div key={persona.id} className="border-b border-line">
                <div className="flex min-h-[44px] items-center justify-between gap-3 px-1 py-2 transition-colors hover:bg-hover">
                  <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                    <div className="flex min-w-0 flex-wrap items-center gap-1.5 font-medium text-fg">
                      <strong className="font-mono text-[12px] font-semibold">{persona.handle}</strong>
                      <Badge variant="accent">{persona.roleLabel}</Badge>
                      <Badge variant="neutral" className="bg-sunk">{formatPersonaAuthBadge(persona)}</Badge>
                      {test && (
                        <Badge
                          variant={testVariant}
                          className={testVariant === 'neutral' ? 'bg-sunk' : undefined}
                          title={isFailure ? test.message : undefined}
                        >
                          {formatPersonaTestStatusLabel(test)}
                        </Badge>
                      )}
                    </div>
                    <div className="text-[12px] text-fg-subtle">
                      Allowlist: {persona.originAllowlist.map(safeHost).join(', ')}
                    </div>
                  </div>
                  <div className="flex flex-none items-center gap-2">
                    <Button
                      type="button"
                      variant="ghost"
                      disabled={test?.status === 'testing'}
                      onClick={() => handleRetryPersona(persona)}
                    >
                      {test?.status === 'testing' ? 'Verifying…' : test?.status === 'ok' ? 'Verify sign-in ✓' : 'Verify sign-in'}
                    </Button>
                    <Button
                      type="button"
                      variant="ghost"
                      disabled={personaAction.pending}
                      onClick={() => openEditModal(persona)}
                    >
                      Edit
                    </Button>
                    <Button
                      type="button"
                      variant="ghost"
                      className="data-[slot=button]:text-danger data-[slot=button]:hover:bg-danger-soft data-[slot=button]:hover:text-danger"
                      disabled={personaAction.pending}
                      onClick={() => setPersonaToDelete(persona)}
                    >
                      Delete
                    </Button>
                  </div>
                </div>
                {showCallout && test && (
                  <div
                    role="alert"
                    data-slot="persona-error-callout"
                    className={`mb-2.5 flex flex-wrap items-start justify-between gap-2.5 rounded-[7px] border px-3 py-2 text-[12px] ${
                      test.status === 'warn'
                        ? 'border-warn-line bg-warn-soft text-fg'
                        : 'border-danger/35 bg-danger-soft text-fg'
                    }`}
                  >
                    <div className="flex min-w-0 flex-1 items-start gap-2">
                      <Icon
                        name="alert"
                        size={14}
                        className={`mt-0.5 flex-none ${test.status === 'warn' ? 'text-warn' : 'text-danger'}`}
                      />
                      <p className="m-0 min-w-0 flex-1 whitespace-normal break-words leading-relaxed text-fg">
                        {test.message}
                      </p>
                    </div>
                    <div className="flex flex-none items-center gap-1.5">
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => openEditModal(persona)}
                      >
                        Edit account
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => handleRetryPersona(persona)}
                      >
                        Retry
                      </Button>
                      <Button
                        type="button"
                        variant="ghost"
                        onClick={() => void handleCopyError(persona.id, test.message)}
                      >
                        {isCopied ? 'Copied' : 'Copy'}
                      </Button>
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        className="size-[26px]"
                        aria-label={`Dismiss error for ${persona.handle}`}
                        onClick={() => setDismissedErrorKeys(prev => ({ ...prev, [persona.id]: test.message }))}
                      >
                        <Icon name="close" size={13} />
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      ) : (
        <div className="mt-3.5 rounded-card border border-line bg-sunk">
          <EmptyState
            icon={<CrossAccountEmptySvg />}
            title="No test accounts yet"
            description="Add one login to scan signed-in views, or two logins (User A & User B) to test cross-account isolation."
            className="max-w-[440px] py-9 [&_[data-slot=empty-state-icon]]:size-auto [&_[data-slot=empty-state-icon]>svg]:h-[88px] [&_[data-slot=empty-state-icon]>svg]:w-[180px]"
            action={
              <Button
                type="button"
                variant="default"
                onClick={openCreateModal}
              >
                Add test account
              </Button>
            }
          />
        </div>
      )}

      <PersonaFormModal
        open={modalOpen}
        onClose={() => {
          setModalOpen(false)
          setEditingPersona(null)
        }}
        project={project}
        assets={resolvedAssets}
        existingPersonas={personas}
        editingPersona={editingPersona}
        onCreated={result => {
          const wasEditing = Boolean(editingPersona)
          setNotice(
            wasEditing
              ? `Updated test account "${result.handle}". Credentials stay encrypted on your machine.`
              : `Saved test account "${result.handle}". Credentials stay encrypted on your machine.`,
          )
          setEditingPersona(null)
          if (wasEditing) {
            onPersonaUpdated?.(result)
          } else {
            onPersonaCreated(result)
          }
        }}
      />

      <Dialog
        open={Boolean(personaToDelete)}
        closeOnEscape={!personaAction.pending}
        onOpenChange={nextOpen => {
          if (!nextOpen && !personaAction.pending) setPersonaToDelete(null)
        }}
      >
        <DialogContent
          role="alertdialog"
          className="flex max-h-[calc(100vh-56px)] max-w-[440px] flex-col overflow-hidden p-0"
        >
          {personaToDelete && (
            <>
              <DialogHeader className="flex-row items-center justify-between gap-2.5 border-b border-line bg-raise px-4 py-2.5">
                <DialogTitle className="inline-flex items-center gap-2 text-[13px] font-semibold text-fg">
                  <Icon name="trash" size={15} className="text-danger" />
                  <span>Delete test account</span>
                </DialogTitle>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="size-[26px]"
                  disabled={personaAction.pending}
                  onClick={() => setPersonaToDelete(null)}
                  aria-label="Close"
                >
                  <Icon name="close" size={14} />
                </Button>
              </DialogHeader>
              <DialogBody className="flex min-h-0 flex-1 flex-col gap-3.5 overflow-y-auto p-4">
                <DialogDescription className="text-[12.5px] leading-5 text-fg-muted">
                  Remove <strong className="font-semibold text-fg">{personaToDelete.handle}</strong> and its saved credential from this project. This cannot be undone.
                </DialogDescription>
                <div className="flex flex-col gap-2 rounded-lg border border-line bg-sunk px-3 py-2.5">
                  <div className="line-clamp-2 text-[13px] font-medium text-fg">
                    {personaToDelete.roleLabel}
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5 tabular-nums">
                    <Badge variant="neutral" className="bg-panel">
                      {formatPersonaAuthBadge(personaToDelete)}
                    </Badge>
                    <Badge variant="neutral" className="bg-panel">
                      {personaToDelete.originAllowlist.map(safeHost).join(', ') || 'No sites listed'}
                    </Badge>
                  </div>
                </div>
                {personaAction.error && (
                  <p className="m-0 text-[12px] text-danger" role="alert">
                    {personaAction.error}
                  </p>
                )}
              </DialogBody>
              <DialogFooter>
                <Button
                  type="button"
                  variant="ghost"
                  disabled={personaAction.pending}
                  onClick={() => setPersonaToDelete(null)}
                >
                  Cancel
                </Button>
                <Button
                  type="button"
                  variant="default"
                  className="data-[slot=button]:bg-danger data-[slot=button]:text-white data-[slot=button]:hover:bg-danger hover:brightness-[1.08]"
                  disabled={personaAction.pending}
                  onClick={() => {
                    const target = personaToDelete
                    void personaAction.submit(() => removePersona({ data: {
                      requestId: crypto.randomUUID(),
                      projectId: project.id,
                      personaId: target.id,
                    } }), () => {
                      setPersonaToDelete(null)
                      setNotice(`Removed test account "${target.handle}".`)
                    })
                  }}
                >
                  <Icon name="trash" size={13} />
                  {personaAction.pending ? 'Deleting…' : 'Delete account'}
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>
    </section>
  )
}
