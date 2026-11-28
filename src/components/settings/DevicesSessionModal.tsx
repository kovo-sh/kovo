import { useEffect, useRef, useState } from 'react'
import { cn } from '../../lib/cn.ts'
import { Icon } from '../run/icons.tsx'
import { Badge } from '../ui/badge.tsx'
import { Button } from '../ui/button.tsx'
import { Dialog, DialogContent, DialogTitle } from '../ui/dialog.tsx'
import { Input } from '../ui/input.tsx'

export interface DevicesSessionModalProps {
  open?: boolean
  onClose: () => void
}

interface PairingLinkResponse {
  url: string
  expiresAt: string
  ttlSeconds: number
}

interface AuthStatusResponse {
  authenticated: boolean
  origin: string
  loopbackOnly: boolean
  publicOriginConfigured: boolean
  activePairingLinks: number
  pairingTtlSeconds: number
}

type SessionState = 'loading' | 'active' | 'expired' | 'unavailable'

function isLoopbackUrl(rawUrl: string | undefined): boolean {
  if (!rawUrl) return false
  try {
    const host = new URL(rawUrl).hostname.toLowerCase()
    return host === '127.0.0.1' || host === 'localhost' || host === '[::1]' || host === '::1'
  } catch {
    return false
  }
}

const SVG_ICON_CLASS =
  'block shrink-0 fill-none stroke-current [stroke-width:1.5] [stroke-linecap:round] [stroke-linejoin:round]'

async function copyTextToClipboard(text: string): Promise<boolean> {
  if (typeof navigator === 'undefined' || !navigator.clipboard?.writeText) return false
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

async function readAuthError(response: Response, fallback: string): Promise<string> {
  if (response.status === 401) return 'Local session expired. Open Kovo using the startup login URL.'
  if (response.status === 404) return 'Local session controls are only available when running the local server.'
  try {
    const contentType = response.headers.get('content-type') ?? ''
    if (contentType.includes('application/json')) {
      const body = await response.json() as { error?: string }
      if (body.error) return body.error
    } else {
      const text = (await response.text()).trim()
      if (text) return text
    }
  } catch {
    // Fall back to default message
  }
  return fallback
}

function formatCountdown(totalSeconds: number): string {
  const clamped = Math.max(0, Math.floor(totalSeconds))
  const minutes = Math.floor(clamped / 60)
  const seconds = clamped % 60
  return `${minutes}:${String(seconds).padStart(2, '0')}`
}

function resolveExpiryMs(link: PairingLinkResponse, mintedAtMs: number): number {
  const parsed = Date.parse(link.expiresAt)
  if (Number.isFinite(parsed)) return parsed
  return mintedAtMs + (link.ttlSeconds > 0 ? link.ttlSeconds : 300) * 1000
}

export function DevicesIcon({ className }: { className?: string }) {
  return (
    <svg
      className={cn('ico block size-3.5 shrink-0', className)}
      width="14"
      height="14"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M2.25 10.75V4.25A1.25 1.25 0 0 1 3.5 3h8a1.25 1.25 0 0 1 1.25 1.25v1.5" />
      <path d="M1.25 11.75h6.5" />
      <rect x="9.75" y="6.75" width="4.5" height="6.75" rx="1" />
      <path d="M11.75 11.75h.5" />
    </svg>
  )
}

/**
 * Loopback-only pairing warning. While the auth status is loading the same
 * box renders as an invisible-content placeholder, so the centred dialog keeps
 * its loaded geometry instead of jumping ~60px when the fetch resolves.
 */
function LoopbackNote({ placeholder = false }: { placeholder?: boolean }) {
  return (
    <div
      role={placeholder ? undefined : 'note'}
      aria-hidden={placeholder || undefined}
      data-slot={placeholder ? 'loopback-note-placeholder' : 'loopback-note'}
      className={cn(
        'flex flex-col gap-1 rounded-[7px] border px-[11px] py-[9px] text-[12px] leading-[17px] text-fg-muted',
        placeholder
          ? 'animate-pulse border-line bg-sunk [&>*]:invisible'
          : 'border-warn/30 bg-warn-soft',
      )}
    >
      <strong className="font-medium text-warn-text">Loopback-only pairing URL</strong>
      <span>
        This server is only reachable on <code className="font-mono text-[11.5px]">127.0.0.1</code> /{' '}
        <code className="font-mono text-[11.5px]">localhost</code>, so pairing links only work in another browser on this same machine. To pair a phone or remote device, run behind an HTTPS reverse proxy and set{' '}
        <code className="font-mono text-[11.5px]">KOVO_PUBLIC_ORIGIN</code>.
      </span>
    </div>
  )
}

export function DevicesSessionModal({ open = true, onClose }: DevicesSessionModalProps) {
  const [sessionState, setSessionState] = useState<SessionState>('loading')
  const [authStatus, setAuthStatus] = useState<AuthStatusResponse | null>(null)
  const [pairingPending, setPairingPending] = useState(false)
  const [pairingLink, setPairingLink] = useState<PairingLinkResponse | null>(null)
  const [expiresAtMs, setExpiresAtMs] = useState<number | null>(null)
  const [nowMs, setNowMs] = useState(() => Date.now())
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'fallback'>('idle')
  const [rotatePending, setRotatePending] = useState(false)
  const [confirmRotate, setConfirmRotate] = useState(false)
  const [statusMessage, setStatusMessage] = useState('')
  const [errorMessage, setErrorMessage] = useState('')
  const urlInputRef = useRef<HTMLInputElement | null>(null)
  const copyTimerRef = useRef<number | null>(null)

  const busy = pairingPending || rotatePending

  // Reflect live server session state whenever the modal opens.
  useEffect(() => {
    if (!open) return
    const controller = new AbortController()
    setSessionState('loading')
    setErrorMessage('')
    void fetch('/_kovo/auth/status', {
      method: 'GET',
      credentials: 'same-origin',
      signal: controller.signal,
    })
      .then(async response => {
        if (controller.signal.aborted) return
        if (response.ok) {
          const data = await response.json() as AuthStatusResponse
          setAuthStatus(data)
          setSessionState(data.authenticated ? 'active' : 'expired')
          return
        }
        setAuthStatus(null)
        if (response.status === 401) {
          setSessionState('expired')
          setErrorMessage(await readAuthError(response, 'Local session expired. Open Kovo using the startup login URL.'))
          return
        }
        setSessionState('unavailable')
        if (response.status === 404) {
          setErrorMessage('Local session controls are only available when running the local server.')
        }
      })
      .catch(() => {
        if (controller.signal.aborted) return
        setAuthStatus(null)
        setSessionState('unavailable')
      })
    return () => controller.abort()
  }, [open])

  // Live 1-second countdown ticker while a pairing link is active.
  useEffect(() => {
    if (!open || expiresAtMs === null) return
    setNowMs(Date.now())
    const id = window.setInterval(() => {
      setNowMs(Date.now())
    }, 1000)
    return () => window.clearInterval(id)
  }, [open, expiresAtMs])

  // Cleanup copied-indicator reset timer on unmount.
  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current)
      }
    }
  }, [])

  // The modal stays mounted (so Base UI can run its exit transition); clear
  // per-visit state only after the close animation has finished.
  function resetAfterClose() {
    setSessionState('loading')
    setPairingLink(null)
    setExpiresAtMs(null)
    setCopyState('idle')
    setConfirmRotate(false)
    setStatusMessage('')
    setErrorMessage('')
  }

  function markCopied() {
    setCopyState('copied')
    if (copyTimerRef.current !== null) {
      window.clearTimeout(copyTimerRef.current)
    }
    copyTimerRef.current = window.setTimeout(() => {
      setCopyState('idle')
      copyTimerRef.current = null
    }, 2400)
  }

  async function handleMintPairingLink() {
    if (busy) return
    setPairingPending(true)
    setErrorMessage('')
    setStatusMessage('')
    setConfirmRotate(false)
    try {
      const response = await fetch('/_kovo/auth/pairing-link', {
        method: 'POST',
        credentials: 'same-origin',
      })
      if (!response.ok) {
        if (response.status === 401) setSessionState('expired')
        else if (response.status === 404) setSessionState('unavailable')
        throw new Error(await readAuthError(response, 'Could not generate a pairing link.'))
      }
      const data = await response.json() as PairingLinkResponse
      const mintedAt = Date.now()
      setSessionState('active')
      setPairingLink(data)
      setExpiresAtMs(resolveExpiryMs(data, mintedAt))
      setNowMs(mintedAt)
      setAuthStatus(prev => (prev ? { ...prev, activePairingLinks: prev.activePairingLinks + 1 } : prev))
      const copied = await copyTextToClipboard(data.url)
      if (copied) {
        markCopied()
      } else {
        setCopyState('fallback')
      }
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Could not generate a pairing link.')
    } finally {
      setPairingPending(false)
    }
  }

  async function handleCopyExisting() {
    if (!pairingLink) return
    setErrorMessage('')
    const copied = await copyTextToClipboard(pairingLink.url)
    if (copied) {
      markCopied()
      return
    }
    urlInputRef.current?.focus()
    urlInputRef.current?.select()
    let execCopied = false
    try {
      execCopied = typeof document !== 'undefined' && document.execCommand('copy')
    } catch {
      execCopied = false
    }
    if (execCopied) {
      markCopied()
    } else {
      setCopyState('fallback')
    }
  }

  async function handleRotateSession() {
    if (busy) return
    setRotatePending(true)
    setErrorMessage('')
    setStatusMessage('')
    try {
      const response = await fetch('/_kovo/auth/rotate-session', {
        method: 'POST',
        credentials: 'same-origin',
      })
      if (!response.ok) {
        if (response.status === 401) setSessionState('expired')
        else if (response.status === 404) setSessionState('unavailable')
        throw new Error(await readAuthError(response, 'Could not sign out other devices.'))
      }
      setSessionState('active')
      setConfirmRotate(false)
      setPairingLink(null)
      setExpiresAtMs(null)
      setCopyState('idle')
      setAuthStatus(prev => (prev ? { ...prev, activePairingLinks: 0 } : prev))
      setStatusMessage('All other devices have been signed out and pending pairing links cleared. This browser stays signed in.')
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Could not sign out other devices.')
    } finally {
      setRotatePending(false)
    }
  }

  const remainingSeconds = expiresAtMs === null ? 0 : Math.max(0, Math.ceil((expiresAtMs - nowMs) / 1000))
  const isExpired = Boolean(pairingLink) && remainingSeconds <= 0
  const isExpiringSoon = Boolean(pairingLink) && remainingSeconds > 0 && remainingSeconds <= 60
  const controlsDisabled = busy || sessionState === 'expired' || sessionState === 'unavailable'
  const pairingLoopbackOnly = Boolean(
    (pairingLink && isLoopbackUrl(pairingLink.url)) ||
    (!pairingLink && authStatus?.loopbackOnly),
  )

  const badgeProps: { variant: 'ok' | 'danger' | 'warn' | 'neutral'; dotClass: string; label: string } =
    sessionState === 'active'
      ? { variant: 'ok', dotClass: 'bg-ok', label: 'Active' }
      : sessionState === 'expired'
        ? { variant: 'danger', dotClass: 'bg-danger', label: 'Expired' }
        : sessionState === 'unavailable'
          ? { variant: 'warn', dotClass: 'bg-warn', label: 'Unavailable' }
          : { variant: 'neutral', dotClass: 'bg-fg-faint', label: 'Checking…' }

  return (
    <Dialog
      open={open}
      closeOnEscape={!busy}
      onOpenChangeComplete={nextOpen => { if (!nextOpen) resetAfterClose() }}
      onOpenChange={(nextOpen, details) => {
        if (!nextOpen) {
          if (busy) {
            details.cancel()
            return
          }
          onClose()
        }
      }}
    >
      <DialogContent className="flex max-h-[calc(100vh-56px)] max-w-[484px] flex-col overflow-hidden rounded-2xl border-line-2 bg-raise p-0">
        <header className="flex flex-none items-center justify-between gap-3 border-b border-line py-[13px] pl-[18px] pr-3.5">
          <div className="flex min-w-0 items-center gap-2 text-fg-muted">
            <DevicesIcon />
            <DialogTitle className="truncate text-[13.5px] font-semibold leading-5 tracking-[-0.012em] text-fg">
              Devices &amp; local session
            </DialogTitle>
          </div>
          <div className="flex flex-none items-center gap-2">
            <Badge variant={badgeProps.variant} className="font-medium">
              <i className={cn('inline-block size-1.5 flex-none rounded-full', badgeProps.dotClass)} aria-hidden="true" />
              {badgeProps.label}
            </Badge>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="size-[26px] flex-none p-0 text-fg-subtle"
              onClick={onClose}
              disabled={busy}
              aria-label="Close"
              title="Close (Esc)"
            >
              <Icon name="close" size={14} className={cn(SVG_ICON_CLASS, 'size-3.5')} />
            </Button>
          </div>
        </header>

        <div className="flex min-h-0 flex-1 flex-col overflow-y-auto">
          <section className="flex flex-col gap-3.5 p-[18px]" aria-label="Pair another device">
            <div className="flex items-start justify-between gap-3">
              <div>
                <h3 className="m-0 mb-1 text-[13px] font-semibold leading-[18px] text-fg">
                  Pair another device
                </h3>
                <p className="m-0 text-[12.5px] leading-[18px] text-fg-muted">
                  Create a single-use 5-minute link to open Kovo on another browser or phone.
                </p>
              </div>
            </div>

            {sessionState === 'loading' ? (
              <LoopbackNote placeholder />
            ) : pairingLoopbackOnly && sessionState === 'active' ? (
              <LoopbackNote />
            ) : null}

            {!pairingLink ? (
              <div className="flex items-center gap-2">
                <Button
                  type="button"
                  variant="default"
                  className="h-7 px-2.5"
                  disabled={controlsDisabled}
                  onClick={() => void handleMintPairingLink()}
                >
                  {pairingPending ? 'Generating link…' : 'Generate pairing link'}
                </Button>
              </div>
            ) : (
              <div className="flex flex-col gap-[9px] rounded-[9px] border border-line-2 bg-sunk p-3">
                <div className="flex items-center justify-between gap-2.5">
                  <span className="text-[12px] font-medium text-fg-muted">One-time pairing link</span>
                  <Badge
                    variant={isExpired ? 'danger' : isExpiringSoon ? 'warn' : 'neutral'}
                    className={cn(
                      'font-medium tabular-nums',
                      !isExpired && !isExpiringSoon && 'bg-panel',
                    )}
                    aria-live="off"
                  >
                    {isExpired ? 'Expired' : `Expires in ${formatCountdown(remainingSeconds)}`}
                  </Badge>
                </div>

                <div className="flex items-center gap-[7px]">
                  <Input
                    ref={urlInputRef}
                    readOnly
                    className={cn(
                      'h-[30px]! flex-1 font-mono text-[11.5px]! leading-none!',
                      isExpired && 'text-fg-subtle! line-through',
                    )}
                    aria-label="One-time device pairing URL"
                    value={pairingLink.url}
                    onFocus={event => event.currentTarget.select()}
                  />
                  {copyState === 'copied' ? (
                    <Button
                      type="button"
                      variant="outline"
                      className="h-7 border border-ok/35 bg-ok-soft px-2.5 text-ok-text shadow-none hover:bg-ok-soft"
                      disabled={isExpired || busy}
                      onClick={() => void handleCopyExisting()}
                    >
                      <Icon name="check" size={13} className={cn(SVG_ICON_CLASS, 'size-[13px]')} />
                      <span>Copied</span>
                    </Button>
                  ) : (
                    <Button
                      type="button"
                      variant="default"
                      className="h-7 px-2.5"
                      disabled={isExpired || busy}
                      onClick={() => void handleCopyExisting()}
                    >
                      <span>Copy link</span>
                    </Button>
                  )}
                </div>

                <div className="flex items-center justify-between gap-2.5">
                  <span className="min-w-0 text-[11.5px] leading-4 text-fg-subtle">
                    {isExpired
                      ? 'This link has expired. Generate a fresh link to pair another device.'
                      : copyState === 'fallback'
                        ? 'Select the link above and press Ctrl+C / Cmd+C to copy.'
                        : 'Single-use link — never exposes your permanent session cookie.'}
                  </span>
                  <Button
                    type="button"
                    variant="ghost"
                    className="h-6 rounded-[5px] px-[7px] text-[12px]"
                    disabled={controlsDisabled}
                    onClick={() => void handleMintPairingLink()}
                  >
                    {pairingPending ? 'Regenerating…' : 'Regenerate'}
                  </Button>
                </div>
              </div>
            )}

            {errorMessage && (
              <div
                role="alert"
                className="flex min-w-0 items-start gap-[7px] rounded-[7px] border border-danger/30 bg-danger-soft px-[11px] py-[9px] text-[12px] leading-[17px] text-danger [overflow-wrap:anywhere]"
              >
                {errorMessage}
              </div>
            )}

            {statusMessage && !errorMessage && (
              <div
                role="status"
                className="flex min-w-0 items-start gap-[7px] rounded-[7px] border border-ok/30 bg-ok-soft px-[11px] py-[9px] text-[12px] leading-[17px] text-ok-text [overflow-wrap:anywhere]"
              >
                <Icon name="check" size={13} className={cn(SVG_ICON_CLASS, 'mt-px size-[13px]')} />
                <span className="min-w-0">{statusMessage}</span>
              </div>
            )}
          </section>

          <footer className="mt-auto border-t border-line bg-sunk px-[18px] py-3.5" aria-label="Session security">
            {!confirmRotate ? (
              <div className="flex flex-col items-start justify-between gap-2.5 sm:flex-row sm:items-center sm:gap-4">
                <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                  <span className="text-[12.5px] font-medium text-fg">Sign out other devices</span>
                  <p className="m-0 text-[11.5px] leading-4 text-fg-subtle">
                    Rotate the local session secret and clear pending pairing links. This browser stays signed in.
                  </p>
                </div>
                <Button
                  type="button"
                  variant="outline"
                  className="h-7 border border-danger/35 bg-panel px-2.5 text-danger shadow-none hover:bg-danger-soft"
                  disabled={controlsDisabled}
                  onClick={() => {
                    setErrorMessage('')
                    setStatusMessage('')
                    setConfirmRotate(true)
                  }}
                >
                  Sign out other devices
                </Button>
              </div>
            ) : (
              <div
                className="flex flex-col gap-[11px] rounded-lg border border-danger/30 bg-danger-soft px-3 py-2.5"
                role="region"
                aria-label="Confirm sign out other devices"
              >
                <p className="m-0 text-[12px] leading-[17px] text-fg">
                  <strong>Sign out all other devices?</strong> Every other browser will be signed out immediately and unused pairing links cleared. This browser stays signed in.
                </p>
                <div className="flex items-center justify-end gap-1.5">
                  <Button
                    type="button"
                    variant="ghost"
                    className="h-7 px-2.5"
                    disabled={rotatePending}
                    onClick={() => setConfirmRotate(false)}
                  >
                    Cancel
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    className="h-7 border-0 bg-danger px-2.5 text-white shadow-none hover:bg-danger hover:brightness-[1.06]"
                    disabled={rotatePending}
                    onClick={() => void handleRotateSession()}
                  >
                    {rotatePending ? 'Signing out…' : 'Confirm sign out'}
                  </Button>
                </div>
              </div>
            )}
          </footer>
        </div>
      </DialogContent>
    </Dialog>
  )
}
