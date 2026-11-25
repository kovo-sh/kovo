import { useEffect, useId, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { Icon } from '../run/icons.tsx'

export interface DevicesSessionModalProps {
  open?: boolean
  onClose: () => void
}

interface PairingLinkResponse {
  url: string
  expiresAt: string
  ttlSeconds: number
}

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
  if (response.status === 401) return 'Local session expired. Open Kovo Hunter using the startup login URL.'
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
      className={'ico' + (className ? ' ' + className : '')}
      viewBox="0 0 16 16"
      aria-hidden="true"
    >
      <path d="M2.25 10.75V4.25A1.25 1.25 0 0 1 3.5 3h8a1.25 1.25 0 0 1 1.25 1.25v1.5" />
      <path d="M1.25 11.75h6.5" />
      <rect x="9.75" y="6.75" width="4.5" height="6.75" rx="1" />
      <path d="M11.75 11.75h.5" />
    </svg>
  )
}

export function DevicesSessionModal({ open = true, onClose }: DevicesSessionModalProps) {
  const titleId = useId()
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
  const closeBtnRef = useRef<HTMLButtonElement | null>(null)
  const copyTimerRef = useRef<number | null>(null)

  const busy = pairingPending || rotatePending

  // Restore focus to trigger on close and focus close button when opened.
  useEffect(() => {
    if (!open || typeof document === 'undefined') return
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
    closeBtnRef.current?.focus()
    return () => {
      previousFocus?.focus?.()
    }
  }, [open])

  // Escape closes modal unless an auth request is in flight.
  useEffect(() => {
    if (!open) return
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !busy) {
        event.preventDefault()
        onClose()
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [open, busy, onClose])

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

  if (!open) return null

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
      const response = await fetch('/_guardian/auth/pairing-link', {
        method: 'POST',
        credentials: 'same-origin',
      })
      if (!response.ok) {
        throw new Error(await readAuthError(response, 'Could not generate a pairing link.'))
      }
      const data = await response.json() as PairingLinkResponse
      const mintedAt = Date.now()
      setPairingLink(data)
      setExpiresAtMs(resolveExpiryMs(data, mintedAt))
      setNowMs(mintedAt)
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
      const response = await fetch('/_guardian/auth/rotate-session', {
        method: 'POST',
        credentials: 'same-origin',
      })
      if (!response.ok) {
        throw new Error(await readAuthError(response, 'Could not sign out other devices.'))
      }
      setConfirmRotate(false)
      setPairingLink(null)
      setExpiresAtMs(null)
      setCopyState('idle')
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

  const dialog = (
    <div
      className="dsm-overlay"
      role="presentation"
      onMouseDown={event => {
        if (event.target === event.currentTarget && !busy) onClose()
      }}
    >
      <div
        className="dsm-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
      >
        <header className="dsm-header">
          <div className="dsm-header-title">
            <DevicesIcon />
            <h2 id={titleId}>Devices &amp; local session</h2>
          </div>
          <div className="dsm-header-right">
            <span className="dsm-pill ok">
              <i className="dsm-dot ok" aria-hidden="true" />
              Active
            </span>
            <button
              ref={closeBtnRef}
              type="button"
              className="dsm-close"
              onClick={onClose}
              disabled={busy}
              aria-label="Close"
              title="Close (Esc)"
            >
              <Icon name="close" />
            </button>
          </div>
        </header>

        <div className="dsm-scroll">
          <section className="dsm-section" aria-label="Pair another device">
            <div className="dsm-section-head">
              <div>
                <h3 className="dsm-section-title">Pair another device</h3>
                <p className="dsm-section-desc">
                  Create a single-use 5-minute link to open Kovo Hunter on another browser or phone.
                </p>
              </div>
            </div>

            {!pairingLink ? (
              <div className="dsm-actions-row">
                <button
                  type="button"
                  className="dsm-btn ink"
                  disabled={busy}
                  onClick={() => void handleMintPairingLink()}
                >
                  {pairingPending ? 'Generating link…' : 'Generate pairing link'}
                </button>
              </div>
            ) : (
              <div className="dsm-link-card">
                <div className="dsm-link-meta">
                  <span className="dsm-link-label">One-time pairing link</span>
                  <span
                    className={
                      'dsm-pill num ' +
                      (isExpired ? 'bad' : isExpiringSoon ? 'warn' : 'muted')
                    }
                    aria-live="off"
                  >
                    {isExpired ? 'Expired' : `Expires in ${formatCountdown(remainingSeconds)}`}
                  </span>
                </div>

                <div className="dsm-link-row">
                  <input
                    ref={urlInputRef}
                    readOnly
                    className={'dsm-link-input' + (isExpired ? ' expired' : '')}
                    aria-label="One-time device pairing URL"
                    value={pairingLink.url}
                    onFocus={event => event.currentTarget.select()}
                  />
                  <button
                    type="button"
                    className={'dsm-btn' + (copyState === 'copied' ? ' ok' : ' primary')}
                    disabled={isExpired || busy}
                    onClick={() => void handleCopyExisting()}
                  >
                    {copyState === 'copied' ? (
                      <>
                        <Icon name="check" size={13} />
                        <span>Copied</span>
                      </>
                    ) : (
                      <span>Copy link</span>
                    )}
                  </button>
                </div>

                <div className="dsm-link-foot">
                  <span className="dsm-link-note">
                    {isExpired
                      ? 'This link has expired. Generate a fresh link to pair another device.'
                      : copyState === 'fallback'
                        ? 'Select the link above and press Ctrl+C / Cmd+C to copy.'
                        : 'Single-use link — never exposes your permanent session cookie.'}
                  </span>
                  <button
                    type="button"
                    className="dsm-btn ghost sm"
                    disabled={busy}
                    onClick={() => void handleMintPairingLink()}
                  >
                    {pairingPending ? 'Regenerating…' : 'Regenerate'}
                  </button>
                </div>
              </div>
            )}

            {errorMessage && (
              <div role="alert" className="dsm-toast err">
                {errorMessage}
              </div>
            )}

            {statusMessage && !errorMessage && (
              <div role="status" className="dsm-toast ok">
                <Icon name="check" size={13} />
                <span>{statusMessage}</span>
              </div>
            )}
          </section>

          <footer className="dsm-footer" aria-label="Session security">
            {!confirmRotate ? (
              <div className="dsm-footer-row">
                <div className="dsm-footer-copy">
                  <span className="dsm-footer-title">Sign out other devices</span>
                  <p className="dsm-footer-desc">
                    Rotate the local session secret and clear pending pairing links. This browser stays signed in.
                  </p>
                </div>
                <button
                  type="button"
                  className="dsm-btn danger"
                  disabled={busy}
                  onClick={() => {
                    setErrorMessage('')
                    setStatusMessage('')
                    setConfirmRotate(true)
                  }}
                >
                  Sign out other devices
                </button>
              </div>
            ) : (
              <div className="dsm-confirm" role="region" aria-label="Confirm sign out other devices">
                <p className="dsm-confirm-text">
                  <strong>Sign out all other devices?</strong> Every other browser will be signed out immediately and unused pairing links cleared. This browser stays signed in.
                </p>
                <div className="dsm-confirm-acts">
                  <button
                    type="button"
                    className="dsm-btn ghost"
                    disabled={rotatePending}
                    onClick={() => setConfirmRotate(false)}
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    className="dsm-btn danger-solid"
                    disabled={rotatePending}
                    onClick={() => void handleRotateSession()}
                  >
                    {rotatePending ? 'Signing out…' : 'Confirm sign out'}
                  </button>
                </div>
              </div>
            )}
          </footer>
        </div>
      </div>
    </div>
  )

  if (typeof document === 'undefined') return dialog
  return createPortal(dialog, document.body)
}
