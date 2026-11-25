import { useRef, useState } from 'react'
import { timeText } from '../common.tsx'

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
  if (response.status === 401) return 'Local session expired. Open Guardian using the startup login URL.'
  if (response.status === 404) return 'Local session controls are only available when running the Guardian local server.'
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

export function DevicesSessionBand() {
  const [pairingPending, setPairingPending] = useState(false)
  const [pairingLink, setPairingLink] = useState<PairingLinkResponse | null>(null)
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'fallback'>('idle')
  const [rotatePending, setRotatePending] = useState(false)
  const [confirmRotate, setConfirmRotate] = useState(false)
  const [statusMessage, setStatusMessage] = useState('')
  const [errorMessage, setErrorMessage] = useState('')
  const urlInputRef = useRef<HTMLInputElement | null>(null)

  async function handleMintPairingLink() {
    if (pairingPending) return
    setPairingPending(true)
    setErrorMessage('')
    setStatusMessage('')
    try {
      const response = await fetch('/_guardian/auth/pairing-link', {
        method: 'POST',
        credentials: 'same-origin',
      })
      if (!response.ok) {
        throw new Error(await readAuthError(response, 'Could not generate a one-time login link.'))
      }
      const data = await response.json() as PairingLinkResponse
      setPairingLink(data)
      const copied = await copyTextToClipboard(data.url)
      if (copied) {
        setCopyState('copied')
        setStatusMessage('One-time login link copied to clipboard.')
      } else {
        setCopyState('fallback')
        setStatusMessage('Clipboard access was denied. Use the Copy button or copy the link below manually.')
      }
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Could not generate a one-time login link.')
    } finally {
      setPairingPending(false)
    }
  }

  async function handleCopyExisting() {
    if (!pairingLink) return
    setErrorMessage('')
    const copied = await copyTextToClipboard(pairingLink.url)
    if (copied) {
      setCopyState('copied')
      setStatusMessage('One-time login link copied to clipboard.')
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
      setCopyState('copied')
      setStatusMessage('One-time login link copied to clipboard.')
    } else {
      setCopyState('fallback')
      setStatusMessage('Select the link above and press Ctrl+C / Cmd+C to copy.')
    }
  }

  async function handleRotateSession() {
    if (rotatePending) return
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
      setCopyState('idle')
      setStatusMessage('All other devices have been signed out and pending login links cleared. This browser stays signed in.')
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Could not sign out other devices.')
    } finally {
      setRotatePending(false)
    }
  }

  return (
    <section className="sw-band" aria-labelledby="devices-session-heading">
      <div className="sw-sec-head">
        <div>
          <p className="sw-eyebrow">Multi-device local access</p>
          <h2 id="devices-session-heading" className="sw-sec-title">Devices &amp; local session</h2>
        </div>
        <span className="sw-tag ok">
          <i className="sw-dot ok" aria-hidden="true" />
          Owner session active
        </span>
      </div>

      <div className="sw-sheet">
        <div className="sw-sheet-row">
          <div className="sw-sheet-row-main">
            <span className="sw-sheet-row-title">Sign in another browser or device</span>
            <p className="sw-sheet-row-desc">
              Generate a one-time URL for another browser on this machine or via your configured HTTPS proxy.
              Single-use link expires in 5 minutes — never shares your permanent session cookie.
            </p>
          </div>
          <div className="sw-sheet-row-act">
            <button
              type="button"
              className="sw-btn ink"
              disabled={pairingPending || rotatePending}
              onClick={() => void handleMintPairingLink()}
            >
              {pairingPending ? 'Generating link…' : 'Copy login link for another device'}
            </button>
          </div>
        </div>

        {pairingLink && (
          <div className="sw-pair-drawer">
            <div className="sw-pair-top">
              <strong>One-time device login link</strong>
              <span className="sw-tag warn sw-num">
                Expires {timeText(Date.parse(pairingLink.expiresAt))}
              </span>
            </div>
            <div className="sw-pair-row">
              <input
                ref={urlInputRef}
                readOnly
                className="sw-input"
                aria-label="One-time device login URL"
                value={pairingLink.url}
                onFocus={event => event.currentTarget.select()}
              />
              <button type="button" className="sw-btn" onClick={() => void handleCopyExisting()}>
                {copyState === 'copied' ? 'Copied' : 'Copy'}
              </button>
            </div>
            <span className="sw-muted" style={{ fontSize: '11.5px' }}>
              Single-use link expires in 5 minutes — never shares your permanent session cookie.
            </span>
          </div>
        )}

        <div className="sw-sheet-row">
          <div className="sw-sheet-row-main">
            <span className="sw-sheet-row-title">Revoke other browser sessions</span>
            <p className="sw-sheet-row-desc">
              Rotate the local session secret stored in 0600 disk storage and invalidate all pending login links while keeping this browser signed in.
            </p>
          </div>
          <div className="sw-sheet-row-act">
            {!confirmRotate && (
              <button
                type="button"
                className="sw-btn danger"
                disabled={rotatePending || pairingPending}
                onClick={() => {
                  setErrorMessage('')
                  setStatusMessage('')
                  setConfirmRotate(true)
                }}
              >
                Sign out other devices
              </button>
            )}
          </div>
        </div>

        {confirmRotate && (
          <div className="sw-confirm-strip" role="region" aria-label="Confirm sign out other devices">
            <p>
              <strong>Sign out all other devices?</strong> Every other browser will be signed out immediately and unused login links invalidated. This browser stays signed in.
            </p>
            <div className="sw-row-acts">
              <button
                type="button"
                className="sw-btn danger"
                disabled={rotatePending}
                onClick={() => void handleRotateSession()}
              >
                {rotatePending ? 'Signing out…' : 'Confirm sign out'}
              </button>
              <button
                type="button"
                className="sw-btn ghost"
                disabled={rotatePending}
                onClick={() => setConfirmRotate(false)}
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {errorMessage && (
          <div role="alert" className="sw-band-foot err">{errorMessage}</div>
        )}
        {statusMessage && !errorMessage && (
          <div role="status" className="sw-band-foot ok">{statusMessage}</div>
        )}
      </div>
    </section>
  )
}
