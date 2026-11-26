import { useEffect, useRef, useState } from 'react'
import { registerPersona, updatePersona } from '../../actions.ts'
import {
  registerBrowserSessionPersona,
  updateBrowserSessionPersonaAction,
} from '../../actions-auth-capture.ts'
import type { PersonaAuthKind, PersonaLoginAdapter, PublicPersona } from '../../domain.ts'
import { parseCurlOrHeaderInput } from '../../server/curl-parse.ts'
import { FormError, useAction } from '../common.tsx'
import { Icon } from '../run/icons.tsx'
import { Badge } from '../ui/badge.tsx'
import { Button } from '../ui/button.tsx'
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
import type { ProjectLoaderData } from './types.ts'
import { LOGIN_URL_PLACEHOLDERS } from './types.ts'

export type UniversalAuthMode = 'browser_session' | 'header_cookie' | 'automated_login'
export type StaticCredentialKind = 'cookie' | 'bearer' | 'header'
export type PersonaSignInMethod = PersonaAuthKind | 'clerk_client' | 'browser_session'

interface CaptureSummary {
  targetOrigin: string
  capturedAt: number
  cookieCount: number
  originCount: number
  hasAuthorizationHeader: boolean
}

interface ActiveCaptureSession {
  captureId: string
  targetOrigin: string
  expiresAt: number
  viewport: { width: number; height: number }
}

interface Props {
  open: boolean
  onClose: () => void
  project: ProjectLoaderData['project']
  existingPersonas: readonly Pick<PublicPersona, 'handle' | 'roleLabel'>[]
  editingPersona?: PublicPersona | null
  onCreated: (created: { id: string; handle: string }) => void
  submitLabel?: string
}

export function deriveUniqueHandle(
  label: string,
  existingHandles: readonly string[],
): string {
  const base = label
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/^[^a-z0-9]+/, '')
    .replace(/-+$/g, '')
    .slice(0, 48) || 'account'

  const taken = new Set(existingHandles.map(h => h.toLowerCase()))
  if (!taken.has(base)) return base

  for (let n = 2; n < 10_000; n += 1) {
    const suffix = `-${n}`
    const candidate = `${base.slice(0, 48 - suffix.length).replace(/-+$/g, '') || 'account'}${suffix}`
    if (!taken.has(candidate)) return candidate
  }
  return `${base.slice(0, 39)}-${Date.now().toString(36).slice(-8)}`
}

export function suggestNextAccountLabel(
  existingPersonas: readonly Pick<PublicPersona, 'handle' | 'roleLabel'>[],
): string {
  const handles = new Set(existingPersonas.map(p => p.handle.toLowerCase()))
  const labels = existingPersonas.map(p => p.roleLabel.trim().toLowerCase())

  const isTaken = (token: string): boolean => {
    const lower = token.toLowerCase()
    if (handles.has(`user-${lower}`) || handles.has(`user_${lower}`)) return true
    const re = new RegExp(`^user\\s+${lower}(?:$|[^a-z0-9])`, 'i')
    return labels.some(l => re.test(l))
  }

  for (let code = 65; code <= 90; code += 1) {
    const letter = String.fromCharCode(code)
    if (!isTaken(letter)) return `User ${letter}`
  }

  for (let n = 1; n < 10_000; n += 1) {
    const token = String(n)
    if (!isTaken(token)) return `User ${token}`
  }
  return 'User'
}

function getKeyModifiers(event: { altKey?: boolean; ctrlKey?: boolean; metaKey?: boolean; shiftKey?: boolean }): number {
  let mask = 0
  if (event.altKey) mask |= 1
  if (event.ctrlKey) mask |= 2
  if (event.metaKey) mask |= 4
  if (event.shiftKey) mask |= 8
  return mask
}

function resolveInitialMode(editingPersona: PublicPersona | null): {
  mode: UniversalAuthMode
  staticKind: StaticCredentialKind
  adapter: PersonaLoginAdapter
} {
  if (!editingPersona) {
    return { mode: 'browser_session', staticKind: 'cookie', adapter: 'auto' }
  }
  if (editingPersona.authKind === 'login') {
    const adapterStr = (editingPersona.loginConfig?.adapter as string | undefined) ?? 'auto'
    if (adapterStr === 'browser_session') {
      return { mode: 'browser_session', staticKind: 'cookie', adapter: 'auto' }
    }
    return {
      mode: 'automated_login',
      staticKind: 'cookie',
      adapter: (editingPersona.loginConfig?.adapter ?? 'auto') as PersonaLoginAdapter,
    }
  }
  return {
    mode: 'header_cookie',
    staticKind: editingPersona.authKind,
    adapter: 'auto',
  }
}

export function PersonaFormModal({
  open,
  onClose,
  project,
  existingPersonas,
  editingPersona = null,
  onCreated,
  submitLabel = 'Save test account',
}: Props) {
  const [authMode, setAuthMode] = useState<UniversalAuthMode>('browser_session')
  const [staticKind, setStaticKind] = useState<StaticCredentialKind>('cookie')
  const [loginAdapter, setLoginAdapter] = useState<PersonaLoginAdapter>('auto')
  const [loginEmail, setLoginEmail] = useState('')
  const [loginUrl, setLoginUrl] = useState('')
  const [verifyPath, setVerifyPath] = useState('')
  const [roleLabel, setRoleLabel] = useState(() => suggestNextAccountLabel(existingPersonas))
  const [headerName, setHeaderName] = useState('')
  const [origins, setOrigins] = useState(() => project.seeds.join('\n'))
  const [secret, setSecret] = useState('')
  const [curlPaste, setCurlPaste] = useState('')
  const [curlNote, setCurlNote] = useState('')
  const [advancedOpen, setAdvancedOpen] = useState(false)

  // Browser Session live-capture & storageState import state
  const [activeCapture, setActiveCapture] = useState<ActiveCaptureSession | null>(null)
  const [captureUrlInput, setCaptureUrlInput] = useState('')
  const [captureBusy, setCaptureBusy] = useState(false)
  const [captureError, setCaptureError] = useState('')
  const [capturedBundleJson, setCapturedBundleJson] = useState('')
  const [capturedSummary, setCapturedSummary] = useState<CaptureSummary | null>(null)
  const [importOpen, setImportOpen] = useState(false)
  const [importJsonText, setImportJsonText] = useState('')
  const [importNote, setImportNote] = useState('')

  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const eventSourceRef = useRef<EventSource | null>(null)
  const lastMoveSentRef = useRef(0)
  const activeCaptureIdRef = useRef<string | null>(null)
  const personaAction = useAction()

  const isBrowserSessionMode = authMode === 'browser_session'
  const isClerkClient = authMode === 'automated_login' && loginAdapter === 'clerk_client'
  const effectiveAuthKind: PersonaAuthKind = authMode === 'header_cookie' ? staticKind : 'login'

  const editingAdapterStr = editingPersona?.authKind === 'login'
    ? ((editingPersona.loginConfig?.adapter as string | undefined) ?? 'auto')
    : null
  const editingIsBrowserSession = editingAdapterStr === 'browser_session'
  const editingIsClerkClient = editingAdapterStr === 'clerk_client'

  const keepingSameAuthKind = Boolean(
    editingPersona &&
    (
      (isBrowserSessionMode && editingIsBrowserSession) ||
      (authMode === 'header_cookie' && editingPersona.authKind === staticKind) ||
      (authMode === 'automated_login' && editingPersona.authKind === 'login' && !editingIsBrowserSession && editingIsClerkClient === isClerkClient)
    ),
  )
  const secretRequired = !keepingSameAuthKind

  function closeLiveStream() {
    if (eventSourceRef.current) {
      eventSourceRef.current.close()
      eventSourceRef.current = null
    }
  }

  async function cancelActiveCaptureSession(captureId?: string | null) {
    const idToCancel = captureId ?? activeCaptureIdRef.current
    closeLiveStream()
    activeCaptureIdRef.current = null
    setActiveCapture(null)
    if (!idToCancel) return
    try {
      await fetch(`/_kovo/auth-capture/${encodeURIComponent(idToCancel)}/cancel`, {
        method: 'POST',
        credentials: 'same-origin',
      })
    } catch {
      // Best-effort cleanup on close/cancel.
    }
  }

  useEffect(() => () => {
    void cancelActiveCaptureSession()
  }, [])

  useEffect(() => {
    if (!open) {
      void cancelActiveCaptureSession()
      return
    }
    const init = resolveInitialMode(editingPersona)
    setAuthMode(init.mode)
    setStaticKind(init.staticKind)
    setLoginAdapter(init.adapter)
    setCaptureError('')
    setCapturedBundleJson('')
    setCapturedSummary(null)
    setImportOpen(false)
    setImportJsonText('')
    setImportNote('')
    if (editingPersona) {
      setRoleLabel(editingPersona.roleLabel)
      setLoginEmail(editingPersona.loginConfig?.email ?? '')
      setLoginUrl(editingPersona.loginConfig?.loginUrl ?? '')
      const cfg = editingPersona.loginConfig as ({ verifyPath?: string } | null | undefined)
      setVerifyPath(typeof cfg?.verifyPath === 'string' ? cfg.verifyPath : '')
      setHeaderName(editingPersona.headerName ?? '')
      setOrigins(editingPersona.originAllowlist.join('\n'))
      setSecret('')
      setCurlPaste('')
      setCurlNote('')
      setAdvancedOpen(false)
      return
    }
    setRoleLabel(suggestNextAccountLabel(existingPersonas))
    setHeaderName('')
    setLoginEmail('')
    setLoginUrl('')
    setVerifyPath('')
    setOrigins(project.seeds.join('\n'))
    setSecret('')
    setCurlPaste('')
    setCurlNote('')
    setAdvancedOpen(false)
  }, [open, project.id, project.seeds, existingPersonas, editingPersona])

  // Stream live CDP JPEG frames onto the embedded <canvas> whenever a capture session is active.
  useEffect(() => {
    if (!activeCapture) {
      closeLiveStream()
      return
    }
    const es = new EventSource(`/_kovo/auth-capture/${encodeURIComponent(activeCapture.captureId)}/stream`)
    eventSourceRef.current = es

    const handleFrame = (ev: MessageEvent) => {
      try {
        const frame = JSON.parse(ev.data) as { data?: string; url?: string }
        if (frame.url) setCaptureUrlInput(frame.url)
        if (!frame.data || !canvasRef.current) return
        const img = new Image()
        img.onload = () => {
          const canvas = canvasRef.current
          if (!canvas) return
          const ctx = canvas.getContext('2d')
          if (!ctx) return
          ctx.drawImage(img, 0, 0, canvas.width, canvas.height)
        }
        img.src = `data:image/jpeg;base64,${frame.data}`
      } catch {
        // Ignore malformed frame payload.
      }
    }

    const handleUrl = (ev: MessageEvent) => {
      try {
        const payload = JSON.parse(ev.data) as { url?: string }
        if (payload.url) setCaptureUrlInput(payload.url)
      } catch { /* ignore */ }
    }

    const handleStatus = (ev: MessageEvent) => {
      try {
        const payload = JSON.parse(ev.data) as { state?: string; reason?: string }
        if (payload.state && payload.state !== 'active') {
          closeLiveStream()
          activeCaptureIdRef.current = null
          setActiveCapture(null)
          if (payload.state === 'expired') {
            setCaptureError(payload.reason || 'Browser sign-in session expired (5 min limit). Start again.')
          }
        }
      } catch { /* ignore */ }
    }

    es.addEventListener('frame', handleFrame as EventListener)
    es.addEventListener('url', handleUrl as EventListener)
    es.addEventListener('status', handleStatus as EventListener)
    es.onerror = () => {
      // EventSource auto-reconnects unless the session ended.
    }

    return () => {
      es.close()
      if (eventSourceRef.current === es) eventSourceRef.current = null
    }
  }, [activeCapture])

  function resetForm() {
    void cancelActiveCaptureSession()
    setRoleLabel(suggestNextAccountLabel(existingPersonas))
    setHeaderName('')
    setAuthMode('browser_session')
    setStaticKind('cookie')
    setLoginAdapter('auto')
    setLoginEmail('')
    setLoginUrl('')
    setVerifyPath('')
    setOrigins(project.seeds.join('\n'))
    setSecret('')
    setCurlPaste('')
    setCurlNote('')
    setCapturedBundleJson('')
    setCapturedSummary(null)
    setImportOpen(false)
    setImportJsonText('')
    setImportNote('')
    setCaptureError('')
    setAdvancedOpen(false)
  }

  function applyCurlParse(rawText: string) {
    const parsed = parseCurlOrHeaderInput(rawText)
    if (!parsed?.recommended) {
      setCurlNote('Could not detect a Cookie:, Authorization: Bearer, or custom auth header.')
      return
    }
    setAuthMode('header_cookie')
    setStaticKind(parsed.recommended.authKind)
    if (parsed.recommended.headerName) setHeaderName(parsed.recommended.headerName)
    if (parsed.origin && !origins.includes(parsed.origin)) {
      setOrigins(prev => prev.trim() ? `${prev.trim()}\n${parsed.origin}` : parsed.origin!)
    }
    setSecret(parsed.recommended.secret)
    setCurlPaste('')
    setCurlNote(parsed.recommended.summary)
  }

  function validateAndStageStorageStateJson(rawText: string) {
    const trimmed = rawText.trim()
    if (!trimmed) {
      setImportNote('Paste or select a Playwright storageState.json file.')
      return
    }
    try {
      const parsed = JSON.parse(trimmed) as Record<string, unknown>
      const inner = parsed.kind === 'browser_session' && parsed.storageState && typeof parsed.storageState === 'object'
        ? (parsed.storageState as { cookies?: unknown[]; origins?: unknown[] })
        : (parsed as { cookies?: unknown[]; origins?: unknown[] })
      const cookies = Array.isArray(inner.cookies) ? inner.cookies : []
      const originList = Array.isArray(inner.origins) ? inner.origins : []
      if (!cookies.length && !originList.length) {
        setImportNote('JSON must contain a Playwright storageState with "cookies" and/or "origins".')
        return
      }
      const allowlist = origins.split(/[\s,]+/).filter(Boolean)
      const firstOrigin = allowlist[0] || project.seeds[0] || ''
      setCapturedBundleJson(trimmed)
      setCapturedSummary({
        targetOrigin: firstOrigin,
        capturedAt: Date.now(),
        cookieCount: cookies.length,
        originCount: originList.length,
        hasAuthorizationHeader: Boolean(
          parsed.observedHeaders && typeof parsed.observedHeaders === 'object' &&
          'Authorization' in (parsed.observedHeaders as Record<string, unknown>),
        ),
      })
      setImportNote(`Staged storageState.json (${cookies.length} cookies across ${originList.length} origin${originList.length === 1 ? '' : 's'}).`)
      setCaptureError('')
    } catch {
      setImportNote('Invalid JSON — export storageState.json from Playwright or DevTools.')
    }
  }

  async function handleStartInteractiveCapture() {
    const allowlist = origins.split(/[\s,]+/).filter(Boolean)
    const targetOrigin = allowlist[0] || project.seeds[0]
    if (!targetOrigin) {
      setCaptureError('Add at least one allowed site origin in Advanced configuration first.')
      setAdvancedOpen(true)
      return
    }
    setCaptureBusy(true)
    setCaptureError('')
    try {
      await cancelActiveCaptureSession()
      const res = await fetch('/_kovo/auth-capture/start', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          projectId: project.id,
          targetOrigin,
          allowedOrigins: allowlist,
        }),
      })
      const payload = await res.json().catch(() => ({})) as {
        captureId?: string
        targetOrigin?: string
        currentUrl?: string
        expiresAt?: number
        viewport?: { width: number; height: number }
        error?: string
      }
      if (!res.ok || !payload.captureId) {
        throw new Error(payload.error || `Could not launch interactive browser (HTTP ${res.status}).`)
      }
      activeCaptureIdRef.current = payload.captureId
      setActiveCapture({
        captureId: payload.captureId,
        targetOrigin: payload.targetOrigin || targetOrigin,
        expiresAt: payload.expiresAt || Date.now() + 5 * 60 * 1000,
        viewport: payload.viewport || { width: 1280, height: 800 },
      })
      setCaptureUrlInput(payload.currentUrl || targetOrigin)
    } catch (err) {
      setCaptureError(err instanceof Error ? err.message : 'Unable to start browser sign-in.')
    } finally {
      setCaptureBusy(false)
    }
  }

  async function handleCompleteInteractiveCapture() {
    if (!activeCapture) return
    setCaptureBusy(true)
    setCaptureError('')
    const id = activeCapture.captureId
    try {
      const res = await fetch(`/_kovo/auth-capture/${encodeURIComponent(id)}/complete`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({}),
      })
      const payload = await res.json().catch(() => ({})) as {
        ok?: boolean
        bundle?: unknown
        summary?: CaptureSummary
        error?: string
      }
      if (!res.ok || !payload.bundle) {
        throw new Error(payload.error || `Could not capture browser session (HTTP ${res.status}).`)
      }
      closeLiveStream()
      activeCaptureIdRef.current = null
      setActiveCapture(null)
      setCapturedBundleJson(JSON.stringify(payload.bundle))
      if (payload.summary) setCapturedSummary(payload.summary)
    } catch (err) {
      setCaptureError(err instanceof Error ? err.message : 'Unable to capture browser session.')
    } finally {
      setCaptureBusy(false)
    }
  }

  async function sendCaptureInput(body: Record<string, unknown>) {
    const id = activeCaptureIdRef.current
    if (!id) return
    try {
      const res = await fetch(`/_kovo/auth-capture/${encodeURIComponent(id)}/input`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (res.ok) {
        const data = await res.json().catch(() => ({})) as { url?: string }
        if (data.url && body.kind === 'navigate') setCaptureUrlInput(data.url)
      }
    } catch {
      // Ignore transient input errors during navigation.
    }
  }

  function mapCanvasCoords(e: React.MouseEvent<HTMLCanvasElement>): { x: number; y: number } {
    const canvas = canvasRef.current
    const vp = activeCapture?.viewport ?? { width: 1280, height: 800 }
    if (!canvas) return { x: 0, y: 0 }
    const rect = canvas.getBoundingClientRect()
    if (!rect.width || !rect.height) return { x: 0, y: 0 }
    return {
      x: Math.max(0, Math.min(vp.width, Math.round(((e.clientX - rect.left) / rect.width) * vp.width))),
      y: Math.max(0, Math.min(vp.height, Math.round(((e.clientY - rect.top) / rect.height) * vp.height))),
    }
  }

  function handleCanvasMouse(type: 'mousePressed' | 'mouseReleased' | 'mouseMoved', e: React.MouseEvent<HTMLCanvasElement>) {
    if (!activeCapture) return
    if (type === 'mouseMoved') {
      const now = Date.now()
      if (now - lastMoveSentRef.current < 45) return
      lastMoveSentRef.current = now
    }
    if (type === 'mousePressed') {
      canvasRef.current?.focus()
    }
    const { x, y } = mapCanvasCoords(e)
    const button = e.button === 2 ? 'right' : e.button === 1 ? 'middle' : 'left'
    void sendCaptureInput({
      kind: 'mouse',
      type,
      x,
      y,
      button: type === 'mouseMoved' ? 'none' : button,
      clickCount: type === 'mouseMoved' ? undefined : (e.detail || 1),
      modifiers: getKeyModifiers(e),
    })
  }

  function handleCanvasWheel(e: React.WheelEvent<HTMLCanvasElement>) {
    if (!activeCapture) return
    e.preventDefault()
    const { x, y } = mapCanvasCoords(e)
    void sendCaptureInput({
      kind: 'mouse',
      type: 'mouseWheel',
      x,
      y,
      deltaX: Math.round(e.deltaX),
      deltaY: Math.round(e.deltaY),
    })
  }

  function handleCanvasKeyDown(e: React.KeyboardEvent<HTMLCanvasElement>) {
    if (!activeCapture) return
    if (e.key === 'Escape') return // allow dialog escape if needed
    e.preventDefault()
    e.stopPropagation()
    const isPrintable = e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey
    if (isPrintable) {
      void sendCaptureInput({ kind: 'key', type: 'insertText', text: e.key })
      return
    }
    void sendCaptureInput({
      kind: 'key',
      type: 'keyDown',
      key: e.key,
      code: e.code,
      windowsVirtualKeyCode: e.keyCode || undefined,
      modifiers: getKeyModifiers(e),
    })
  }

  function handleCanvasKeyUp(e: React.KeyboardEvent<HTMLCanvasElement>) {
    if (!activeCapture) return
    if (e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) return
    e.preventDefault()
    e.stopPropagation()
    void sendCaptureInput({
      kind: 'key',
      type: 'keyUp',
      key: e.key,
      code: e.code,
      windowsVirtualKeyCode: e.keyCode || undefined,
      modifiers: getKeyModifiers(e),
    })
  }

  function handleCanvasPaste(e: React.ClipboardEvent<HTMLCanvasElement>) {
    if (!activeCapture) return
    const text = e.clipboardData.getData('text')
    if (!text) return
    e.preventDefault()
    void sendCaptureInput({ kind: 'key', type: 'insertText', text })
  }

  function handleSubmit(event: React.FormEvent) {
    event.preventDefault()
    const cleanLabel = roleLabel.trim() || suggestNextAccountLabel(existingPersonas)
    const generatedHandle = deriveUniqueHandle(
      cleanLabel,
      existingPersonas.map(p => p.handle),
    )
    const allowlist = origins.split(/[\s,]+/).filter(Boolean)
    if (allowlist.length === 0) {
      setAdvancedOpen(true)
    }

    // Mode 1: Universal Browser Session (interactive live capture or storageState.json import)
    if (isBrowserSessionMode) {
      const storageState = capturedBundleJson.trim() || importJsonText.trim()
      if (!keepingSameAuthKind && !storageState) {
        setCaptureError('Sign in with the embedded browser or import a storageState.json file first.')
        return
      }
      const cleanVerifyPath = verifyPath.trim()
      if (editingPersona) {
        void personaAction.submit(() => updateBrowserSessionPersonaAction({ data: {
          requestId: crypto.randomUUID(),
          projectId: project.id,
          personaId: editingPersona.id,
          roleLabel: cleanLabel,
          originAllowlist: allowlist,
          ...(storageState ? { storageState } : {}),
          ...(cleanVerifyPath ? { verifyPath: cleanVerifyPath } : {}),
        } }), updated => {
          resetForm()
          onClose()
          onCreated(updated)
        })
        return
      }
      void personaAction.submit(() => registerBrowserSessionPersona({ data: {
        requestId: crypto.randomUUID(),
        projectId: project.id,
        handle: generatedHandle,
        roleLabel: cleanLabel,
        originAllowlist: allowlist,
        storageState,
        ...(cleanVerifyPath ? { verifyPath: cleanVerifyPath } : {}),
        canaryMarkers: [],
      } }), created => {
        resetForm()
        onClose()
        onCreated(created)
      })
      return
    }

    // Mode 2 (Header / Cookie / cURL) & Mode 3 (Automated Login CI / Staging)
    const headerNameRaw = headerName.trim()
    const loginUrlRaw = loginUrl.trim()
    if (editingPersona) {
      void personaAction.submit(() => updatePersona({ data: {
        requestId: crypto.randomUUID(),
        projectId: project.id,
        personaId: editingPersona.id,
        roleLabel: cleanLabel,
        originAllowlist: allowlist,
        authKind: effectiveAuthKind,
        ...(effectiveAuthKind === 'header' && headerNameRaw ? { headerName: headerNameRaw } : {}),
        ...(effectiveAuthKind === 'login' ? {
          loginConfig: {
            adapter: isClerkClient ? 'clerk_client' : loginAdapter,
            ...(!isClerkClient ? { email: loginEmail.trim() } : {}),
            ...(loginUrlRaw ? { loginUrl: loginUrlRaw } : {}),
          },
        } : {}),
        ...(secret.trim() ? { secret } : {}),
      } }), updated => {
        resetForm()
        onClose()
        onCreated(updated)
      })
      return
    }
    void personaAction.submit(() => registerPersona({ data: {
      requestId: crypto.randomUUID(),
      projectId: project.id,
      handle: generatedHandle,
      roleLabel: cleanLabel,
      originAllowlist: allowlist,
      authKind: effectiveAuthKind,
      ...(effectiveAuthKind === 'header' && headerNameRaw ? { headerName: headerNameRaw } : {}),
      ...(effectiveAuthKind === 'login' ? {
        loginConfig: {
          adapter: isClerkClient ? 'clerk_client' : loginAdapter,
          ...(!isClerkClient ? { email: loginEmail.trim() } : {}),
          ...(loginUrlRaw ? { loginUrl: loginUrlRaw } : {}),
        },
      } : {}),
      secret,
      canaryMarkers: [],
    } }), created => {
      resetForm()
      onClose()
      onCreated(created)
    })
  }

  return (
    <Dialog
      open={open}
      closeOnEscape={!personaAction.pending && !activeCapture}
      onOpenChange={nextOpen => {
        if (!nextOpen && !personaAction.pending) {
          void cancelActiveCaptureSession()
          onClose()
        }
      }}
    >
      <DialogContent className={`flex max-h-[calc(100vh-48px)] flex-col overflow-hidden p-0 transition-all ${activeCapture ? 'max-w-[920px]' : 'max-w-[700px]'}`}>
        <form className="flex min-h-0 flex-1 flex-col" onSubmit={handleSubmit}>
          <DialogHeader className="flex-row items-center justify-between gap-2.5 border-b border-line bg-raise px-4 py-2.5">
            <DialogTitle className="text-[13px] font-semibold text-fg">
              {editingPersona ? 'Edit test account' : 'Add test account'}
            </DialogTitle>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="size-[26px]"
              onClick={() => {
                void cancelActiveCaptureSession()
                onClose()
              }}
              disabled={personaAction.pending}
              aria-label="Close"
            >
              <Icon name="close" size={14} />
            </Button>
          </DialogHeader>

          <DialogBody className="flex min-h-0 flex-1 flex-col gap-3.5 overflow-y-auto p-4">
            <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
              Account label
              <Input
                className="w-full"
                name="roleLabel"
                required
                maxLength={160}
                placeholder="User A"
                value={roleLabel}
                onChange={e => setRoleLabel(e.target.value)}
              />
            </label>

            {/* Universal 3-Mode Auth Selector */}
            <div className="grid gap-1.5" role="radiogroup" aria-label="Authentication mode">
              <span className="text-[12px] font-medium text-fg-muted">Authentication method</span>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                <button
                  type="button"
                  role="radio"
                  aria-checked={authMode === 'browser_session'}
                  onClick={() => {
                    setAuthMode('browser_session')
                    setCaptureError('')
                  }}
                  className={`flex flex-col items-start gap-1 rounded-[7px] border p-2.5 text-left transition-colors ${
                    authMode === 'browser_session'
                      ? 'border-accent bg-accent-soft/50 text-fg'
                      : 'border-line bg-panel text-fg-muted hover:bg-hover'
                  }`}
                >
                  <div className="flex w-full items-center justify-between gap-1.5">
                    <span className="text-[12.5px] font-semibold text-fg">Browser Session</span>
                    <Badge variant="accent">Recommended</Badge>
                  </div>
                  <span className="text-[11px] leading-snug text-fg-subtle">
                    Works with SSO, Passkeys, MFA, CAPTCHA, Clerk, Auth0, Supabase &amp; auto-refreshes.
                  </span>
                </button>

                <button
                  type="button"
                  role="radio"
                  aria-checked={authMode === 'header_cookie'}
                  onClick={() => {
                    void cancelActiveCaptureSession()
                    setAuthMode('header_cookie')
                  }}
                  className={`flex flex-col items-start gap-1 rounded-[7px] border p-2.5 text-left transition-colors ${
                    authMode === 'header_cookie'
                      ? 'border-accent bg-accent-soft/50 text-fg'
                      : 'border-line bg-panel text-fg-muted hover:bg-hover'
                  }`}
                >
                  <span className="text-[12.5px] font-semibold text-fg">Header / Cookie / cURL</span>
                  <span className="text-[11px] leading-snug text-fg-subtle">
                    Paste Bearer token, Cookie, custom header, or DevTools Copy as cURL.
                  </span>
                </button>

                <button
                  type="button"
                  role="radio"
                  aria-checked={authMode === 'automated_login'}
                  onClick={() => {
                    void cancelActiveCaptureSession()
                    setAuthMode('automated_login')
                  }}
                  className={`flex flex-col items-start gap-1 rounded-[7px] border p-2.5 text-left transition-colors ${
                    authMode === 'automated_login'
                      ? 'border-accent bg-accent-soft/50 text-fg'
                      : 'border-line bg-panel text-fg-muted hover:bg-hover'
                  }`}
                >
                  <span className="text-[12.5px] font-semibold text-fg">Automated Login (CI / Staging)</span>
                  <span className="text-[11px] leading-snug text-fg-subtle">
                    Email + password form/JSON sign-in for non-MFA local labs &amp; staging CI.
                  </span>
                </button>
              </div>
            </div>

            {/* Mode 1: Universal Browser Session (Embedded Live-Login Canvas + storageState.json Fallback) */}
            {authMode === 'browser_session' && (
              <div className="grid gap-2.5 rounded-[7px] border border-line bg-sunk/60 p-3">
                {!activeCapture ? (
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <Button
                        type="button"
                        variant="default"
                        disabled={captureBusy || personaAction.pending}
                        onClick={() => void handleStartInteractiveCapture()}
                      >
                        <Icon name="globe" size={14} />
                        {captureBusy ? 'Launching browser…' : 'Sign in with browser'}
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
                        disabled={captureBusy || personaAction.pending}
                        onClick={() => setImportOpen(prev => !prev)}
                      >
                        {importOpen ? 'Hide storageState import' : 'Import storageState.json'}
                      </Button>
                    </div>
                    {capturedSummary && (
                      <Badge variant="ok">
                        Captured {capturedSummary.cookieCount} cookie{capturedSummary.cookieCount === 1 ? '' : 's'}
                        {capturedSummary.originCount > 0 ? ` · ${capturedSummary.originCount} origin${capturedSummary.originCount === 1 ? '' : 's'}` : ''}
                        {capturedSummary.hasAuthorizationHeader ? ' · Bearer' : ''}
                      </Badge>
                    )}
                    {!capturedSummary && keepingSameAuthKind && (
                      <span className="text-[11.5px] text-fg-subtle">
                        Leave blank to keep existing secret (or re-capture to refresh cookies).
                      </span>
                    )}
                  </div>
                ) : (
                  <div className="grid gap-2">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <Input
                        className="min-w-0 flex-1 font-mono text-[12px]"
                        aria-label="Browser address bar"
                        value={captureUrlInput}
                        onChange={e => setCaptureUrlInput(e.target.value)}
                        onKeyDown={e => {
                          if (e.key === 'Enter') {
                            e.preventDefault()
                            void sendCaptureInput({ kind: 'navigate', url: captureUrlInput })
                          }
                        }}
                        placeholder="https://app.example.com/login"
                      />
                      <Button
                        type="button"
                        variant="outline"
                        disabled={captureBusy}
                        onClick={() => void sendCaptureInput({ kind: 'navigate', url: captureUrlInput })}
                      >
                        Go
                      </Button>
                      <Button
                        type="button"
                        variant="default"
                        disabled={captureBusy}
                        onClick={() => void handleCompleteInteractiveCapture()}
                      >
                        <Icon name="check" size={13} />
                        {captureBusy ? 'Capturing…' : "I'm signed in — capture session"}
                      </Button>
                      <Button
                        type="button"
                        variant="ghost"
                        disabled={captureBusy}
                        onClick={() => void cancelActiveCaptureSession()}
                      >
                        Cancel browser
                      </Button>
                    </div>
                    <div className="relative overflow-hidden rounded-[6px] border border-line bg-black">
                      <canvas
                        ref={canvasRef}
                        width={activeCapture.viewport.width}
                        height={activeCapture.viewport.height}
                        tabIndex={0}
                        aria-label="Interactive sign-in browser"
                        className="block aspect-[16/10] w-full cursor-pointer outline-none focus:ring-2 focus:ring-accent"
                        onMouseDown={e => handleCanvasMouse('mousePressed', e)}
                        onMouseUp={e => handleCanvasMouse('mouseReleased', e)}
                        onMouseMove={e => handleCanvasMouse('mouseMoved', e)}
                        onWheel={handleCanvasWheel}
                        onKeyDown={handleCanvasKeyDown}
                        onKeyUp={handleCanvasKeyUp}
                        onPaste={handleCanvasPaste}
                        onContextMenu={e => e.preventDefault()}
                      />
                    </div>
                    <p className="m-0 text-[11.5px] text-fg-subtle">
                      Click inside the browser to focus and sign in (including SSO, MFA, Passkeys, or CAPTCHA). When you reach your signed-in app view, click <strong>I&apos;m signed in — capture session</strong>.
                    </p>
                  </div>
                )}

                {importOpen && !activeCapture && (
                  <div className="grid gap-1.5 border-t border-line pt-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="text-[12px] font-medium text-fg-muted">
                        Import Playwright <code className="font-mono">storageState.json</code>
                      </span>
                      <label className="cursor-pointer text-[11.5px] font-medium text-accent hover:underline">
                        Choose .json file
                        <input
                          type="file"
                          accept=".json,application/json"
                          className="sr-only"
                          onChange={e => {
                            const file = e.target.files?.[0]
                            if (!file) return
                            void file.text().then(text => {
                              setImportJsonText(text)
                              validateAndStageStorageStateJson(text)
                            })
                          }}
                        />
                      </label>
                    </div>
                    <Textarea
                      className="w-full font-mono text-[11.5px]"
                      rows={4}
                      value={importJsonText}
                      onChange={e => setImportJsonText(e.target.value)}
                      placeholder='{"cookies": [...], "origins": [...]}'
                    />
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[11.5px] text-fg-subtle">{importNote}</span>
                      <Button
                        type="button"
                        variant="outline"
                        disabled={!importJsonText.trim()}
                        onClick={() => validateAndStageStorageStateJson(importJsonText)}
                      >
                        Validate JSON
                      </Button>
                    </div>
                  </div>
                )}

                {captureError && (
                  <p className="m-0 text-[12px] text-danger" role="alert">
                    {captureError}
                  </p>
                )}
              </div>
            )}

            {/* Mode 2: Header / Cookie / cURL */}
            {authMode === 'header_cookie' && (
              <div className="grid gap-2.5">
                <div className="grid gap-1.5">
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
                      placeholder="Paste DevTools Copy as cURL, Cookie:, or Authorization: Bearer header…"
                    />
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => applyCurlParse(curlPaste)}
                      disabled={!curlPaste.trim()}
                    >
                      Paste from cURL
                    </Button>
                  </div>
                  {curlNote && <span className="text-[11.5px] text-fg-subtle">{curlNote}</span>}
                </div>

                <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                  Credential type
                  <NativeSelect
                    className="w-full"
                    name="authKind"
                    value={staticKind}
                    onChange={e => setStaticKind(e.target.value as StaticCredentialKind)}
                  >
                    <option value="cookie">Session cookie (Cookie: …)</option>
                    <option value="bearer">Bearer token (Authorization: Bearer …)</option>
                    <option value="header">Custom request header</option>
                  </NativeSelect>
                </label>

                {staticKind === 'header' ? (
                  <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-2">
                    <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                      Header name
                      <Input
                        className="w-full font-mono text-[12px]"
                        name="headerName"
                        required
                        pattern="[A-Za-z0-9-]{1,64}"
                        placeholder="X-Api-Key"
                        value={headerName}
                        onChange={e => setHeaderName(e.target.value)}
                      />
                    </label>
                    <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                      Credential secret
                      <Input
                        className="w-full"
                        name="secret"
                        type="password"
                        required={secretRequired}
                        maxLength={4096}
                        autoComplete="off"
                        value={secret}
                        onChange={e => setSecret(e.target.value)}
                        placeholder={keepingSameAuthKind ? 'Leave blank to keep existing secret' : 'Never displayed back after saving'}
                      />
                    </label>
                  </div>
                ) : (
                  <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                    Credential secret
                    <Input
                      className="w-full"
                      name="secret"
                      type="password"
                      required={secretRequired}
                      maxLength={4096}
                      autoComplete="off"
                      value={secret}
                      onChange={e => setSecret(e.target.value)}
                      placeholder={keepingSameAuthKind ? 'Leave blank to keep existing secret' : 'Never displayed back after saving'}
                    />
                  </label>
                )}
              </div>
            )}

            {/* Mode 3: Automated Login (CI / Staging) */}
            {authMode === 'automated_login' && (
              isClerkClient ? (
                <div className="grid gap-2.5">
                  <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                    Clerk __client cookie (legacy)
                    <Input
                      className="w-full font-mono text-[12px]"
                      name="secret"
                      type="password"
                      required={secretRequired}
                      maxLength={4096}
                      autoComplete="off"
                      value={secret}
                      onChange={e => setSecret(e.target.value)}
                      placeholder={
                        keepingSameAuthKind
                          ? 'Leave blank to keep existing secret'
                          : 'Paste __client cookie value from DevTools (clerk.yourdomain.com)'
                      }
                    />
                    <small className="text-[11.5px] font-normal text-fg-subtle">
                      Legacy adapter — prefer <strong>Browser Session</strong> for universal auto-refresh across all identity providers.
                    </small>
                  </label>
                  <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                    Clerk Frontend API URL (optional)
                    <Input
                      className="w-full"
                      name="loginUrl"
                      type="url"
                      maxLength={500}
                      autoComplete="off"
                      value={loginUrl}
                      onChange={e => setLoginUrl(e.target.value)}
                      placeholder={LOGIN_URL_PLACEHOLDERS.clerk_client}
                    />
                  </label>
                </div>
              ) : (
                <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-2">
                  <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                    Email
                    <Input
                      className="w-full"
                      name="loginEmail"
                      type="email"
                      required
                      maxLength={320}
                      autoComplete="off"
                      value={loginEmail}
                      onChange={e => setLoginEmail(e.target.value)}
                      placeholder="test-a@example.com"
                    />
                  </label>
                  <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                    Password
                    <Input
                      className="w-full"
                      name="secret"
                      type="password"
                      required={secretRequired}
                      maxLength={4096}
                      autoComplete="off"
                      value={secret}
                      onChange={e => setSecret(e.target.value)}
                      placeholder={keepingSameAuthKind ? 'Leave blank to keep existing secret' : 'Encrypted on your machine'}
                    />
                  </label>
                </div>
              )
            )}

            <Disclosure
              open={advancedOpen}
              onOpenChange={setAdvancedOpen}
              className="border-t border-line pt-2.5"
            >
              <DisclosureTrigger className="h-auto bg-transparent px-0 py-1 text-fg-muted shadow-none hover:bg-transparent hover:text-fg">
                Advanced configuration
              </DisclosureTrigger>
              <DisclosureContent className="grid gap-2.5 pt-2.5">
                {authMode === 'browser_session' && (
                  <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                    Auto-refresh path (optional)
                    <Input
                      className="w-full font-mono text-[12px]"
                      name="verifyPath"
                      maxLength={256}
                      autoComplete="off"
                      value={verifyPath}
                      onChange={e => setVerifyPath(e.target.value)}
                      placeholder="/ (e.g. /dashboard or /app)"
                    />
                    <small className="text-[11.5px] font-normal text-fg-subtle">
                      Visited in a headless browser on refresh so the app&apos;s own JS SDK rotates short-lived tokens automatically.
                    </small>
                  </label>
                )}

                {authMode === 'automated_login' && (
                  <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-2">
                    <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                      Auth adapter
                      <NativeSelect
                        className="w-full"
                        name="loginAdapter"
                        value={loginAdapter}
                        onChange={e => setLoginAdapter(e.target.value as PersonaLoginAdapter)}
                      >
                        <option value="auto">Auto-detect</option>
                        <option value="form">Login Form (Browser)</option>
                        <option value="json">JSON API / Better Auth</option>
                        <option value="clerk">Clerk (legacy)</option>
                        <option value="clerk_client">Clerk __client cookie (auto-refresh)</option>
                        <option value="supabase">Supabase Auth (legacy)</option>
                      </NativeSelect>
                    </label>
                    <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                      Login URL (optional)
                      <Input
                        className="w-full"
                        name="loginUrl"
                        type="url"
                        maxLength={500}
                        autoComplete="off"
                        value={loginUrl}
                        onChange={e => setLoginUrl(e.target.value)}
                        placeholder={LOGIN_URL_PLACEHOLDERS[loginAdapter]}
                      />
                    </label>
                  </div>
                )}

                <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                  Allowed sites (one per line or comma-separated)
                  <Textarea
                    className="w-full font-mono text-[12px]"
                    name="originAllowlist"
                    rows={2}
                    value={origins}
                    onChange={e => setOrigins(e.target.value)}
                  />
                </label>
              </DisclosureContent>
            </Disclosure>

            <FormError error={personaAction.error} />
          </DialogBody>

          <DialogFooter className="flex-wrap">
            <span className="mr-auto text-[12px] text-fg-subtle">
              Credentials stay encrypted on your machine and are never sent to AI models.
            </span>
            <Button
              type="button"
              variant="ghost"
              disabled={personaAction.pending}
              onClick={() => {
                void cancelActiveCaptureSession()
                onClose()
              }}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="default"
              disabled={personaAction.pending || Boolean(activeCapture)}
            >
              {personaAction.pending ? 'Saving…' : editingPersona ? 'Save changes' : submitLabel}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
