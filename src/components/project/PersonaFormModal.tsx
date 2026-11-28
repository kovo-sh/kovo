import { useEffect, useMemo, useRef, useState } from 'react'
import { registerPersona, updatePersona } from '../../actions.ts'
import {
  registerBrowserSessionPersona,
  updateBrowserSessionPersonaAction,
} from '../../actions-auth-capture.ts'
import type { PersonaAuthKind, PersonaLoginAdapter, PersonaPrivilege, PublicPersona } from '../../domain.ts'
import { cn } from '../../lib/cn.ts'
import { parseCurlOrHeaderInput } from '../../server/curl-parse.ts'
import { useAction } from '../common.tsx'
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
import { LOGIN_URL_PLACEHOLDERS, safeHost } from './types.ts'

export type UniversalAuthMode = 'browser_session' | 'header_cookie' | 'automated_login'
export type StaticCredentialKind = 'cookie' | 'bearer' | 'header'
export type PersonaSignInMethod = PersonaAuthKind | 'clerk_client' | 'browser_session'

interface CaptureSummary {
  targetOrigin: string
  capturedAt: number
  cookieCount: number
  originCount: number
  origins?: string[]
  headerNames?: string[]
  hasAuthorizationHeader: boolean
  verifyOrigin?: string
  verifyPath?: string
  capturedAppOrigins?: string[]
  capturedIdpOrigins?: string[]
}

interface ActiveCaptureSession {
  captureId: string
  targetOrigin: string
  expiresAt: number
  viewport: { width: number; height: number }
}

const EMPTY_ASSETS: readonly ProjectLoaderData['assets'][number][] = []

export function buildProjectDefaultOrigins(
  project: Pick<ProjectLoaderData['project'], 'seeds' | 'defaultScope'>,
  assets: readonly Pick<ProjectLoaderData['assets'][number], 'origin' | 'thirdParty'>[] = EMPTY_ASSETS,
): string[] {
  const ordered: string[] = []
  const seen = new Set<string>()
  const pushOrigin = (raw: string | undefined | null) => {
    if (typeof raw !== 'string') return
    const trimmed = raw.trim()
    if (!trimmed) return
    let normalized = trimmed
    try {
      normalized = new URL(trimmed).origin
    } catch {
      // Keep raw string when not a full URL; server validation will check it.
    }
    if (seen.has(normalized)) return
    seen.add(normalized)
    ordered.push(normalized)
  }
  for (const origin of project.defaultScope ?? []) pushOrigin(origin)
  for (const origin of project.seeds ?? []) pushOrigin(origin)
  for (const asset of assets ?? []) {
    if (!asset.thirdParty) pushOrigin(asset.origin)
  }
  return ordered
}

function parseOriginList(raw: string): string[] {
  const seen = new Set<string>()
  const result: string[] = []
  for (const item of raw.split(/[\s,]+/)) {
    const trimmed = item.trim()
    if (!trimmed || seen.has(trimmed)) continue
    seen.add(trimmed)
    result.push(trimmed)
  }
  return result
}

interface Props {
  open: boolean
  onClose: () => void
  project: ProjectLoaderData['project']
  assets?: readonly ProjectLoaderData['assets'][number][]
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
  assets = EMPTY_ASSETS,
  existingPersonas,
  editingPersona = null,
  onCreated,
  submitLabel = 'Save test account',
}: Props) {
  const defaultProjectOrigins = useMemo(
    () => buildProjectDefaultOrigins(project, assets),
    [project.seeds, project.defaultScope, assets],
  )
  const [authMode, setAuthMode] = useState<UniversalAuthMode>('browser_session')
  const [staticKind, setStaticKind] = useState<StaticCredentialKind>('cookie')
  const [loginAdapter, setLoginAdapter] = useState<PersonaLoginAdapter>('auto')
  const [loginEmail, setLoginEmail] = useState('')
  const [loginUrl, setLoginUrl] = useState('')
  const [verifyOrigin, setVerifyOrigin] = useState('')
  const [verifyPath, setVerifyPath] = useState('')
  const [idpOriginsText, setIdpOriginsText] = useState('')
  const [selectedStartOrigin, setSelectedStartOrigin] = useState(() => defaultProjectOrigins[0] ?? '')
  const [roleLabel, setRoleLabel] = useState(() => suggestNextAccountLabel(existingPersonas))
  const [tenantRef, setTenantRef] = useState('')
  const [privilege, setPrivilege] = useState<PersonaPrivilege | ''>('')
  const [headerName, setHeaderName] = useState('')
  const [origins, setOrigins] = useState(() => defaultProjectOrigins.join('\n'))
  const [secret, setSecret] = useState('')
  const [secretError, setSecretError] = useState('')
  const [curlPaste, setCurlPaste] = useState('')
  const [curlNote, setCurlNote] = useState('')
  const [advancedOpen, setAdvancedOpen] = useState(false)

  // Browser Session live-capture (server-side escrow captureToken) & explicit storageState import state
  const [activeCapture, setActiveCapture] = useState<ActiveCaptureSession | null>(null)
  const [captureUrlInput, setCaptureUrlInput] = useState('')
  const [currentRemoteUrl, setCurrentRemoteUrl] = useState('')
  const [hasReceivedFrame, setHasReceivedFrame] = useState(false)
  const [navFlags, setNavFlags] = useState({ canBack: false, canForward: false })
  const [captureBusy, setCaptureBusy] = useState(false)
  const [captureError, setCaptureError] = useState('')
  const [browserNavError, setBrowserNavError] = useState('')
  const [capturedToken, setCapturedToken] = useState('')
  const [importedStorageStateJson, setImportedStorageStateJson] = useState('')
  const [capturedSummary, setCapturedSummary] = useState<CaptureSummary | null>(null)
  const [importOpen, setImportOpen] = useState(false)
  const [importJsonText, setImportJsonText] = useState('')
  const [importNote, setImportNote] = useState('')

  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const roleLabelRef = useRef<HTMLInputElement | null>(null)
  const submitErrorRef = useRef<HTMLParagraphElement | null>(null)
  const addressInputRef = useRef<HTMLInputElement | null>(null)
  const eventSourceRef = useRef<EventSource | null>(null)
  const lastMoveSentRef = useRef(0)
  const activeCaptureIdRef = useRef<string | null>(null)
  const isEditingUrlRef = useRef(false)
  const lastSyncedRemoteUrlRef = useRef('')
  const navHistoryRef = useRef<string[]>([])
  const navHistoryIndexRef = useRef(-1)
  const pendingHistoryIndexRef = useRef<number | null>(null)
  const personaAction = useAction()
  useEffect(() => {
    // A pasted/parsed secret or a different auth method makes the inline secret error stale.
    setSecretError('')
  }, [authMode, staticKind, loginAdapter, secret])
  useEffect(() => {
    if (!personaAction.error) return
    submitErrorRef.current?.scrollIntoView({ block: 'nearest' })
    submitErrorRef.current?.focus()
  }, [personaAction.error])

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

  function syncRemoteUrl(
    remoteUrl: string | undefined,
    options?: { force?: boolean; recordHistory?: boolean },
  ) {
    const trimmed = typeof remoteUrl === 'string' ? remoteUrl.trim() : ''
    if (!trimmed) return
    const prevRemote = lastSyncedRemoteUrlRef.current
    const changed = trimmed !== prevRemote
    setCurrentRemoteUrl(trimmed)

    if (options?.recordHistory !== false && changed) {
      if (pendingHistoryIndexRef.current !== null) {
        navHistoryIndexRef.current = pendingHistoryIndexRef.current
        pendingHistoryIndexRef.current = null
      } else {
        const nextStack = navHistoryRef.current.slice(0, navHistoryIndexRef.current + 1)
        if (nextStack[nextStack.length - 1] !== trimmed) {
          nextStack.push(trimmed)
        }
        navHistoryRef.current = nextStack
        navHistoryIndexRef.current = nextStack.length - 1
      }
      setNavFlags({
        canBack: navHistoryIndexRef.current > 0,
        canForward: navHistoryIndexRef.current < navHistoryRef.current.length - 1,
      })
    }

    if (options?.force || (!isEditingUrlRef.current && changed)) {
      lastSyncedRemoteUrlRef.current = trimmed
      setCaptureUrlInput(trimmed)
    } else if (changed) {
      lastSyncedRemoteUrlRef.current = trimmed
    }
  }

  function resolveNavigationTarget(raw: string): string {
    const trimmed = raw.trim()
    if (!trimmed) return ''
    if (/^https?:\/\//i.test(trimmed)) return trimmed
    if (trimmed.startsWith('/') && activeCapture?.targetOrigin) {
      return `${activeCapture.targetOrigin.replace(/\/+$/, '')}${trimmed}`
    }
    if (/^(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?(?:\/|$)/i.test(trimmed)) {
      return `http://${trimmed}`
    }
    return `https://${trimmed}`
  }

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
    isEditingUrlRef.current = false
    lastSyncedRemoteUrlRef.current = ''
    navHistoryRef.current = []
    navHistoryIndexRef.current = -1
    pendingHistoryIndexRef.current = null
    setNavFlags({ canBack: false, canForward: false })
    setHasReceivedFrame(false)
    setCurrentRemoteUrl('')
    setBrowserNavError('')
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
    setBrowserNavError('')
    setCapturedToken('')
    setImportedStorageStateJson('')
    setCapturedSummary(null)
    setImportOpen(false)
    setImportJsonText('')
    setImportNote('')
    if (editingPersona) {
      setRoleLabel(editingPersona.roleLabel)
      setTenantRef(editingPersona.tenantRef ?? '')
      setPrivilege(editingPersona.privilege ?? '')
      setLoginEmail(editingPersona.loginConfig?.email ?? '')
      setLoginUrl(editingPersona.loginConfig?.loginUrl ?? '')
      const cfg = editingPersona.loginConfig
      const nextVerifyOrigin = typeof cfg?.verifyOrigin === 'string' ? cfg.verifyOrigin : ''
      setVerifyOrigin(nextVerifyOrigin)
      setVerifyPath(typeof cfg?.verifyPath === 'string' ? cfg.verifyPath : '')
      setIdpOriginsText(Array.isArray(cfg?.idpOrigins) ? cfg.idpOrigins.join('\n') : '')
      setHeaderName(editingPersona.headerName ?? '')
      setOrigins(editingPersona.originAllowlist.join('\n'))
      setSelectedStartOrigin(
        (nextVerifyOrigin && editingPersona.originAllowlist.includes(nextVerifyOrigin))
          ? nextVerifyOrigin
          : (editingPersona.originAllowlist[0] ?? defaultProjectOrigins[0] ?? ''),
      )
      setSecret('')
      setCurlPaste('')
      setCurlNote('')
      setAdvancedOpen(false)
      return
    }
    setRoleLabel(suggestNextAccountLabel(existingPersonas))
    setTenantRef('')
    setPrivilege('')
    setHeaderName('')
    setLoginEmail('')
    setLoginUrl('')
    setVerifyOrigin('')
    setVerifyPath('')
    setIdpOriginsText('')
    setOrigins(defaultProjectOrigins.join('\n'))
    setSelectedStartOrigin(defaultProjectOrigins[0] ?? '')
    setSecret('')
    setCurlPaste('')
    setCurlNote('')
    setAdvancedOpen(false)
  }, [open, project.id, defaultProjectOrigins, existingPersonas, editingPersona])

  // Stream live CDP JPEG frames onto the embedded <canvas> whenever a capture session is active.
  useEffect(() => {
    if (!activeCapture) {
      closeLiveStream()
      return
    }
    const es = new EventSource(`/_kovo/auth-capture/${encodeURIComponent(activeCapture.captureId)}/stream`)
    eventSourceRef.current = es

    const handleInit = (ev: MessageEvent) => {
      try {
        const payload = JSON.parse(ev.data) as { url?: string; lastError?: string | null }
        if (payload.url) syncRemoteUrl(payload.url)
        if (typeof payload.lastError === 'string' && payload.lastError.trim()) {
          setBrowserNavError(payload.lastError.trim())
        }
      } catch { /* ignore */ }
    }

    const handleFrame = (ev: MessageEvent) => {
      try {
        const frame = JSON.parse(ev.data) as { data?: string; url?: string }
        setCaptureError('')
        if (frame.url) syncRemoteUrl(frame.url)
        if (!frame.data || !canvasRef.current) return
        const img = new Image()
        img.onload = () => {
          const canvas = canvasRef.current
          if (!canvas) return
          const ctx = canvas.getContext('2d')
          if (!ctx) return
          ctx.drawImage(img, 0, 0, canvas.width, canvas.height)
          setHasReceivedFrame(true)
        }
        img.src = `data:image/jpeg;base64,${frame.data}`
      } catch {
        // Ignore malformed frame payload.
      }
    }

    const handleUrl = (ev: MessageEvent) => {
      try {
        const payload = JSON.parse(ev.data) as { url?: string }
        setCaptureError('')
        if (payload.url) syncRemoteUrl(payload.url)
      } catch { /* ignore */ }
    }

    const handleNavError = (ev: MessageEvent) => {
      try {
        const payload = JSON.parse(ev.data) as { message?: string }
        const message = typeof payload.message === 'string' ? payload.message.trim() : ''
        setBrowserNavError(message)
      } catch { /* ignore */ }
    }

    const handleStatus = (ev: MessageEvent) => {
      try {
        const payload = JSON.parse(ev.data) as { state?: string; reason?: string }
        if (payload.state && payload.state !== 'active') {
          closeLiveStream()
          activeCaptureIdRef.current = null
          isEditingUrlRef.current = false
          setActiveCapture(null)
          if (payload.state === 'expired') {
            setCaptureError(payload.reason || 'Browser sign-in session expired (5 min limit). Start again.')
          }
        }
      } catch { /* ignore */ }
    }

    let aborted = false
    es.addEventListener('init', handleInit as EventListener)
    es.addEventListener('frame', handleFrame as EventListener)
    es.addEventListener('url', handleUrl as EventListener)
    es.addEventListener('nav_error', handleNavError as EventListener)
    es.addEventListener('status', handleStatus as EventListener)
    es.onerror = () => {
      if (aborted) return
      void fetch('/_kovo/auth/status', { method: 'HEAD', credentials: 'same-origin', cache: 'no-store' })
        .then(res => {
          if (aborted) return
          if (res.status === 401) {
            closeLiveStream()
            activeCaptureIdRef.current = null
            setActiveCapture(null)
            setCaptureError('Local session expired — open the Kovo startup bootstrap URL to sign back in.')
            return
          }
          if (es.readyState === EventSource.CLOSED) {
            setCaptureError('Live browser stream closed. Start sign-in again if the session expired.')
          } else {
            setCaptureError('Live browser stream interrupted — reconnecting…')
          }
        })
        .catch(() => {
          if (!aborted) setCaptureError('Live browser stream interrupted — reconnecting…')
        })
    }

    return () => {
      aborted = true
      es.close()
      if (eventSourceRef.current === es) eventSourceRef.current = null
    }
  }, [activeCapture])

  function resetForm() {
    void cancelActiveCaptureSession()
    setRoleLabel(suggestNextAccountLabel(existingPersonas))
    setTenantRef('')
    setPrivilege('')
    setHeaderName('')
    setAuthMode('browser_session')
    setStaticKind('cookie')
    setLoginAdapter('auto')
    setLoginEmail('')
    setLoginUrl('')
    setVerifyOrigin('')
    setVerifyPath('')
    setIdpOriginsText('')
    setOrigins(defaultProjectOrigins.join('\n'))
    setSelectedStartOrigin(defaultProjectOrigins[0] ?? '')
    setSecret('')
    setSecretError('')
    setCurlPaste('')
    setCurlNote('')
    setCapturedToken('')
    setImportedStorageStateJson('')
    setCapturedSummary(null)
    setImportOpen(false)
    setImportJsonText('')
    setImportNote('')
    setCaptureError('')
    setBrowserNavError('')
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
      setCapturedToken('')
      setImportedStorageStateJson(trimmed)
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

  const startingHostOptions = useMemo(() => {
    const combined = [...parseOriginList(origins), ...defaultProjectOrigins]
    const seen = new Set<string>()
    const result: string[] = []
    for (const item of combined) {
      if (!item || seen.has(item)) continue
      seen.add(item)
      result.push(item)
    }
    return result
  }, [origins, defaultProjectOrigins])

  const effectiveStartOrigin = startingHostOptions.includes(selectedStartOrigin)
    ? selectedStartOrigin
    : (startingHostOptions[0] ?? '')

  async function handleStartInteractiveCapture() {
    const allowlist = parseOriginList(origins)
    const targetOrigin = effectiveStartOrigin || allowlist[0] || defaultProjectOrigins[0]
    if (!targetOrigin) {
      setCaptureError('Add at least one allowed site origin in Advanced configuration first.')
      setAdvancedOpen(true)
      return
    }
    const mergedAllowlist = [...new Set([targetOrigin, ...allowlist, ...defaultProjectOrigins])]
    setCaptureBusy(true)
    setCaptureError('')
    setBrowserNavError('')
    try {
      await cancelActiveCaptureSession()
      const res = await fetch('/_kovo/auth-capture/start', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          projectId: project.id,
          targetOrigin,
          allowedOrigins: mergedAllowlist,
        }),
      })
      const payload = await res.json().catch(() => ({})) as {
        captureId?: string
        targetOrigin?: string
        currentUrl?: string
        lastError?: string | null
        expiresAt?: number
        viewport?: { width: number; height: number }
        error?: string
      }
      if (!res.ok || !payload.captureId) {
        throw new Error(payload.error || `Could not launch interactive browser (HTTP ${res.status}).`)
      }
      activeCaptureIdRef.current = payload.captureId
      const initialUrl = payload.currentUrl || targetOrigin
      isEditingUrlRef.current = false
      lastSyncedRemoteUrlRef.current = initialUrl
      navHistoryRef.current = [initialUrl]
      navHistoryIndexRef.current = 0
      pendingHistoryIndexRef.current = null
      setNavFlags({ canBack: false, canForward: false })
      setHasReceivedFrame(false)
      setCurrentRemoteUrl(initialUrl)
      setCaptureUrlInput(initialUrl)
      setBrowserNavError(typeof payload.lastError === 'string' ? payload.lastError : '')
      setActiveCapture({
        captureId: payload.captureId,
        targetOrigin: payload.targetOrigin || targetOrigin,
        expiresAt: payload.expiresAt || Date.now() + 5 * 60 * 1000,
        viewport: payload.viewport || { width: 1280, height: 800 },
      })
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
        captureToken?: string
        verifyOrigin?: string
        verifyPath?: string
        capturedAppOrigins?: string[]
        capturedIdpOrigins?: string[]
        summary?: CaptureSummary
        error?: string
      }
      if (!res.ok || !payload.captureToken) {
        throw new Error(payload.error || `Could not capture browser session (HTTP ${res.status}).`)
      }
      closeLiveStream()
      activeCaptureIdRef.current = null
      isEditingUrlRef.current = false
      lastSyncedRemoteUrlRef.current = ''
      navHistoryRef.current = []
      navHistoryIndexRef.current = -1
      pendingHistoryIndexRef.current = null
      setNavFlags({ canBack: false, canForward: false })
      setHasReceivedFrame(false)
      setBrowserNavError('')
      setActiveCapture(null)
      setCapturedToken(payload.captureToken)
      setImportedStorageStateJson('')
      setImportJsonText('')

      const nextVerifyOrigin = payload.verifyOrigin || payload.summary?.verifyOrigin || activeCapture.targetOrigin
      const nextVerifyPath = payload.verifyPath || payload.summary?.verifyPath || '/'
      const nextAppOrigins = payload.capturedAppOrigins ?? payload.summary?.capturedAppOrigins ?? (nextVerifyOrigin ? [nextVerifyOrigin] : [])
      const nextIdpOrigins = payload.capturedIdpOrigins ?? payload.summary?.capturedIdpOrigins ?? []

      const existingOrigins = parseOriginList(origins)
      const mergedAppOrigins = [
        ...(nextVerifyOrigin ? [nextVerifyOrigin] : []),
        ...nextAppOrigins,
        ...existingOrigins,
      ].filter((origin, idx, arr) => Boolean(origin) && arr.indexOf(origin) === idx)
      if (mergedAppOrigins.length > 0) {
        setOrigins(mergedAppOrigins.join('\n'))
      }
      if (nextVerifyOrigin) {
        setVerifyOrigin(nextVerifyOrigin)
        setSelectedStartOrigin(nextVerifyOrigin)
      }
      setVerifyPath(nextVerifyPath)

      const existingIdpOrigins = parseOriginList(idpOriginsText)
      const mergedIdpOrigins = [...existingIdpOrigins, ...nextIdpOrigins]
        .filter((origin, idx, arr) => Boolean(origin) && arr.indexOf(origin) === idx)
      if (mergedIdpOrigins.length > 0) {
        setIdpOriginsText(mergedIdpOrigins.join('\n'))
      }

      if (payload.summary) {
        setCapturedSummary({
          ...payload.summary,
          verifyOrigin: nextVerifyOrigin,
          verifyPath: nextVerifyPath,
          capturedAppOrigins: nextAppOrigins,
          capturedIdpOrigins: nextIdpOrigins,
        })
      }
    } catch (err) {
      setCaptureError(err instanceof Error ? err.message : 'Unable to capture browser session.')
    } finally {
      setCaptureBusy(false)
    }
  }

  async function sendCaptureInput(
    body: Record<string, unknown>,
    options?: { forceUrlSync?: boolean; recordHistory?: boolean },
  ) {
    const id = activeCaptureIdRef.current
    if (!id) return
    const isHover = body.kind === 'mouse' && body.type === 'mouseMoved'
    const isNavigate = body.kind === 'navigate'
    try {
      const res = await fetch(`/_kovo/auth-capture/${encodeURIComponent(id)}/input`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (res.ok) {
        const data = await res.json().catch(() => ({})) as { url?: string }
        if (isNavigate) {
          setBrowserNavError('')
        }
        if (data.url && isNavigate) {
          isEditingUrlRef.current = false
          syncRemoteUrl(data.url, {
            force: options?.forceUrlSync ?? true,
            recordHistory: options?.recordHistory,
          })
        }
        return
      }
      const errData = await res.json().catch(() => ({})) as { error?: string }
      if (res.status === 401) {
        closeLiveStream()
        activeCaptureIdRef.current = null
        setActiveCapture(null)
        setCaptureError('Local session expired — open the Kovo startup bootstrap URL to sign back in.')
        return
      }
      if (res.status === 404) {
        closeLiveStream()
        activeCaptureIdRef.current = null
        setActiveCapture(null)
        setCaptureError(errData.error || 'Browser sign-in session ended or expired. Start again.')
        return
      }
      if (isNavigate) {
        setBrowserNavError(errData.error || `Navigation failed (HTTP ${res.status}).`)
        return
      }
      if (!isHover) {
        setCaptureError(errData.error || `Browser input failed (HTTP ${res.status}).`)
      }
    } catch {
      if (isNavigate) {
        setBrowserNavError('Could not deliver navigation request to the interactive browser — check your connection.')
        return
      }
      if (!isHover) {
        setCaptureError('Could not deliver input to the interactive browser — check your connection.')
      }
    }
  }

  function handleAddressBarNavigate(rawUrl: string) {
    const resolved = resolveNavigationTarget(rawUrl)
    if (!resolved) return
    setCaptureError('')
    setBrowserNavError('')
    isEditingUrlRef.current = false
    addressInputRef.current?.blur()
    setCaptureUrlInput(resolved)
    void sendCaptureInput({ kind: 'navigate', url: resolved }, { forceUrlSync: true, recordHistory: true })
  }

  function handleHistoryStep(delta: -1 | 1) {
    const targetIdx = navHistoryIndexRef.current + delta
    const targetUrl = navHistoryRef.current[targetIdx]
    if (!targetUrl) return
    pendingHistoryIndexRef.current = targetIdx
    isEditingUrlRef.current = false
    setCaptureError('')
    setBrowserNavError('')
    setCaptureUrlInput(targetUrl)
    void sendCaptureInput({ kind: 'navigate', url: targetUrl }, { forceUrlSync: true, recordHistory: true })
  }

  function handleBrowserReload() {
    const targetUrl = lastSyncedRemoteUrlRef.current || activeCapture?.targetOrigin || ''
    if (!targetUrl) return
    isEditingUrlRef.current = false
    setCaptureError('')
    setBrowserNavError('')
    void sendCaptureInput({ kind: 'navigate', url: targetUrl }, { forceUrlSync: true, recordHistory: false })
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
    const cleanTenantRef = tenantRef.trim() || null
    const cleanPrivilege: PersonaPrivilege | null = privilege || null
    const generatedHandle = deriveUniqueHandle(
      cleanLabel,
      existingPersonas.map(p => p.handle),
    )
    const allowlist = origins.split(/[\s,]+/).filter(Boolean)
    if (allowlist.length === 0) {
      setAdvancedOpen(true)
    }

    // Mode 1: Universal Browser Session (server-side escrowed captureToken or explicit storageState.json import)
    if (isBrowserSessionMode) {
      const token = capturedToken.trim()
      const storageState = token ? '' : (importedStorageStateJson.trim() || importJsonText.trim())
      if (!keepingSameAuthKind && !token && !storageState) {
        setCaptureError('Sign in with the embedded browser or import a storageState.json file first.')
        return
      }
      const cleanVerifyOrigin = verifyOrigin.trim()
      const cleanVerifyPath = verifyPath.trim()
      const parsedIdpOrigins = parseOriginList(idpOriginsText)
      const saveBrowserMeta = async (personaId: string) => {
        if (!cleanVerifyOrigin && parsedIdpOrigins.length === 0 && !editingPersona) return
        const res = await fetch('/_kovo/auth-capture/persona-config', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            projectId: project.id,
            personaId,
            verifyOrigin: cleanVerifyOrigin || null,
            ...(cleanVerifyPath ? { verifyPath: cleanVerifyPath } : {}),
            idpOrigins: parsedIdpOrigins,
          }),
        })
        if (!res.ok) {
          const errPayload = await res.json().catch(() => ({})) as { error?: string }
          throw new Error(errPayload.error || `Could not save browser session verification settings (HTTP ${res.status}).`)
        }
      }
      if (editingPersona) {
        void personaAction.submit(async () => {
          const updated = await updateBrowserSessionPersonaAction({ data: {
            requestId: crypto.randomUUID(),
            projectId: project.id,
            personaId: editingPersona.id,
            roleLabel: cleanLabel,
            tenantRef: cleanTenantRef,
            privilege: cleanPrivilege,
            originAllowlist: allowlist,
            ...(token ? { captureToken: token } : storageState ? { storageState } : {}),
            ...(cleanVerifyPath ? { verifyPath: cleanVerifyPath } : {}),
          } })
          await saveBrowserMeta(updated.id)
          return updated
        }, updated => {
          resetForm()
          onClose()
          onCreated(updated)
        })
        return
      }
      void personaAction.submit(async () => {
        const created = await registerBrowserSessionPersona({ data: {
          requestId: crypto.randomUUID(),
          projectId: project.id,
          handle: generatedHandle,
          roleLabel: cleanLabel,
          tenantRef: cleanTenantRef,
          privilege: cleanPrivilege,
          originAllowlist: allowlist,
          ...(token ? { captureToken: token } : { storageState }),
          ...(cleanVerifyPath ? { verifyPath: cleanVerifyPath } : {}),
          canaryMarkers: [],
        } })
        await saveBrowserMeta(created.id)
        return created
      }, created => {
        resetForm()
        onClose()
        onCreated(created)
      })
      return
    }

    // Mode 2 (Header / Cookie / cURL) & Mode 3 (Automated Login CI / Staging)
    if (secretRequired && !secret.trim()) {
      setSecretError(effectiveAuthKind === 'login' && !isClerkClient ? 'Enter the account password.' : 'Enter the credential secret.')
      requestAnimationFrame(() => {
        const el = document.querySelector<HTMLInputElement>('[data-slot="persona-form"] [name="secret"]')
        el?.scrollIntoView({ block: 'nearest' })
        el?.focus()
      })
      return
    }
    const headerNameRaw = headerName.trim()
    const loginUrlRaw = loginUrl.trim()
    if (editingPersona) {
      void personaAction.submit(() => updatePersona({ data: {
        requestId: crypto.randomUUID(),
        projectId: project.id,
        personaId: editingPersona.id,
        roleLabel: cleanLabel,
        tenantRef: cleanTenantRef,
        privilege: cleanPrivilege,
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
      tenantRef: cleanTenantRef,
      privilege: cleanPrivilege,
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

  const captureVp = activeCapture?.viewport ?? { width: 1280, height: 800 }
  const isSecureRemoteUrl = currentRemoteUrl.startsWith('https://')

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
      <DialogContent
        data-capture-active={activeCapture ? 'true' : 'false'}
        initialFocus={roleLabelRef}
        className={cn(
          // Size changes snap (no layout tween); only the enter/exit opacity+scale animates.
          'flex flex-col overflow-hidden p-0 transition-[opacity,scale] duration-[var(--d2)] ease-kovo',
          activeCapture
            ? 'h-[92vh] max-h-[92vh] w-[95vw] max-w-[1600px]'
            : 'mb-auto mt-[min(12vh,96px)] max-h-[calc(100vh-min(12vh,96px)-32px)] w-full max-w-[720px]',
        )}
      >
        {activeCapture ? (
          <div
            key="capture"
            className="flex min-h-0 flex-1 flex-col bg-panel transition-opacity duration-150 ease-kovo starting:opacity-0 motion-reduce:transition-none"
          >
            {/* Browser Window Title Chrome */}
            <div className="flex shrink-0 flex-wrap items-center justify-between gap-2.5 border-b border-line bg-raise px-3.5 py-2">
              <div className="flex min-w-0 items-center gap-2.5">
                <span className="flex shrink-0 items-center gap-1.5" aria-hidden="true">
                  <span className="size-2.5 rounded-full bg-danger/70" />
                  <span className="size-2.5 rounded-full bg-warn/70" />
                  <span className="size-2.5 rounded-full bg-ok/70" />
                </span>
                <div className="flex min-w-0 items-center gap-1.5">
                  <Icon name="globe" size={13} className="shrink-0 text-fg-subtle" />
                  <DialogTitle className="truncate text-[12.5px] font-semibold text-fg">
                    Sign-in browser · {roleLabel.trim() || 'Test account'}
                  </DialogTitle>
                </div>
                <Badge variant="accent" className="hidden sm:inline-flex">
                  Live session
                </Badge>
              </div>
              <div className="flex shrink-0 items-center gap-2">
                <Button
                  type="button"
                  variant="default"
                  className="h-[28px] px-3"
                  disabled={captureBusy}
                  onClick={() => void handleCompleteInteractiveCapture()}
                >
                  <Icon name="check" size={13} />
                  {captureBusy ? 'Capturing…' : "I'm signed in — capture session"}
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  className="h-[28px]"
                  disabled={captureBusy}
                  onClick={() => void cancelActiveCaptureSession()}
                >
                  Cancel
                </Button>
              </div>
            </div>

            {/* Browser Navigation + Omnibox Toolbar */}
            <div className="flex shrink-0 items-center gap-1.5 border-b border-line bg-sunk px-3 py-2">
              <div className="flex shrink-0 items-center gap-0.5">
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="size-[28px] rounded-full"
                  disabled={captureBusy || !navFlags.canBack}
                  onClick={() => handleHistoryStep(-1)}
                  aria-label="Back"
                  title="Back"
                >
                  <Icon name="arrowL" size={13} />
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="size-[28px] rounded-full"
                  disabled={captureBusy || !navFlags.canForward}
                  onClick={() => handleHistoryStep(1)}
                  aria-label="Forward"
                  title="Forward"
                >
                  <Icon name="arrowR" size={13} />
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="size-[28px] rounded-full"
                  disabled={captureBusy}
                  onClick={handleBrowserReload}
                  aria-label="Reload"
                  title="Reload"
                >
                  <svg
                    className="ico block size-3.5"
                    viewBox="0 0 16 16"
                    fill="none"
                    aria-hidden="true"
                  >
                    <path d="M13.25 8a5.25 5.25 0 1 1-1.35-3.5" />
                    <path d="M13.25 2.75v2.5h-2.5" />
                  </svg>
                </Button>
              </div>

              <div className="flex h-[32px] min-w-0 flex-1 items-center gap-1.5 rounded-full border border-line-2 bg-panel pl-3 pr-1.5 transition-colors focus-within:border-accent-line focus-within:ring-2 focus-within:ring-accent-soft">
                <Icon
                  name={isSecureRemoteUrl ? 'lock' : 'globe'}
                  size={13}
                  className={cn('shrink-0', isSecureRemoteUrl ? 'text-ok' : 'text-fg-subtle')}
                />
                <input
                  ref={addressInputRef}
                  type="text"
                  name="browserAddressBar"
                  aria-label="Browser address bar"
                  autoComplete="off"
                  spellCheck={false}
                  className="h-full min-w-0 flex-1 border-0 bg-transparent px-1 font-mono text-[12px] text-fg shadow-none focus:shadow-none focus:outline-none"
                  value={captureUrlInput}
                  onFocus={() => {
                    isEditingUrlRef.current = true
                  }}
                  onBlur={() => {
                    isEditingUrlRef.current = false
                  }}
                  onChange={e => {
                    isEditingUrlRef.current = true
                    setCaptureUrlInput(e.target.value)
                  }}
                  onKeyDown={e => {
                    if (e.key === 'Enter') {
                      e.preventDefault()
                      handleAddressBarNavigate(captureUrlInput)
                      return
                    }
                    if (e.key === 'Escape') {
                      e.preventDefault()
                      isEditingUrlRef.current = false
                      setCaptureUrlInput(lastSyncedRemoteUrlRef.current || activeCapture.targetOrigin)
                      addressInputRef.current?.blur()
                    }
                  }}
                  placeholder="Enter URL (e.g. https://app.example.com/login)"
                />
                {captureUrlInput.length > 0 && (
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="size-[22px] shrink-0 rounded-full text-fg-subtle hover:text-fg"
                    aria-label="Clear address bar"
                    title="Clear URL"
                    onMouseDown={e => e.preventDefault()}
                    onClick={() => {
                      isEditingUrlRef.current = true
                      setCaptureUrlInput('')
                      addressInputRef.current?.focus()
                    }}
                  >
                    <Icon name="close" size={11} />
                  </Button>
                )}
              </div>

              <Button
                type="button"
                variant="outline"
                className="h-[30px] shrink-0 rounded-full px-3"
                disabled={captureBusy || !captureUrlInput.trim()}
                onMouseDown={e => e.preventDefault()}
                onClick={() => handleAddressBarNavigate(captureUrlInput)}
              >
                Go
              </Button>
            </div>

            {browserNavError && (
              <div
                role="alert"
                data-testid="capture-nav-error"
                className="flex shrink-0 items-center justify-between gap-2.5 border-b border-danger/35 bg-danger-soft px-3.5 py-2 text-[12px] text-fg"
              >
                <div className="flex min-w-0 flex-1 items-center gap-2">
                  <Icon name="alert" size={14} className="shrink-0 text-danger" />
                  <span className="min-w-0 flex-1 whitespace-normal break-words leading-snug">
                    {browserNavError}
                  </span>
                </div>
                <div className="flex shrink-0 items-center gap-1.5">
                  <Button
                    type="button"
                    variant="outline"
                    className="h-[24px] px-2 text-[11.5px]"
                    disabled={captureBusy}
                    onClick={handleBrowserReload}
                  >
                    Retry
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="size-[24px]"
                    aria-label="Dismiss navigation error"
                    onClick={() => setBrowserNavError('')}
                  >
                    <Icon name="close" size={12} />
                  </Button>
                </div>
              </div>
            )}

            {/* Live Browser Viewport Canvas */}
            <div
              className="relative flex min-h-0 flex-1 items-center justify-center overflow-hidden bg-sunk"
              style={{ containerType: 'size' }}
            >
              <canvas
                ref={canvasRef}
                width={captureVp.width}
                height={captureVp.height}
                tabIndex={0}
                aria-label="Interactive sign-in browser"
                className="block cursor-pointer border-x border-line-2 bg-white shadow-surface outline-none focus-visible:ring-2 focus-visible:ring-accent"
                style={{
                  width: `min(100cqw, calc(100cqh * ${captureVp.width} / ${captureVp.height}))`,
                  height: `min(100cqh, calc(100cqw * ${captureVp.height} / ${captureVp.width}))`,
                }}
                onMouseDown={e => handleCanvasMouse('mousePressed', e)}
                onMouseUp={e => handleCanvasMouse('mouseReleased', e)}
                onMouseMove={e => handleCanvasMouse('mouseMoved', e)}
                onWheel={handleCanvasWheel}
                onKeyDown={handleCanvasKeyDown}
                onKeyUp={handleCanvasKeyUp}
                onPaste={handleCanvasPaste}
                onContextMenu={e => e.preventDefault()}
              />
              {!hasReceivedFrame && !browserNavError && (
                <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center gap-1.5 bg-sunk/90 px-4 text-center text-[12.5px] text-fg-muted">
                  <span className="font-medium text-fg">Connecting to live sign-in browser…</span>
                  <span className="font-mono text-[11.5px] text-fg-subtle">{activeCapture.targetOrigin}</span>
                </div>
              )}
            </div>

            {/* Slim Browser Status Footer */}
            <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-t border-line bg-raise px-3.5 py-2 text-[11.5px]">
              {captureError ? (
                <p className="m-0 flex min-w-0 flex-1 items-center gap-1.5 text-danger" role="alert">
                  <Icon name="alert" size={13} className="shrink-0" />
                  <span className="truncate">{captureError}</span>
                </p>
              ) : (
                <p className="m-0 flex min-w-0 flex-1 items-center gap-2 text-fg-muted">
                  <span className="size-2 shrink-0 rounded-full bg-ok" aria-hidden="true" />
                  <span>
                    Sign in below — Kovo captures cookies &amp; storage automatically when you click{' '}
                    <strong className="font-semibold text-fg">I&apos;m signed in — capture session</strong>.
                  </span>
                </p>
              )}
              <span className="shrink-0 font-mono text-[11px] text-fg-subtle">
                SSO · Passkeys · MFA · CAPTCHA
              </span>
            </div>
          </div>
        ) : (
          <form
            key="form"
            className="flex min-h-0 flex-1 flex-col transition-opacity duration-150 ease-kovo starting:opacity-0 motion-reduce:transition-none"
            onSubmit={handleSubmit}
            data-slot="persona-form"
          >
            <DialogHeader className="shrink-0 flex-row items-center justify-between gap-2.5 border-b border-line bg-raise px-4 py-3">
              <DialogTitle className="text-[13.5px] font-semibold text-fg">
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

            <DialogBody className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto overflow-x-hidden p-4">
              <div className="grid gap-1.5">
                <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)_minmax(0,1fr)]">
                  <label className="grid min-w-0 gap-1.5 text-[12px] font-medium text-fg-muted">
                    Account label
                    <Input
                      ref={roleLabelRef}
                      className="w-full min-w-0"
                      name="roleLabel"
                      required
                      maxLength={160}
                      placeholder="User A"
                      value={roleLabel}
                      onChange={e => setRoleLabel(e.target.value)}
                    />
                  </label>
                  <label className="grid min-w-0 gap-1.5 text-[12px] font-medium text-fg-muted">
                    Privilege role
                    <NativeSelect
                      className="w-full min-w-0"
                      name="privilege"
                      aria-label="Privilege role"
                      value={privilege}
                      onChange={e => setPrivilege(e.target.value as PersonaPrivilege | '')}
                    >
                      <option value="">Unspecified</option>
                      <option value="viewer">Viewer</option>
                      <option value="member">Member</option>
                      <option value="admin">Admin</option>
                      <option value="owner">Owner</option>
                    </NativeSelect>
                  </label>
                  <label className="grid min-w-0 gap-1.5 text-[12px] font-medium text-fg-muted">
                    Tenant / org
                    <Input
                      className="w-full min-w-0"
                      name="tenantRef"
                      maxLength={120}
                      autoComplete="off"
                      placeholder="e.g. acme"
                      value={tenantRef}
                      onChange={e => setTenantRef(e.target.value)}
                    />
                  </label>
                </div>
                <small className="text-[11.5px] font-normal leading-[16px] text-fg-subtle">
                  Specify privilege and tenant/org so cross-tenant and role-escalation checks work with any account label.
                </small>
              </div>

              {/* Universal 3-Mode Auth Selector */}
              <div className="grid gap-2" role="radiogroup" aria-label="Authentication mode">
                <span className="text-[12px] font-medium text-fg-muted">Authentication method</span>
                <div className="grid grid-cols-1 items-stretch gap-2.5 sm:grid-cols-3">
                  <button
                    type="button"
                    role="radio"
                    aria-checked={authMode === 'browser_session'}
                    onClick={() => {
                      setAuthMode('browser_session')
                      setCaptureError('')
                    }}
                    className={cn(
                      'flex h-auto w-full min-w-0 cursor-pointer flex-col items-start justify-start gap-1.5 whitespace-normal rounded-[9px] border px-3 py-2.5 text-left font-normal shadow-none transition-colors',
                      authMode === 'browser_session'
                        ? 'border-accent-line bg-accent-soft text-fg hover:bg-accent-soft'
                        : 'border-line-2 bg-panel text-fg hover:border-line-strong hover:bg-hover',
                    )}
                  >
                    <div className="flex w-full flex-wrap items-center justify-between gap-1.5">
                      <span className="text-[12.5px] font-semibold leading-[17px] text-fg">Browser Session</span>
                      <Badge variant="accent" className="h-[18px] px-1.5 text-[10.5px]">Recommended</Badge>
                    </div>
                    <span className="text-[11.5px] leading-[16px] text-fg-muted">
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
                    className={cn(
                      'flex h-auto w-full min-w-0 cursor-pointer flex-col items-start justify-start gap-1.5 whitespace-normal rounded-[9px] border px-3 py-2.5 text-left font-normal shadow-none transition-colors',
                      authMode === 'header_cookie'
                        ? 'border-accent-line bg-accent-soft text-fg hover:bg-accent-soft'
                        : 'border-line-2 bg-panel text-fg hover:border-line-strong hover:bg-hover',
                    )}
                  >
                    <span className="text-[12.5px] font-semibold leading-[17px] text-fg">Header / Cookie / cURL</span>
                    <span className="text-[11.5px] leading-[16px] text-fg-muted">
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
                    className={cn(
                      'flex h-auto w-full min-w-0 cursor-pointer flex-col items-start justify-start gap-1.5 whitespace-normal rounded-[9px] border px-3 py-2.5 text-left font-normal shadow-none transition-colors',
                      authMode === 'automated_login'
                        ? 'border-accent-line bg-accent-soft text-fg hover:bg-accent-soft'
                        : 'border-line-2 bg-panel text-fg hover:border-line-strong hover:bg-hover',
                    )}
                  >
                    <span className="text-[12.5px] font-semibold leading-[17px] text-fg">Automated Login (CI / Staging)</span>
                    <span className="text-[11.5px] leading-[16px] text-fg-muted">
                      Email + password form/JSON sign-in for non-MFA local labs &amp; staging CI.
                    </span>
                  </button>
                </div>
              </div>

              {/* Mode 1: Universal Browser Session (Embedded Live-Login Browser + storageState.json Fallback) */}
              {authMode === 'browser_session' && (() => {
                const reviewVerifyOrigin = verifyOrigin.trim() || capturedSummary?.verifyOrigin || capturedSummary?.targetOrigin || ''
                const reviewVerifyPath = verifyPath.trim() || capturedSummary?.verifyPath || '/'
                const reviewVerifyUrl = reviewVerifyOrigin
                  ? `${reviewVerifyOrigin}${reviewVerifyPath.startsWith('/') ? reviewVerifyPath : `/${reviewVerifyPath}`}`
                  : ''
                const reviewScopeHosts = [...new Set(parseOriginList(origins).map(safeHost).filter(Boolean))]
                const reviewIdpHosts = [...new Set(parseOriginList(idpOriginsText).map(safeHost).filter(Boolean))]
                const reviewPillText = [
                  reviewVerifyUrl ? `Verify at ${reviewVerifyUrl}` : '',
                  reviewScopeHosts.length > 0 ? `Scope: ${reviewScopeHosts.join(', ')}` : '',
                  reviewIdpHosts.length > 0 ? `IdP: ${reviewIdpHosts.join(', ')}` : '',
                ].filter(Boolean).join(' · ')
                return (
                <div className="grid gap-3 rounded-[9px] border border-line-2 bg-sunk p-3.5">
                  <p className="m-0 text-[12px] leading-[18px] text-fg-muted">
                    Open a live sign-in browser to capture session cookies and storage after you log in, or import an existing Playwright <code className="font-mono text-[11.5px] text-fg">storageState.json</code> file.
                  </p>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex min-w-0 flex-wrap items-center gap-2">
                      {startingHostOptions.length > 0 && (
                        <NativeSelect
                          aria-label="Starting host"
                          name="startingHost"
                          className="h-[28px] w-auto min-w-[160px] max-w-[240px] font-mono text-[11.5px]"
                          value={effectiveStartOrigin}
                          disabled={captureBusy || personaAction.pending}
                          onChange={e => setSelectedStartOrigin(e.target.value)}
                        >
                          {startingHostOptions.map(originOption => (
                            <option key={originOption} value={originOption}>
                              {safeHost(originOption)}
                            </option>
                          ))}
                        </NativeSelect>
                      )}
                      <Button
                        type="button"
                        variant="outline"
                        className="h-[28px] shrink-0 px-3"
                        disabled={captureBusy || personaAction.pending}
                        onClick={() => void handleStartInteractiveCapture()}
                      >
                        <Icon name="globe" size={14} />
                        {captureBusy ? 'Launching browser…' : 'Sign in with browser'}
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
                        className="h-[28px] shrink-0"
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

                  {capturedSummary && reviewPillText && (
                    <div
                      data-testid="captured-session-review"
                      className="flex min-w-0 items-center justify-between gap-2 rounded-[7px] border border-ok/35 bg-ok-soft px-2.5 py-1.5 text-[11.5px] text-fg"
                    >
                      <div className="flex min-w-0 flex-1 items-center gap-1.5">
                        <Icon name="check" size={13} className="shrink-0 text-ok" />
                        <span className="min-w-0 flex-1 truncate font-mono text-[11.5px]" title={reviewPillText}>
                          {reviewPillText}
                        </span>
                      </div>
                      <button
                        type="button"
                        className="h-auto shrink-0 cursor-pointer whitespace-normal border-0 bg-transparent px-1 py-0 text-[11.5px] font-medium text-accent shadow-none hover:underline"
                        onClick={() => setAdvancedOpen(true)}
                      >
                        Edit
                      </button>
                    </div>
                  )}

                  {importOpen && (
                    <div className="grid gap-2 border-t border-line pt-3">
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
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="min-w-0 flex-1 text-[11.5px] text-fg-subtle">{importNote}</span>
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
                )
              })()}

              {/* Mode 2: Header / Cookie / cURL */}
              {authMode === 'header_cookie' && (
                <div className="grid gap-3">
                  <div className="grid gap-1.5">
                    <span className="text-[12px] font-medium text-fg-muted">Quick paste (optional)</span>
                    <div className="flex items-center gap-2">
                      <Input
                        className="min-w-0 flex-1 font-mono text-[12px]"
                        aria-label="Paste cURL or auth header"
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
                        className="h-[28px] shrink-0"
                        onClick={() => applyCurlParse(curlPaste)}
                        disabled={!curlPaste.trim()}
                      >
                        Paste from cURL
                      </Button>
                    </div>
                    {curlNote && <span className="text-[11.5px] text-fg-subtle">{curlNote}</span>}
                  </div>

                  <label className="grid gap-1.5 text-[12px] font-medium text-fg-muted">
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
                    <div className="grid grid-cols-1 items-start gap-3 sm:grid-cols-2">
                      <label className="grid gap-1.5 text-[12px] font-medium text-fg-muted">
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
                      <label className="grid gap-1.5 text-[12px] font-medium text-fg-muted">
                        Credential secret
                        <Input
                          className="w-full"
                          name="secret"
                          type="password"
                          maxLength={4096}
                          autoComplete="off"
                          aria-invalid={secretError ? true : undefined}
                          aria-describedby={secretError ? 'persona-secret-err' : undefined}
                          value={secret}
                          onChange={e => {
                            setSecret(e.target.value)
                            if (secretError) setSecretError('')
                          }}
                          placeholder={keepingSameAuthKind ? 'Leave blank to keep existing secret' : 'Never displayed back after saving'}
                        />
                        {secretError && (
                          <p id="persona-secret-err" className="form-error m-0 text-[11.5px] font-normal">{secretError}</p>
                        )}
                      </label>
                    </div>
                  ) : (
                    <label className="grid gap-1.5 text-[12px] font-medium text-fg-muted">
                      Credential secret
                      <Input
                        className="w-full"
                        name="secret"
                        type="password"
                        maxLength={4096}
                        autoComplete="off"
                        aria-invalid={secretError ? true : undefined}
                        aria-describedby={secretError ? 'persona-secret-err' : undefined}
                        value={secret}
                        onChange={e => {
                          setSecret(e.target.value)
                          if (secretError) setSecretError('')
                        }}
                        placeholder={keepingSameAuthKind ? 'Leave blank to keep existing secret' : 'Never displayed back after saving'}
                      />
                      {secretError && (
                        <p id="persona-secret-err" className="form-error m-0 text-[11.5px] font-normal">{secretError}</p>
                      )}
                    </label>
                  )}
                </div>
              )}

              {/* Mode 3: Automated Login (CI / Staging) */}
              {authMode === 'automated_login' && (
                isClerkClient ? (
                  <div className="grid gap-3">
                    <label className="grid gap-1.5 text-[12px] font-medium text-fg-muted">
                      Clerk __client cookie (legacy)
                      <Input
                        className="w-full font-mono text-[12px]"
                        name="secret"
                        type="password"
                        maxLength={4096}
                        autoComplete="off"
                        aria-invalid={secretError ? true : undefined}
                        aria-describedby={secretError ? 'persona-secret-err' : undefined}
                        value={secret}
                        onChange={e => {
                          setSecret(e.target.value)
                          if (secretError) setSecretError('')
                        }}
                        placeholder={
                          keepingSameAuthKind
                            ? 'Leave blank to keep existing secret'
                            : 'Paste __client cookie value from DevTools (clerk.yourdomain.com)'
                        }
                      />
                      {secretError && (
                        <p id="persona-secret-err" className="form-error m-0 text-[11.5px] font-normal">{secretError}</p>
                      )}
                      <small className="text-[11.5px] font-normal text-fg-subtle">
                        Legacy adapter — prefer <strong>Browser Session</strong> for universal auto-refresh across all identity providers.
                      </small>
                    </label>
                    <label className="grid gap-1.5 text-[12px] font-medium text-fg-muted">
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
                  <div className="grid grid-cols-1 items-start gap-3 sm:grid-cols-2">
                    <label className="grid gap-1.5 text-[12px] font-medium text-fg-muted">
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
                    <label className="grid gap-1.5 text-[12px] font-medium text-fg-muted">
                      Password
                      <Input
                        className="w-full"
                        name="secret"
                        type="password"
                        maxLength={4096}
                        autoComplete="off"
                        aria-invalid={secretError ? true : undefined}
                        aria-describedby={secretError ? 'persona-secret-err' : undefined}
                        value={secret}
                        onChange={e => {
                          setSecret(e.target.value)
                          if (secretError) setSecretError('')
                        }}
                        placeholder={keepingSameAuthKind ? 'Leave blank to keep existing secret' : 'Encrypted on your machine'}
                      />
                      {secretError && (
                        <p id="persona-secret-err" className="form-error m-0 text-[11.5px] font-normal">{secretError}</p>
                      )}
                    </label>
                  </div>
                )
              )}

              <Disclosure
                open={advancedOpen}
                onOpenChange={setAdvancedOpen}
                className="border-t border-line pt-3"
              >
                <DisclosureTrigger className="h-auto bg-transparent px-0 py-1 text-fg-muted shadow-none hover:bg-transparent hover:text-fg">
                  Advanced configuration
                </DisclosureTrigger>
                <DisclosureContent className="grid gap-3 pt-2.5">
                  {authMode === 'browser_session' && (
                    <div className="grid gap-3">
                      <div className="grid grid-cols-1 items-start gap-3 sm:grid-cols-2">
                        <label className="grid gap-1.5 text-[12px] font-medium text-fg-muted">
                          Verify origin (optional)
                          <Input
                            className="w-full font-mono text-[12px]"
                            name="verifyOrigin"
                            maxLength={253}
                            autoComplete="off"
                            value={verifyOrigin}
                            onChange={e => setVerifyOrigin(e.target.value)}
                            placeholder={effectiveStartOrigin || 'https://app.example.com'}
                          />
                        </label>
                        <label className="grid gap-1.5 text-[12px] font-medium text-fg-muted">
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
                        </label>
                      </div>
                      <label className="grid gap-1.5 text-[12px] font-medium text-fg-muted">
                        Approved IdP / SSO origins (optional, one per line)
                        <Textarea
                          className="w-full font-mono text-[12px]"
                          name="idpOrigins"
                          rows={2}
                          value={idpOriginsText}
                          onChange={e => setIdpOriginsText(e.target.value)}
                          placeholder="https://clerk.example.com"
                        />
                        <small className="text-[11.5px] font-normal text-fg-subtle">
                          Auto-captured from your interactive sign-in; permitted during unattended background token refresh.
                        </small>
                      </label>
                    </div>
                  )}

                  {authMode === 'automated_login' && (
                    <div className="grid grid-cols-1 items-start gap-3 sm:grid-cols-2">
                      <label className="grid gap-1.5 text-[12px] font-medium text-fg-muted">
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
                      <label className="grid gap-1.5 text-[12px] font-medium text-fg-muted">
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

                  <label className="grid gap-1.5 text-[12px] font-medium text-fg-muted">
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
            </DialogBody>

            <DialogFooter className="shrink-0 flex-wrap items-center justify-between gap-2.5 px-4 py-2.5">
              {personaAction.error && (
                <p
                  ref={submitErrorRef}
                  role="alert"
                  tabIndex={-1}
                  data-slot="submit-error"
                  className="form-error m-0 max-h-24 basis-full overflow-y-auto text-[12px] outline-none [overflow-wrap:anywhere]"
                >
                  {personaAction.error}
                </p>
              )}
              <span className="min-w-0 text-[12px] text-fg-subtle">
                Credentials stay encrypted on your machine and are never sent to AI models.
              </span>
              <div className="flex shrink-0 items-center gap-2">
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
                  disabled={personaAction.pending}
                >
                  {personaAction.pending ? 'Saving…' : editingPersona ? 'Save changes' : submitLabel}
                </Button>
              </div>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}
