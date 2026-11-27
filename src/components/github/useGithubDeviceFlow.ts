import { useCallback, useEffect, useRef, useState } from 'react'
import {
  cancelGithubDeviceFlowAction,
  pollGithubDeviceFlowAction,
  startGithubDeviceFlowAction,
} from '../../actions.ts'

/** The one-time code and polling parameters returned when a GitHub Device Flow starts. */
export type ActiveDeviceFlow = Awaited<ReturnType<typeof startGithubDeviceFlowAction>>

/** Poll result after the operator approves the app on GitHub. */
export type GithubDeviceFlowAuthorized = Extract<
  Awaited<ReturnType<typeof pollGithubDeviceFlowAction>>,
  { status: 'authorized' }
>

export interface UseGithubDeviceFlowOptions {
  /** Whether the server has a GitHub App Client ID available for one-click sign-in (true by default via Kovo Security). */
  configured?: boolean
  /** Block starting or cancelling while another action on the screen is in flight. */
  disabled?: boolean
  /** Called after GitHub approves the sign-in and the account status is refreshed. */
  onAuthorized: (result: GithubDeviceFlowAuthorized) => void | Promise<void>
  /** Optional hook fired just before a new flow starts, e.g. to clear a notice. */
  onStart?: () => void
}

export interface GithubDeviceFlowState {
  flow: ActiveDeviceFlow | null
  starting: boolean
  codeCopied: boolean
  error: string
  clientId: string
  setClientId: (value: string) => void
  clearError: () => void
  start: () => Promise<void>
  cancel: () => Promise<void>
  copyCode: () => Promise<void>
}

function clipboardWrite(text: string): Promise<boolean> {
  if (typeof navigator === 'undefined' || !navigator.clipboard?.writeText) return Promise.resolve(false)
  return navigator.clipboard.writeText(text).then(() => true).catch(() => false)
}

/**
 * Shared GitHub App Device Flow state machine: start, poll, cancel, and copy the
 * one-time code. Consumers own account refresh and notices via `onAuthorized`.
 */
export function useGithubDeviceFlow({
  configured = true,
  disabled = false,
  onAuthorized,
  onStart,
}: UseGithubDeviceFlowOptions): GithubDeviceFlowState {
  const [flow, setFlow] = useState<ActiveDeviceFlow | null>(null)
  const [clientId, setClientIdState] = useState('')
  const [starting, setStarting] = useState(false)
  const [codeCopied, setCodeCopied] = useState(false)
  const [error, setError] = useState('')

  // Keep callbacks fresh without restarting the polling timer on every render.
  const callbacksRef = useRef({ onAuthorized })
  callbacksRef.current = { onAuthorized }

  const flowId = flow?.flowId ?? null
  const intervalSec = flow?.intervalSec ?? 5

  useEffect(() => {
    if (!flowId) return
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | undefined

    const scheduleNext = (delaySec: number) => {
      if (cancelled) return
      timer = setTimeout(() => { void pollOnce() }, Math.max(1, delaySec) * 1000)
    }

    const pollOnce = async () => {
      if (cancelled) return
      try {
        const res = await pollGithubDeviceFlowAction({ data: { flowId } })
        if (cancelled) return
        if (res.status === 'pending') {
          scheduleNext(res.intervalSec)
          return
        }
        if (res.status === 'slow_down') {
          setFlow(prev => (prev && prev.flowId === flowId ? { ...prev, intervalSec: res.intervalSec } : prev))
          scheduleNext(res.intervalSec)
          return
        }
        if (res.status === 'authorized') {
          setFlow(null)
          setCodeCopied(false)
          setClientIdState('')
          setError('')
          await callbacksRef.current.onAuthorized(res)
          return
        }
        setFlow(null)
        setError(res.error || 'GitHub sign-in did not complete.')
      } catch (err) {
        if (cancelled) return
        setFlow(null)
        setError(err instanceof Error ? err.message : 'GitHub sign-in polling failed.')
      }
    }

    scheduleNext(intervalSec)
    return () => {
      cancelled = true
      if (timer) clearTimeout(timer)
    }
  }, [flowId, intervalSec])

  const setClientId = useCallback((value: string) => {
    setClientIdState(value)
    setError('')
  }, [])

  const clearError = useCallback(() => setError(''), [])

  const start = useCallback(async () => {
    if (starting || disabled) return
    const trimmed = clientId.trim()
    if (trimmed.length > 0 && trimmed.length < 6) {
      setError('Enter a valid GitHub App Client ID (at least 6 characters).')
      return
    }
    if (!configured && trimmed.length < 6) {
      setError('Enter your GitHub App Client ID to start sign-in.')
      return
    }
    onStart?.()
    setStarting(true)
    setError('')
    setCodeCopied(false)
    try {
      const started = await startGithubDeviceFlowAction({
        data: trimmed ? { clientId: trimmed } : undefined,
      })
      setFlow(started)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not start GitHub sign-in.')
    } finally {
      setStarting(false)
    }
  }, [clientId, configured, disabled, onStart, starting])

  const cancel = useCallback(async () => {
    const activeId = flow?.flowId
    setFlow(null)
    setCodeCopied(false)
    setError('')
    if (!activeId) return
    try {
      await cancelGithubDeviceFlowAction({ data: { flowId: activeId } })
    } catch {
      // Best-effort cleanup; local state is already reset.
    }
  }, [flow?.flowId])

  const copyCode = useCallback(async () => {
    if (!flow) return
    setCodeCopied(await clipboardWrite(flow.userCode))
  }, [flow])

  return {
    flow,
    starting,
    codeCopied,
    error,
    clientId,
    setClientId,
    clearError,
    start,
    cancel,
    copyCode,
  }
}
