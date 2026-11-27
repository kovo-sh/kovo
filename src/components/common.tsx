import { Link, useRouter } from '@tanstack/react-router'
import { useState } from 'react'
import { KovoMark } from './brand/KovoMark.tsx'

export const timeText = (value: number) => new Date(value).toLocaleString(undefined, {
  month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit',
})

export interface HumanTime {
  label: string
  full: string
}

export function formatHumanTime(
  isoOrMs: string | number | Date | null | undefined,
  nowMs: number = Date.now(),
): HumanTime {
  if (isoOrMs === null || isoOrMs === undefined || isoOrMs === '') {
    return { label: '', full: '' }
  }
  const ms = typeof isoOrMs === 'number'
    ? isoOrMs
    : isoOrMs instanceof Date
      ? isoOrMs.getTime()
      : Date.parse(isoOrMs)
  if (!Number.isFinite(ms)) return { label: '', full: '' }

  const date = new Date(ms)
  const full = date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  })

  const diffMs = nowMs - ms
  const oneDayMs = 24 * 60 * 60 * 1000
  if (diffMs >= -60_000 && diffMs < oneDayMs) {
    if (diffMs < 60_000) return { label: 'just now', full }
    const minutes = Math.floor(diffMs / 60_000)
    if (minutes < 60) {
      return { label: minutes === 1 ? '1 minute ago' : `${minutes} minutes ago`, full }
    }
    const hours = Math.floor(minutes / 60)
    return { label: hours === 1 ? '1 hour ago' : `${hours} hours ago`, full }
  }

  const sameYear = date.getFullYear() === new Date(nowMs).getFullYear()
  const label = date.toLocaleDateString(
    undefined,
    sameYear
      ? { month: 'short', day: 'numeric' }
      : { month: 'short', day: 'numeric', year: 'numeric' },
  )
  return { label, full }
}

export function useAction(refresh?: () => Promise<void>) {
  const router = useRouter()
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')
  async function submit<T>(action: () => Promise<T>, onSuccess?: (result: T) => void | Promise<void>) {
    if (pending) return
    setError('')
    setPending(true)
    try {
      const result = await action()
      if (refresh) await refresh()
      else await router.invalidate()
      await onSuccess?.(result)
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Kovo could not complete the action.')
    } finally {
      setPending(false)
    }
  }
  return { pending, error, submit }
}

export function FormError({ error }: { error: string }) {
  return error ? <p role="alert" className="form-error">{error}</p> : null
}

export function Brand() {
  return <Link className="brand" to="/" aria-label="Kovo workspace">
    <KovoMark size={20} />
    <span>Kovo</span>
  </Link>
}

export function Status({ status }: { status: string }) {
  return <span className="state" data-status={status}><i aria-hidden="true" />{status.replaceAll('_', ' ')}</span>
}
