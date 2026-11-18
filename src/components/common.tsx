import { Link, useRouter } from '@tanstack/react-router'
import { useState } from 'react'

export const timeText = (value: number) => new Date(value).toLocaleString(undefined, {
  month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit',
})

export function useAction() {
  const router = useRouter()
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')
  async function submit<T>(action: () => Promise<T>, onSuccess?: (result: T) => void | Promise<void>) {
    if (pending) return
    setError('')
    setPending(true)
    try {
      const result = await action()
      await router.invalidate()
      await onSuccess?.(result)
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Guardian could not complete the action.')
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
  return <Link className="brand" to="/" aria-label="Guardian workspace">
    <svg width="22" height="24" viewBox="0 0 26 28" aria-hidden="true">
      <path fill="currentColor" d="M13 1 24 5.8V13c0 6.6-5.7 11.4-11 13.8C7.7 24.4 2 19.6 2 13V5.8L13 1Z" />
      <path fill="var(--on-accent)" d="M17.9 8.6a7 7 0 0 0-9 .9 6.2 6.2 0 0 0 3.1 10.3v-3.1h3.5v-4.2H12v-1.9h5.9V8.6Z" />
    </svg>
    <span>Guardian</span>
  </Link>
}

export function Status({ status }: { status: string }) {
  return <span className="state" data-status={status}><i aria-hidden="true" />{status.replaceAll('_', ' ')}</span>
}
