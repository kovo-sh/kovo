import { useCallback, useMemo, useState } from 'react'
import type { Dispatch, SetStateAction } from 'react'

/**
 * Draft-safe form state over a server value that can change in the background
 * (loader revalidation, 10s health polls, another device saving).
 *
 *   draft  — what the input shows
 *   base   — the server value the draft was last synced to
 *   server — the latest server value seen
 *
 * Invariants:
 *   - pristine (draft === base) and not held → server updates flow into the draft;
 *   - dirty or held (e.g. the input is focused) → the draft is NEVER overwritten;
 *     `serverChanged` flips so the UI can offer "Updated elsewhere · Reload";
 *   - an edit made while the server is ahead (the "Updated elsewhere" state) pins
 *     the draft, even if it happens to equal the old base value: it is the
 *     operator's explicit choice and must survive releasing focus;
 *   - a server value equal to the draft (e.g. our own save landed) converges
 *     the draft back to pristine without touching it.
 */
export interface ServerDraftState<T> {
  draft: T
  base: T
  server: T
  /** Set by an edit made while `base !== server`; cleared on accept/reset/convergence. */
  pinned: boolean
}

export interface ServerDraftOptions<T> {
  equals?: (a: T, b: T) => boolean
  /** Treat the draft as in-progress even when unchanged (e.g. while its input has focus). */
  hold?: boolean
}

export interface ServerDraftMeta<T> {
  /** The draft differs from the server value it was based on. */
  dirty: boolean
  /** The server moved on since the draft was based on it (only meaningful while dirty / held). */
  serverChanged: boolean
  /** Latest server value. */
  serverValue: T
  /** Discard local edits and load the latest server value. */
  reset: () => void
  /** Accept the newer server value ("Updated elsewhere · Reload"); same outcome as `reset`. */
  acceptServer: () => void
}

export function initialServerDraft<T>(server: T): ServerDraftState<T> {
  return { draft: server, base: server, server, pinned: false }
}

/**
 * Pure reconciliation step (the hook runs it on every render). Returns the same
 * object when nothing changes, so it is safe to call during render.
 */
export function reconcileServerDraft<T>(
  state: ServerDraftState<T>,
  server: T,
  options: ServerDraftOptions<T> = {},
): ServerDraftState<T> {
  const equals = options.equals ?? Object.is
  const next = equals(state.server, server) ? state : { ...state, server }
  if (equals(next.base, server)) return next.pinned && equals(next.draft, server) ? { ...next, pinned: false } : next
  const pristine = equals(next.draft, next.base) && !next.pinned
  if (pristine && !options.hold) return initialServerDraft(server)
  if (equals(next.draft, server)) return { draft: next.draft, base: server, server, pinned: false }
  return next
}

/** Derived flags for a reconciled state. */
export function serverDraftFlags<T>(state: ServerDraftState<T>, equals: (a: T, b: T) => boolean = Object.is) {
  const dirty = state.pinned || !equals(state.draft, state.base)
  return { dirty, serverChanged: !equals(state.base, state.server) }
}

/** Apply a local edit (value or updater) to the draft; editing while the server is ahead pins it. */
export function editServerDraft<T>(
  state: ServerDraftState<T>,
  value: SetStateAction<T>,
  equals: (a: T, b: T) => boolean = Object.is,
): ServerDraftState<T> {
  const draft = typeof value === 'function' ? (value as (prev: T) => T)(state.draft) : value
  if (Object.is(draft, state.draft)) return state
  return { ...state, draft, pinned: state.pinned || !equals(state.base, state.server) }
}

export function useServerDraft<T>(
  serverValue: T,
  options: ServerDraftOptions<T> = {},
): [T, Dispatch<SetStateAction<T>>, ServerDraftMeta<T>] {
  const { equals = Object.is, hold = false } = options
  const [stored, setStored] = useState(() => initialServerDraft(serverValue))
  const state = reconcileServerDraft(stored, serverValue, { equals, hold })
  // Render-phase sync (guarded): the reconciled value is used in this very render, so a
  // pristine field never shows a stale frame and a dirty one is never touched.
  if (state !== stored) setStored(state)

  const setDraft = useCallback<Dispatch<SetStateAction<T>>>(value => {
    setStored(prev => editServerDraft(prev, value, equals))
  }, [equals])
  const reset = useCallback(() => setStored(prev => initialServerDraft(prev.server)), [])
  const { dirty, serverChanged } = serverDraftFlags(state, equals)
  const meta = useMemo<ServerDraftMeta<T>>(
    () => ({ dirty, serverChanged, serverValue: state.server, reset, acceptServer: reset }),
    [dirty, serverChanged, state.server, reset],
  )
  return [state.draft, setDraft, meta]
}
