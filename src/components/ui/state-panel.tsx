import { useState } from 'react'
import type { ReactNode } from 'react'
import { cn } from '../../lib/cn.ts'
import { Icon } from '../run/icons.tsx'
import type { IconName } from '../run/icons.tsx'
import { Button } from './button.tsx'

/**
 * One state primitive for every "the happy path isn't here" surface: empty
 * lists, route errors, 404s, degraded data and quarantined stream records.
 *
 *   kind     → which glyph + tone (empty | error | not-found | degraded | quarantined)
 *   variant  → layout (page | section | inline | banner)
 *
 * Human copy stays in the title/description; raw codes, messages and
 * diagnostics only ever render inside the collapsed monospace <details>.
 */
export type StatePanelKind = 'empty' | 'error' | 'not-found' | 'degraded' | 'quarantined'
export type StatePanelVariant = 'page' | 'section' | 'inline' | 'banner'

export interface StatePanelProps {
  kind?: StatePanelKind
  variant?: StatePanelVariant
  /** Glyph override. `null` hides the glyph; `undefined` uses the kind default (none for `empty`). */
  icon?: ReactNode
  title: ReactNode
  description?: ReactNode
  /** Primary call to action (Button / Link). */
  action?: ReactNode
  secondaryAction?: ReactNode
  /** Raw technical detail (error code, message, diagnostics). Rendered collapsed, monospace. */
  details?: string | null
  detailsLabel?: string
  /** Show a "Copy diagnostics" button inside the technical block. */
  copyDetails?: boolean
  /** Banner-only dismiss handler; renders a "Dismiss" ghost button when set. */
  onDismiss?: () => void
  headingLevel?: 'h1' | 'h2' | 'h3'
  role?: 'alert' | 'status'
  /** `data-slot` prefix (EmptyState keeps its historical `empty-state*` slots). */
  slot?: string
  className?: string
  children?: ReactNode
  'data-testid'?: string
}

interface KindStyle { glyph: IconName | null; chip: string; banner: string }

const KIND_STYLE: Record<StatePanelKind, KindStyle> = {
  empty: { glyph: null, chip: 'text-fg-faint', banner: 'border-line-2 bg-raise' },
  'not-found': { glyph: 'search', chip: 'bg-sunk text-fg-subtle', banner: 'border-line-2 bg-raise' },
  error: { glyph: 'alert', chip: 'bg-danger-soft text-danger', banner: 'border-danger/35 bg-raise' },
  degraded: { glyph: 'alert', chip: 'bg-warn-soft text-warn-text', banner: 'border-warn-line bg-raise' },
  quarantined: { glyph: 'shield', chip: 'bg-warn-soft text-warn-text', banner: 'border-warn-line bg-raise' },
}

const ROOT_CLASS: Record<StatePanelVariant, string> = {
  page: 'mx-auto flex w-full max-w-[460px] flex-col items-center gap-3 text-center',
  section: 'mx-auto flex w-full max-w-[360px] flex-col items-center gap-3 px-6 py-10 text-center',
  inline: 'flex w-full min-w-0 flex-col items-start gap-2 text-left',
  banner: 'flex w-full min-w-0 flex-col gap-2 rounded-card border px-3.5 py-3 text-left shadow-popover',
}

const TITLE_CLASS: Record<StatePanelVariant, string> = {
  page: 'm-0 text-[15px] font-semibold leading-[22px] tracking-[-0.012em] text-fg',
  section: 'm-0 text-[13px] font-medium leading-5 text-fg',
  inline: 'm-0 text-[13px] font-medium leading-5 text-fg',
  banner: 'm-0 text-[13px] font-medium leading-5 text-fg',
}

const DESCRIPTION_CLASS: Record<StatePanelVariant, string> = {
  page: 'm-0 text-[12.5px] leading-5 text-fg-muted text-balance',
  section: 'm-0 text-[12px] leading-5 text-fg-subtle text-balance',
  inline: 'm-0 text-[12px] leading-5 text-fg-subtle',
  banner: 'm-0 text-[12px] leading-[18px] text-fg-muted',
}

function Glyph({ kind, icon, variant, slot }: { kind: StatePanelKind; icon: ReactNode; variant: StatePanelVariant; slot: string }) {
  const style = KIND_STYLE[kind]
  if (icon === null) return null
  if (icon === undefined && !style.glyph) return null
  // Empty states keep their historical faint, unboxed 28px glyph slot.
  if (kind === 'empty') {
    return (
      <div data-slot={`${slot}-icon`} className="flex size-8 flex-none items-center justify-center text-fg-faint [&>svg]:size-7">
        {icon ?? <Icon name={style.glyph!} />}
      </div>
    )
  }
  return (
    <span
      data-slot={`${slot}-icon`}
      aria-hidden="true"
      className={cn('grid flex-none place-items-center rounded-full', variant === 'banner' ? 'size-6' : 'size-8', style.chip)}
    >
      {icon ?? <Icon name={style.glyph!} />}
    </span>
  )
}

/** Copy text to the clipboard; resolves false when the browser refuses. */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text)
      return true
    }
  } catch {
    // Permission denied or insecure context: fall through to the textarea path.
  }
  if (typeof document === 'undefined') return false
  const area = document.createElement('textarea')
  area.value = text
  area.setAttribute('readonly', '')
  area.style.position = 'fixed'
  area.style.opacity = '0'
  document.body.appendChild(area)
  area.select()
  let ok = false
  try { ok = document.execCommand('copy') } catch { ok = false }
  area.remove()
  return ok
}

/** "Copy diagnostics" button with a transient "Copied" confirmation. */
export function CopyDiagnosticsButton({ text, className }: { text: string; className?: string }) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle')
  const label = state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed' : 'Copy diagnostics'
  return (
    <Button
      type="button"
      variant="outline"
      className={cn('h-6 rounded-[5px] px-[7px] text-[12px]', className)}
      data-state={state}
      onClick={() => {
        void copyText(text).then(ok => {
          setState(ok ? 'copied' : 'failed')
          window.setTimeout(() => setState('idle'), 1800)
        })
      }}
    >
      <Icon name={state === 'copied' ? 'check' : 'copy'} />
      {label}
    </Button>
  )
}

function TechnicalDetails({ details, label, copy, slot }: { details: string; label: string; copy: boolean; slot: string }) {
  return (
    <details data-slot={`${slot}-details`} className="w-full min-w-0 rounded-lg border border-line bg-sunk px-3 py-2 text-left text-[12px] text-fg-muted">
      <summary className="cursor-pointer select-none font-medium">{label}</summary>
      <pre className="mt-2 max-h-[200px] min-w-0 overflow-auto whitespace-pre-wrap font-mono text-[11.5px] leading-[17px] text-fg-muted [overflow-wrap:anywhere]">
        {details}
      </pre>
      {copy ? <div className="mt-2 flex justify-end"><CopyDiagnosticsButton text={details} /></div> : null}
    </details>
  )
}

function Actions({ action, secondaryAction, onDismiss, slot, variant }: Pick<StatePanelProps, 'action' | 'secondaryAction' | 'onDismiss' | 'variant'> & { slot: string }) {
  if (!action && !secondaryAction && !onDismiss) return null
  const align = variant === 'page' || variant === 'section' ? 'justify-center' : 'justify-start'
  return (
    <div data-slot={`${slot}-action`} className={cn('mt-1 flex flex-wrap items-center gap-2', align)}>
      {action}
      {secondaryAction}
      {onDismiss ? (
        <Button type="button" variant="ghost" className="h-6 rounded-[5px] px-[7px] text-[12px]" onClick={onDismiss}>
          Dismiss
        </Button>
      ) : null}
    </div>
  )
}

export function StatePanel({
  kind = 'empty',
  variant = 'section',
  icon,
  title,
  description,
  action,
  secondaryAction,
  details,
  detailsLabel = 'Technical details',
  copyDetails = false,
  onDismiss,
  headingLevel,
  role,
  slot = 'state-panel',
  className,
  children,
  'data-testid': testId,
}: StatePanelProps) {
  const Heading = headingLevel ?? (variant === 'page' ? 'h1' : 'h3')
  const banner = variant === 'banner'
  const body = (
    <>
      <div className="flex min-w-0 flex-col gap-1">
        <Heading data-slot={`${slot}-title`} className={TITLE_CLASS[variant]}>{title}</Heading>
        {description ? <p data-slot={`${slot}-description`} className={DESCRIPTION_CLASS[variant]}>{description}</p> : null}
      </div>
      {children}
    </>
  )
  return (
    <div
      data-slot={slot}
      data-kind={kind}
      data-variant={variant}
      data-testid={testId}
      role={role}
      className={cn(ROOT_CLASS[variant], banner && KIND_STYLE[kind].banner, className)}
    >
      {banner ? (
        <div className="flex min-w-0 items-start gap-2.5">
          <Glyph kind={kind} icon={icon} variant={variant} slot={slot} />
          <div className="flex min-w-0 flex-1 flex-col gap-1">{body}</div>
        </div>
      ) : (
        <>
          <Glyph kind={kind} icon={icon} variant={variant} slot={slot} />
          {body}
        </>
      )}
      <Actions action={action} secondaryAction={secondaryAction} onDismiss={onDismiss} slot={slot} variant={variant} />
      {details ? <TechnicalDetails details={details} label={detailsLabel} copy={copyDetails} slot={slot} /> : null}
    </div>
  )
}

// ---------------------------------------------------------------- server error → human copy

export type StateErrorCode =
  | 'unauthorized' | 'forbidden' | 'not-found' | 'invalid' | 'server' | 'unavailable' | 'timeout' | 'malformed' | 'unknown'

export interface StateErrorCopy {
  code: StateErrorCode
  /** HTTP status when one could be read from the error. */
  status: number | null
  kind: StatePanelKind
  title: string
  description: string
}

const ERROR_COPY: Record<StateErrorCode, Omit<StateErrorCopy, 'code' | 'status'>> = {
  unauthorized: { kind: 'error', title: 'Your session has expired', description: 'Sign in again to keep working. Nothing in your workspace was changed.' },
  forbidden: { kind: 'error', title: 'You don’t have access to this', description: 'This workspace session can’t open that item. Ask the workspace owner, or head back to your projects.' },
  'not-found': { kind: 'not-found', title: 'This item no longer exists', description: 'It may have been deleted or moved. Head back to your projects to find it.' },
  invalid: { kind: 'error', title: 'That link isn’t valid', description: 'The address points to something Kovo can’t look up. Check the link, or head back to your projects.' },
  server: { kind: 'error', title: 'Kovo hit an internal error', description: 'Something went wrong on the Kovo server while loading this page. Try again in a moment.' },
  unavailable: { kind: 'degraded', title: 'Kovo is temporarily unavailable', description: 'The local Kovo server didn’t answer. It may be restarting; try again in a few seconds.' },
  timeout: { kind: 'degraded', title: 'The request timed out', description: 'Kovo took too long to answer. Check that the server is still running, then try again.' },
  malformed: { kind: 'error', title: 'Kovo received data it couldn’t read', description: 'A response was incomplete or malformed. Reloading usually fixes this; your data is unaffected.' },
  unknown: { kind: 'error', title: 'Something went wrong', description: 'Something went wrong while loading this page. Try again, or head back to your projects.' },
}

const STATUS_CODE: ReadonlyArray<[(s: number) => boolean, StateErrorCode]> = [
  [s => s === 401, 'unauthorized'],
  [s => s === 403, 'forbidden'],
  [s => s === 404 || s === 410, 'not-found'],
  [s => s === 400 || s === 422, 'invalid'],
  [s => s === 408 || s === 504, 'timeout'],
  [s => s === 502 || s === 503, 'unavailable'],
  [s => s >= 500 && s < 600, 'server'],
]

function readStatus(error: unknown): number | null {
  if (!error || typeof error !== 'object') return null
  const e = error as Record<string, unknown>
  for (const value of [e.status, e.statusCode, (e.response as Record<string, unknown> | undefined)?.status]) {
    if (typeof value === 'number' && Number.isInteger(value) && value >= 400 && value < 600) return value
  }
  return null
}

function errorName(error: unknown): string {
  return error && typeof error === 'object' && typeof (error as { name?: unknown }).name === 'string' ? (error as { name: string }).name : ''
}

/** Plain message of any thrown value ('' when it has none). */
export function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message
  if (typeof error === 'string') return error
  if (error && typeof error === 'object' && 'message' in error && typeof error.message === 'string') return error.message
  return ''
}

function classifyByMessage(name: string, message: string): StateErrorCode {
  if (name === 'TimeoutError' || name === 'AbortError' || /\btimed? ?out\b/i.test(message)) return 'timeout'
  if (name === 'ZodError' || /^\s*\[\s*\{[\s\S]*"code"\s*:/.test(message) || /\binvalid (?:id|uuid|input|request)\b/i.test(message)) return 'invalid'
  if (name === 'SyntaxError' || /\b(?:unexpected token|malformed|not valid json|unexpected end of json)\b/i.test(message)) return 'malformed'
  if (/\bnot found\b/i.test(message)) return 'not-found'
  if (/\b(?:unauthori[sz]ed|sign in|session expired)\b/i.test(message)) return 'unauthorized'
  if (/\b(?:forbidden|access denied)\b/i.test(message)) return 'forbidden'
  if (/\b(?:failed to fetch|networkerror|econnrefused|service unavailable|bad gateway)\b/i.test(message)) return 'unavailable'
  const status = /\b(4\d\d|5\d\d)\b/.exec(message)
  if (status) return STATUS_CODE.find(([match]) => match(Number(status[1])))?.[1] ?? 'unknown'
  return 'unknown'
}

/** Map any thrown value (HTTP status, Zod/JSON/timeout errors, plain messages) to human copy. */
export function describeStateError(error: unknown): StateErrorCopy {
  const status = readStatus(error)
  const code = status !== null
    ? STATUS_CODE.find(([match]) => match(status))?.[1] ?? 'unknown'
    : classifyByMessage(errorName(error), errorMessage(error))
  return { code, status, ...ERROR_COPY[code] }
}

/** Mono diagnostics block for an error: code, HTTP status, and the raw message. */
export function stateErrorDetails(error: unknown, extra: ReadonlyArray<string | null | undefined> = []): string {
  const copy = describeStateError(error)
  const message = errorMessage(error).trim()
  return [
    `code: ${copy.code}`,
    copy.status !== null ? `status: ${copy.status}` : null,
    errorName(error) ? `type: ${errorName(error)}` : null,
    ...extra,
    message ? `message: ${message}` : null,
  ].filter(Boolean).join('\n')
}
