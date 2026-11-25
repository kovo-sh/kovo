// Global ⌘K command palette and keyboard shortcut sheet for non-run workspace routes.
// Matches /runs/$runId's Palette design & interaction model using @base-ui/react Dialog.
import { useNavigate } from '@tanstack/react-router'
import { useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { cn } from '../../lib/cn.ts'
import { Kbd, KbdGroup } from '../run/display.tsx'
import { host, modKey, runLabel } from '../run/format.ts'
import { StatusGlyph } from '../run/glyphs.tsx'
import { Icon } from '../run/icons.tsx'
import type { IconName } from '../run/icons.tsx'
import { runStatusLabel } from '../run/meta.ts'
import { Button } from '../ui/button.tsx'
import { Dialog, DialogContent, DialogTitle } from '../ui/dialog.tsx'

const SHORT_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'] as const
const MINUTE_MS = 60_000
const HOUR_MS = 3_600_000
const DAY_MS = 24 * HOUR_MS

/**
 * Human-friendly timestamp:
 * - < 24h old: relative ("just now", "8m ago" / "8 minutes ago", "2h ago" / "2 hours ago")
 * - >= 24h old: concise calendar date ("Nov 22", or "Nov 22, 2025" if a different year)
 */
export function formatRelativeTime(ms: number, opts?: { compact?: boolean; now?: number }): string {
  if (!Number.isFinite(ms)) return ''
  const now = opts?.now ?? Date.now()
  const diff = now - ms
  if (diff >= -MINUTE_MS && diff < DAY_MS) {
    if (diff < MINUTE_MS) return 'just now'
    if (diff < HOUR_MS) {
      const mins = Math.floor(diff / MINUTE_MS)
      return opts?.compact ? `${mins}m ago` : `${mins} ${mins === 1 ? 'minute' : 'minutes'} ago`
    }
    const hrs = Math.floor(diff / HOUR_MS)
    return opts?.compact ? `${hrs}h ago` : `${hrs} ${hrs === 1 ? 'hour' : 'hours'} ago`
  }
  const d = new Date(ms)
  const ref = new Date(now)
  const day = `${SHORT_MONTHS[d.getMonth()]} ${d.getDate()}`
  return d.getFullYear() === ref.getFullYear() ? day : `${day}, ${d.getFullYear()}`
}

/** Full local date + time for hover tooltips (e.g. "Nov 24, 2026, 9:00 PM"). */
export function formatFullDateTime(ms: number): string {
  if (!Number.isFinite(ms)) return ''
  return new Date(ms).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  })
}

/** Lightweight client clock tick so relative timestamps stay fresh while open. */
export function useNow(intervalMs = 60_000): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    setNow(Date.now())
    const id = window.setInterval(() => setNow(Date.now()), intervalMs)
    return () => window.clearInterval(id)
  }, [intervalMs])
  return now
}

export interface ShellProjectItem {
  id: string
  name: string
  environment: 'public' | 'local-lab'
  seeds: string[]
  runCount: number
  hostCount: number
  latestRun: {
    id: string
    goal: string
    status: string
    phase: string
    startedAt: number
    confirmedCount: number
    findingCount: number
  } | null
}

export interface ShellRecentRun {
  id: string
  projectId: string
  projectName: string
  goal: string
  status: string
  phase: string
  startedAt: number
  confirmedCount: number
  findings: number
}

export type PoolHealth = 'healthy' | 'degraded' | 'unconfigured'

export interface ShellWorkspaceData {
  workspace: { id: string; name: string }
  projects: ShellProjectItem[]
  recentRuns: ShellRecentRun[]
  hasModel: boolean
  poolHealth: PoolHealth
}

interface GlobalCommand {
  id: string
  section: 'Navigation' | 'Projects' | 'Recent runs' | 'Actions'
  label: string
  sub?: string
  title?: string
  icon: IconName | ReactNode
  right?: string
  rightTitle?: string
  rightMono?: boolean
  keys?: string[]
  run: () => void
}

const SECTION_ORDER: GlobalCommand['section'][] = ['Navigation', 'Projects', 'Recent runs', 'Actions']
const SECTION_BIAS: Record<GlobalCommand['section'], number> = {
  Navigation: 0,
  Projects: 0.2,
  'Recent runs': 0.5,
  Actions: 0.7,
}

function Highlight({ text, q }: { text: string; q: string }) {
  const toks = q.split(/\s+/).filter(Boolean).map(s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
  if (!toks.length) return <>{text}</>
  const parts = text.split(new RegExp('(' + toks.join('|') + ')', 'gi'))
  return <>{parts.map((p, i) => (i % 2 ? <mark key={i} className="bg-transparent font-medium text-accent">{p}</mark> : p))}</>
}

function poolHealthText(health: PoolHealth): string {
  if (health === 'healthy') return 'Healthy'
  if (health === 'degraded') return 'Degraded'
  return 'Unconfigured'
}

export function GlobalPalette({
  open,
  prefill,
  onClose,
  onOpenNewProject,
  onOpenHelp,
  onOpenDevices,
  theme,
  toggleTheme,
  data,
}: {
  open: boolean
  prefill: string
  onClose: () => void
  onOpenNewProject: () => void
  onOpenHelp: () => void
  onOpenDevices?: () => void
  theme: 'light' | 'dark'
  toggleTheme: () => void
  data: ShellWorkspaceData
}) {
  const navigate = useNavigate()
  const now = useNow()
  const [q, setQ] = useState(prefill)
  const [idx, setIdx] = useState(0)
  const listRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (open) {
      setQ(prefill)
      setIdx(0)
    }
  }, [open, prefill])

  const commands = useMemo<GlobalCommand[]>(() => {
    const out: GlobalCommand[] = [
      {
        id: 'nav.projects',
        section: 'Navigation',
        label: 'Projects',
        sub: 'workspace home list',
        icon: 'grid',
        keys: ['G', 'P'],
        run: () => { void navigate({ to: '/' }) },
      },
      {
        id: 'nav.settings',
        section: 'Navigation',
        label: 'Model settings',
        sub: 'providers api keys failover pool devices',
        icon: 'sliders',
        right: poolHealthText(data.poolHealth),
        run: () => { void navigate({ to: '/settings', search: {} }) },
      },
    ]

    for (const p of data.projects) {
      const seedHosts = p.seeds.map(host)
      const primaryHost = seedHosts[0] ?? ''
      const rightHint = primaryHost
        ? (seedHosts.length > 1 ? `${primaryHost} +${seedHosts.length - 1}` : primaryHost)
        : `${p.runCount} runs`
      out.push({
        id: 'proj.' + p.id,
        section: 'Projects',
        label: p.name,
        sub: `${seedHosts.join(' ')} ${p.environment}`,
        icon: p.environment === 'local-lab' ? 'lock' : 'globe',
        right: rightHint,
        run: () => { void navigate({ to: '/projects/$projectId', params: { projectId: p.id } }) },
      })
    }

    for (const r of data.recentRuns) {
      const rel = formatRelativeTime(r.startedAt, { compact: true, now })
      const full = formatFullDateTime(r.startedAt)
      out.push({
        id: 'run.' + r.id,
        section: 'Recent runs',
        label: r.projectName,
        sub: `${r.goal} ${r.projectName} ${r.id} ${r.status}`,
        title: `${r.projectName} — ${runLabel(r.goal)} (${full})`,
        icon: <StatusGlyph status={r.status} />,
        right: `${rel} · ${runStatusLabel(r.status)}`,
        rightTitle: full,
        rightMono: false,
        run: () => { void navigate({ to: '/runs/$runId', params: { runId: r.id }, search: {} }) },
      })
    }

    out.push(
      {
        id: 'act.new-project',
        section: 'Actions',
        label: 'New project',
        sub: 'create project add seeds target',
        icon: 'plus',
        keys: ['N'],
        run: onOpenNewProject,
      },
      ...(onOpenDevices
        ? [{
            id: 'act.devices',
            section: 'Actions' as const,
            label: 'Devices & local session',
            sub: 'pair another device phone browser pairing link sign out rotate session',
            icon: 'lock' as const,
            right: 'Pair device',
            run: onOpenDevices,
          }]
        : []),
      {
        id: 'act.theme',
        section: 'Actions',
        label: theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme',
        sub: 'toggle theme appearance dark light mode',
        icon: theme === 'dark' ? 'sun' : 'moon',
        keys: ['⇧', 'T'],
        run: toggleTheme,
      },
      {
        id: 'act.help',
        section: 'Actions',
        label: 'Keyboard shortcuts',
        sub: 'help keys',
        icon: 'keyboard',
        keys: ['?'],
        run: onOpenHelp,
      },
    )

    return out
  }, [data, now, navigate, onOpenNewProject, onOpenHelp, onOpenDevices, theme, toggleTheme])

  const items = useMemo(() => {
    const query = q.trim().toLowerCase()
    if (!query) {
      return [
        ...commands.filter(c => c.section === 'Navigation'),
        ...commands.filter(c => c.section === 'Projects').slice(0, 6),
        ...commands.filter(c => c.section === 'Recent runs').slice(0, 6),
        ...commands.filter(c => c.section === 'Actions'),
      ]
    }
    const toks = query.split(/\s+/)
    const scored = commands
      .map(c => {
        const hay = (c.label + ' ' + (c.sub ?? '') + ' ' + (c.right ?? '') + ' ' + c.section).toLowerCase()
        if (!toks.every(t => hay.includes(t))) return null
        const lab = c.label.toLowerCase()
        const score = (lab.startsWith(toks[0]) ? 0 : lab.includes(toks[0]) ? 1 : 2) + SECTION_BIAS[c.section]
        return { c, score }
      })
      .filter((x): x is { c: GlobalCommand; score: number } => Boolean(x))
      .sort((a, b) => a.score - b.score)
      .map(x => x.c)
    return SECTION_ORDER.flatMap(sec => scored.filter(c => c.section === sec).slice(0, 8))
  }, [commands, q])

  const cur = Math.min(idx, Math.max(0, items.length - 1))

  useEffect(() => {
    if (!open) return
    listRef.current?.querySelector('[data-active="true"]')?.scrollIntoView({ block: 'nearest' })
  }, [open, cur, items])

  const runItem = (i: number) => {
    const it = items[i]
    if (!it) return
    onClose()
    it.run()
  }

  let lastSection = ''
  return <Dialog open={open} onOpenChange={next => { if (!next) onClose() }}>
    <DialogContent
      aria-label="Command palette"
      className="mb-auto mt-[10vh] max-w-[620px] overflow-hidden rounded-2xl border-0 bg-raise p-0 shadow-popover [&_svg]:block [&_svg]:flex-none"
    >
      <DialogTitle className="sr-only">Command palette</DialogTitle>
      <div className="flex h-[50px] items-center gap-2.5 border-b border-line px-4 text-fg-subtle">
        <Icon name="search" />
        <input
          autoFocus
          value={q}
          placeholder="Jump to a project, run, settings, or action…"
          autoComplete="off"
          spellCheck={false}
          aria-label="Search workspace"
          className="h-auto min-w-0 flex-1 rounded-none border-0 bg-transparent p-0 text-[14.5px] text-fg shadow-none outline-none placeholder:text-fg-subtle focus:shadow-none focus:outline-none"
          onChange={e => { setQ(e.target.value); setIdx(0) }}
          onKeyDown={e => {
            if (e.key === 'ArrowDown' || (e.ctrlKey && e.key === 'n')) {
              e.preventDefault()
              setIdx(Math.min(items.length - 1, cur + 1))
            } else if (e.key === 'ArrowUp' || (e.ctrlKey && e.key === 'p')) {
              e.preventDefault()
              setIdx(Math.max(0, cur - 1))
            } else if (e.key === 'Enter') {
              e.preventDefault()
              runItem(cur)
            }
          }}
        />
        <span className="whitespace-nowrap rounded-[5px] border border-line-2 px-[7px] py-0.5 text-[11.5px] text-fg-subtle">
          {data.workspace.name}
        </span>
      </div>
      <div className="max-h-[400px] overflow-auto p-1.5" ref={listRef} role="listbox">
        {items.length === 0 && (
          <div className="p-7 text-center text-[12.5px] text-fg-subtle">No matches for “{q}”</div>
        )}
        {items.map((it, i) => {
          const head = it.section !== lastSection
            ? <div className="px-2.5 pb-1 pt-2 text-[11.5px] font-medium text-fg-subtle">{it.section}</div>
            : null
          lastSection = it.section
          const isCurrent = i === cur
          return <div key={it.id}>
            {head}
            <div
              className={cn(
                'flex h-9 cursor-pointer items-center gap-2.5 rounded-[7px] px-2.5 text-fg-muted',
                isCurrent && 'bg-press',
              )}
              data-active={isCurrent ? 'true' : undefined}
              role="option"
              aria-selected={isCurrent}
              title={it.title}
              onMouseMove={() => { if (!isCurrent) setIdx(i) }}
              onClick={() => runItem(i)}
            >
              <span className="inline-flex size-3.5 flex-none items-center justify-center">
                {typeof it.icon === 'string' ? <Icon name={it.icon as IconName} /> : it.icon}
              </span>
              <span className="min-w-0 flex-1 truncate text-fg">
                <Highlight text={it.label} q={q.trim()} />
              </span>
              {it.keys
                ? <span className="flex-none text-[12px] text-fg-subtle"><KbdGroup keys={it.keys} /></span>
                : it.right
                  ? <span
                      className={cn(
                        'max-w-[220px] truncate whitespace-nowrap text-[12px] text-fg-subtle',
                        it.rightMono === false ? 'tabular-nums' : 'font-mono',
                      )}
                      title={it.rightTitle}
                      suppressHydrationWarning
                    >
                      {it.right}
                    </span>
                  : null}
            </div>
          </div>
        })}
      </div>
      <div className="flex items-center gap-4 border-t border-line bg-sunk px-3.5 py-2 text-[11.5px] text-fg-subtle">
        <span className="inline-flex items-center gap-1.5"><Kbd>↑</Kbd><Kbd>↓</Kbd> navigate</span>
        <span className="inline-flex items-center gap-1.5"><Kbd>↵</Kbd> open</span>
        <span className="inline-flex items-center gap-1.5"><Kbd>esc</Kbd> close</span>
      </div>
    </DialogContent>
  </Dialog>
}

const GLOBAL_SHORTCUTS: [string, [string, string][]][] = [
  ['Navigation', [
    ['mod K', 'Command palette'],
    ['G P', 'Go to Projects'],
    ['G S', 'Go to Model settings'],
    ['?', 'Keyboard shortcuts'],
  ]],
  ['Actions', [
    ['N', 'New project'],
    ['⇧ T', 'Toggle light / dark theme'],
    ['Esc', 'Close modal or palette'],
  ]],
]

export function GlobalHelpSheet({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [mod, setMod] = useState('Ctrl')
  useEffect(() => setMod(modKey()), [])

  return <Dialog open={open} onOpenChange={next => { if (!next) onClose() }}>
    <DialogContent
      aria-label="Keyboard shortcuts"
      className="max-h-[76vh] max-w-[540px] overflow-auto rounded-2xl border-0 bg-raise px-5 pb-4 pt-[18px] shadow-popover [&_svg]:block [&_svg]:flex-none"
    >
      <div className="mb-1 flex items-center justify-between">
        <DialogTitle className="text-[13.5px] font-semibold text-fg">Keyboard shortcuts</DialogTitle>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="text-fg-subtle hover:text-fg"
          onClick={onClose}
          aria-label="Close shortcuts"
        >
          <Icon name="close" />
        </Button>
      </div>
      {GLOBAL_SHORTCUTS.map(([section, rows]) => <div key={section}>
        <h5 className="mb-1 mt-3.5 text-[11.5px] font-medium text-fg-subtle">{section}</h5>
        <div className="grid grid-cols-2 gap-x-6 max-[720px]:grid-cols-1">
          {rows.map(([keys, label]) => <div
            key={label}
            className="flex items-center justify-between gap-2 border-b border-line py-[5px] text-[12.5px] text-fg-muted"
          >
            <span>{label}</span>
            <span className="kbd-group">
              {keys.split(' ').map((k, i) => <span key={i} className="kbd">{k === 'mod' ? mod : k}</span>)}
            </span>
          </div>)}
        </div>
      </div>)}
    </DialogContent>
  </Dialog>
}
