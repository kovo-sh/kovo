// Global ⌘K command palette and keyboard shortcut sheet for non-run workspace routes.
// Matches /runs/$runId's Palette design & interaction model.
import { useNavigate } from '@tanstack/react-router'
import { useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { Kbd, KbdGroup } from '../run/display.tsx'
import { host, modKey, runLabel, short } from '../run/format.ts'
import { StatusGlyph } from '../run/glyphs.tsx'
import { Icon } from '../run/icons.tsx'
import type { IconName } from '../run/icons.tsx'
import { runStatusLabel } from '../run/meta.ts'

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
  icon: IconName | ReactNode
  right?: string
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
  return <>{parts.map((p, i) => (i % 2 ? <mark key={i}>{p}</mark> : p))}</>
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
  theme,
  toggleTheme,
  data,
}: {
  open: boolean
  prefill: string
  onClose: () => void
  onOpenNewProject: () => void
  onOpenHelp: () => void
  theme: 'light' | 'dark'
  toggleTheme: () => void
  data: ShellWorkspaceData
}) {
  const navigate = useNavigate()
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
      out.push({
        id: 'run.' + r.id,
        section: 'Recent runs',
        label: runLabel(r.goal),
        sub: `${r.goal} ${r.projectName} ${r.id} ${r.status}`,
        icon: <StatusGlyph status={r.status} />,
        right: `${short(r.id)} · ${runStatusLabel(r.status)}`,
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
  }, [data, navigate, onOpenNewProject, onOpenHelp, theme, toggleTheme])

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
    listRef.current?.querySelector('.gpal-item.on')?.scrollIntoView({ block: 'nearest' })
  }, [open, cur, items])

  if (!open) return null

  const runItem = (i: number) => {
    const it = items[i]
    if (!it) return
    onClose()
    it.run()
  }

  let lastSection = ''
  return <div className="sh-overlay" onMouseDown={e => { if (e.target === e.currentTarget) onClose() }}>
    <div className="gpal" role="dialog" aria-modal="true" aria-label="Command palette">
      <div className="gpal-in">
        <Icon name="search" />
        <input
          autoFocus
          value={q}
          placeholder="Jump to a project, run, settings, or action…"
          autoComplete="off"
          spellCheck={false}
          aria-label="Search workspace"
          onChange={e => { setQ(e.target.value); setIdx(0) }}
          onKeyDown={e => {
            if (e.key === 'Escape') { e.preventDefault(); onClose() }
            else if (e.key === 'ArrowDown' || (e.ctrlKey && e.key === 'n')) {
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
        <span className="gpal-scope">{data.workspace.name}</span>
      </div>
      <div className="gpal-list" ref={listRef} role="listbox">
        {items.length === 0 && <div className="gpal-empty">No matches for “{q}”</div>}
        {items.map((it, i) => {
          const head = it.section !== lastSection ? <div className="gpal-sec">{it.section}</div> : null
          lastSection = it.section
          return <div key={it.id}>
            {head}
            <div
              className={'gpal-item' + (i === cur ? ' on' : '')}
              role="option"
              aria-selected={i === cur}
              onMouseMove={() => { if (i !== cur) setIdx(i) }}
              onClick={() => runItem(i)}
            >
              <span className="g">
                {typeof it.icon === 'string' ? <Icon name={it.icon as IconName} /> : it.icon}
              </span>
              <span className="l"><Highlight text={it.label} q={q.trim()} /></span>
              {it.keys
                ? <span className="r"><KbdGroup keys={it.keys} /></span>
                : it.right
                  ? <span className="r mono">{it.right}</span>
                  : null}
            </div>
          </div>
        })}
      </div>
      <div className="gpal-f">
        <span><Kbd>↑</Kbd><Kbd>↓</Kbd> navigate</span>
        <span><Kbd>↵</Kbd> open</span>
        <span><Kbd>esc</Kbd> close</span>
      </div>
    </div>
  </div>
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
  if (!open) return null
  return <div className="sh-overlay" onMouseDown={e => { if (e.target === e.currentTarget) onClose() }}>
    <div className="ghelp" role="dialog" aria-modal="true" aria-label="Keyboard shortcuts">
      <div className="ghelp-top">
        <h3>Keyboard shortcuts</h3>
        <button type="button" className="sh-icon-btn" onClick={onClose} aria-label="Close shortcuts">
          <Icon name="close" />
        </button>
      </div>
      {GLOBAL_SHORTCUTS.map(([section, rows]) => <div key={section}>
        <h5>{section}</h5>
        <div className="ghelp-grid">
          {rows.map(([keys, label]) => <div key={label}>
            <span>{label}</span>
            <span className="kbd-group">
              {keys.split(' ').map((k, i) => <span key={i} className="kbd">{k === 'mod' ? mod : k}</span>)}
            </span>
          </div>)}
        </div>
      </div>)}
    </div>
  </div>
}
