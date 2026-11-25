// ⌘K command palette and the keyboard-shortcut sheet, built on @base-ui/react Dialog.
import { useNavigate } from '@tanstack/react-router'
import { createContext, useContext, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { Dialog, DialogContent, DialogTitle } from '../ui/dialog.tsx'
import { useRun } from './data.tsx'
import { Kbd, KbdGroup } from './display.tsx'
import { fmtAgo, fmtFullDateTime, host, modKey, runLabel, short } from './format.ts'
import { SevGlyph, StatusGlyph } from './glyphs.tsx'
import { Icon } from './icons.tsx'
import type { IconName } from './icons.tsx'
import { useShortcuts } from './keyboard.tsx'
import { PHASE_LABEL, RISKL, runStatusLabel, SEV_ORDER, VIEWS } from './meta.ts'
import { useLinks, useNav } from './nav.tsx'
import { useTheme } from './theme.ts'
import { cn, RW } from './tw.ts'

export interface PaletteCommand {
  id: string
  section: string
  label: string
  /** Extra text that matches the query but isn't shown (e.g. full goal). */
  sub?: string
  icon?: IconName | ReactNode
  /** Right-hand hint: plain text (rendered mono) or key caps. */
  right?: string
  keys?: string[]
  run: () => void
}

interface PaletteApi {
  open: (prefill?: string) => void
  close: () => void
  isOpen: boolean
  openHelp: () => void
  closeHelp: () => void
  helpOpen: boolean
  register: (owner: symbol, cmds: PaletteCommand[]) => void
  unregister: (owner: symbol) => void
  extra: () => PaletteCommand[]
}
const PaletteContext = createContext<PaletteApi | null>(null)
export function usePalette() {
  const v = useContext(PaletteContext)
  if (!v) throw new Error('usePalette() must be used inside <PaletteProvider>')
  return v
}

/** Register commands for as long as the calling component is mounted. */
export function usePaletteCommands(commands: PaletteCommand[]) {
  const api = usePalette()
  const owner = useRef(Symbol('palette'))
  const ref = useRef(commands)
  ref.current = commands
  useEffect(() => { api.register(owner.current, ref.current) })
  useEffect(() => { const o = owner.current; return () => api.unregister(o) }, [api])
}

export function PaletteProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<{ open: boolean; prefill: string }>({ open: false, prefill: '' })
  const [helpOpen, setHelpOpen] = useState(false)
  const reg = useRef(new Map<symbol, PaletteCommand[]>())
  const api = useMemo<PaletteApi>(() => ({
    open: prefill => { setHelpOpen(false); setState({ open: true, prefill: prefill ?? '' }) },
    close: () => setState(s => ({ ...s, open: false })),
    isOpen: state.open,
    openHelp: () => { setState(s => ({ ...s, open: false })); setHelpOpen(true) },
    closeHelp: () => setHelpOpen(false),
    helpOpen,
    register: (o, c) => { reg.current.set(o, c) },
    unregister: o => { reg.current.delete(o) },
    extra: () => [...reg.current.values()].flat(),
  }), [state.open, helpOpen])
  return <PaletteContext.Provider value={api}>
    {children}
    {state.open && <Palette prefill={state.prefill} />}
    {helpOpen && <HelpSheet />}
  </PaletteContext.Provider>
}

const SECTION_ORDER = ['Views', 'Runs', 'Findings', 'Workers', 'Hosts', 'Actions']
const SECTION_BIAS: Record<string, number> = { Views: 0, Runs: 0, Actions: 0.5, Findings: 1, Workers: 1.5, Hosts: 1.2 }

function Highlight({ text, q }: { text: string; q: string }) {
  const toks = q.split(/\s+/).filter(Boolean).map(s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
  if (!toks.length) return <>{text}</>
  const parts = text.split(new RegExp('(' + toks.join('|') + ')', 'gi'))
  return <>{parts.map((p, i) => i % 2 ? <mark key={i} className="bg-transparent font-medium text-accent">{p}</mark> : p)}</>
}

function useBaseCommands(): PaletteCommand[] {
  const { model, runs } = useRun()
  const navigate = useNavigate()
  const nav = useNav()
  const links = useLinks()
  const pal = usePalette()
  const { theme, toggle } = useTheme()
  return useMemo(() => {
    const out: PaletteCommand[] = []
    VIEWS.forEach(v => out.push({ id: 'view.' + v.id, section: 'Views', label: 'Go to ' + v.label, icon: v.icon, keys: ['G', v.key.toUpperCase()], run: () => nav.setView(v.id) }))
    runs.forEach(r => out.push({
      id: 'run.' + r.id, section: 'Runs', label: runLabel(r.goal), sub: r.goal + ' ' + r.projectName + ' ' + r.id,
      icon: <StatusGlyph status={r.status} />, right: r.projectName + ' · ' + fmtAgo(r.createdAt) + ' · ' + runStatusLabel(r.status), run: () => nav.switchRun(r.id),
    }))
    out.push({ id: 'act.chat', section: 'Actions', label: 'Open the board · message the coordinator', icon: 'chat', keys: ['C'], run: () => nav.openChat(null) })
    out.push({ id: 'act.settings', section: 'Actions', label: 'Open settings', icon: 'sliders', run: () => void navigate({ to: '/settings', search: { runId: model.run.id } }) })
    out.push({ id: 'act.pane', section: 'Actions', label: nav.paneCollapsed ? 'Show right panel' : 'Hide right panel', icon: 'panelR', keys: [']'], run: () => nav.togglePane() })
    out.push({ id: 'act.theme', section: 'Actions', label: 'Toggle light / dark theme', icon: theme === 'dark' ? 'sun' : 'moon', keys: ['⇧', 'T'], run: toggle })
    out.push({ id: 'act.help', section: 'Actions', label: 'Show keyboard shortcuts', icon: 'keyboard', keys: ['?'], run: pal.openHelp })
    model.findings.slice().sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]).forEach(f => out.push({
      id: 'f.' + f.id, section: 'Findings', label: f.title, icon: <SevGlyph sev={f.severity} />, right: host(f.origin), run: () => links.finding(f.id),
    }))
    model.detail.assignments.forEach(a => out.push({
      id: 'w.' + a.id, section: 'Workers', label: a.title, icon: <StatusGlyph status={a.status} />, right: PHASE_LABEL[a.phase] ?? a.phase, run: () => links.worker(a.id),
    }))
    model.surface.origins.forEach(o => out.push({
      id: 'h.' + o.origin, section: 'Hosts', label: o.host, icon: <span className="flex text-fg-subtle"><Icon name="globe" /></span>, right: RISKL[o.tier], run: () => links.host(o.origin),
    }))
    return out
  }, [model, runs, navigate, nav, links, pal, theme, toggle])
}

function Palette({ prefill }: { prefill: string }) {
  const pal = usePalette()
  const base = useBaseCommands()
  const { detail, model } = useRun()
  const [q, setQ] = useState(prefill)
  const [idx, setIdx] = useState(0)
  const listRef = useRef<HTMLDivElement>(null)
  const items = useMemo(() => {
    const src = base.concat(pal.extra())
    const query = q.trim().toLowerCase()
    if (!query) {
      const f = src.filter(i => i.section === 'Findings').slice(0, 5)
      return src.filter(i => i.section === 'Views' || i.section === 'Runs' || i.section === 'Actions').concat(f)
    }
    const toks = query.split(/\s+/)
    const scored = src.map(i => {
      const hay = (i.label + ' ' + (i.sub ?? '') + ' ' + (i.right ?? '') + ' ' + i.section).toLowerCase()
      if (!toks.every(t => hay.includes(t))) return null
      const lab = i.label.toLowerCase()
      return { i, score: (lab.startsWith(toks[0]) ? 0 : lab.includes(toks[0]) ? 1 : 2) + (SECTION_BIAS[i.section] ?? 1) }
    }).filter((x): x is { i: PaletteCommand; score: number } => !!x).sort((a, b) => a.score - b.score).map(x => x.i)
    const present = [...new Set(scored.map(i => i.section))]
    const secs = SECTION_ORDER.filter(s => present.includes(s)).concat(present.filter(s => !SECTION_ORDER.includes(s)))
    return secs.flatMap(s => scored.filter(i => i.section === s).slice(0, 10))
  }, [base, pal, q])
  const cur = Math.min(idx, Math.max(0, items.length - 1))
  useEffect(() => { listRef.current?.querySelector('[data-active="true"]')?.scrollIntoView({ block: 'nearest' }) }, [cur, items])
  const run = (i: number) => { const it = items[i]; if (!it) return; pal.close(); it.run() }
  useShortcuts([{ key: 'Escape', allowInInput: true, run: () => pal.close() }], { priority: 100, exclusive: true })
  let last = ''
  return <Dialog open onOpenChange={open => { if (!open) pal.close() }}>
    <DialogContent
      className="max-w-[620px] overflow-hidden rounded-2xl border-line-2 bg-raise p-0"
      aria-label="Command palette"
    >
      <DialogTitle className="sr-only">Run command palette</DialogTitle>
      <div className="flex h-[50px] items-center gap-2.5 border-b border-line px-4 text-fg-subtle">
        <Icon name="search" />
        <input
          autoFocus
          value={q}
          placeholder="Jump to a run, view, finding, worker, or action…"
          autoComplete="off"
          spellCheck={false}
          aria-label="Search commands"
          className={cn(RW.rawInput, 'text-[14.5px]')}
          onChange={e => { setQ(e.target.value); setIdx(0) }}
          onKeyDown={e => {
            if (e.key === 'ArrowDown' || (e.ctrlKey && e.key === 'n')) { e.preventDefault(); setIdx(Math.min(items.length - 1, cur + 1)) }
            else if (e.key === 'ArrowUp' || (e.ctrlKey && e.key === 'p')) { e.preventDefault(); setIdx(Math.max(0, cur - 1)) }
            else if (e.key === 'Enter') { e.preventDefault(); run(cur) }
          }}
        />
        <span
          className="flex-none rounded-[5px] px-[7px] py-0.5 text-[11.5px] text-fg-subtle shadow-[inset_0_0_0_1px_var(--line-2)]"
          title={`${detail.project.name} · Started ${fmtFullDateTime(model.run.createdAt)} · Run ${short(model.run.id)}`}
          suppressHydrationWarning
        >
          {detail.project.name} · {fmtAgo(model.run.createdAt)}
        </span>
      </div>
      <div className="max-h-[400px] overflow-auto p-1.5" ref={listRef} role="listbox">
        {!items.length && <div className="p-7 text-center text-fg-subtle">No matches for “{q}”</div>}
        {items.map((it, i) => {
          const head = it.section !== last ? <div className="px-2.5 pb-1 pt-2 text-[11.5px] font-medium text-fg-subtle">{it.section}</div> : null
          last = it.section
          const active = i === cur
          return <div key={it.id}>
            {head}
            <div
              className={cn(
                'flex h-9 cursor-pointer items-center gap-2.5 rounded-[7px] px-2.5 text-fg-muted',
                active && 'bg-press',
              )}
              data-active={active ? 'true' : undefined}
              role="option"
              aria-selected={active}
              onMouseMove={() => { if (!active) setIdx(i) }}
              onClick={() => run(i)}
            >
              <span className="inline-flex size-3.5 flex-none items-center justify-center">
                {typeof it.icon === 'string' ? <Icon name={it.icon as IconName} /> : it.icon}
              </span>
              <span className="min-w-0 flex-1 truncate text-fg"><Highlight text={it.label} q={q.trim()} /></span>
              {it.keys
                ? <span className="max-w-[200px] truncate whitespace-nowrap text-[12px] text-fg-subtle"><KbdGroup keys={it.keys} /></span>
                : it.right
                  ? <span className="max-w-[200px] truncate whitespace-nowrap font-mono text-[12px] text-fg-subtle">{it.right}</span>
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

/** The shortcut sheet. Views that add keys should add rows here. */
export const SHORTCUT_SHEET: [string, [string, string][]][] = [
  ['General', [['mod K', 'Command palette'], ['?', 'This sheet'], ['G then O Q F W S E A R', 'Go to a view'], ['1 – 8', 'Go to a view'], ['[', 'Previous run'], [']', 'Hide / show right panel'], ['⇧ T', 'Toggle theme'], ['C', 'Board · message the coordinator'], ['Esc', 'Close detail / overlay']]],
  ['Lists', [['J / K', 'Next / previous row'], ['↵ / O', 'Open row'], ['/', 'Filter'], ['⇧ G', 'Cycle grouping']]],
  ['Queue', [['A', 'Approve · accept · queue'], ['D', 'Deny · dismiss · not needed'], ['F', 'False positive'], ['C', 'Ask coordinator about item'], ['Z', 'Undo last decision']]],
  ['Workflow', [['← ↑ ↓ →', 'Move between workers'], ['+ / −', 'Zoom'], ['0', 'Fit graph'], ['↵', 'Center selection'], ['L', 'Graph / list'], ['⇧ R', 'Replay · Space plays']]],
  ['Surface', [['← ↑ ↓ →', 'Move the cell cursor'], ['↵', 'Open cell'], ['Esc', 'Clear filter, then selection']]],
]

function HelpSheet() {
  const pal = usePalette()
  const [mod, setMod] = useState('Ctrl')
  useEffect(() => setMod(modKey()), [])
  useShortcuts([{ key: ['Escape', '?'], run: () => pal.closeHelp() }], { priority: 100, exclusive: true })
  return <Dialog open onOpenChange={open => { if (!open) pal.closeHelp() }}>
    <DialogContent className="max-h-[76vh] max-w-[600px] overflow-auto rounded-2xl border-line-2 bg-raise px-5 pb-3.5 pt-[18px]">
      <DialogTitle className="m-0 mb-1 text-[13.5px] font-semibold text-fg">Keyboard shortcuts</DialogTitle>
      {SHORTCUT_SHEET.map(([h, rows]) => <div key={h}>
        <h5 className="mb-1 mt-3.5 text-[11.5px] font-medium text-fg-subtle">{h}</h5>
        <div className="grid grid-cols-2 gap-x-7">
          {rows.map(([k, l]) => <div key={l} className="flex items-center justify-between border-b border-line py-[5px] text-[12.5px] text-fg-muted">
            <span>{l}</span>
            <KbdGroup keys={k.split(' ').map(x => (x === 'mod' ? mod : x))} />
          </div>)}
        </div>
      </div>)}
    </DialogContent>
  </Dialog>
}
