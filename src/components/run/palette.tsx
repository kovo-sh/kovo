// ⌘K command palette and the keyboard-shortcut sheet.
//
// Views add their own commands while mounted:
//   usePaletteCommands([
//     { id: 'wf.replay', section: 'Actions', label: 'Replay the run in the workflow graph', icon: 'replay', keys: ['⇧', 'R'], run: startReplay },
//   ])
// Sections render in this order: Views, Runs, Findings, Workers, Hosts, Actions
// (any other section name is appended). With an empty query the palette shows
// Views, Runs, Actions and the top five findings.
import { createContext, useContext, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { useRun } from './data.tsx'
import { Kbd, KbdGroup } from './display.tsx'
import { host, modKey, runLabel, short } from './format.ts'
import { SevGlyph, StatusGlyph } from './glyphs.tsx'
import { Icon } from './icons.tsx'
import type { IconName } from './icons.tsx'
import { useShortcuts } from './keyboard.tsx'
import { RISKL, runStatusLabel, SEV_ORDER, PHASE_LABEL, VIEWS } from './meta.ts'
import { useLinks, useNav } from './nav.tsx'
import { useTheme } from './theme.ts'

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
  return <>{parts.map((p, i) => i % 2 ? <mark key={i}>{p}</mark> : p)}</>
}

function useBaseCommands(): PaletteCommand[] {
  const { model, runs } = useRun()
  const nav = useNav()
  const links = useLinks()
  const pal = usePalette()
  const { theme, toggle } = useTheme()
  return useMemo(() => {
    const out: PaletteCommand[] = []
    VIEWS.forEach(v => out.push({ id: 'view.' + v.id, section: 'Views', label: 'Go to ' + v.label, icon: v.icon, keys: ['G', v.key.toUpperCase()], run: () => nav.setView(v.id) }))
    runs.forEach(r => out.push({
      id: 'run.' + r.id, section: 'Runs', label: runLabel(r.goal), sub: r.goal + ' ' + r.projectName,
      icon: <StatusGlyph status={r.status} />, right: short(r.id) + ' · ' + runStatusLabel(r.status), run: () => nav.switchRun(r.id),
    }))
    out.push({ id: 'act.chat', section: 'Actions', label: 'Open the board · message the coordinator', icon: 'chat', keys: ['C'], run: () => nav.openChat(null) })
    out.push({ id: 'act.theme', section: 'Actions', label: 'Toggle light / dark theme', icon: theme === 'dark' ? 'sun' : 'moon', keys: ['⇧', 'T'], run: toggle })
    out.push({ id: 'act.help', section: 'Actions', label: 'Show keyboard shortcuts', icon: 'keyboard', keys: ['?'], run: pal.openHelp })
    model.findings.slice().sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]).forEach(f => out.push({
      id: 'f.' + f.id, section: 'Findings', label: f.title, icon: <SevGlyph sev={f.severity} />, right: host(f.origin), run: () => links.finding(f.id),
    }))
    model.detail.assignments.forEach(a => out.push({
      id: 'w.' + a.id, section: 'Workers', label: a.title, icon: <StatusGlyph status={a.status} />, right: PHASE_LABEL[a.phase] ?? a.phase, run: () => links.worker(a.id),
    }))
    model.surface.origins.forEach(o => out.push({
      id: 'h.' + o.origin, section: 'Hosts', label: o.host, icon: <span style={{ color: 'var(--fg-3)', display: 'flex' }}><Icon name="globe" /></span>, right: RISKL[o.tier], run: () => links.host(o.origin),
    }))
    return out
  }, [model, runs, nav, links, pal, theme, toggle])
}

function Palette({ prefill }: { prefill: string }) {
  const pal = usePalette()
  const base = useBaseCommands()
  const { model } = useRun()
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
  useEffect(() => { listRef.current?.querySelector('.pi.on')?.scrollIntoView({ block: 'nearest' }) }, [cur, items])
  const run = (i: number) => { const it = items[i]; if (!it) return; pal.close(); it.run() }
  useShortcuts([{ key: 'Escape', allowInInput: true, run: () => pal.close() }], { priority: 100, exclusive: true })
  let last = ''
  return <div className="overlay open" onMouseDown={e => { if (e.target === e.currentTarget) pal.close() }}>
    <div className="pal" role="dialog" aria-modal="true" aria-label="Command palette">
      <div className="pal-in">
        <Icon name="search" />
        <input autoFocus value={q} placeholder="Jump to a run, view, finding, worker, or action…" autoComplete="off" spellCheck={false}
          aria-label="Search commands"
          onChange={e => { setQ(e.target.value); setIdx(0) }}
          onKeyDown={e => {
            if (e.key === 'ArrowDown' || (e.ctrlKey && e.key === 'n')) { e.preventDefault(); setIdx(Math.min(items.length - 1, cur + 1)) }
            else if (e.key === 'ArrowUp' || (e.ctrlKey && e.key === 'p')) { e.preventDefault(); setIdx(Math.max(0, cur - 1)) }
            else if (e.key === 'Enter') { e.preventDefault(); run(cur) }
          }} />
        <span className="pal-scope mono">{short(model.run.id)}</span>
      </div>
      <div className="pal-list" ref={listRef} role="listbox">
        {!items.length && <div className="pal-empty">No matches for “{q}”</div>}
        {items.map((it, i) => {
          const head = it.section !== last ? <div className="pal-sec">{it.section}</div> : null
          last = it.section
          return <div key={it.id}>
            {head}
            <div className={'pi' + (i === cur ? ' on' : '')} role="option" aria-selected={i === cur} onMouseMove={() => { if (i !== cur) setIdx(i) }} onClick={() => run(i)}>
              <span className="g">{typeof it.icon === 'string' ? <Icon name={it.icon as IconName} /> : it.icon}</span>
              <span className="l"><Highlight text={it.label} q={q.trim()} /></span>
              {it.keys ? <span className="r"><KbdGroup keys={it.keys} /></span> : it.right ? <span className="r mono">{it.right}</span> : null}
            </div>
          </div>
        })}
      </div>
      <div className="pal-f"><span><Kbd>↑</Kbd><Kbd>↓</Kbd> navigate</span><span><Kbd>↵</Kbd> open</span><span><Kbd>esc</Kbd> close</span></div>
    </div>
  </div>
}

/** The shortcut sheet (F's help). Views that add keys should add rows here. */
export const SHORTCUT_SHEET: [string, [string, string][]][] = [
  ['General', [['mod K', 'Command palette'], ['?', 'This sheet'], ['G then O Q F W S E A R', 'Go to a view'], ['1 – 8', 'Go to a view'], ['[ / ]', 'Previous / next run'], ['⇧ T', 'Toggle theme'], ['C', 'Board · message the coordinator'], ['Esc', 'Close detail / overlay']]],
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
  return <div className="overlay open" onMouseDown={e => { if (e.target === e.currentTarget) pal.closeHelp() }}>
    <div className="help" role="dialog" aria-modal="true" aria-label="Keyboard shortcuts">
      <h3>Keyboard shortcuts</h3>
      {SHORTCUT_SHEET.map(([h, rows]) => <div key={h}>
        <h5>{h}</h5>
        <div className="help-grid">
          {rows.map(([k, l]) => <div key={l}><span>{l}</span><span className="kbd-group">{k.split(' ').map((x, i) => <span key={i} className="kbd">{x === 'mod' ? mod : x}</span>)}</span></div>)}
        </div>
      </div>)}
    </div>
  </div>
}
