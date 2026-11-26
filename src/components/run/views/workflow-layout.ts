// Workflow graph model (Agent W): stacks, layout, lineage, replay spans.
// Pure functions over the RunModel plus a tiny shared store for the UI state
// the graph and the inspectors both need (expanded stacks, camera requests).
//
// Layout (prototype F): workers sit in phase columns. Inside a phase they are
// layered by in-phase causal depth, wrapped into sub-columns of WF.R rows, and
// pulled toward the rows of their parents so handoffs read left to right.
import { useMemo, useSyncExternalStore } from 'react'
import { workerHistory } from '../../../domain.ts'
import { isLiveWorkerStatus } from '../../../server/run-status.ts'
import { isTerminalStepStatus } from '../../../step-status.ts'
import { useRunModel } from '../data.tsx'
import type { Assignment, ChainStep, RunEvent, RunModel } from '../model.ts'

export const WF = { NW: 264, NH: 88, RG: 14, SG: 20, PG: 92, HH: 58, R: 7, PAD: 40 } as const
/** Below this zoom the cards switch to a title-only render with large finding badges. */
export const LOD_K = 0.58

export interface StackGroup { id: string; title: string; phase: string; members: string[] }
export interface Stacks { of: Map<string, string>; groups: Map<string, StackGroup> }

export type NodeKind = 'worker' | 'stack' | 'queue' | 'report'
export interface WfNode {
  id: string
  kind: NodeKind
  phase: string
  pi: number
  row: number
  x: number
  y: number
  createdAt: number
  a?: Assignment
  g?: StackGroup
  members?: Assignment[]
  steps?: ChainStep[]
}
export interface WfEdge { key: string; from: string; to: string; kind: 'handoff' | 'causal' | 'report'; n: number }
export interface WfHead {
  phase: string
  x: number
  w: number
  n: number
  done: number
  live: boolean
  earlier: number
  expanded: StackGroup[]
}
export interface WfLayout {
  nodes: WfNode[]
  byId: Map<string, WfNode>
  edges: WfEdge[]
  inc: Map<string, string[]>
  out: Map<string, string[]>
  heads: WfHead[]
  W: number
  H: number
  report: WfNode | null
  /** worker id → "Earlier goal · Revision 2" / "Host removed from scope" (original trace's history labels) */
  history: Map<string, string>
  stacks: Stacks
}

export const QUEUE_ID = 'queued-steps'
export const isLive = (a: Assignment) => isLiveWorkerStatus(a.status)
const isOpenStep = (status: ChainStep['status']) => !isTerminalStepStatus(status) || status === 'blocked'

/** ≥ 8 workers in one phase sharing one title template ("Baseline capture · host") fold into a stack. */
export function buildStacks(assignments: readonly Assignment[]): Stacks {
  const byKey = new Map<string, Assignment[]>()
  for (const a of assignments) {
    const k = 'g:' + a.phase + ':' + a.title.split(' · ')[0]
    const list = byKey.get(k)
    if (list) list.push(a)
    else byKey.set(k, [a])
  }
  const of = new Map<string, string>()
  const groups = new Map<string, StackGroup>()
  for (const [k, list] of byKey) {
    if (list.length < 8 || list.filter(a => a.title.includes(' · ')).length < list.length * 0.8) continue
    groups.set(k, { id: k, title: k.split(':').slice(2).join(':'), phase: list[0].phase, members: list.map(a => a.id) })
    for (const a of list) of.set(a.id, k)
  }
  return { of, groups }
}

/** Chain steps that are planned but have no worker yet (the original trace's "Queued chain steps" lane). */
export const queuedSteps = (m: RunModel) => m.detail.chainSteps.filter(s => !s.assignedWorkerId && isOpenStep(s.status)).sort((a, b) => a.seq - b.seq)

export function buildLayout(m: RunModel, stacks: Stacks, expanded: ReadonlySet<string>): WfLayout {
  const d = m.detail
  const phases = m.workflow.phases
  const rep = (id: string) => { const g = stacks.of.get(id); return g && !expanded.has(g) ? g : id }

  // units: workers, stacks, and the queued-steps card
  const units = new Map<string, WfNode>()
  for (const a of d.assignments) {
    const r = rep(a.id)
    if (r === a.id) { units.set(r, { id: r, kind: 'worker', a, phase: a.phase, createdAt: a.createdAt, pi: 0, row: 0, x: 0, y: 0 }); continue }
    const g = stacks.groups.get(r)!
    const u = units.get(r)
    if (u) { u.createdAt = Math.min(u.createdAt, a.createdAt); continue }
    units.set(r, { id: r, kind: 'stack', g, phase: g.phase, members: g.members.map(id => m.workerById.get(id)!).filter(Boolean), createdAt: a.createdAt, pi: 0, row: 0, x: 0, y: 0 })
  }
  const queued = queuedSteps(m)
  if (queued.length) {
    units.set(QUEUE_ID, { id: QUEUE_ID, kind: 'queue', phase: 'investigation', steps: queued, createdAt: Infinity, pi: 0, row: 0, x: 0, y: 0 })
  }

  // representative edges, deduplicated with multiplicity
  const edges: WfEdge[] = []
  const ek = new Map<string, WfEdge>()
  for (const e of m.workflow.edges) {
    const f = rep(e.from), t = rep(e.to)
    if (f === t) continue
    const k = f + '>' + t
    const prev = ek.get(k)
    if (prev) { prev.n++; if (e.kind === 'handoff') prev.kind = 'handoff'; continue }
    const edge: WfEdge = { key: k, from: f, to: t, kind: e.kind, n: 1 }
    ek.set(k, edge)
    edges.push(edge)
  }
  const inc = new Map<string, string[]>()
  const out = new Map<string, string[]>()
  const link = (from: string, to: string) => {
    inc.set(to, [...(inc.get(to) ?? []), from])
    out.set(from, [...(out.get(from) ?? []), to])
  }
  edges.forEach(e => link(e.from, e.to))

  const history = workerHistory(d.run, d.assignments)
  const nodes: WfNode[] = []
  const byId = new Map<string, WfNode>()
  const heads: WfHead[] = []
  const rowY = (r: number) => WF.HH + r * (WF.NH + WF.RG)
  let x = 0
  phases.forEach((p, pi) => {
    const us = [...units.values()].filter(u => u.phase === p).sort((a, b) => a.createdAt - b.createdAt)
    if (!us.length && !['discovery', 'threat_model', 'investigation', 'verification'].includes(p)) return
    const inPhase = new Set(us.map(u => u.id))
    const depth = new Map<string, number>()
    const dep = (u: WfNode): number => {
      const known = depth.get(u.id)
      if (known != null) return known
      depth.set(u.id, 0)
      let best = 0
      for (const pid of inc.get(u.id) ?? []) {
        const pu = units.get(pid)
        if (pu && inPhase.has(pid) && pu.createdAt <= u.createdAt) best = Math.max(best, dep(pu) + 1)
      }
      depth.set(u.id, best)
      return best
    }
    us.forEach(dep)
    const layers: WfNode[][] = []
    us.forEach(u => { const k = depth.get(u.id)!; (layers[k] ??= []).push(u) })
    const cols: WfNode[][] = []
    layers.filter(Boolean).forEach(L => { for (let i = 0; i < L.length; i += WF.R) cols.push(L.slice(i, i + WF.R)) })
    if (!cols.length) cols.push([])
    const x0 = x
    cols.forEach((col, ci) => {
      const desired = (u: WfNode) => {
        const ps = (inc.get(u.id) ?? []).map(id => byId.get(id)).filter((n): n is WfNode => !!n)
        return ps.length ? ps.reduce((s, n) => s + n.row, 0) / ps.length : null
      }
      const withD = col.map(u => ({ u, dsr: desired(u) }))
      withD.sort((a, b) => Number(a.dsr == null) - Number(b.dsr == null) || (a.dsr ?? 0) - (b.dsr ?? 0) || a.u.createdAt - b.u.createdAt)
      const cap = Math.max(WF.R, col.length)
      const used = new Set<number>()
      const mid = (cap - 1) / 2
      const noParents = withD.every(v => v.dsr == null)
      let nextFree = noParents ? Math.max(0, Math.floor((cap - col.length) / 2)) : 0
      const nearest = (target: number) => {
        let best = -1, bd = 1e9
        for (let k = 0; k < cap; k++) { if (used.has(k)) continue; const dd = Math.abs(k - target); if (dd < bd) { bd = dd; best = k } }
        return best
      }
      for (const { u, dsr } of withD) {
        const r = dsr == null && noParents ? nextFree++ : nearest(dsr ?? mid)
        used.add(r)
        const n: WfNode = { ...u, pi, row: r, x: x + ci * (WF.NW + WF.SG), y: rowY(r) }
        nodes.push(n)
        byId.set(n.id, n)
      }
    })
    const w = cols.length * (WF.NW + WF.SG) - WF.SG
    const ws = d.assignments.filter(a => a.phase === p)
    const current = ws.filter(a => !history.has(a.id))
    heads.push({
      phase: p, x: x0, w, n: current.length, done: current.filter(a => a.status === 'complete').length,
      live: ws.some(isLive), earlier: ws.length - current.length,
      expanded: [...stacks.groups.values()].filter(g => g.phase === p && expanded.has(g.id)),
    })
    x += w + WF.PG
  })

  let report: WfNode | null = null
  if (m.report) {
    let ins = nodes.filter(n => (n.phase === 'verification' || n.phase === 'retest') && n.kind !== 'queue')
    if (!ins.length) { const maxPi = Math.max(...nodes.map(n => n.pi)); ins = nodes.filter(n => n.pi === maxPi && n.kind !== 'queue') }
    const avg = ins.length ? Math.round(ins.reduce((s, n) => s + n.row, 0) / ins.length) : 0
    report = { id: 'report', kind: 'report', phase: 'report', pi: heads.length, row: avg, x, y: rowY(Math.min(avg, WF.R - 1)), createdAt: m.report.createdAt }
    heads.push({ phase: 'report', x, w: WF.NW, n: 1, done: 1, live: false, earlier: 0, expanded: [] })
    for (const n of ins) {
      const e: WfEdge = { key: n.id + '>report', from: n.id, to: 'report', kind: 'report', n: 1 }
      edges.push(e)
      link(n.id, 'report')
    }
    byId.set('report', report)
  }
  const H = Math.max(WF.HH + WF.NH, ...nodes.map(n => n.y + WF.NH), report ? report.y + WF.NH : 0)
  const W = report ? report.x + WF.NW : Math.max(WF.NW, x - WF.PG)
  return { nodes, byId, edges, inc, out, heads, W, H, report, history, stacks }
}

export const allNodes = (L: WfLayout) => (L.report ? L.nodes.concat(L.report) : L.nodes)
export const bounds = (L: WfLayout) => ({ x: -WF.PAD, y: -WF.PAD / 2, w: L.W + WF.PAD * 2, h: L.H + WF.PAD * 1.5 })

/** Full upstream and downstream lineage of a node in the layout (stacks count as one node). */
export function nodeLineage(L: WfLayout, id: string) {
  const walk = (map: Map<string, string[]>) => {
    const set = new Set<string>()
    const st = [id]
    while (st.length) for (const n of map.get(st.pop()!) ?? []) if (!set.has(n)) { set.add(n); st.push(n) }
    return set
  }
  return { up: walk(L.inc), down: walk(L.out) }
}

/** Edge keys on the focus node's lineage (upstream chain into it, downstream chain out of it). */
export function hotEdges(L: WfLayout, id: string, up: Set<string>, down: Set<string>) {
  const hot = new Set<string>()
  for (const e of L.edges) {
    const upPath = (e.from === id || up.has(e.from)) && (e.to === id || up.has(e.to))
    const downPath = (e.from === id || down.has(e.from)) && (e.to === id || down.has(e.to))
    if (upPath || downPath) hot.add(e.key)
  }
  return hot
}

export function edgePath(L: WfLayout, e: WfEdge) {
  const a = L.byId.get(e.from), b = L.byId.get(e.to)
  if (!a || !b) return ''
  const sx = a.x + WF.NW, sy = a.y + WF.NH / 2, tx = b.x, ty = b.y + WF.NH / 2
  if (tx >= sx + 8) {
    const dx = Math.max(36, (tx - sx) * 0.5)
    return `M${sx} ${sy} C${sx + dx} ${sy} ${tx - dx} ${ty} ${tx} ${ty}`
  }
  const rx = Math.max(sx, b.x + WF.NW), bulge = 34
  return `M${sx} ${sy} C${rx + bulge} ${sy} ${rx + bulge} ${ty} ${b.x + WF.NW} ${ty}`
}

// ---------------------------------------------------------------- replay spans

export interface Span { t0: number; t1: number; spans?: [number, number][] }

/** start = created_at; end = worker.complete event, else the last artefact the worker produced. Live workers never end. */
export function replaySpans(L: WfLayout, m: RunModel, events: readonly RunEvent[]) {
  const doneEv = new Map<string, number>()
  for (const e of events) {
    if (e.kind !== 'worker.complete' && e.kind !== 'worker.failed') continue
    const id = e.detail?.assignmentId
    if (typeof id === 'string') doneEv.set(id, e.createdAt)
  }
  const lastArt = new Map<string, number>()
  const bump = (id: string | null | undefined, t: number) => { if (id && t) lastArt.set(id, Math.max(lastArt.get(id) ?? 0, t)) }
  m.detail.facts.forEach(f => bump(f.assignmentId, f.createdAt))
  m.detail.evidence.forEach(e => bump(e.assignmentId, e.createdAt))
  m.detail.exchangesSummary.forEach(e => bump(e.assignmentId, e.createdAt))
  const span = (a: Assignment): [number, number] => [a.createdAt, isLive(a) ? Infinity : (doneEv.get(a.id) ?? Math.max(lastArt.get(a.id) ?? 0, a.createdAt + 12000))]
  const out = new Map<string, Span>()
  for (const n of L.nodes) {
    if (n.kind === 'worker') { const [t0, t1] = span(n.a!); out.set(n.id, { t0, t1 }) }
    else if (n.kind === 'stack') { const s = n.members!.map(span); out.set(n.id, { t0: Math.min(...s.map(v => v[0])), t1: Math.max(...s.map(v => v[1])), spans: s }) }
    else if (n.kind === 'queue') { const t0 = Math.min(...n.steps!.map(s => s.createdAt)); out.set(n.id, { t0, t1: Infinity }) }
  }
  if (L.report) out.set('report', { t0: L.report.createdAt || m.end, t1: L.report.createdAt || m.end })
  let t1 = m.end
  for (const s of out.values()) t1 = Math.max(t1, Number.isFinite(s.t1) ? s.t1 : s.t0)
  for (const e of events) if (e.kind === 'finding.verified') t1 = Math.max(t1, e.createdAt)
  return { spans: out, t0: m.base, t1 }
}

// ---------------------------------------------------------------- shared UI store

type Listener = () => void
const expandedByRun = new Map<string, Set<string>>()
const listeners = new Set<Listener>()
const EMPTY = new Set<string>()
const emit = () => listeners.forEach(l => l())
const subscribe = (l: Listener) => { listeners.add(l); return () => { listeners.delete(l) } }

/** Expanded stacks for a run (shared by the graph and the inspectors; survives view switches). */
export function useExpanded(runId: string): ReadonlySet<string> {
  return useSyncExternalStore(subscribe, () => expandedByRun.get(runId) ?? EMPTY, () => EMPTY)
}
export function setExpanded(runId: string, gid: string, on: boolean) {
  const cur = expandedByRun.get(runId) ?? EMPTY
  if (cur.has(gid) === on) return
  const next = new Set(cur)
  if (on) next.add(gid)
  else next.delete(gid)
  expandedByRun.set(runId, next)
  emit()
}

/** Camera requests from outside the graph (inspector "Center in graph"). */
type CamRequest = { type: 'center'; id: string }
const camListeners = new Set<(r: CamRequest) => void>()
export const requestCamera = (r: CamRequest) => camListeners.forEach(l => l(r))
export function onCameraRequest(l: (r: CamRequest) => void) { camListeners.add(l); return () => { camListeners.delete(l) } }

// ---------------------------------------------------------------- memoised access

const cache = new WeakMap<RunModel, { stacks: Stacks; byExp: WeakMap<ReadonlySet<string>, WfLayout> }>()
export function getLayout(m: RunModel, expanded: ReadonlySet<string>): WfLayout {
  let c = cache.get(m)
  if (!c) { c = { stacks: buildStacks(m.detail.assignments), byExp: new WeakMap() }; cache.set(m, c) }
  let L = c.byExp.get(expanded)
  if (!L) { L = buildLayout(m, c.stacks, expanded); c.byExp.set(expanded, L) }
  return L
}
/** The current graph layout (shared cache: the view and the inspectors get the same object). */
export function useWorkflowLayout() {
  const m = useRunModel()
  const expanded = useExpanded(m.run.id)
  return useMemo(() => getLayout(m, expanded), [m, expanded])
}
