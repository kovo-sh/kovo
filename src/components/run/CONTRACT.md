# Run workspace contract (prototype F in production)

Read this before touching anything in `src/components/run/`. The spec is
`.ui-reference/f-unified/` (index.html, NOTES.md, shots/). Match its visuals,
density, motion and keyboard model; use real data and real commands.

## 1. File ownership

The page was built in parallel by four agents; the map below is kept as the module layout
(who owns what is now just "whoever changes it", see `README.md`). Shared modules are the
foundation row; view modules depend on them, never on each other's internals.

| Area | Files |
|---|---|
| **Foundation** (shared) | `shell.tsx`, `data.tsx`, `model.ts`, `nav.tsx`, `decisions.tsx`, `keyboard.tsx`, `palette.tsx`, `toast.tsx`, `motion.tsx`, `display.tsx`, `controls.tsx`, `glyphs.tsx`, `icons.tsx`, `meta.ts`, `format.ts`, `theme.ts`, `pane.tsx`, `coordinator.tsx`, `rail.tsx`, `header.tsx`, `overlays.tsx`, `run.css`, `views/index.tsx`, `views/overview.tsx`, `views/consent.tsx`, `views/lab.tsx`, `CONTRACT.md` |
| **Agent Q** | `views/queue.tsx`, `views/findings.tsx`, `views/queue-findings.css` (+ new files `views/queue-*.tsx`, `views/findings-*.tsx`) |
| **Agent W** | `views/workflow.tsx`, `views/workflow.css` (+ `views/workflow-*.tsx`) |
| **Agent S** | `views/surface.tsx`, `views/exchanges.tsx`, `views/activity.tsx`, `views/report.tsx`, `views/surface-lists.css` (+ `views/surface-*.tsx` etc.) |

Each view module keeps two named exports, already wired into the router
(`views/index.tsx`):

```tsx
export function FindingsView() { … }                 // the centre view; no props, use hooks
export const findingsInspectors: InspectorMap = {    // right-pane inspectors you own, by selection kind
  finding: FindingInspector,
}
```

Selection kinds (each has exactly one inspector; kinds are unique across views):

| Kind | Id | Inspector (file) |
|---|---|---|
| `evidence` | evidence artifact id | `EvidenceInspector` (`pane.tsx`) |
| `queue` | queue item key: `ap:<approvalId>`, `cv:<coverageId>`, `f:<findingId>`, `b:<checkId>:<status>`, `consent:<phase>` | `QueueInspector` (`views/queue.tsx`) |
| `finding` | finding id | `FindingInspector` (`views/findings-inspector.tsx`) |
| `worker` | assignment id | `WorkerInspector` (`views/workflow-inspector.tsx`) |
| `stack` | stack group id (collapsed sibling workers in the graph) | `StackInspector` |
| `steps` | `queued` (the queued-steps node: planned chain steps not yet dispatched) | `StepsInspector` |
| `step` | chain step id (a queued step without a worker) | `StepInspector` |
| `digest` | cold-graph digest id (highlights the workers it covers) | `DigestInspector` |
| `cell` | `<origin>\|<category>` (surface matrix cell) | `CellInspector` (`views/surface.tsx`) |
| `host` | origin | `HostInspector` (`views/surface.tsx`) |
| `endpoint` | endpoint id (Surface → Endpoints mode) | `EndpointInspector` (`views/surface-endpoints.tsx`) |
| `exchange` | exchange id, or `ev:<eventId>` for a broker denial | `ExchangeInspector` (`views/exchanges.tsx`) |
| `event` | event id | `EventInspector` (`views/activity.tsx`) |

A kind without an inspector would render `FallbackInspector` ("TODO"); none should remain.

Styles: F's CSS for every view is **already ported** into `run.css` (`.toolbar .tabs .tab
.filter .dd .seg .list .ghead .row .tag .qrow .qbtn .stampl .abar .wf-* .node .edge .mini
.replay .mx td.c .lg .locator .doc .dtable .matrix .vstrip …`), so most views need no new CSS: reuse F's class names verbatim. If you need more, use your own stylesheet
(already linked by the route, after `run.css`): Q → `views/queue-findings.css`, W → `views/workflow.css`,
S → `views/surface-lists.css`. Scope every rule under `.rw`. Shared rules (anything two views use) belong in `run.css`.

## 2. Reading run data

```tsx
const { detail, model, events, eventsReady, counts, runs, connection, send, pending } = useRun()
const model = useRunModel()   // memoised RunModel, rebuilt when the detail refreshes
const v = useVerdict()        // B's headline + confidence (also the Findings strip and Report title)
```

- `detail` is `RunDetail` (`../run-state.ts`): camelCase rows. It refreshes in place
  over SSE (paused/running runs update live), so derive with `useMemo(…, [model])`.
- `detail.exchangesSummary` holds the newest **500** exchanges (no headers; fetch one
  with `readExchange` GET, search with `searchRunExchanges` GET). True totals:
  `counts.exchanges`, `counts.events`.
- `events` is the **full** event stream (oldest first), replayed from SSE and growing
  live. `eventsReady` turns true once the replay settles. Thousands of rows: virtualise.
- `model` (see `model.ts` for types and comments):
  - `findings` (current, non-superseded) / `allFindings`, `findingById`
  - `workerById`, `stepById`, `stepByWorker`, `exchangeById`, `evidenceById`, `factById`, `approvalById`
  - `factsByWorker`, `evidenceByWorker`, `exchangesByWorker`, `exchangesByOrigin`
  - cross-links: `findingWorkers` (finding → worker ids that recorded its cited evidence or made its cited exchanges;
    chain-fact authors are upstream inputs, not counted),
    `workerFindings`, `exchangeFindings`, `evidenceFindings`
  - `risk` (threat-model entry by origin), `scopeOrigins`, `report` (latest), `needsModel`
  - `queue` (E's Decide / Review / Follow up / Done base, with baseline-check bundling) and `queueItem` by key
  - `surface`: D's matrix model: `origins` (host, risk tier, tags, counts), `apex`, `cov[origin][category]`,
    `findingsByOrigin`, `findingsByCell[origin|category]`, `workersByOrigin`, `approvalsByOrigin`; helpers `cellKey`, `cellStatus`
  - `workflow`: `phases` (columns), `byPhase`, `edges` (`handoff` = input_assignment_id, `causal` = parent facts and
    step dependencies), `upstream`/`downstream`; helper `lineage(model.workflow, id)` → `{ up, down }`
  - `coordinatorMessages`, `workerMessages`; `base` / `end` timestamps
  - helpers: `bySeriousness`, `worstSeverity`, `coverageCounts`, `trafficHistogram`
- Vocabulary lives in `meta.ts` (`VIEWS`, `SEV*`, `normFStatus` (confirmed covers `static_verified`),
  `stLabel`, `CATS`, `covCat`, `prettyCat`, `COV_L`, `RISK*`, `PHASE_LABEL`, `CHECK_HEADERS`); formatting in `format.ts`.

## 3. Selection, the inspector, cross-links

The URL holds the view and selection: `/runs/<id>?view=findings&sel=finding:<id>`.
`/runs/<id>/workers/<wid>` maps to Workflow with that worker selected.

```tsx
const nav = useNav()
nav.view, nav.sel                              // { kind, id } | null
nav.select({ kind: 'finding', id })            // open in the inspector (current view); `{ push: true }` keeps Back
nav.select(sel, { anim: 'left' })              // queue advance: next item slides in from the right
nav.setView('surface')                         // restores that view's last selection
nav.open('workflow', { kind: 'worker', id })   // cross-view jump; pushes the current selection on the Back stack
nav.back(); nav.close()                        // Esc pops the stack, then closes
nav.openChat({ label: item.title, sel })       // coordinator in the pane with a context chip ("Back to item")

const links = useLinks()   // preferred for cross-links (all push Back):
links.finding(id) · links.worker(id) · links.exchange(id) · links.cell(origin, category) · links.host(origin)
links.queueItem(key) · links.event(id) · links.evidence(id) (opens in the current view) · links.view(v)
```

Views own their selection highlight: a row is "current" when `nav.sel?.kind === yourKind && nav.sel.id === row.id`.
When nothing is selected (and on Overview/Report) the pane shows the Board (`coordinator.tsx`: roster, pinned
approvals, filters, board posts merged with the coordinator thread, composer). `useBoardUnread()` feeds the Board
button badge in `PaneHeader`.
**Queue**: the run lands on Queue when approvals are pending; select the first open item on mount if `nav.sel` is empty.

Inspector skeleton (F's `.d` content, `.sec` sections, `.props` grid, `.linkrow` links):

```tsx
export function FindingInspector({ sel }: InspectorProps) {
  return <>
    <PaneHeader title="Finding" sub="3 of 68" extra={<NavButtons/>} />   // Back + Close are automatic
    <PaneBody><div className="d">… <Section title="Found by" right="2 workers">…<LinkRow …/></Section></div></PaneBody>
    <PaneFooter stamped={stamp}>…actions…</PaneFooter>                    // optional sticky action bar (.abar)
  </>
}
```

Per-view UI state that must survive view switches (tabs, grouping, filter, collapsed groups, camera):
`const [group, setGroup] = useViewState('findings.group', 'severity')`.

## 4. Keyboard and palette

```tsx
useShortcuts([
  { key: 'G', run: cycleGrouping },               // Shift+G arrives as 'G'
  { key: '/', run: () => filterRef.current?.focus() },
  { key: ['a'], run: () => act('a') },            // return false to fall through
  { key: 'mod+z', run: undo },
], { priority: 10 })                               // views default to 10; shell is 0; overlays 100
const { index } = useListNav({ ids: flatRowIds, kind: 'finding' })   // J/K/↓/↑ select, ↵/O open
```

The shell already binds: ⌘K, ?, G+letter and 1–8, [ ], ⇧T, C, Esc (chat → Back → close), Z / ⌘Z
(undo toast, then last local queue decision). Bindings are skipped while typing unless `allowInInput`;
Enter/Space on a focused control are left alone. View keys from F's sheet are yours to implement
(Queue A/D/F/C, Workflow arrows/+/−/0/↵/L/⇧R/Space, Surface arrows/↵/Esc, Lists `/` and ⇧G).
The help sheet is `SHORTCUT_SHEET` in `palette.tsx` (already lists them all).

Palette: Views, Runs, Findings, Workers, Hosts and core Actions are built in. Add view commands while mounted:
`usePaletteCommands([{ id: 'wf.replay', section: 'Actions', label: 'Replay the run in the workflow graph', icon: 'replay', keys: ['⇧','R'], run }])`.

## 5. Commands, decisions, toasts

- **Only** mutate through `send(command)` from `useRun()` (`Command` = `runCommand` minus runId/requestId).
  It resolves after the detail refreshed, rejects on failure (an error toast is shown for you).
  Real commands available: `decide_approval`, `approve_similar_endpoint`, `approve_all_pending`, `retest_finding`,
  `cancel_step`, `inject_hint`, `message`, `raise_budget`, `set_approval_policy`, `scope`, `candidate`, `revise`,
  `discover`, `pause`, `resume`, `stop`. There is **no** server API for accepting/dismissing/false-positive on
  findings: those stay local triage (decision store, persisted per run).
- Queue decisions go through the **shared decision store** (also used by the coordinator's pinned approvals and the
  consent sheet): `const q = useDecisions()` → `q.sections`, `q.openCount`, `q.decideCount`, `q.get(key)`,
  `q.canAct(key, act)`, `q.decide(key, act, { command?, message? })`, `q.reopen(key)`, `actionsFor(item)`,
  `ACTIONS[act]` (label/tone/icon for stamps), `approvalCommand(id, 'approve'|'deny')`.
  With a `command` the decision stamps now and **sends when the 6 s undo window closes** (Undo/Z sends nothing).
  Suggested mapping: approval A/D → `approvalCommand`; follow-up "Queue follow-up" → `inject_hint` with the
  coverage summary and `targetAssetId` when known; findings A/D/F → local.
- Toasts: `const toast = useToast()`; `toast.show(text, { icon, sub, tone: 'error' })`;
  `toast.undoable({ message, icon, sub, commit, undo })` for any other irreversible action (stop, approve-all, scope
  revision already use it). One toast at a time; a new undoable commits the previous one.

## 6. Motion and tokens

- One curve: `var(--ease)` = `cubic-bezier(.2,.8,.2,1)`; durations `var(--d1|d2|d3)` = 120/180/240 ms; `var(--spring)`
  for toasts, switches, stamps. JS: `ease(t)`, `DUR`, `EASE_CSS`, `tween(from, to, ms, onFrame)`.
- `useReducedMotion()` (render) / `reducedMotion()` / `T(ms)` (handlers, rAF): every animation must become instant.
  CSS animations/transitions are globally disabled under `prefers-reduced-motion` inside `.rw`.
- Primitives: `AnimatedNumber` (420 ms tick from the previous value; reuse ids like `'q.open'` so they tick on run
  switch), `Meter` (grows from its previous value), `usePulse(value)` (badge pulse). The view cross-fade and the
  inspector entrance (`nav.select(sel, { anim })`) are done by the shell. WAAPI (`el.animate`) and smooth scrolling
  are not covered by the CSS kill switch: guard them with `reducedMotion()`.
- Tokens (`run.css`, light + dark, driven by the app's `html[data-appearance]`): `--bg --rail --panel --sunk --raise`,
  `--line --line-2 --line-strong`, `--fg --fg-2 --fg-3 --fg-4`, `--hover --press --sel --sel-line`, `--accent*` (only
  for selection/focus/current), `--crit --high --med --low --info`, `--ok --warn --bad` (+ `-soft`, `-line`), surface map
  `--rep --fu --okc --ro --na --hatch --un --xh`, graph `--canvas --dot --edge --edge-2 --row-h --row-s`.
  Never hard-code colours; check both themes (`useTheme()` / ⇧T).
- Inter, 13px/20px, tabular numerals (`.num`), mono via `.mono`. Rows are 36px, toolbars 42px, pane header 44px.
- Display components (`display.tsx`): `Kbd`, `KbdGroup`, `Tag`, `EmptyState` (F's empty state), `Skeleton`,
  `HostLabel` (bold label + dimmed apex, middle truncation), `LinkRow`, `Seg`, `Section`, `Props`.
  Glyphs (`glyphs.tsx`): `SevGlyph`, `StatusGlyph`, `EventGlyph`, `CovSwatch`, `PinGlyph`, `TierBars`, `PhaseTrack`.
  Icons: `<Icon name="…" />` (one 1.5-stroke family).
- Toolbar and list controls (`controls.tsx`, used by every list view): `Tabs` (F's toolbar tabs; what doesn't fit
  folds into "More · n"), `FilterBox` (`/` focuses, ↓/↵ jump to the first match, Esc clears then leaves), `Dropdown`
  (F's `.dd`, closes on outside click / Esc), `VList` (variable-height windowed list with scroll anchoring for
  prepends), `Tip` (cursor tooltip), `matchQ`, `useDebounced`.
- Exchanges anywhere: `<ExchangeLink id />` (`pane.tsx`, method · status · path row that opens Exchanges; rows outside
  the newest-500 window are read by id) and `useFullExchange(id)` / `loadExchange` (`data.tsx`, one shared cache for
  headers + body). `prettyBody` (`format.ts`) formats bodies.

## 7. Verification rules (all agents)

`npm run check` must pass; zero console errors/warnings. Screenshot light and dark at 1440×900 against F's shots.
Playwright **must** intercept every non-GET request (`page.route('**/*', …)` → fulfill a mock) and assert payloads
instead of letting them through (see `README.md` for the QA harness and the e2e specs that cover this page)
(cookie: visit `/` first; data: `GUARDIAN_DATA_DIR=/tmp/guardian-ui-data`).
