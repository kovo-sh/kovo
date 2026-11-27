# Run workspace (`/runs/:runId`)

The run page: rail, run line, eight views (Overview, Queue, Findings, Workflow, Surface,
Exchanges, Activity, Report) and a right-hand inspector pane. It is the production version of
prototype F ("Unified"). `CONTRACT.md` is the API reference for the shared modules: read it
before adding a view, an inspector or a cross-link.

## Where things live

- `shell.tsx` mounts the providers in this order: keyboard → toasts → data → nav → decisions →
  overlays → palette. The route (`src/routes/runs.$runId.tsx`) parses `?view=&sel=`, maps the legacy
  `?view=trace` and `/runs/:id/workers/:wid` to Workflow, and links the four stylesheets.
- `data.tsx`: the live run (loader snapshot + SSE replay/stream + coalesced `runData` refreshes),
  `send(command)` (the only mutation path) and the shared full-exchange cache.
- `model.ts`: pure derivations, rebuilt once per snapshot. Views read from `useRunModel()` instead of
  re-deriving. A worker is linked to a finding only if it recorded the cited evidence or made a cited
  exchange; chain-fact authors are upstream inputs and are not counted.
- `nav.tsx`: URL-backed view + selection, the Back stack (Esc pops it), `useLinks()` cross-links,
  `useViewState()` (per-run UI state that survives view switches), `useListNav()` (J/K/↑/↓/↵).
- `keyboard.tsx`: one listener with layered bindings. Priorities: 0 shell, 10 views, 20 inspector or
  composer, 50 to 90 popovers and dropdowns, 100 exclusive overlays (palette, help, scope editor). Return
  `false` from a handler to let the key fall through.
- `controls.tsx` and `display.tsx`: shared toolbar and list controls and display atoms. Reuse them;
  don't add a view-local dropdown, tab strip, filter box or virtual list.
- `views/*`: one module per view, each exporting `XView` and `xInspectors` (see `views/index.tsx`).
- `coordinator.tsx`: the **Board** (v5 swarm message board), shown in the pane when nothing is selected,
  on Overview and Report, or after C / the Board button in any inspector header. It holds the roster,
  pinned Tier 3 approvals, kind and handle filters, and a timeline that merges board posts with the
  coordinator thread. Coordinator and Kovo replies are not posted to the board; operator messages
  are mirrored onto it by the server. Plain text sends `message`; text with @mentions sends `board_post`.

## Rules that are easy to break

- **Mutations**: only `send()` from `useRun()`. Anything irreversible goes through the decision store
  or `toast.undoable` (the command is sent when the 6 s undo window closes; Undo sends nothing).
- **Local-only state must say so.** There is no server API for accepting, dismissing or marking a
  finding as a false positive, so that triage lives in `localStorage` (`kovo-queue:<runId>`), and
  every place that shows it says "saved in this browser only". Follow-ups on finished runs are local
  for the same reason.
- **Capped data must say so.** `detail.exchangesSummary` holds the newest 500 exchanges; true totals are
  in `useRun().counts`. `searchRunExchanges` has no offset and stops at 100 hits, and the Exchanges
  view says so when it hits the cap.
- **Styles**: every rule is scoped under `.rw`. `app.css` still styles the other pages (index,
  projects, settings) and is loaded on this page too. Its few class names that collide with F's
  (`.brand`, `.badge`, `.eyebrow`, `.toolbar`, `.btn.primary`) are neutralised at the end of `run.css`.
- **Motion**: CSS animations are switched off under `prefers-reduced-motion`. WAAPI and smooth scrolling
  are not, so guard them with `reducedMotion()` / `T(ms)`.
- **Consent**: the consent decision key carries the phase (`consentKey(run)`), so approving discovery
  doesn't mark the later scope review as done.

## Verifying changes

- `npm run check`, then `npm run build` and `PORT=<port> KOVO_DATA_DIR=<a private copy of a data dir> npm start`.
- In Playwright scripts, intercept every non-GET request (`context.route('**/*', …)`), fulfil it with a
  mock, and assert the payload. Never let approve, resume, consent, retest, cancel or message reach a
  real server.
- The e2e specs that drive this page are `tests/guardian-v2.spec.ts` and `tests/guardian-v4.spec.ts`,
  with helpers in `tests/browser-flows.ts` (`openScopeReview`, `saveScope`, `openView`). Specs that need
  worker containers fail without Docker. That happens with the old page too.
