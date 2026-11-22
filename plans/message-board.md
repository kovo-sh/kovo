# Guardian Swarm Message Board — Implementation Plan

**Status:** Proposed  
**Scope:** All capability tiers (`Tier 0` through `Tier 3`, `public` and `local-lab`)  
**UI Placement:** Right split-pane in `RunWorkspace` (replaces the `Coordinator` tab; keeps `Worker Inspector` alongside it)

---

## 1. Motivation & Design Philosophy

Guardian v4 already has a strong typed blackboard (`facts`, `endpoints`, `chain_steps`, `graph_edges`, `replay_specs`, `findings`), 7 domain specialists (`SPECIALIST_PROFILES`), SSE live updates, scope/taint isolation, and deterministic Zero-LLM verification (`ReplayVerifier`).

Today, however, orchestration is strictly hub-and-spoke with ephemeral workers:
- Each `ChainStep` spawns a one-shot `assignment` that exits when done. Cross-domain discoveries have to round-trip through `facts` → debounced `runChainPlanner` → a brand-new cold specialist.
- Failed `DeclarativeReplaySpec` submissions trigger a cold Phase-3 Refinement worker instead of letting the warm authoring specialist repair the spec in 1–2 turns.
- The right-hand `Coordinator` pane (`startCoordinator` in `src/server/execution.ts`) is a 1-on-1 Q&A sidecar with aggregate summary counts; the operator cannot see specialist handoffs in one stream or directly address a specialist.

### Core Principle: Hybrid Blackboard + Swarm Board
The Message Board **does not replace** Guardian's typed blackboard or Zero-LLM verification invariants:

| Layer | Tables / Modules | Source of Truth For |
| :--- | :--- | :--- |
| **Typed Blackboard** *(existing)* | `facts`, `endpoints`, `chain_steps`, `replay_specs`, `findings`, `coverage_entries` | Machine-queryable observations, deduplication, taint tracking, deterministic Zero-LLM proofs |
| **Swarm Message Board** *(new)* | `board_members`, `board_messages` | Public briefs, peer handoffs, `@mention` wakeups, warm specialist continuity, operator war-room |

Every board message is an audit-logged, redacted, scope-attributed coordination signal—never an unverified finding claim and never a substitute for `ReplayVerifier`.

---

## 2. Locked Product Decisions

1. **Enabled across all tiers (`Tier 0` – `Tier 3`, `public` and `local-lab`):**
   - **Tier 0 (Offline Prepared / Repo-Only):** `@coordinator`, offline static/policy specialists, and `@verifier` coordinate prepared evidence, DNS exports, access policy discrepancies, and SAST/source-audit suspects with zero live egress.
   - **Tier 1 (Read-Only + Safe Probes):** Read-only specialists share discovered endpoints, JS/API routes, headers, and safe probe leads without duplicate crawling.
   - **Tier 2 (Multi-Persona Validation):** Auth/session and BOLA/BFLA specialists hand off persona resource handles (`factId`) and coordinate cross-tenant checks.
   - **Tier 3 (Approval-Gated State & Execution):** Inline Tier 3 approval cards appear directly in the board stream alongside specialist context; approving resumes the paused specialist cleanly.
2. **Right-pane UI replacing the `Coordinator` tab:**
   - The right split-pane in `src/components/run-workspace.tsx` switches from **`Coordinator` | `Worker Inspector`** to **`Board` | `Worker Inspector`**.
   - **Full backwards compatibility:** Typing a plain message in the composer without an `@handle` defaults to `@coordinator` (routing to the coordinator turn handler). Typing `@<handle> ...` posts publicly to the board and routes directly to that specialist (waking it if `waiting`).

---

## 3. Roster & Warm Specialist Lifecycle

### 3.1 Canonical Roster Handles
Map Guardian's existing 7 `SpecialistProfile`s (`src/server/agent-session.ts`) plus deterministic system actors to short, ergonomic handles:

| Handle | Role | Maps To | Spawn Policy |
| :--- | :--- | :--- | :--- |
| `@coordinator` | `coordinator` | Coordinator / Chain Planner | Always present on run start |
| `@operator` | `operator` | Human operator | Implicit author for UI/CLI messages |
| `@verifier` | `verifier` | `ReplayVerifier` (0 LLM cost) | Deterministic system actor |
| `@broker` | `system` | `RequestBroker` / Approval Gate (0 LLM cost) | Deterministic system actor |
| `@bola` | `specialist` | `bola-bfla-specialist` | Lazy on first step or `@mention` |
| `@injection` | `specialist` | `injection-parser-specialist` | Lazy on first step or `@mention` |
| `@auth` | `specialist` | `auth-session-oauth-specialist` | Lazy on first step or `@mention` |
| `@browser` | `specialist` | `client-browser-dom-specialist` | Lazy on first step or `@mention` |
| `@graphql` | `specialist` | `graphql-api-specialist` | Lazy on first step or `@mention` |
| `@logic` | `specialist` | `business-logic-race-specialist` | Lazy on first step or `@mention` |
| `@edge` | `specialist` | `protocol-cache-edge-specialist` | Lazy on first step or `@mention` |

- **Multi-trial shards:** Crown-jewel multi-trial fanout (`trialGroupId`, `trialIndex > 0`) uses suffixed handles (`@bola-2`, `@injection-2`) that retire immediately when a sibling wins Zero-LLM confirmation.
- **Handle validation regex:** `^[a-z][a-z0-9_-]{1,23}$` (reserved: `all`, `system`, `verifier`, `broker`, `operator`, `coordinator`).

### 3.2 Member State Machine

```text
  (lazy spawn) ──▶ working ──(step/turn done)──▶ waiting (asleep, $0 idle cost)
                     │  ▲                           │
                     │  └────(@mention / brief)─────┘
                     │
                     ├──(Tier 3 approval gate)──▶ paused ──(approved/denied)──▶ working
                     │
                     └──(context cap / scope revoke / run stop / early-stop)──▶ retired
```

- **`waiting` preserves session state:** The member keeps its `@earendil-works/pi-durable` `sessionId` and `lastReadSeq` cursor on disk at zero runtime cost until woken by a targeted `@mention` or a new `ChainStep` brief.
- **Concurrency & budget compliance:** Waking a `waiting` member enqueues a wakeup job against Guardian's existing `workerConcurrency` semaphore, `budgetUsd`, `budgetRequests`, and `K=6` diminishing-returns gate.
- **Context ceiling & clean retirement:** When a warm specialist reaches its configured turn ceiling (e.g., `maxTurnsCeiling`) or prompt-token budget (~60% of model context window), Guardian forces a concise closure summary post to the board and marks the member `retired`. Any subsequent work for that profile spawns a fresh member (`@bola-r2` or recycled session) seeded from `facts` and the closure post.

---

## 4. Data Model & Migrations

### 4.1 SQLite Schema (`src/server/schema.ts` + lossless auto-migration in `src/server/store.ts`)

Add two tables in `Store.initSchema()` (preserving lossless upgrade from existing v4 SQLite DBs):

```ts
export const boardMembers = sqliteTable('board_members', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id),
  handle: text('handle').notNull(), // e.g. 'coordinator', 'bola', 'auth', 'bola-2'
  role: text('role').$type<'coordinator' | 'specialist' | 'verifier' | 'system'>().notNull(),
  specialistProfile: text('specialist_profile').$type<SpecialistProfile | null>(),
  sessionId: text('session_id').notNull(),
  activeAssignmentId: text('active_assignment_id'),
  state: text('state').$type<'working' | 'waiting' | 'paused' | 'retired'>().notNull(),
  roleAffinity: text('role_affinity').$type<RoleAffinity | null>(),
  lastReadSeq: integer('last_read_seq').default(0).notNull(),
  turnsUsed: integer('turns_used').default(0).notNull(),
  postsCount: integer('posts_count').default(0).notNull(),
  peerHopsUsed: integer('peer_hops_used').default(0).notNull(),
  scopeRevision: integer('scope_revision').notNull(),
  goalRevision: integer('goal_revision').notNull(),
  sourceOrigins: text('source_origins', { mode: 'json' }).$type<string[]>().notNull(),
  createdAt: integer('created_at').notNull(),
  updatedAt: integer('updated_at').notNull(),
}, table => [
  uniqueIndex('board_members_run_handle').on(table.runId, table.handle),
  index('board_members_run_state').on(table.runId, table.state),
])

export const boardMessages = sqliteTable('board_messages', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id),
  seq: integer('seq').notNull(), // strictly monotonic per run (1, 2, 3, ...)
  authorHandle: text('author_handle').notNull(),
  authorRole: text('author_role').$type<'operator' | 'coordinator' | 'specialist' | 'verifier' | 'system'>().notNull(),
  kind: text('kind').$type<'brief' | 'claim' | 'handoff' | 'lead' | 'blocker' | 'approval' | 'verdict' | 'status' | 'note'>().notNull(),
  mentions: text('mentions', { mode: 'json' }).$type<string[]>().notNull(),
  body: text('body').notNull(), // redacted, capped <= 1200 chars
  refFactIds: text('ref_fact_ids', { mode: 'json' }).$type<string[]>().notNull(),
  refExchangeIds: text('ref_exchange_ids', { mode: 'json' }).$type<string[]>().notNull(),
  refFindingIds: text('ref_finding_ids', { mode: 'json' }).$type<string[]>().notNull(),
  refStepId: text('ref_step_id'),
  refApprovalId: text('ref_approval_id'),
  replyToSeq: integer('reply_to_seq'),
  scopeRevision: integer('scope_revision').notNull(),
  goalRevision: integer('goal_revision').notNull(),
  sourceOrigins: text('source_origins', { mode: 'json' }).$type<string[]>().notNull(),
  tainted: integer('tainted', { mode: 'boolean' }).default(false).notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [
  uniqueIndex('board_messages_run_seq').on(table.runId, table.seq),
  index('board_messages_run_tainted').on(table.runId, table.tainted, table.seq),
])
```

### 4.2 Store Helpers (`src/server/store.ts`)
- `upsertBoardMember(run, input)` / `updateBoardMemberState(runId, handle, patch)` / `listBoardMembers(runId)`
- `postBoardMessage(run, input, secrets)`:
  - Allocates next `seq` inside an `IMMEDIATE` SQLite transaction.
  - Runs `redact(body, secrets)` and enforces `body.length <= 1200`.
  - Validates all `mentions` against active roster handles (or `'all'` if `authorRole` is `operator | coordinator | system`).
  - Persists row and emits `board.message` event (triggering existing SSE listeners in `api.runs.$runId.events.ts`).
- `listBoardMessages(runId, { sinceSeq?, limit?, includeTainted?, authorHandle?, kind? })`
- `taintBoardMessagesForRevokedOrigins(runId, approvedOrigins)`:
  - Called during scope revision/revocation alongside `facts` tainting; marks any `board_messages` with a non-approved `sourceOrigin` as `tainted = true` and retires any `board_members` whose `sourceOrigins` intersect the revoked origins.
- Include `boardMembers` and `boardMessages` in `Store.runDetail(runId)` so `RunWorkspace` receives them with zero extra round trips.

### 4.3 Domain & Action Contracts (`src/domain.ts`, `src/actions.ts`)
- Extend `runCommand` in `src/domain.ts`:
  - Keep existing `{ action: 'message', message: string }` working seamlessly: parse leading/inline `@<handle>` mentions; if none are present, default `mentions: ['coordinator']`.
  - Add optional `{ action: 'board_post', body: string, mentions?: string[], replyToSeq?: number }` and `{ action: 'retire_member', handle: string }` for explicit operator control from the Board UI.
- Reuse existing `messages` table mirror (or migrate coordinator replies to `board_messages` while continuing to mirror operator/coordinator messages into `messages` during transition so existing v2/v3/v4 Playwright & boundary tests remain 100% green).

---

## 5. Agent Tool Surface & Orchestration (`agent-session.ts` & `execution.ts`)

### 5.1 Worker Tools (`SPECIALIST_COMMON_TOOLS` in `src/server/agent-session.ts`)
Add two compact tools to `SPECIALIST_COMMON_TOOLS` (available across all 7 specialist profiles and all tiers):

1. **`board_post`**
   ```ts
   {
     kind: 'claim' | 'handoff' | 'lead' | 'blocker' | 'status' | 'note',
     body: string,               // concise summary, max 1200 chars, no raw HTTP bodies
     mentions?: string[],        // optional roster handles to wake (max 1 specialist per turn)
     refFactIds?: string[],      // evidence handles backing this post
     refExchangeIds?: string[],
     refFindingIds?: string[],
     refStepId?: string,
     replyToSeq?: number,
   }
   ```
   Returns `{ ok: true, seq, mentionedHandles, wakeupsScheduled }` or `{ ok: false, reason }` if rate-limited, scope-invalid, or missing required evidence handles on a peer handoff.

2. **`board_read`**
   ```ts
   {
     sinceSeq?: number,
     kind?: BoardMessageKind,
     authorHandle?: string,
     limit?: number,             // default 20, max 50
   }
   ```
   Returns untainted, approved-scope messages only, with `body` already redacted and truncated.

### 5.2 Zero-Polling Delta Injection
Whenever a specialist starts a step or wakes from `waiting`:
- `execution.ts` fetches all untainted, in-scope `board_messages` with `seq > member.lastReadSeq` that either mention `@<handle>`, mention `@all`, share a `sourceOrigin`, or have `kind` in `['brief', 'blocker', 'verdict']`.
- Injects them into the turn prompt wrapped in an explicit untrusted-data boundary:
  ```xml
  <board_delta since_seq="14" latest_seq="19" untrusted_target_derived="true">
  [#15][brief] @coordinator -> @auth: Verify JWT validation & session fixation on https://app.local (step_04)
  [#18][handoff] @auth -> @bola: Cross-tenant token mint observed on /api/impersonate [facts: fact_42, exchanges: ex_108]. Test /api/v2/invoices/{id}.
  [#19][verdict] @verifier -> @injection: Replay spec spec_09 failed (control HTTP 500; check csrfBind) [step: step_02].
  </board_delta>
  ```
- Updates `member.lastReadSeq = latestSeq` atomically upon turn start.

### 5.3 Deterministic System Posters (0 LLM Cost)
Wire deterministic hooks in `src/server/execution.ts`:
- **Step Dispatch (`startInvestigationStep`):** `@coordinator` posts a `brief` mentioning `@<handle>` with `refStepId` and target origins so peers see claimed work immediately.
- **Verification Verdict (`verifyReplaySpecInline` & Phase-3 verifier):** `@verifier` posts a `verdict` (`confirmed` with finding chip, or sanitized `InlineVerifyFeedback` mentioning the authoring `@<handle>`). On failure with remaining `attempt_count`, wakes the warm specialist for a bounded 2-turn inline repair instead of launching a cold refinement worker.
- **Circuit Breaker / Rate-Limit (`RequestBroker`):** `@broker` posts a `blocker` mentioning `@all` when an origin circuit opens or cooldown triggers.
- **Tier 3 Approval Gate (`approvalRequests`):** `@broker` posts an `approval` item linked via `refApprovalId`; operator approval/denial updates the card and posts a short resolution status waking the `paused` specialist.
- **Multi-Trial Early-Stop:** When a winning sibling confirms via Zero-LLM verification, `@verifier` posts the confirmation and retires canceled sibling handles cleanly.

### 5.4 Coordinator Integration
Upgrade `startCoordinator` in `src/server/execution.ts`:
- Triggered whenever an operator posts a message mentioning `@coordinator` (including plain messages with no `@mention`).
- Sees recent `board_messages` (last 20 untainted) + `board_members` roster states in addition to run counters, and can either reply directly on the board, enqueue/reprioritize a `ChainStep`, or delegate via `@<specialist>` handoff.
- `runChainPlanner` reads recent `blocker` and `handoff` board posts so it does not re-queue steps already ruled out or actively claimed on the board.

---

## 6. Security, Anti-Chatter & Budget Guardrails

These invariants are mandatory and must be covered by dedicated boundary tests (`tests/v4-board-boundaries.test.ts`):

1. **Redaction on Every Write (`redact.ts`):**
   - All `board_messages.body` text is scrubbed with the run's active `NamedSecret[]` (persona cookies, JWTs, CSRF tokens, API keys, custom headers) *before* SQLite insert and SSE broadcast.
2. **Scope & Taint Isolation:**
   - Every post carries `scopeRevision` and `sourceOrigins`.
   - `board_post` rejects any `sourceOrigin` not in `run.approved`.
   - Scope revocation immediately flips `tainted = true` on affected `board_messages` and marks affected `board_members` as `retired`, guaranteeing revoked-origin data never leaks into subsequent specialist wakes.
3. **Indirect Prompt-Injection Firewall:**
   - Strict `body` cap (`<= 1,200` chars); reject raw HTML/markup or multi-line HTTP header dumps (specialists must reference `refExchangeIds` / `refFactIds` instead).
   - Peer board messages are always serialized inside `<board_delta untrusted_target_derived="true">` delimiters with system instructions stating that peer posts are advisory hypotheses—never authoritative instructions to override scope, capability tier, or approval gates.
4. **Evidence-Gated Peer Wakeups & Anti-Chatter Caps:**
   - A specialist may include **at most 1** peer `@mention` per turn, and **only** when attaching at least one `refFactIds`, `refExchangeIds`, or `refStepId` (or when `kind === 'blocker'`).
   - **Hop cap:** Max `2` consecutive peer-to-peer wakeups (`peerHopsUsed`) without an intervening new `fact`, `exchange`, `replay_spec`, or `@operator`/`@coordinator` intervention.
   - **Per-specialist post cap:** Soft cap (e.g., 12 posts per specialist session) and explicit **no-ack prompt rule** ("Never post just to acknowledge receipt; only post claims, evidence-backed handoffs, blockers, or closure summaries").
   - **`@all` restriction:** Only `operator`, `coordinator`, and `system` may use `@all`.
5. **Tier-0 Zero-Network Guarantee:**
   - Board wakeups on Tier 0 never unlock live network tools; every woken specialist still runs under `filterHandlersForSpecialist` and tier-enforced `RequestBroker` guards.

---

## 7. Right-Pane UI Design (`RunWorkspace`)

### 7.1 Layout Changes (`src/components/run-workspace.tsx`)
Replace the `Coordinator` tab in the resizable right split-pane (`.chat-pane`):
- **Header tabs:** `Board` (with unread badge count when viewing `Worker Inspector`) | `Worker Inspector` (when a worker is selected from Trace/Overview/Roster).
- **Roster Strip (top of Board pane):**
  - Horizontal scrollable pill row displaying `@coordinator` and all spawned `board_members` with live status indicators:
    - `● @bola` (working — accent pulse)
    - `○ @auth` (waiting — muted)
    - `⏸ @injection` (paused — attention)
    - `✓ @edge` (retired — dimmed)
  - Clicking a pill offers two quick actions: **Filter board by handle** or **Inspect worker transcript** (switches right-pane tab to `Worker Inspector` for that member's `activeAssignmentId`).
- **Inline Approvals Bar:**
  - Keep pending Tier 3 approval cards pinned cleanly at the top (or rendered inline with `Approve` / `Approve similar` / `Deny` buttons), synced with `refApprovalId` board posts.
- **Board Timeline (`src/components/run-board.tsx`):**
  - Reuses existing `MessageScroller` / `Bubble` primitives from `src/components/ui/message.tsx`.
  - Each post displays: author badge (`@auth`), kind pill (`BRIEF`, `HANDOFF`, `VERDICT`, `BLOCKER`, `LEAD`), timestamp, `@mention` chips, redacted markdown-lite body, and clickable reference chips (`fact_42`, `ex_108`, `finding_03`) that open `EvidenceDialog` or jump to Exchanges/Report.
  - Filter toggle bar: `All` | `Handoffs & Verdicts` | `Blockers` | `@<selected-handle>`.
- **Operator Composer with `@mention` Autocomplete:**
  - Typing `@` opens a compact popover listing active/spawnable roster handles (`@coordinator`, `@bola`, `@injection`, `@auth`, `@browser`, `@graphql`, `@logic`, `@edge`, `@all`).
  - Submitting with no `@mention` automatically targets `@coordinator`, preserving 100% muscle-memory compatibility with the previous Coordinator Chat.

---

## 8. Phased Implementation Plan

### Phase 1 — Deterministic War-Room Board & Right-Pane UI *(Zero Extra LLM Cost)*
**Goal:** Land schema, store, SSE, deterministic system posters, and the new right-pane `Board` UI with zero additional LLM token spend.
- **Files:**
  - `src/domain.ts`: Add `BoardMemberRole`, `BoardMemberState`, `BoardMessageKind`, handle regex, and `runCommand` board extensions.
  - `src/server/schema.ts` & `src/server/store.ts`: Add `board_members` & `board_messages` tables, auto-migration, redacted `postBoardMessage`, `listBoardMessages`, scope-revocation tainting, and `runDetail` hydration.
  - `src/server/execution.ts`: Emit deterministic `brief`, `verdict`, `approval`, and `blocker` posts; route operator composer messages (defaulting plain text to `@coordinator`) through `board_messages` (with backwards-compatible mirror to `messages`).
  - `src/components/run-board.tsx` *(new)*, `src/components/run-workspace.tsx`, `src/app.css`: Replace `Coordinator` tab with `Board` tab, roster pills, filter chips, clickable evidence/exchange chips, and `@mention` composer autocomplete.
- **Verification:**
  - `npm run check && npm run build`
  - Unit & boundary tests for redaction, scope-revocation tainting, and `@mention` routing.
  - Playwright E2E verifying right-pane `Board` tab renders live briefs/verdicts/approvals and plain messages still receive `@coordinator` replies (all existing `guardian-v2.spec.ts` and `guardian-v4.spec.ts` passing).

### Phase 2 — Specialist `board_post` / `board_read` & Passive Peer Awareness
**Goal:** Give existing specialists visibility into peer claims/blockers/leads and allow structured handoff posts without changing worker lifecycle yet.
- **Files:**
  - `src/server/agent-session.ts`: Register `board_post` and `board_read` in `SPECIALIST_COMMON_TOOLS`, add no-ack and untrusted-delta system prompt instructions.
  - `src/server/execution.ts`: Wire `board_post` / `board_read` handlers with anti-chatter & scope checks; inject compact `<board_delta>` at worker start and into `runChainPlanner`.
- **Verification:**
  - Unit tests for `board_post` validation (char cap, secret redaction, scope check, evidence-gated mentions, `@all` restriction).
  - Verify duplicate probing drops on multi-specialist runs without inflating token spend.

### Phase 3 — Warm Persistent Specialists & `@mention` Wakeups
**Goal:** Transition specialists from one-shot exit to `waiting` sleep/wake sessions with `@verifier` inline spec repair and cross-specialist handoffs across all tiers.
- **Files:**
  - `src/server/execution.ts`: Maintain `board_members` `waiting` pool, wakeup scheduler respecting `workerConcurrency` & budgets, `@verifier` → specialist 2-turn inline repair wakeup, context-ceiling retirement, and hop-count loop breaker.
  - `tests/v4-board-boundaries.test.ts` *(new)*: Full security & lifecycle boundary suite (secret redaction, scope-revocation taint + member retirement, hop-cap loop prevention, Tier-0 zero-network preservation, concurrency cap compliance).
- **Benchmark Gate:**
  - Run `npm run benchmark:recall -- --suite xben-25` and `local-lab/saas-lab` comparing baseline vs. Swarm Board enabled across all tiers.
  - Success criteria: **higher or equal Zero-LLM confirmed recall**, **0 decoy false positives**, **0 boundary regressions**, and **bounded/improved cost per confirmed finding**.

---

## 9. Files Touched Summary

| Area | Files |
| :--- | :--- |
| Schema & Persistence | `src/domain.ts`, `src/server/schema.ts`, `src/server/store.ts`, `src/actions.ts` |
| Orchestration & Tools | `src/server/agent-session.ts`, `src/server/execution.ts`, `src/server/replay-verifier.ts` |
| Live Transport | `src/routes/api.runs.$runId.events.ts` *(reuses existing SSE event bus)* |
| Frontend UI | `src/components/run-board.tsx` *(new)*, `src/components/run-workspace.tsx`, `src/components/run-state.ts`, `src/app.css` |
| Tests | `tests/v4-board-boundaries.test.ts` *(new)*, `tests/guardian-v4.spec.ts` |
