# Guardian v1

Guardian is a local defensive security assessment workspace for websites and related assets the operator owns or is explicitly authorized to assess. It turns a run goal into an inventory, evidence-backed findings, and a report that explains what Guardian checked, what it confirmed, and what remains open.

Guardian is an independent TypeScript implementation licensed under Apache-2.0. Artex informed the product design. The original design demo uses synthetic records and scripted worker activity. The production app runs against local workspace data.

## Workspace, projects, and runs

| Entity | What it owns |
| --- | --- |
| Workspace | Projects, model configurations, and workspace-scoped credentials. V1 creates a single personal workspace on first launch. |
| Project | One business, website, or related entity. It retains seed assets, approved scope, an asset inventory, and finding history. Related authorized domains can belong to the same project. |
| Run | One goal, a history of goal and scope revisions, one coordinator thread, worker assignments and threads, evidence, findings, and reports. |
| Report | A snapshot of a run's scope, coverage, findings, evidence, and unresolved work at a recorded point in time. |

Runs are independent. A new run can start with the project's saved scope and inventory, then records its own approvals, checks, and results. Earlier reports keep the scope and evidence that applied when they were generated. Saving a run revision and updating project defaults are separate actions. V1 is a single-user local install. Workspace ownership and actor IDs belong in the data model so shared workspaces and role-based access can be implemented later.

## First launch and model setup

1. Open the personal workspace and prompt for an API key. Preselect **OpenRouter** and **DeepSeek V4.1 Flash 1017** (`deepseek/deepseek-v4.1-flash-1017`).
2. Give the user a **Test connection** action. Verify authentication, the selected model, and the streaming and tool-call behavior Guardian needs using synthetic input. Explain errors in terms of the field or capability the user can fix.
3. Offer an advanced form with a model ID, base URL, and protocol choice. Support endpoints compatible with OpenAI Responses or Anthropic Messages. A workspace model configuration serves both coordinator and workers by default.
4. Save a successful configuration to the workspace. Explain that the selected provider receives sanitized context and evidence excerpts. Let the user replace the key or select a different compatible model from workspace settings.
5. Help the user create a project, enter related seed domains, and write the first run goal in plain language.

The API key stays on the local server. A connection test can be retried without saving credentials or creating a run.

## Run lifecycle

| Phase or gate | Behavior |
| --- | --- |
| **Discovery consent** | Record the user's electronic consent for the seed assets before starting discovery. Show the seeds and what discovery will use. |
| **Discovery** | Build a candidate inventory from user-provided records and passive sources. Attribute each candidate to its source and flag potentially third-party services. |
| **Scope approval** | Require the user to select specific hosts, review exclusions, and record consent before analysis starts. Third-party services are unchecked by default. Capture the approved scope and its effective time for this run. |
| **Analysis** | Review approved assets through defensive checks of configuration, supplied records, and other permitted evidence. Record candidates with an affected asset, rationale, supporting evidence, and coverage caveats. |
| **Verification** | Have workers run bounded defensive checks against prepared evidence or local control fixtures. Record each check's expected and observed behavior and the evidence supporting its conclusion. Set a finding to confirmed only when the check supports it. Otherwise record it as dismissed or inconclusive with a reason. |
| **Reporting** | Generate a complete report after verification finishes. Generate a clearly marked partial report when the run stops or fails before completion. |

Discovery finishes before analysis. Analysis finishes before verification. If a candidate host appears after approval, record its source and link it from the inventory row. Keep it outside the run's scope until the user adds it through a recorded approval. The user can add it to the current run or leave it for a future run. Verification is performed by workers. The user approves scope and steers the run.

Access policy decisions can be reviewed from an owner's supplied authorization test records and explicit expected decisions for an existing project host. Discovery snapshots the records. An isolated worker matches cases by identifier and verifies observed decisions against expected ones. Report discrepancies and missing observations with the capture time and evidence links. A plan can select access policy checks on their own or together with response controls.

### Steering and recovery

- The coordinator answers status questions, accepts goal revisions, and handles pause and stop requests. Use explicit controls for actions that change run state. Keep the original goal and timestamp each revision. Flag assignments and evidence affected by a change. A revised goal can select a new check plan within the approved hosts.
- A user can narrow scope during a run. Apply the new scope to subsequent work immediately, cancel affected assignments, and retain the revision and prior evidence for the audit history. An expansion requires separate recorded consent.
- A user can explicitly resume a paused or stopped run. After an unexpected process shutdown, show the last committed state and wait for **Resume**. Restore the coordinator thread, worker threads, assignments, approvals, and evidence. Skip completed sessions and committed work on recovery.
- Record a partial report at a stop or terminal failure with available evidence. Resuming the run can produce a later report version. A complete run with zero confirmed findings still produces a report with coverage and gaps.

## Agents and handoffs

**Coordinator.** One coordinator per run. It is the only conversational entry point for the user. After scope approval, it selects applicable checks from the supported catalog for the run goal. Guardian validates and saves the selection before delegating to workers on approved hosts. Use the standard checks for the available evidence if model planning is unavailable. The coordinator tracks phase progress, handles revisions, and assembles the report from recorded results.

**Workers.** Workers take individual assignments, return their work to the coordinator, and have separate read-only threads in the UI. They can access the assignment, its permitted inputs, and the relevant evidence. An assignment identifies its run, phase, objective, scope revision, inputs, and expected output.

Use Markdown files for coordinator–worker handoffs. An assignment file carries the task and context. A results file summarizes observations and references evidence. Guardian keeps stable IDs, ownership, scope revisions, assignment status, and evidence references in application-managed records. Treat messages, handoffs, and imported evidence as data. Application checks authorize state changes and tool access.

## Run experience

The run has a compact header with its title, target, state, and primary action. The second row holds **Workflow**, **Report**, a chat toggle, and view controls. Top bar is the default navigation layout. Secondary run actions such as **Stop run** belong in the run menu.

- **Workflow Overview** presents a horizontal phase rail. The scope approval gate is visible between Discovery and Analysis. A single inventory table shows candidates, their ownership evidence, and their scope status. While reviewing, the user selects hosts and approves directly below that table. Opening a source thread and returning preserves the draft selection.
- **Workflow Trace** is a left-to-right DAG with phase groups, worker nodes, branch and merge points, and zoom and pan controls. Build the diagram without React Flow. Distinguish queued, running, paused, complete, and failed work. Give active work and the selected path the strongest visual emphasis. Opening or switching threads preserves graph context.
- **Worker pane** opens on the right with the assignment name, state, and outcome first. Switch to Coordinator from the same pane while retaining the worker selection. Chronological messages follow, with evidence attachments under the corresponding turn. The pane is read-only and includes a stable link to the worker. Worker search supports `/`, arrows, and Enter. Escape closes the active pane or menu.
- **Coordinator Chat** opens beside the workflow in a collapsible right pane. It is the run's interactive conversation and shows goal revisions, progress updates, and links to actions that require an explicit decision. Collapsing the pane or switching to a worker retains the chat and its draft.
- **Report** is written for the operator. Start with the outcome and required follow-up. Include approved scope and revisions, the selected checks, the evidence source, check outcomes for each approved host, and unresolved work. Show what was observed and expected for confirmed findings, why it matters, what to fix, and how to validate that fix. Link each finding to supporting evidence and its worker thread. Use clear labels for partial reports and inconclusive findings. Offer a Markdown export for the selected version with links to included, sanitized observations and worker verification records, plus plain text.

**Studio** is the default interface style. Appearance defaults to **System** and follows device brightness changes live, using **Porcelain** in light mode and **Studio dark** in dark mode. Explicit choices in **View** are saved in the browser. **Light** and **Dark** override the device setting.

Use compact navigation, restrained borders, and emphasis that follows the current task. **View** offers Workspace, Canvas, and Review layouts. Keep body text readable and keyboard focus visible in both appearances. On narrow screens the worker pane can stack below the workflow and the graph can scroll within its viewport.

### Motion

- Use Motion for React (`motion/react`) to open and close the chat pane and crossfade when switching worker threads. Start with 180–220 ms for pane transitions. Preserve the selected node, graph viewport, and chat draft.
- Use CSS transitions for hover, press, selection, and workflow status changes. Start around 120 ms for interaction feedback. Fade in selected paths, keep worker nodes in place as results arrive, and show keyboard focus immediately.
- Honor the system's reduced-motion preference. Show the same state changes without sliding or scaling.

## Technical architecture

### Web application

- Build the React UI with TanStack Start and Vite. Serve the production build from one local Node.js server bound to loopback. Use TanStack Router for project, run, and worker thread URLs. Render the interactive workflow and chat on the client.
- Use shadcn/ui's Base UI components for shared controls, menus, and dialogs. Style the installed source with Guardian's Studio and Porcelain tokens. Compose the right pane with shadcn AI Elements' Chat pattern, including Message Scroller, Message, Bubble, and Input Group. Use shadcn Trace for worker activity and evidence rows alongside the horizontal workflow DAG. [Chat](https://ui.shadcn.com/docs/ai-elements/base/chat) · [Trace](https://ui.shadcn.com/docs/components/base/trace)
- Use TanStack Start server functions for reads and actions such as scope approval, pause, resume, and opening a report. Stream run events through a server route using server-sent events (SSE). On reconnect, replay committed events after the client's last event ID.
- Validate the expected host on every request and require a valid local session for actions, evidence, and event streams. Check the origin on state-changing browser requests. Render imported pages, evidence, transcripts, and model output as escaped text or sanitized markup, including in report exports.
- Initialize one Guardian service per server process. It owns SQLite, Pi Durable, and run recovery. Server functions and routes call the service. Opening a page or reconnecting the stream leaves a paused run paused.

### Runtime and persistence

- Implement application and agent logic in TypeScript. Use Drizzle ORM for Guardian's SQLite schema and queries. Generate and commit versioned SQL migrations with Drizzle Kit. Apply pending migrations before accepting requests. Keep evidence artifacts in a local application-managed directory.
- Use `@earendil-works/pi-durable` for persistent coordinator and worker conversations, model turns, and resumable agent execution. Pin the dependency and isolate its integration. Validate the OpenRouter default and both supported protocols against the pinned version.
- Guardian owns lifecycle state, phase gates, consent and scope revisions, worker assignments, evidence, and report versions. Persist ordered run events with the domain updates they describe. Project state, chat, and workflow should agree after reload or reconnect.
- Associate each assignment with a stable session ID. Persist assignment admission before dispatch. On recovery, reconcile saved assignments and sessions before starting more work. Use stable operation IDs for retried writes so duplicate runs, worker threads, evidence records, and reports are prevented. Guardian checks whether a run is eligible to resume before reopening an agent session.
- Use immutable IDs for workspaces, projects, runs, workers, findings, and artifacts. Scope all data access to the workspace. Link artifacts to their producing assignment and scope revision. Use stable run and worker IDs in deep links so changing a display title does not break them.

### Authorization and execution

- Record consent with the actor, run, approved seeds or hosts, exclusions, and timestamp. Worker permissions follow the current approved scope. Apply authorization in application-managed tools outside the agent.
- Use just-bash as the v1 worker shell for offline evidence analysis. Workers can compose shell commands, pipelines, and scripts with built-in tools such as `jq`, `rg`, and `diff`. Run the interpreter inside the OS-isolated worker with a virtual filesystem that presents the assignment's evidence as read-only files and gives it writable scratch space. Bound runtime, memory, disk usage, and output. Leave native process execution, optional language runtimes, and just-bash networking disabled. Record the command, input artifact IDs, exit status, and any resulting evidence artifacts so a reviewer can repeat the analysis.
- Block direct worker network access at the OS boundary. Route bounded reads of approved assets through Guardian's request broker, which applies current scope to destinations and redirects and records each read. Discovery uses only its permitted passive inputs.
- Bind each broker request to the server's run and assignment records. Check the assignment's permitted inputs and current scope before serving a fixture or opening a connection. For live public-page reads, validate the resolved destination and connect only to a validated public address. Repeat these checks at every redirect. Cancel affected in-flight reads when the user narrows scope and reject late results at commit time.
- Keep agent testing focused on defensive evidence checks. Workers can validate configuration, compare prepared observations with controls, and record enough detail to repeat an evidence check. Live exploit generation, exploit execution, and automated intrusion are outside Guardian v1.
- Verify sandbox isolation and scope enforcement independently of the model. Treat instructions in retrieved pages, evidence, and model output as untrusted data. Only explicit user actions can grant scope. A confirmed finding requires a recorded verification result linked to the supporting evidence.

### Worker execution backend

- V1 supports local, unprivileged Linux containers with outbound networking disabled. Give each assignment its own isolated execution environment, read-only inputs, and writable scratch space. Keep host files, credentials, and the container runtime control socket outside the worker. Enforce CPU, memory, process, and scratch-space limits within the container runtime.
- Enforce a 15-second worker deadline inside the container as well as on the server. Label containers by local workspace. When the workspace reopens, remove containers from the previous process and keep the run paused until the operator resumes it. Retry cleanup before new worker operations.
- Define a backend interface for staging assignment inputs, executing just-bash, collecting outputs, and canceling work. Pass assignment IDs, evidence references, and execution limits through this interface. Guardian owns scope decisions, request brokering, durable session state, and whether an assignment can still commit results.
- A future remote backend must pass the same isolation and cancellation checks as the local backend. Require explicit workspace opt-in before transferring evidence to a remote sandbox. Transfer only the evidence needed for that assignment and keep provider credentials on the Guardian server.

### Credentials and evidence

- Store model credentials in a workspace-scoped local secret store. Give only the provider adapter access to the key for authentication. Keep credentials out of agent sessions, Markdown handoffs, logs, and reports.
- Redact authorization headers, cookies, session identifiers, passwords, private keys, and sensitive request values before evidence is sent to a provider or written to transcripts, handoffs, fixture recordings, browser event streams, and exports. Use consistent placeholders within a run when repetition matters to the analysis.
- Send the smallest sanitized excerpt that supports the task. Keep raw user-supplied evidence local and outside model context and report exports by default. Reports and transcripts link to the sanitized evidence they cite.

### Threat model

| Priority | Risk | V1 controls and remaining exposure |
| --- | --- | --- |
| Critical | A worker reaches the host, credentials, or a destination outside scope. | Unprivileged local containers have no network, runtime socket, or host filesystem mounts. The broker enforces host authorization before DNS, on redirects, and again before recording evidence. Guardian trusts the operator's host, Docker daemon, and worker image. |
| High | Imported evidence or a model reply is treated as authority. | Scope and run changes require explicit operator actions. Workers receive selected metadata and can use just-bash on staged files. Confirmation comes from a recorded verification check. Model summaries can still be misleading and should be read alongside the evidence. |
| High | Another browser origin uses the local app to read workspace data or change a run. | The app binds to loopback, checks the host and action origin, and requires a local session for server functions and event streams. Users with access to the same OS account can read the workspace. |
| High | A credential or sensitive record leaks through a model call, artifact, or fixture. | Owner-only files hold workspace keys. Target responses contribute selected metadata. Transcripts, handoffs, and exports use redacted text. Review fixture changes before committing them. Treat the configured model provider as a recipient of the excerpts it processes. |
| High | A restarted or revoked assignment continues under stale approval. | Persist effective scope revisions and lease each assignment. Cancel affected in-flight work, reject late commits, and require explicit resume after an interruption. Keep prior evidence and report versions for audit. |
| Medium | An operator mistakes a report for proof of ownership or complete coverage. | Consent is recorded electronic authorization. Reports name the approved hosts, checks, evidence, and coverage gaps. |

## Testing strategy

Automated browser end-to-end tests in Playwright are the primary regression suite. Run them against the production build with a fresh SQLite database and evidence directory per test. Exercise the real UI, server, Pi Durable integration, and persistence. Replay model responses at the provider HTTP boundary so the suite exercises the production request and response handling.

- Capture fixtures from real provider calls on synthetic projects and prepared evidence. Start with the default OpenRouter and DeepSeek V4.1 Flash configuration. Add recordings for each supported protocol. Keep the provider, model ID, protocol, and scenario with each fixture.
- Preserve HTTP status, provider event order, streamed text deltas, tool calls, and finish reasons. Redact credentials and sensitive payloads before writing fixtures to disk. Normalize volatile IDs and timestamps consistently across related requests and responses. Match requests by scenario, conversation, and turn so parallel worker timing does not change which response is replayed.
- Commit reviewed fixtures and replay them locally and in CI without API keys or outbound network access. Fail on unexpected model requests with a diff of the sanitized request. Capture and refresh fixtures through a separate, explicit command that uses developer credentials and shows the changes for review.
- Assert user-visible results and durable state, such as approved scope, evidence links, and assignments after restart. Use controlled replay failures for cases such as interrupted streams, rate limits, or malformed responses when a live capture cannot reproduce them reliably. Use focused unit tests for rules that are easier to verify directly.

For local fixture capture, read the OpenRouter key from `~/.config/guardian-fixtures/openrouter.key`. Keep the file outside the repository with owner-only permissions. The development key passed OpenRouter's `GET /api/v1/key` authentication check with HTTP 200. Model inference and fixture capture are separate checks.

### Report quality benchmark

Use the same authorized, reproducible defensive assessment cases for Guardian and Artex. Establish expected results independently for each host and check before scoring. Include multi-host, healthy, missing-evidence, and interrupted runs. Record tool and model versions, case counts, per-check results, and misses so the comparison can be repeated.

- Guardian should match or exceed Artex on precision and recall for confirmed findings on the agreed suite. Count unsupported cases as uncovered. A missing observation should be visibly inconclusive or untested.
- Each Guardian confirmation must lead to an approved supporting observation and the verification that substantiates it. The saved export should make this evidence reviewable offline and identify any unavailable records.
- Have reviewers use each report to identify the highest-priority fix, explain the impact, and describe how to verify the fix. Record whether they can complete those tasks from the report alone.

The Northstar case matrix defines expected verdicts for four report versions from recorded inputs. `npm run benchmark:reports` runs the production browser flows and saves the exported reports and a case-by-case scorecard. Regular end-to-end tests assert the same verdicts and verify the portable evidence links. The scorecard can include separately reviewed Artex verdicts for the same cases. [Northstar case matrix](tests/report-benchmark.ts)

## V1 acceptance criteria

- From a fresh install, connect an OpenRouter key using the preset model, then connect to a test endpoint for each supported protocol. A rejected key or unsupported tool-call response produces a specific setup error.
- Complete a report through each supported protocol. For Messages, stop the process after a worker saves its tool result. Reopen the run, resume explicitly, and verify that the saved tool result and source observation lead to one confirmed finding.
- Create a project with related seed domains. Consent to passive discovery, review the candidates, inspect evidence, and approve scope. Analysis stays gated until approval, and third-party assets are excluded by default.
- Open the 34-worker synthetic run. Navigate phase groups, find and deep-link to a read-only worker thread, and return from evidence to the scope table without losing draft selections.
- During analysis, revise the goal, narrow scope, and review a newly found asset. Work linked to changed scope is canceled, while the new asset stays outside scope until approved.
- Add a host while an approved read is pending. Reopen its source record, approve the expanded scope, and verify that the broker reads the new host after consent. The report covers both hosts under the revised scope.
- Restart while a coordinator plan is pending. Resume explicitly, then verify that the plan yields one set of assignments. Revise an in-flight goal to focus on one response check and verify that the new worker handoff and report reflect that choice.
- Stop a run and read its partial report. Restart the app mid-run and confirm that work waits for explicit resume. Resume from the last committed state without duplicate assignments, findings, or reports.
- Run the TanStack Start production build on loopback. Open a worker thread through its deep link. With a run paused, restart the server and verify that the event stream reconnects from the last event ID and the run stays paused until explicit resume.
- Finish verification with confirmed response policy gaps and inconclusive fixture results. Follow a confirmed finding to its observed value, expected setting, remediation, and worker verification. Run the zero-finding case and verify that the report shows which checks met the baseline.
- Download a partial report and the complete version from the same run. Verify that each Markdown export resolves its evidence links offline within its own approved scope, identifies any unavailable records, and reflects the selected version.
- Replay the four Northstar benchmark report versions. Verify each expected verdict in the saved export. Check that every confirmation includes the scoped source, its worker verification, the impact, and how to validate the fix.
- Import recorded access decisions for an existing project host. Verify matching decisions, a decision that differs from policy, and a missing decision. Run access policy alone and with response checks. Confirm that each finding links to its own input and the corresponding worker comparison.
- Have a worker compose a just-bash pipeline that extracts fields from prepared JSON evidence, compares them with a baseline, and writes a derived artifact. Verify that the report links to the artifact and that the worker record identifies the commands and inputs. Verify that attempts to read files outside the assignment and make direct network requests are denied.
- Through the broker, verify that an approved read succeeds. Reject redirects out of scope and DNS responses that resolve an approved public hostname to a private address. Remove the approved host while a fixture read is pending. Verify that a subsequent read is denied and the pending result never becomes evidence.
- Verify that untrusted evidence cannot grant scope, confirm a finding, or execute markup in the UI or report. Verify that the loopback API rejects unexpected hosts, cross-origin actions, and event streams without a valid local session.
- Verify that the production worker container cannot read host files or credentials, access the runtime control socket, or connect directly to a healthy test endpoint. Verify that the container enforces its resource limits.
- Kill the server after Docker creates a verification container. Reopen the workspace and verify that Guardian removes that container and leaves other workspaces' containers alone. Resume the saved assignment explicitly and verify that it produces one verification record. Hold a worker's input stream open and verify that the image enforces the deadline independently.
- Seed test credentials and sensitive raw evidence. Verify that neither appears in model inputs, transcripts, fixture recordings, event streams, or report exports.
- Check the approval flow and worker pane in light and dark at desktop and narrow viewport sizes. Verify keyboard navigation and system appearance changes.
- Complete one opt-in live smoke run for `dyad.sh` using the production build, from explicit scope approval through opening the final report. Use live DeepSeek V4.1 Flash calls through OpenRouter and bounded read-only requests to public pages through Guardian's request broker. Approve any subdomain individually before reading it and enforce the approved scope on every redirect. Verify that the report links to evidence from the run. Routine local and CI end-to-end tests replay model and network fixtures offline.

## Deferred

- Shared workspaces, multiple users, and role-based access enforcement.
- Cross-run finding comparisons, automatic trend analysis, and attribution of findings as new, recurring, or resolved.
- Public hosting and unattended recurring runs.
- Remote worker execution backends such as Daytona.
