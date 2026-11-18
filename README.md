# Guardian

Local defensive evidence review for websites the operator owns or has permission to assess. See [SPEC.md](SPEC.md) for the v1 design and [VERIFICATION.md](VERIFICATION.md) for the test results.

## Run locally

Use Node.js 24.13.1 or newer and a local Linux Docker daemon for evidence workers.

```sh
npm ci
npm run worker:build
npm run build
npm start
```

Rebuild the local worker image with `npm run worker:build` after updating Guardian to pick up changes to the container runtime.

Open http://127.0.0.1:8000. Use **Model settings** to enter an OpenRouter key, test the DeepSeek Flash preset, and save it. Advanced settings accept OpenAI Responses and Anthropic Messages-compatible providers.

Create a project with the authorized hosts and start a run. Review and approve specific hosts after inventory discovery. The coordinator selects checks for the goal from the available evidence. Runs use supplied records by default. Enable **Read approved public pages during this run** to allow selected HSTS, MIME sniffing protection, and referrer policy checks to collect HTTPS response metadata through the scope broker. The report records the plan, the expected and observed settings, and links each confirmed gap to its verification evidence. [HTTP Strict Transport Security](https://www.rfc-editor.org/rfc/rfc6797.html) · [Fetch Standard](https://fetch.spec.whatwg.org/#x-content-type-options-header) · [Referrer Policy](https://www.w3.org/TR/referrer-policy/#referrer-policy-header-dfn)

In **Supply prepared evidence**, enter the observed fields for the host. Use `absent` in `contentTypeOptions` or `referrerPolicy` when the header was absent from a captured response. Leave fields out when the source did not record them. If the response record has a UTC timestamp, include it in `recordedAt` so the export shows when the supplied observation was made.

In **Report**, choose a version and open **Export**. **Markdown with evidence** includes sanitized source observations and worker comparisons for offline review. **Plain text** is also available.

Use **Import DNS export** to bring in candidates from a local, self-contained zone file. The preview shows hosts from A, AAAA, and CNAME records and flags aliases to outside the zone. Guardian records host and source information, then puts the imported candidates into the next run's scope review for selection. [DNS master-file syntax](https://www.rfc-editor.org/rfc/rfc1035.html#section-5.1)

For a host found during a run, use **Add candidate** and enter its source. Open the source record from the inventory row, then select the host in **Review scope** and save a new approval to include it in the run.

The server binds to loopback. Set `PORT` to use a different port. Set `GUARDIAN_DATA_DIR` to choose a private data directory. Its default is `.guardian/`.

## Review access policy records

Use **Import access records** on the project. Supply a JSON file for an existing project host with the intended decisions from your policy and the decisions recorded by your authorization tests. The worker matches case IDs and compares the decisions in the local sandbox. A missing recorded decision remains inconclusive. Access policy checks use the supplied records.

```json
{
  "origin": "https://portal.example",
  "recordedAt": "2026-11-17T15:45:00Z",
  "expected": [
    { "caseId": "read-summary", "role": "team-viewer", "capability": "read-summary", "decision": "allow" }
  ],
  "observed": [
    { "caseId": "read-summary", "decision": "allow" }
  ]
}
```

Use non-sensitive case, role, and capability labels, unique case IDs in each list, and a UTC timestamp. The importer accepts up to 64 cases. Imports are available to the next discovery. Runs that already captured their inventory keep their saved record.

An expected `deny` case can include `"impactIfAllowed": "sensitive-records"` for access to sensitive records or `"impactIfAllowed": "organization-admin"` for organization-wide administration. A verified unintended grant then rates high or critical, respectively. The finding links to the source policy and explains where the impact rating came from.

## Verify

```sh
npx playwright install chromium
npm run check
npm run test:e2e
npm run test:boundaries
```

Playwright runs against the production build with a temporary SQLite database per test. It replays recorded OpenRouter streams and local network fixtures through Guardian's request guards. The verification job uses the same tests on Linux.

Record fresh fixtures explicitly with `npm run fixtures:capture -- responses`, `messages`, or `workflow`. Use `npm run fixtures:capture -- response-referrer --protocol messages` to record one named workflow scene using Messages. Capture uses only synthetic inputs and reads the key from `~/.config/guardian-fixtures/openrouter.key`, with owner-only permissions.

The separate opt-in command `npm run smoke:live -- --live` runs the production browser flow against live OpenRouter and the approved Dyad public home pages. It prints the local report path and data directory. Resume that run with `npm run smoke:live -- --live --resume <data-directory>` if it stops early.

## Benchmark reports

Run `npm run benchmark:reports` to replay the Northstar cases through the production app. The output goes to `test-results/report-benchmark/`. The `summary.json` regression scorecard covers the original four report versions. The `comparison-manifest.json` and `comparison-scorecard.json` also cover the same access issue on two approved hosts and a run with verified high and critical access discrepancies. Each report has a shared-input packet and an ordered run recording through the event that saved that version. These files link to the exact report export by digest. Copy the directory to a private workspace before adding Artex results or reader scores.

To compare independently reviewed Artex reports for the same cases, set `GUARDIAN_ARTEX_REPORT_RESULTS` to a local JSON file outside `test-results/`. Use the scorecard's `suite` value, the Artex `version` and `model`, an `unmatchedConfirmations` count, and a `cases` object keyed by each case ID in the scorecard. Each case takes one of `confirmed`, `met`, `inconclusive`, or `untested`. Use `untested` for unsupported cases. Keep the source reports with the verdicts so the comparison can be audited.

### Compare matched reports

Use the offline scorecard for the release comparison. Keep the input packets, reports, and reviewed recordings in a private local directory. Use `{ "path": "report.md", "sha256": "…" }` for each file reference, with paths relative to the manifest directory and digests from `sha256sum`.

```sh
npm run --silent compare:reports -- .guardian/comparison/manifest.json > .guardian/comparison/scorecard.json
```

The manifest has `format` set to `1`, a `suite` name, a `mode` of `assessment` or `report-only`, and a list of `scenarios`. Give each scenario a unique `id` and these fields.

| Field | Contents |
| --- | --- |
| `input` | Reference to JSON containing the shared `goal`, `scope` as HTTPS origins, `stoppingPoint` as `complete` or `interrupted`, and `capturedEvidence`. Set `overlappingObservations` to true for the multi-host case that uses them. Set `heldOut` on the scenario for a case reserved from tuning. |
| `cases` | The verdicts established before reading the reports. Each entry has an `asset`, an `issue` identifier, and an `expected` verdict. Include `severity` on expected confirmations. |
| `guardian` and `artex` | Optional results with the tool `version`, `model`, shared `inputSha256`, a `report` file reference, and reviewed `verdicts`. Each verdict has an `asset`, `issue`, and `verdict`. Enter one row per displayed confirmation, including repeats. Include the reported `severity` to compare it with the expected rating. For Guardian confirmations, label the `evidence` as `supported`, `missing`, `unrelated`, or `out-of-scope` after checking the original observation and verification. |
| `runRecord` inside each product result | For an assessment, reference a JSON record containing `inputSha256`, `reportSha256`, and a `recording` file reference to the saved run. If the native recording uses another format, include an `audit` file reference to a reviewed JSON event excerpt. |
| `reviews` | Optional paired reviews. Enter a `reader` ID, `guardian` and `artex` answers, and optional `notes`. Each product's answers contain its `reportSha256` and a `tasks` object with grades for the same tasks. Use `coverage` for every report. For scenarios with expected findings, also grade `priority`, `remediation`, `impact`, `evidence`, and `recheck`. Grade each answer as `correct`, `incorrect`, or `unanswered`. |

Use the same asset and issue identifiers in the expected cases and both sets of verdicts. Mark unsupported checks `untested`. Put pre-adjudicated export exercises in `report-only` mode. The scorecard checks file integrity and uses the recorded judgments to score precision, recall, misses by severity, duplicate findings, and reader tasks. Review the saved artifacts when adjudicating any verdict or evidence link.

For an assessment, record the reported severity of every expected high or critical finding. The scorecard fails a verified Guardian recording for a missed finding at either level or a missing or different rating. The accuracy section lists the scenario, asset, issue, expected severity, reported verdict, and reported severity for each failure. This criterion applies as soon as a Guardian recording verifies.

The accuracy section also lists coverage overclaims. A verified Guardian recording fails if a check labeled untested has a reported result, or a check labeled inconclusive appears as passed or confirmed.

The recording audit uses a string `runId`, the `status` at export, an `approval` object with the final approval's `eventId` and `scope`, and an `events` array in increasing numeric `id` order. Give each event its `kind`. Use `run.created` at the start, `scope.approved` with the approved origins in `scope` for each approval, and `report.complete` or `report.partial` at the chosen report save. Record bounded reads as `broker.allowed` or `broker.observed` with their destination `origin`. Use `complete` for a complete report and `stopped`, `paused`, or `failed` for an interrupted run. Guardian's export records include the `reportVersion` and `reportId`. The scorecard checks the Guardian run and version against the Markdown. Keep the native recording alongside any reviewed excerpt.

A passing release scorecard requires matched run records, representative cases, and paired reader results. Invalid references or a failed criterion exit with an error. A failed comparison still writes the scorecard so the reasons can be reviewed.

## View the sample run

```sh
GUARDIAN_DATA_DIR=.guardian/sample npm run sample
GUARDIAN_DATA_DIR=.guardian/sample GUARDIAN_OFFLINE=1 PORT=8002 npm start
```

Open the path printed by `sample` at http://127.0.0.1:8002 and select **Trace** to see the 34-worker graph. The production sample uses synthetic records in a separate workspace.

## Design prototype

```sh
npm run demo:build
PORT=8001 npm run demo
```

The design demo uses synthetic records and scripted worker activity. Its data is separate from the production app.
