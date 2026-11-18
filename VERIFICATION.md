# Guardian v1 verification

Verified on November 18, 2026 using the TanStack Start production build, Chromium, SQLite, and the local Linux Docker worker image.

| Check | Result |
| --- | --- |
| `npm run check` | TypeScript passed on Node.js 24.22.3. |
| `npm run test:e2e` | Eleven production browser tests passed. They cover workspace onboarding, both provider protocols, a rejected key, passive DNS and access policy imports, explicit scope approval, revised check plans, coordinator chat, new assets awaiting approval, worker deep links, restart and event replay, evidence exports for multiple report versions, and output-limit recovery. |
| `npm run test:boundaries` | Eleven tests passed. They cover plan and access case validation, mixed DNS results, out-of-scope redirects, overlapping revocation, canceled resolution, verifier and export selection after a scope change, cross-host attribution, older and ambiguous observations, local Docker socket enforcement, read-only evidence, process-level network isolation, and container resource limits. |
| GitHub Actions | The access policy commit passed the workflow on a fresh Ubuntu checkout, including the Docker worker build, eleven boundary tests, and eleven production browser tests. [Hosted verification run for `853eb27`](https://github.com/wwwillchen/guardian/actions/runs/44277267781) |
| `npm run sample` | The 34-worker graph opened in light and dark at wide and narrow widths. Browser checks verified keyboard worker search, menu and dialog behavior, worker selection, read-only chat, and preservation of the scope and coordinator drafts. |

## Recorded provider and network fixtures

Sixteen checked-in OpenRouter recordings contain twenty-two HTTP responses from `deepseek/deepseek-v4.1-flash-1017`. The connection tests replay both Responses and Messages. The Responses workflow exercises broad and focused plans, a coordinator status reply, parallel analysis, recorded tool arguments, Docker-based verification, and reports with confirmed findings, coverage gaps, or zero findings. Three worker recordings include an actual provider output limit. Four synthetic planning calls cover the expanded catalog, while response-worker recordings are reused.

The production browser tests use a fresh workspace and local HTTP fixtures. They hold a broker response open while the operator revokes its host, then verify that the pending result never becomes evidence. A second test narrows scope and stops the server with a provider stream pending. Explicit resume reuses the saved response under the current approval, continues the original Pi Durable conversation, and completes the report after one broker request and one saved prompt for that host. Fixture credentials and response cookie values are absent from the matched model requests, saved transcripts, and exported reports.

The DNS import test verifies candidate provenance, recognition of third-party aliases, explicit scope selection for imported hosts, and omission of raw address and TXT values from the inventory evidence. An offline copy of the existing Dyad workspace also migrated successfully and reopened its prior report and evidence.

## Coordinator planning and recovery

The browser stops the server while a broad plan is in flight. The run view reconnects and waits for explicit resume. With one saved planner prompt and one committed plan, analysis continues and later resumes from its own saved work. The report preserves the selected checks and goal revision.

A second scenario replaces a pending broad plan with a referrer-only goal. It records one plan for the new revision and one brokered fixture read for the approved host. The worker handoff, verification receipt, and report show only the selected check. A controlled provider failure uses the standard plan, and the worker completes its comparison from the recorded metadata.

Both saved Dyad report versions and the linked worker thread reopened from an offline copy after the plan migration. A separate upgrade test interrupted the coordinator on the previous build and resumed its original saved prompt on the new build.

## Response policy reports

The multi-host browser fixture confirms HSTS, MIME sniffing protection, and referrer policy gaps from one approved response. It reports the second host's HTTP 503 response as inconclusive. The browser follows a finding to the recorded observation, the Docker worker's successful comparison, and its read-only thread. It also checks that the export includes the observed and expected settings and how to check the fix. A synthetic secret in cookie and referrer headers stays out of the evidence and export.

The healthy fixture reports zero findings and three checks that meet the baseline. A stopped run shows pending verification and resumes into a later report version. Both fixtures reuse the checked-in provider recordings. A visual check opened the new report in desktop light mode and at 390 pixels in dark mode. The migration preserved both prior Dyad reports and their three-read audit on an offline copy.

## Access policy reports

The browser imports expected policy cases and recorded decisions for an existing host. It rejects a file for an unknown host and strips extra fields before submitting the import. The isolated worker matches cases by identifier. The access-only scenario found two discrepancies and one passing case, with one missing decision marked inconclusive. It made zero page requests even with public reads authorized. A second, combined run made one approved fixture read, confirmed five differences across both evidence sources, and kept the original run's evidence after the project records were replaced.

The report links the source record, capture time, and worker comparison. The browser verified the text export and evidence links. A separate worker check processed 64 expected access cases plus one response comparison and omitted the unmatched case from the comparisons. An upgrade opened the previous build's report and retained its three findings. Both saved Dyad report versions also reopened from an offline copy, preserving the three-read audit.

## Portable report evidence

The browser downloaded the partial and complete versions from one stopped and resumed run. Mixed-source and zero-finding exports include links from worker comparisons to the captured inputs. Every link and JSON digest in the mixed-source export matched. Historical access policy exports retained the earlier capture time after records were replaced. Seeded private data and raw tool fields stayed outside the downloads.

The scope boundary test exported each version after a scope change and reapproval. The restricted version omitted the removed origin and affected evidence. The earlier version preserved its approved scope. A simulated cross-host input reference was marked unavailable. An offline copy of the Dyad workspace exported both original report versions, resolved both legacy verification records, and retained the three-read audit. The export menu was checked in desktop light mode and at 390 pixels in dark mode.

The Artex Markdown renderer and the Guardian app were given the same synthetic access policy case. Artex's renderer received two pre-adjudicated discrepancies. Both exports described those discrepancies and the source timestamp. Guardian's export included the omitted decision as inconclusive and linked the policy snapshot and verification. The matched assessment benchmark remains open.

## Live Dyad smoke run

One run used the default OpenRouter Responses preset and explicit approval for `dyad.sh` and `www.dyad.sh`. The broker recorded three public-page reads. `dyad.sh` responded with `308`, and the approved redirect and direct request to `www.dyad.sh` each responded with `200`. Both final observations describe `www.dyad.sh`. A later offline regression test verifies that a final response on a different host leaves the initiating host's HTTPS policy inconclusive.

One initial model turn reached its output limit and the run saved a partial report. After adding and testing local evidence fallback for that condition, the operator resumed the same run. Guardian reused both observations with zero additional Dyad requests. Report version 2 covered both approved origins, linked two derived analysis artifacts, and showed zero confirmed HSTS findings. The browser follow-through opened verification evidence and then its read-only worker thread. The SQLite database, reports, and credentials from this run stay in the local `.guardian/dyad-smoke` directory on the verification machine.

The latest production build reopened the saved complete report and linked worker evidence in offline mode. Both report versions and the three-read audit were preserved.

## Dependency audit

`npm audit --omit=dev` identified one high-severity upstream advisory in the `picomatch` dependency tree used by the TanStack and Vite tooling. The advisory lists no patched version for the installed release line. [GitHub advisory](https://github.com/advisories/GHSA-fc5q-39xc-vjpf)
