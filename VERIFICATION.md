# Guardian v1 verification

Verified on November 18, 2026 using the TanStack Start production build, Chromium, SQLite, and the local Linux Docker worker image.

| Check | Result |
| --- | --- |
| `npm run check` | TypeScript passed on Node.js 24.22.3. |
| `npm run test:e2e` | Nineteen production browser tests passed. They cover both provider protocols through complete reports, returning from model setup to an approved run, key rejection, passive DNS and access policy imports, scope changes during planning and analysis, coordinator chat, worker deep links, recovery from interrupted calls, container cleanup after a crash, evidence exports, and prioritization of access policy findings. |
| `npm run test:boundaries` | Thirty tests passed. Fifteen cover scope, evidence, and the worker runtime. Six cover provider streaming and redaction. Nine cover the matched report scorecard, including incorrectly bound recordings, scope revisions, missing coverage grades, and incorrect high or critical findings. |
| `npm run benchmark:reports` | All 19 regression verdicts matched. The assessment manifest adds eight cases on two approved hosts and four cases with documented access impacts. All 31 verdicts matched. All ten confirmations had the expected severity, scoped observation, and verification. |
| GitHub Actions | The model setup commit passed on a fresh Ubuntu checkout, including the Docker worker build, twenty-nine boundary and comparison tests, nineteen production browser tests, and all thirty-one assessment verdicts. [Hosted verification run for `7b228c7`](https://github.com/wwwillchen/guardian/actions/runs/44292705700) |
| `npm run sample` | The 34-worker graph opened in light and dark at wide and narrow widths. Browser checks verified keyboard worker search, menu and dialog behavior, worker selection, read-only chat, and preservation of the scope and coordinator drafts. |

## Recorded provider and network fixtures

Eighteen checked-in OpenRouter recordings contain twenty-five HTTP responses from `deepseek/deepseek-v4.1-flash-1017`. The connection tests replay both Responses and Messages. The Responses workflow exercises broad and focused plans, a coordinator status reply, parallel analysis, recorded tool arguments, Docker-based verification, and reports with confirmed findings, coverage gaps, or zero findings. Three Responses worker recordings include an actual provider output limit.

The first synthetic Messages analysis response reached the output limit before calling its tool. The DeepSeek preset now sends its thinking-off setting explicitly in Messages requests. Four new Messages responses captured the connection check, a focused plan, a worker tool call, and the model's response to the result. [OpenRouter Messages compatibility](https://openrouter.ai/docs/guides/coding-agents/claude-code-integration)

The production browser test replayed those streams and killed Guardian while the worker's follow-up response was pending. The derived receipt was already visible under the worker's tool-result message. Restart left the run paused and preserved the attachment. Explicit resume reused one brokered fixture observation, the same analysis receipt and worker message, and the original Pi Durable user and tool-result entries. The finished report confirmed the expected referrer policy gap and linked the successful Docker verification. The Responses replay followed a report's verification link to the worker's message and its evidence.

The browser replay revoked a previously verified fixture key. The next connection check replaced the success message with the provider rejection. Save made a fresh request and left the workspace without a saved credential. A two-page check finished an older successful request after a newer rejection and verified that Save still rechecked the key.

A fresh workspace approved a run before connecting a model. It stayed on the same approval and made no page requests while setup was pending. After a rejected key, saving the verified key returned to that run. The paused run waited for Resume and then planned only the requested Referrer-Policy check. A separate active-run replay started after model save and completed the same focused check. The final production build also passed focused browser checks for the setup flow, DNS approvals, and the 34-worker sample.

A local synthetic provider split a dummy credential across streaming events for each supported protocol. The Pi Durable sessions and recorded calls contained the replacement and omitted the credential fragments. Focused checks covered valid tool JSON after redaction, event ordering, release at the terminal event, and safe errors for malformed or oversized responses.

The production browser tests use a fresh workspace and local HTTP fixtures. They hold a broker response open while the operator revokes its host, then verify that the pending result never becomes evidence. A second test narrows scope and stops the server with a provider stream pending. Explicit resume reuses the saved response under the current approval, continues the original Pi Durable conversation, and completes the report after one broker request and one saved prompt for that host. Fixture credentials and response cookie values are absent from the matched model requests, saved transcripts, and exported reports.

The scope-narrowing test opened a second browser tab at revision one and disconnected its event stream. The first tab removed a host. The second tab's save was rejected and reopened from revision two with the removed host unchecked and consent cleared. The run completed under revision two after one fixture request per original host. A storage check also verified that a run stopped before its first scope approval waits for explicit resume before it can advance.

The DNS import test verifies candidate provenance, recognition of third-party aliases, explicit scope selection for imported hosts, and omission of raw address and TXT values from the inventory evidence. An offline copy of the Dyad workspace opened the legacy inventory evidence links and exported both reports with all three broker audit entries preserved.

The browser added a second host while the first approved fixture response was pending. After a reload, the inventory row opened the second host's own source record. Selecting the host left the first approval in effect until the operator consented to the new scope. Each host was read once. The report covered both under revision 2, and the audit retained both approvals. A storage test verified that older candidates link to the original inventory only when their origin appears in it.

## Coordinator planning and recovery

The browser stops the server while a broad plan is in flight. The run view reconnects and waits for explicit resume. With one saved planner prompt and one committed plan, analysis continues and later resumes from its own saved work. The report preserves the selected checks and goal revision.

A second scenario replaces a pending broad plan with a referrer-only goal. It records one plan for the new revision and one brokered fixture read for the approved host. The worker handoff, verification receipt, and report show only the selected check. A controlled provider failure uses the standard plan, and the worker completes its comparison from the recorded metadata.

The browser removed the sole host supplying access policy records while the original plan request was pending. The old request closed. A controlled HTTP 503 for the revised plan exercised the fallback for the remaining evidence. Scope revision 2 recorded one plan, one analysis and verification pair, and one fixture read for the remaining host. The report showed three response checks that met the baseline. A storage test also submitted an earlier plan directly and verified that it created no assignments.

An upgrade test opened an older run with a saved scope revision and an interrupted planning session. Guardian waited for explicit resume, then saved one revised plan in a session for the current approval and made one approved fixture read.

Both saved Dyad report versions and the linked worker thread reopened from an offline copy after the plan migration. A separate upgrade test interrupted the coordinator on the previous build and resumed its original saved prompt on the new build.

## Worker lifetime and recovery

The browser test killed the production server after Docker had created a verification container. On restart Guardian removed the workspace's abandoned container and left a container labeled for another workspace in place. The assignment remained paused with its lease cleared. Explicit resume reused the assignment and saved one verification record. The provider stream was replayed once and the run made zero page requests.

A separate test held the real container's input stream open without a Guardian server. The image terminated the worker at its 15-second deadline, and Docker removed the container. An offline upgrade check reopened both saved Dyad reports and retained the original three broker audit entries.

## Response policy reports

The multi-host browser fixture confirms HSTS, MIME sniffing protection, and referrer policy gaps from one approved response. It reports the second host's HTTP 503 response as inconclusive. The browser follows a finding to the recorded observation, the Docker worker's successful comparison, and its read-only thread. It also checks that the export includes the observed and expected settings and how to check the fix. A synthetic secret in cookie and referrer headers stays out of the evidence and export.

The healthy fixture reports zero findings and three checks that meet the baseline. A stopped run shows pending verification and resumes into a later report version. Both fixtures reuse the checked-in provider recordings. A visual check opened the new report in desktop light mode and at 390 pixels in dark mode. The migration preserved both prior Dyad reports and their three-read audit on an offline copy.

## Access policy reports

The browser imports expected policy cases and recorded decisions for an existing host. It rejects a file for an unknown host and strips extra fields before submitting the import. The isolated worker matches cases by identifier. The access-only scenario found two discrepancies and one passing case, with one missing decision marked inconclusive. It made zero page requests even with public reads authorized. A second, combined run made one approved fixture read, confirmed five differences across both evidence sources, and kept the original run's evidence after the project records were replaced.

The report links the source record, capture time, and worker comparison. The browser verified the text export and evidence links. A separate worker check processed 64 expected access cases plus one response comparison and omitted the unmatched case from the comparisons. An upgrade opened the previous build's report and retained its three findings. Both saved Dyad report versions also reopened from an offline copy, preserving the three-read audit.

The serious-impact fixture paired a verified organization-wide administrative grant with access to sensitive records. The browser showed critical and high findings respectively, put the critical finding first, and followed that link by keyboard. A correctly denied administrative operation met the baseline and a missing payroll decision remained inconclusive. The Markdown export preserved the expected rating, supplied classification, recorded decision, and isolated worker verification for both findings. The access-only run made zero page reads. Both archived Dyad exports matched byte for byte before and after the change on offline copies, and the audit still recorded three reads.

## Portable report evidence

The browser downloaded the partial and complete versions from one stopped and resumed run. Mixed-source and zero-finding exports include links from worker comparisons to the captured inputs. Every link and JSON digest in the mixed-source export matched. Historical access policy exports retained the earlier capture time after records were replaced. Seeded private data and raw tool fields stayed outside the downloads.

The scope boundary test exported each version after a scope change and reapproval. The restricted version omitted the removed origin and affected evidence. The earlier version preserved its approved scope. A simulated cross-host input reference was marked unavailable. An offline copy of the Dyad workspace exported both original report versions, resolved both legacy verification records, and retained the three-read audit. The export menu was checked in desktop light mode and at 390 pixels in dark mode.

The report and both exports put check totals and the first fix before the detailed findings. The access policy replay placed the excess billing permission first and the browser followed its link with the keyboard. The response replay showed two tied findings, and the healthy report listed verified checks. Both archived Dyad reports exported byte for byte identically on offline copies and retained the three-read audit.

The interrupted response replay showed six untested checks across two hosts in the browser, plain text, and Markdown. After resume produced version two, version one retained its original coverage. A browser run stopped after recovery from a crash during verification showed all four access-policy cases as untested, then resumed the same worker assignment and saved one verification record. A mixed storage case retained one host's committed result next to another host's untested checks. Stopping during planning recorded that the plan was pending.

The Artex Markdown renderer and the Guardian app were given the same synthetic access policy case. Artex's renderer received two pre-adjudicated discrepancies. Both exports described those discrepancies and the source timestamp. Guardian's export included the omitted decision as inconclusive and linked the policy snapshot and verification. A read-only aggregate check of the Artex database found 34 pending findings and zero tasks or findings mentioning the Northstar fixture. The matched assessment benchmark remains open.

## Northstar report benchmark

The production browser replay scored 19 pre-labeled cases from four exported reports. Five expected confirmations were found with zero false confirmations, giving 5/5 precision and 5/5 recall on this suite. Four cases met the baseline. Four had insufficient evidence and were shown as inconclusive. The six interrupted cases remained untested.

Every confirmation linked to the scoped source record and the successful worker comparison. All five included expected and observed values, impact, remediation, and a way to check the fix. The access policy report put the medium-severity billing-export issue first and identified the role and policy decision to recheck.

An importer check used synthetic verdicts to verify rejection of missing cases and scoring of a false confirmation, an out-of-suite confirmation, and a missed expected result. Matched Artex results and the comparative reviewer exercise remain open.

A separate replay used two archived root response captures from the local Artex task files. The expected verdicts were set from the saved response headers before running Guardian. The production browser imported the allowed metadata and source timestamps. With local provider recordings and a controlled planning failure, the isolated verifier matched all six cases. Two checks met the baseline, one gap was confirmed, and three were inconclusive. The browser and Markdown evidence retained the original timestamps. Those timestamps stayed local and the run made zero brokered page reads. The Artex task was marked done with 34 pending findings and no captured traffic linked to those findings. The replay supplies a holdout for Guardian's accuracy and handoff. A paired Artex baseline is still pending.

## Matched report scorecard

The comparison command verified the artifacts for a four-case Northstar access policy exercise. The pair used the export from Guardian's production browser replay and the output from Artex's native Markdown renderer. Artex rendered pre-adjudicated findings from the same local policy record. The Guardian export linked the original observation and verification for both confirmations. The local scorecard records evidence as passed and assessment accuracy and reader results as pending. The reader worksheet uses copies with neutral titles.

Tests exercised a matched synthetic suite, including a duplicate confirmation, a high-severity miss, and out-of-scope evidence. They rejected a changed report, results tied to a different input, a mismatched run record, and reader answers for a stale report version. The command also returned exit status 1 with a readable scorecard when a confirmation's evidence was marked unrelated.

The severity test failed a matched pair with equal precision and recall when Guardian missed a high finding. It also rejected a confirmation with an absent rating. In a copy of the saved 39-case manifest, changing a reported critical rating to high made the comparison command exit with status 1 and identify the affected scenario, asset, and issue. The original Guardian recordings passed the severity check.

The reader scorecard includes paired coverage grades for healthy, incomplete, and finding-bearing reports. A synthetic comparison stayed pending when the interrupted report lacked a coverage grade and failed when the reader misidentified its coverage. The scorecard identifies the affected scenario.

The browser benchmark writes a Guardian assessment manifest with input packets, exported reports, and ordered events ending at the save event for each version. The interrupted report's recording ends before verification. The new cross-host case found the same billing policy gap on two hosts with independent evidence links, plus a separate access discrepancy. Offline copies of the two legacy Dyad reports exported byte-for-byte identical Markdown before and after adding the report event details. The three broker audit entries were preserved.

The comparison command checked the archived Guardian recordings against their recorded scopes, stopping points, and Markdown report versions. Tests rejected correctly hashed records for a different scope, checkpoint, or report version. They accepted a read under an earlier approval and rejected a response recorded after that host was removed. An opaque native archive kept comparative accuracy pending until it had a structured audit.

The checked-in fixture replay and a separate browser replay of the frozen Cedar input covered 39 labeled cases. The Cedar run used the recorded connection and access-policy planning turns and made zero page reads. All eight Cedar verdicts matched. Each of its three confirmed findings resolved to its own policy snapshot and isolated worker comparison. Matched Artex assessments and independent reader judgments remain pending.

## Live Dyad smoke run

One run used the default OpenRouter Responses preset and explicit approval for `dyad.sh` and `www.dyad.sh`. The broker recorded three public-page reads. `dyad.sh` responded with `308`, and the approved redirect and direct request to `www.dyad.sh` each responded with `200`. Both final observations describe `www.dyad.sh`. A later offline regression test verifies that a final response on a different host leaves the initiating host's HTTPS policy inconclusive.

One initial model turn reached its output limit and the run saved a partial report. After adding and testing local evidence fallback for that condition, the operator resumed the same run. Guardian reused both observations with zero additional Dyad requests. Report version 2 covered both approved origins, linked two derived analysis artifacts, and showed zero confirmed HSTS findings. The browser follow-through opened verification evidence and then its read-only worker thread. The SQLite database, reports, and credentials from this run stay in the local `.guardian/dyad-smoke` directory on the verification machine.

The latest production build downloaded both saved report versions from an offline copy after the worker message migration and opened the verification receipt under Supporting evidence in its read-only worker thread. Both exports matched the originals byte for byte. The audit retained the original three reads.

## Dependency audit

`npm audit --omit=dev` identified one high-severity upstream advisory in the `picomatch` dependency tree used by the TanStack and Vite tooling. The advisory lists no patched version for the installed release line. [GitHub advisory](https://github.com/advisories/GHSA-fc5q-39xc-vjpf)
