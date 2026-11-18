# Guardian v1 verification

Verified on November 18, 2026 using the TanStack Start production build, Chromium, SQLite, and the local Linux Docker worker image.

| Check | Result |
| --- | --- |
| `npm run check` | TypeScript passed on Node.js 24.22.3. |
| `npm run test:e2e` | Twenty-four production browser tests passed. They cover both provider protocols through complete reports, model setup and key rejection, passive DNS and access policy imports, scope changes and replanning, coordinator chat, worker deep links, interruption recovery, container cleanup, and completed and in-flight verification after scope revocation. |
| `npm run test:boundaries` | Thirty-five tests passed. Nineteen cover scope, evidence, and the worker runtime. Six cover provider streaming and redaction. Ten cover the matched report scorecard, including incorrectly bound recordings, scope revisions, coverage overclaims, and incorrect high or critical findings. |
| `npm run benchmark:reports` | The four original report versions matched 34/34 regression verdicts at 100% precision and recall, with 8/8 confirmations linked to evidence and a verification receipt. The seven-scenario assessment manifest matched 55/55 labeled verdicts. |
| Matched Artex suite | `compare:reports` exited 0 with status `passed`. The four-scenario pair matched 39 labeled cases; Guardian scored 1.00 precision, 1.00 recall, 15/15 correct severity ratings, passing evidence, zero coverage overclaims, and 8 paired-reader results at or above Artex on every task. |
| Live Dyad scope run | A real OpenRouter run approved 30 `dyad.sh` hosts and completed report version 2 with 32 confirmed gaps. Against the existing Artex report, all 66 definitively assessed overlapping header cells agreed and none disagreed; 84 cells remained inconclusive under Guardian's non-2xx coverage policy. |
| GitHub Actions | The response reuse commit passed on a fresh Ubuntu checkout, including the Docker worker build, thirty-four boundary and comparison tests, twenty-one production browser tests, and all thirty-one assessment verdicts. [Hosted verification run for `01aae1b`](https://github.com/wwwillchen/guardian/actions/runs/44297918279) |
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

Another browser replay changed the goal while a worker's model reply was pending after its evidence command completed. The original request closed. The completed report used the revised plan and linked the current verification. The original thread reopened after a server restart and showed the saved receipt under its earlier goal. The workflow counted one current analysis worker and kept the canceled worker accessible. The scope tests also marked a removed host's worker and checked the earlier approval labels after reapproval.

The browser removed the sole host supplying access policy records while the original plan request was pending. The old request closed. A controlled HTTP 503 for the revised plan exercised the fallback for the remaining evidence. Scope revision 2 recorded one plan, one analysis and verification pair, and one fixture read for the remaining host. The report showed three response checks that met the baseline. A storage test also submitted an earlier plan directly and verified that it created no assignments.

The scope expansion replay held an analysis reply after the first fixture response was captured. The operator approved a host with supplied access records, and Guardian requested a revised plan. Restart preserved the pending plan and required explicit resume. The recorded combined plan canceled the original attempt and carried its capture into the new analysis. The export retained the original capture time and identified the source evidence and approval. The broker made one fixture read per host, and the final report attributed the access finding to the newly approved host.

A storage test selected the original checks on the revised approval and preserved the completed assignment. Its partial report identified the pending plan. Two redirect tests checked the saved origin chain. One excluded reused evidence after a later revocation. The other rejected reuse after an intervening revocation even though the most recent approval included the redirect host again.

An upgrade test opened an older run with a saved scope revision and an interrupted planning session. Guardian waited for explicit resume, then saved one revised plan in a session for the current approval and made one approved fixture read.

Both saved Dyad report versions and the linked worker thread reopened from an offline copy after the plan migration. A separate upgrade test interrupted the coordinator on the previous build and resumed its original saved prompt on the new build.

## Worker lifetime and recovery

The browser test killed the production server after Docker had created a verification container. On restart Guardian removed the workspace's abandoned container and left a container labeled for another workspace in place. The assignment remained paused with its lease cleared. Explicit resume reused the assignment and saved one verification record. The provider stream was replayed once and the run made zero page requests.

A separate test held the real container's input stream open without a Guardian server. The image terminated the worker at its 15-second deadline, and Docker removed the container. An offline upgrade check reopened both saved Dyad reports and retained the original three broker audit entries.

The report replay followed a verification worker to its recorded analysis and source inventory. The graph selected that branch and linked the two verification workers recorded in the completed report to the report node. The revised-goal replay checked the saved input assignment ID on the new verification. A storage test recovered an older worker link from its receipt and rejected a cross-host reference.

The 34-worker sample showed 26 recorded connections. Fit brought the worker lanes inside the scrollable viewport, and the selected branch was inspected in Porcelain and Studio dark. A migrated offline copy of the Dyad workspace resolved the verification, analysis, and inventory links. Both downloaded Markdown reports matched their original digests and the audit retained its three reads.

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

A separate production browser check opened a paused fixture run, revoked an intermediate redirect host, and stopped the run. The new partial report showed one inconclusive check and two untested checks for the remaining host. Both download formats omitted the earlier observation and its verification link. The earlier Markdown report retained its original digest.

The mixed-source browser replay used recorded provider turns, an approved loopback redirect chain, and isolated worker verification. After the redirect host was removed and the run resumed, the report retained the primary host's critical and high access findings, one matching access decision, and one missing decision. Three response checks became inconclusive. The new Markdown included only the approved access snapshot and its scoped verification, with the original verification timestamp. The earlier report exported byte for byte identically. A boundary test rejected a mismatched snapshot, a conflicting comparison, and outcomes from a failed verifier.

A second replay removed the redirect host while a mixed comparison was running. Guardian canceled the old execution and restarted the same assignment on its approved access snapshot. The run ledger recorded one committed worker verification under scope revision 2. The finished report included both serious access findings, and the fixture log contained the four original page reads.

The report and both exports put check totals and the first fix before the detailed findings. The access policy replay placed the excess billing permission first and the browser followed its link with the keyboard. The response replay showed two tied findings, and the healthy report listed verified checks. Both archived Dyad reports exported byte for byte identically on offline copies and retained the three-read audit.

The interrupted response replay showed six untested checks across two hosts in the browser, plain text, and Markdown. After resume produced version two, version one retained its original coverage. A browser run stopped after recovery from a crash during verification showed all four access-policy cases as untested, then resumed the same worker assignment and saved one verification record. A mixed storage case retained one host's committed result next to another host's untested checks. Stopping during planning recorded that the plan was pending.

The Artex Markdown renderer and the Guardian app were given the same synthetic access policy case. Artex's renderer received two pre-adjudicated discrepancies. Both exports described those discrepancies and the source timestamp. Guardian's export included the omitted decision as inconclusive and linked the policy snapshot and verification. A read-only aggregate check of the Artex database found 34 pending findings and zero tasks or findings mentioning the Northstar fixture. That renderer-only exercise remained report-only; the live matched assessment below supersedes it for the release comparison.

## Northstar report benchmark

The production browser replay scored 19 pre-labeled cases from four exported reports. Five expected confirmations were found with zero false confirmations, giving 5/5 precision and 5/5 recall on this suite. Four cases met the baseline. Four had insufficient evidence and were shown as inconclusive. The six interrupted cases remained untested.

Every confirmation linked to the scoped source record and the successful worker comparison. All five included expected and observed values, impact, remediation, and a way to check the fix. The access policy report put the medium-severity billing-export issue first and identified the role and policy decision to recheck.

An importer check used synthetic verdicts to verify rejection of missing cases and scoring of a false confirmation, an out-of-suite confirmation, and a missed expected result. Matched Artex results and the two-pass comparative reviewer exercise are recorded in the matched assessment section below.

A separate replay used two archived root response captures from the local Artex task files. The expected verdicts were set from the saved response headers before running Guardian. The production browser imported the allowed metadata and source timestamps. With local provider recordings and a controlled planning failure, the isolated verifier matched all six cases. Two checks met the baseline, one gap was confirmed, and three were inconclusive. The browser and Markdown evidence retained the original timestamps. The replay made zero brokered page reads.

The local Artex archive includes the saved report for that task. Its recorded scope consisted of one root domain and 32 subdomains. The Guardian replay used the two explicitly approved origins and their supplied root response metadata. All 34 Artex findings were pending, with zero linked traffic records and zero retests. A later paired run used a narrow controlled target with the same reviewed scope, inputs, and stopping point; see the matched assessment section below.

## Matched report scorecard

The comparison command verified the artifacts for a four-case Northstar access policy exercise. The pair used the export from Guardian's production browser replay and the output from Artex's native Markdown renderer. Artex rendered pre-adjudicated findings from the same local policy record. The Guardian export linked the original observation and verification for both confirmations. The local scorecard recorded evidence as passed; that report-only pair left assessment accuracy and reader results pending and was superseded by the live matched assessment below. The reader worksheet uses copies with neutral titles.

Tests exercised a matched synthetic suite, including a duplicate confirmation, a high-severity miss, and out-of-scope evidence. They rejected a changed report, results tied to a different input, a mismatched run record, and reader answers for a stale report version. The command also returned exit status 1 with a readable scorecard when a confirmation's evidence was marked unrelated.

The severity test failed a matched pair with equal precision and recall when Guardian missed a high finding. It also rejected a confirmation with an absent rating. In a copy of the saved 39-case manifest, changing a reported critical rating to high made the comparison command exit with status 1 and identify the affected scenario, asset, and issue. The original Guardian recordings passed the severity check.

The coverage test rejected a pass for a missing-evidence case and an inconclusive result for an untested case. Finding precision and recall stayed the same. The comparison command identified the two overclaims and exited with status 1 on a copy of the saved manifest. All 39 original verdicts matched with zero overclaims.

The reader scorecard includes paired coverage grades for healthy, incomplete, and finding-bearing reports. A synthetic comparison stayed pending when the interrupted report lacked a coverage grade and failed when the reader misidentified its coverage. The scorecard identifies the affected scenario.

The browser benchmark writes a Guardian assessment manifest with input packets, exported reports, and ordered events ending at the save event for each version. The interrupted report's recording ends before verification. The new cross-host case found the same billing policy gap on two hosts with independent evidence links, plus a separate access discrepancy. Offline copies of the two legacy Dyad reports exported byte-for-byte identical Markdown before and after adding the report event details. The three broker audit entries were preserved.

The comparison command checked the archived Guardian recordings against their recorded scopes, stopping points, and Markdown report versions. Tests rejected correctly hashed records for a different scope, checkpoint, or report version. They accepted a read under an earlier approval and rejected a response recorded after that host was removed. An opaque native archive kept comparative accuracy pending until it had a structured audit.

The checked-in fixture replay and a separate browser replay of the frozen Cedar input covered 39 labeled cases. The Cedar run used the recorded connection and access-policy planning turns and made zero page reads. All eight Cedar verdicts matched. Each of its three confirmed findings resolved to its own policy snapshot and isolated worker comparison. The matched Artex assessment and independent reader judgments are recorded below.

## Matched defensive assessment against Artex

Guardian and a local Artex instance assessed the same controlled HTTPS hosts with one shared goal on 2026-11-18. The target served `northstar.example` with missing browser controls, a reflected-origin credentialed CORS route, a stack trace, and an unprotected session cookie; `docs.northstar.example` returned HTTP 503; `healthy.northstar.example` served the six supported controls. Expected findings and severities were set from those responses before either report was read. Guardian used the captured observations as supplied evidence. Artex read the same hosts with read-only GET/HEAD/OPTIONS requests. Both products used `deepseek/deepseek-v4.1-flash-1017`; Artex was revision `fded32fb8fc67fc3c6ff492b6cde0d1d5550657e`.

The suite has four matched scenarios: a two-host complete assessment, a healthy complete report, an interrupted report stopped before verification, and a held-out deep packet with one high CORS finding. Reader copies changed only the first heading. Native reports, input packets, run records, event audits, and target request logs are in the private `.guardian/artex-matched` workspace.

`npm run --silent compare:reports -- .guardian/artex-matched/comparison/manifest.json` exited 0 with scorecard status `passed`; all five coverage flags were true.

| Criterion | Guardian | Artex |
| --- | --- | --- |
| Labeled cases | 39 | 39 |
| Confirmed findings correctly matched | 15 | 15 |
| Precision / recall | 1.00 / 1.00 | 0.469 / 1.00 |
| Expected high or critical ratings | 1/1 | 1/1 |
| Severity ratings correct | 15/15 | 3/15 |
| Evidence support | passed | not scored |
| Coverage overclaims | 0 | not scored |
| Paired readers: priority / remediation / impact / evidence / recheck / coverage | 4 / 4 / 4 / 4 / 4 / 8 | 2 / 0 / 4 / 4 / 0 / 0 |

Guardian's report put a concrete first fix and its remediation ahead of the detail, linked each confirmation to source and verification evidence, listed a remediation plan, and kept inconclusive and untested checks visible. Artex's strongest finding and PoC were comparable, but it gave no remediation, recheck, or coverage table, and it reported the unavailable docs host as confirmed gaps rather than inconclusive. The extra Artex confirmations, including two harness-dependent TLS observations, were retained in the precision denominator. No critical finding was present in this scoped response assessment; the single high finding was rated correctly by both products.

## Live Dyad smoke run

One run used the default OpenRouter Responses preset and explicit approval for `dyad.sh` and `www.dyad.sh`. The broker recorded three public-page reads. `dyad.sh` responded with `308`, and the approved redirect and direct request to `www.dyad.sh` each responded with `200`. Both final observations describe `www.dyad.sh`. A later offline regression test verifies that a final response on a different host leaves the initiating host's HTTPS policy inconclusive.

One initial model turn reached its output limit and the run saved a partial report. After adding and testing local evidence fallback for that condition, the operator resumed the same run. Guardian reused both observations with zero additional Dyad requests. Report version 2 covered both approved origins, linked two derived analysis artifacts, and showed zero confirmed HSTS findings. The browser follow-through opened verification evidence and then its read-only worker thread. The SQLite database, reports, and credentials from this run stay in the local `.guardian/dyad-smoke` directory on the verification machine.

The latest production build downloaded both saved report versions from an offline copy after the worker message migration and opened the verification receipt under Supporting evidence in its read-only worker thread. Both exports matched the originals byte for byte. The audit retained the original three reads.

## Live Dyad 30-host scope run

A second live run expanded the approved scope to 30 `dyad.sh` hosts taken from the existing Artex task: the apex, the marketing and application subdomains, and the API, upload, auth, preview, gateway, and dangling hosts. The operator approved all 30 after discovery and authorized read-only public responses. Guardian read each approved root once and completed report version 2.

The run exposed a real provider edge case. The model returned an empty `derive_evidence` tool call for `accounts.dyad.sh`, and the failed tool result previously stopped the remaining 28 paused assignments. The worker now recognizes a tool call that produced no usable command and runs the standard observation extraction itself, recording that deterministic handoff in the worker thread. The same run then resumed, reused the captured 403 observation, and completed every host.

Report version 2 recorded 32 confirmed gaps (21 low, 11 informational), 37 checks meeting baseline, 108 inconclusive checks, and 3 not applicable. The confirmed gaps were 10 CSP, 10 frame protection, 8 MIME sniffing, 3 server disclosure, and 1 HSTS finding.

The existing Artex report's scope matrix covers 24 of the 30 hosts. On the overlapping HSTS, CSP, frame, MIME, referrer, and server checks, 66 cells had a definitive Guardian result and every one agreed with the Artex expectation; none disagreed. The remaining 84 cells were inconclusive because Guardian does not treat a 308, 403, 404, or 525 root as a usable response. Artex inspected headers on some error responses and counted them as gaps, which accounts for the difference. Artex-only DNS takeover, TLS protocol, certificate, authentication/authorization, upload, GraphQL, and CORS/exploitation findings remain outside Guardian's supported evidence and are not counted as Guardian misses.

Artifacts, including the exported report, run recording, comparison table, and per-host results, are in the private `.guardian/dyad-live` workspace.

## Dependency audit

`npm audit --omit=dev` identified one high-severity upstream advisory in the `picomatch` dependency tree used by the TanStack and Vite tooling. The advisory lists no patched version for the installed release line. [GitHub advisory](https://github.com/advisories/GHSA-fc5q-39xc-vjpf)
