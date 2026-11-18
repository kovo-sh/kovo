# Guardian v1 verification

Verified on November 18, 2026 using the TanStack Start production build, Chromium, SQLite, and the local Linux Docker worker image.

| Check | Result |
| --- | --- |
| `npm run check` | TypeScript passed on Node.js 24.22.3. |
| `npm run test:e2e` | Nine production browser tests passed. They cover workspace onboarding, both provider protocols, a rejected key, passive DNS import, explicit scope approval, goal revisions, new assets awaiting approval, worker deep links, restart and event replay, partial and complete reporting, response policy evidence and remediation, and output-limit recovery. |
| `npm run test:boundaries` | Nine tests passed. They cover mixed DNS results, out-of-scope redirects, overlapping revocation, canceled resolution, verifier and report selection after a scope change, cross-host attribution, older and ambiguous observations, local Docker socket enforcement, read-only evidence, process-level network isolation, and container resource limits. |
| GitHub Actions | The preceding DNS import commit passed the workflow on a fresh Ubuntu checkout, including the Docker worker build, eight boundary tests, and nine production browser tests. [Hosted verification run for `e8dfb5a`](https://github.com/wwwillchen/guardian/actions/runs/44272421359) |
| `npm run sample` | The 34-worker graph opened in light and dark at wide and narrow widths. Browser checks verified keyboard worker search, menu and dialog behavior, worker selection, read-only chat, and preservation of the scope and coordinator drafts. |

## Recorded provider and network fixtures

Seven checked-in OpenRouter recordings contain twelve HTTP responses from `deepseek/deepseek-v4.1-flash-1017`. The connection tests replay both Responses and Messages. The larger Responses scenarios exercise a coordinator reply, parallel analysis, real recorded tool arguments, Docker-based verification, a confirmed and inconclusive report, and a separate zero-finding report. One regression case uses a controlled incomplete event based on a recorded worker stream.

The production browser tests use a fresh workspace and local HTTP fixtures. They hold a broker response open while the operator revokes its host, then verify that the pending result never becomes evidence. A second test narrows scope and stops the server with a provider stream pending. Explicit resume reuses the saved response under the current approval, continues the original Pi Durable conversation, and completes the report after one broker request and one saved prompt for that host. Fixture credentials and response cookie values are absent from the matched model requests, saved transcripts, and exported reports.

The DNS import test verifies candidate provenance, recognition of third-party aliases, explicit scope selection for imported hosts, and omission of raw address and TXT values from the inventory evidence. An offline copy of the existing Dyad workspace also migrated successfully and reopened its prior report and evidence.

## Response policy reports

The multi-host browser fixture confirms HSTS, MIME sniffing protection, and referrer policy gaps from one approved response. It reports the second host's HTTP 503 response as inconclusive. The browser follows a finding to the recorded observation, the Docker worker's successful comparison, and its read-only thread. It also checks that the export includes the observed and expected settings and how to check the fix. A synthetic secret in cookie and referrer headers stays out of the evidence and export.

The healthy fixture reports zero findings and three checks that meet the baseline. A stopped run shows pending verification and resumes into a later report version. Both fixtures reuse the checked-in provider recordings. A visual check opened the new report in desktop light mode and at 390 pixels in dark mode. The migration preserved both prior Dyad reports and their three-read audit on an offline copy. The comparative Artex report benchmark remains open.

## Live Dyad smoke run

One run used the default OpenRouter Responses preset and explicit approval for `dyad.sh` and `www.dyad.sh`. The broker recorded three public-page reads. `dyad.sh` responded with `308`, and the approved redirect and direct request to `www.dyad.sh` each responded with `200`. Both final observations describe `www.dyad.sh`. A later offline regression test verifies that a final response on a different host leaves the initiating host's HTTPS policy inconclusive.

One initial model turn reached its output limit and the run saved a partial report. After adding and testing local evidence fallback for that condition, the operator resumed the same run. Guardian reused both observations with zero additional Dyad requests. Report version 2 covered both approved origins, linked two derived analysis artifacts, and showed zero confirmed HSTS findings. The browser follow-through opened verification evidence and then its read-only worker thread. The SQLite database, reports, and credentials from this run stay in the local `.guardian/dyad-smoke` directory on the verification machine.

The latest production build reopened the saved complete report and linked worker evidence in offline mode. Both report versions and the three-read audit were preserved.

## Dependency audit

`npm audit --omit=dev` identified one high-severity upstream advisory in the `picomatch` dependency tree used by the TanStack and Vite tooling. The advisory lists no patched version for the installed release line. [GitHub advisory](https://github.com/advisories/GHSA-fc5q-39xc-vjpf)
