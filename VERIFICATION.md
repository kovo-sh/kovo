# Guardian v1 verification

Verified on November 18, 2026 using the TanStack Start production build, Chromium, SQLite, and the local Linux Docker worker image.

| Check | Result |
| --- | --- |
| `npm run check` | TypeScript passed. |
| `npm run test:e2e` | Eight production browser tests passed. They cover workspace onboarding, both provider protocols, a rejected key, explicit scope approval, goal revisions, new assets awaiting approval, worker deep links, restart and event replay, partial and complete reporting, and output-limit recovery. |
| `npm run test:boundaries` | Six tests passed. They cover mixed DNS results, out-of-scope redirects, overlapping revocation, canceled resolution, local Docker socket enforcement, read-only evidence, process-level network isolation, and the container's resource configuration. |
| `npm run sample` | The 34-worker graph opened in light and dark at wide and narrow widths. Browser checks verified keyboard worker search, menu and dialog behavior, worker selection, read-only chat, and preservation of the scope and coordinator drafts. |

## Recorded provider and network fixtures

Seven checked-in OpenRouter recordings contain twelve HTTP responses from `deepseek/deepseek-v4.1-flash-1017`. The connection tests replay both Responses and Messages. The larger Responses scenarios exercise a coordinator reply, parallel analysis, real recorded tool arguments, Docker-based verification, a confirmed and inconclusive report, and a separate zero-finding report. One regression case uses a controlled incomplete event based on a recorded worker stream.

The production browser tests use a fresh workspace and local HTTP fixtures. They hold a broker response open while the operator revokes its host, then verify that the pending result never becomes evidence. A second test narrows scope and stops the server with a provider stream pending. Explicit resume reuses the saved response under the current approval, continues the original Pi Durable conversation, and completes the report after one broker request and one saved prompt for that host. Fixture credentials and response cookie values are absent from the matched model requests, saved transcripts, and exported reports.

## Live Dyad smoke run

One run used the default OpenRouter Responses preset and explicit approval for `dyad.sh` and `www.dyad.sh`. The broker recorded three public-page reads. `dyad.sh` responded with `308`, and the approved redirect and direct request to `www.dyad.sh` each responded with `200`.

One initial model turn reached its output limit and the run saved a partial report. After adding and testing local evidence fallback for that condition, the operator resumed the same run. Guardian reused both observations with zero additional Dyad requests. Report version 2 covered both approved origins, linked two derived analysis artifacts, and showed zero confirmed HSTS findings. The browser follow-through opened verification evidence and then its read-only worker thread. The SQLite database, reports, and credentials from this run stay in the local `.guardian/dyad-smoke` directory on the verification machine.

## Dependency audit

`npm audit --omit=dev` identified one high-severity upstream advisory in the `picomatch` dependency tree used by the TanStack and Vite tooling. The advisory lists no patched version for the installed release line. [GitHub advisory](https://github.com/advisories/GHSA-fc5q-39xc-vjpf)
