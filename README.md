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

Open http://127.0.0.1:8000. Use **Model settings** to enter an OpenRouter key, test the DeepSeek Flash preset, and save it. Advanced settings accept OpenAI Responses and Anthropic Messages-compatible providers.

Create a project with the authorized hosts and start a run. Review and approve specific hosts after inventory discovery. Runs use supplied response metadata by default. Enable **Read approved public pages during this run** to collect selected HTTPS response metadata through the scope broker. The current verification check reviews the recorded HTTP Strict Transport Security (HSTS) policy. Open the workflow graph to inspect worker threads and the report to follow verification back to its evidence.

Use **Import DNS export** to bring in candidates from a local, self-contained zone file. The preview shows hosts from A, AAAA, and CNAME records and flags aliases to outside the zone. Guardian records host and source information, then puts the imported candidates into the next run's scope review for selection. [DNS master-file syntax](https://www.rfc-editor.org/rfc/rfc1035.html#section-5.1)

The server binds to loopback. Set `PORT` to use a different port. Set `GUARDIAN_DATA_DIR` to choose a private data directory. Its default is `.guardian/`.

## Verify

```sh
npx playwright install chromium
npm run check
npm run test:e2e
npm run test:boundaries
```

Playwright runs against the production build with a temporary SQLite database per test. It replays recorded OpenRouter streams and local network fixtures through Guardian's request guards. The verification job uses the same tests on Linux.

Record fresh fixtures explicitly with `npm run fixtures:capture -- responses`, `messages`, or `workflow`. Capture uses only synthetic inputs and reads the key from `~/.config/guardian-fixtures/openrouter.key`, with owner-only permissions.

The separate opt-in command `npm run smoke:live -- --live` runs the production browser flow against live OpenRouter and the approved Dyad public home pages. It prints the local report path and data directory. Resume that run with `npm run smoke:live -- --live --resume <data-directory>` if it stops early.

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
