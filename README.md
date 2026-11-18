# Guardian

Local defensive evidence review for websites the operator owns or has permission to assess. See [SPEC.md](SPEC.md) for the v1 design and acceptance criteria.

## Run locally

Use Node.js 24.13.1 or newer.

```sh
npm ci
npm run build
npm start
```

Open http://127.0.0.1:8000. The server binds to loopback. Set `PORT` to use a different port. Guardian stores the workspace and evidence under `.guardian/` by default. Set `GUARDIAN_DATA_DIR` to use another private directory.

The production app currently supports projects, supplied inventory, discovery consent, scope approval, worker threads, run controls, and partial reports. The analysis and verification execution integrations are under development.

## Verify

```sh
npx playwright install chromium
npm run check
npm run test:e2e
```

Playwright runs against the production build with a temporary data directory. The browser tests cover approval, deep links, restart recovery, and the local HTTP trust boundary.

## Design prototype

```sh
npm run demo:build
PORT=8001 npm run demo
```

The design demo uses synthetic records and scripted worker activity. Its data is separate from the production app.
