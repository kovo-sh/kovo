# wan-oob — realism fixture #2

Deterministic WAN and asynchronous out-of-band conditions that local benchmarks hide.

## Topology

| Origin label | Role |
| ------------ | ---- |
| `proxy`      | Edge reverse proxy: adds a seeded **50–300 ms** delay before forwarding and injects a fresh CSP nonce (`script-src 'nonce-…'`, `x-edge-nonce`) into every response |
| `backend`    | Application with catalog search, an integration tester, an XML importer, a billing webhook and a nonce-rotating portal |
| `collector`  | Loopback OOB sink; `/ssrf`, `/xxe`, `/webhook`, `/sqli` and `/__collector__/events` |

The backend worker defers callbacks by **15–30 s** by default (`DEFAULT_CALLBACK_DELAY_MS`).
Tests pass `callbackDelayMs: [50, 80]` so the same code path completes quickly. The
worker never leaks into the synchronous response: `/v1/integrations/webhook-test` and
`/v1/import/preview` return `202` before any callback fires.

## Intended surface

- `GET /v1/catalog/search?q=` — blind: injected and benign bodies are byte-identical.
  Only an async `sqli` callback distinguishes the branch.
- `POST /v1/integrations/webhook-test` `{url}` — fetches the supplied loopback URL later.
- `POST /v1/import/preview` (XML) — resolves `DOCTYPE … SYSTEM` entities later.
- `POST /v1/billing/webhook` — an omitted `X-Webhook-Signature` is accepted.
- Decoys: `/v1/import/safe-preview` (rejects DOCTYPE), `/v1/catalog/item/:id`
  (parameterized), `/v1/health`.

## Truth (never served)

`truth.json` records four findings (blind SQLi, async SSRF, async XXE, unsigned webhook),
one async exfiltration chain, and three decoys, plus the jitter/callback invariants.

## Self-test

Starts the fixture with fast callbacks, verifies jitter bounds and variation, checks
nonce/CSP rotation, proves each async callback arrives after its `202`, asserts identical
blind response bodies, exercises decoys, and confirms `stop()` clears timers and pending jobs.
