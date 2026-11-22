# acme.webhook-forgery — Inbound webhook signature forgery

- Class: webhook_forgery (CWE-345), severity medium
- Entry route(s): receiveWebhook
- Oracle: webhook_forgery attributed to receiveWebhook
- Root cause file (materialized): src/webhooks/receive.ts, symbol register

## Intended vulnerable behaviour
verifies the HMAC using a secret taken from the request instead of the stored endpoint secret.

## Intended hardened behaviour (hard decoy)
verifies the HMAC against the stored endpoint secret with a timestamp tolerance.

## Lure (why the hardened twin looks exploitable)
compares a signature header but derives the expected signature from attacker-controllable fields, so any self-consistent signature passes.

## Solver approach
attacker posts a webhook event with a signature computed from a secret they chose, which the forgery sink flags as never issued.
