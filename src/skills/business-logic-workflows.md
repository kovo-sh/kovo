# Business Logic, State Machines & Workflow Integrity Audit
Tags: business-logic, workflow, state-machine, billing, quota, race-condition, idempotency
Summary: Audit multi-step workflows, billing/credit invariants, coupon/invite redemptions, approval state transitions, and rate/quota enforcement for step-skipping, replay, and concurrency defects.

## 1. High-Value Business Logic Invariants
Start by mapping domain state machines in `/repos` (`run_sast_scan`, `derive_evidence`) or OpenAPI/UI flows before probing:
1. **Multi-Step Workflow Step-Skipping:** Checkout, onboarding, MFA enrollment, KYC, or password-reset flows where Step 3 accepts a direct request without verifying server-side that Steps 1 and 2 completed.
2. **Client-Trusted Pricing, Roles & Totals:** Endpoints that accept `price`, `discount`, `currency`, `quantity` (negative/zero/fractional), `plan`, or `status` from client requests instead of computing authoritative values server-side.
3. **Single-Use & Quota Enforcement (TOCTOU / Race Windows):**
   - Coupon redemption, gift card/credit transfer, referral reward, trial activation, vote/poll submission, or API credit deduction implemented as non-atomic `SELECT balance -> check -> UPDATE balance` instead of a single atomic conditional `UPDATE ... WHERE balance >= cost` or database transaction with row-level locking (`SELECT ... FOR UPDATE`).
4. **Idempotency & Replay Gaps:** Webhook handlers or payment-confirmation endpoints lacking idempotency-key deduplication (allowing duplicate credit grants on replayed delivery).
5. **State Transition Validation:** Endpoints allowing invalid transitions (e.g., `cancelled -> refunded`, `draft -> approved`, or modifying an already finalized order/invoice).

## 2. Offline Source Audit Strategy
- Use `derive_evidence` to trace every mutation of balances, credits, subscriptions, seats, roles, invites, and order states.
- Check whether invariants are enforced inside database constraints (`CHECK (balance >= 0)`, `UNIQUE` redemption keys) and atomic transactions rather than application-memory checks.

## 3. Safe Verification (`RequestBroker`)
- Always restrict mutating workflow tests to Tier 2/3 (with HITL approval) or `local-lab` using dedicated disposable test personas/resources.
- For suspected TOCTOU/concurrency bugs on single-use test actions, confirm via `kovo_verify` using `ctx.prove_race_burst({ requests, readRoute, balanceField, unitDebit })` (`2–10` synchronized requests) verifying that multiple concurrent requests succeeded when only one should have.
- For negative-value/step-skipping logic flaws, verify via `kovo_verify` using `ctx.prove_persisted_mutation({ readRoute, mutation, fieldPath, expectDelta })` (or `ctx.http` + `ctx.expect`, or `ctx.chain(...)` / `ctx.seal_capability` + `ctx.prove_composite` for multi-hop workflows), then `return ctx.result({ title })`.

## 4. Closure & Counterevidence
- In `counterevidence`, evaluate whether an asynchronous reconciliation job, database constraint, or Stripe/payment-provider authoritative check prevents real financial or integrity impact.
- Close verified invariants via `record_coverage` (`status: "ruled_out"`, `enforcingControl: "<file:line of atomic constraint or state guard>"`).
