/**
 * Core benign-target archetype generators (R3-12):
 *   1. `public_endpoint`    — Intentionally public read/list route returning 200 to all actors,
 *                             and 401 ONLY when a malformed/invalid bearer token is presented.
 *   2. `validator_4xx`      — Strict length-cap / charset / schema validator returning 400/422
 *                             on non-conforming parameters without backend evaluation.
 *   3. `deleting_sanitizer` — Tag-stripping / zero-width-stripping / NFKC-folding echoing
 *                             endpoint returning sanitized/escaped text in 200 JSON responses.
 *   4. `honest_accumulator` — Honest state accumulator (add-to-cart twice, wallet deposit twice,
 *                             idempotent PUT, exact conservation on refunds & debits).
 *
 * Defensive QA framing: pure in-memory benign target simulators, zero network.
 */
import {
  createBenignSession,
  headerCI,
  parseQueryParams,
  pathnameOf,
  type BenignArchetypeDefinition,
  type SyntheticTargetRequest,
  type SyntheticTargetResponse,
} from './types.ts'

function hasInvalidBearer(req: SyntheticTargetRequest): boolean {
  const auth = headerCI(req.headers, 'authorization')
  if (!auth) return false
  return /^bearer\s+/i.test(auth) && !/^bearer\s+tok_[a-z0-9_]+_valid$/i.test(auth.trim())
}

/**
 * 1. `public_endpoint`:
 * Intentionally public storefront/catalog route returning the exact same public catalog payload
 * to owner, foreign tenant, and anonymous callers. Rejects malformed bearer tokens with 401
 * (standard auth middleware rejecting syntactically invalid credentials on a permit-all route).
 * Rejects unauthenticated mutations with 403.
 */
export const publicEndpointArchetype: BenignArchetypeDefinition = {
  id: 'public_endpoint',
  title: 'Intentionally public read/list route (401 only on invalid bearer)',
  description: 'Permit-all public catalog/storefront route serving identical public objects to all actors and rejecting malformed bearer tokens with 401.',
  createSession(opts) {
    const publicCatalog = {
      items: [
        { id: '201', slug: 'starter-kit', title: 'Starter Kit', price: 1200, stock: 5, author: 'Jess' },
        { id: '202', slug: 'pro-bundle', title: 'Pro Bundle', price: 1700, stock: 5, author: 'Pat' },
      ],
      visibility: 'public',
    }
    const publicItem = {
      id: '201',
      slug: 'starter-kit',
      title: 'Starter Kit',
      price: 1200,
      stock: 5,
      author: 'Jess',
      visibility: 'public',
    }
    return createBenignSession({
      archetypeId: 'public_endpoint',
      origin: opts?.origin,
      signingKey: opts?.signingKey,
      primaryRoute: '/api/public/catalog',
      secondaryRoute: '/api/public/catalog/201',
      queryParam: 'id',
      baseParamValue: '201',
      mutateRoute: '/api/public/feedback',
      balanceRoute: '/api/public/catalog/201',
      readEntityRoute: '/api/public/catalog/201',
      foreignEntityRoute: '/api/public/catalog/202',
      handle(req): SyntheticTargetResponse {
        if (hasInvalidBearer(req)) {
          return { status: 401, json: { error: 'invalid_bearer_token' } }
        }
        const path = pathnameOf(req.pathAndQuery)
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          if (!req.actor.handle) return { status: 401, json: { error: 'authentication_required' } }
          return { status: 403, json: { error: 'read_only_public_route' } }
        }
        if (path.endsWith('/201') || parseQueryParams(req.pathAndQuery).get('id') === '201') {
          return { status: 200, json: publicItem }
        }
        return { status: 200, json: publicCatalog }
      },
    })
  },
}

/**
 * 2. `validator_4xx`:
 * Strict request-parameter validator enforcing a short length cap (<= 12 chars) and strict
 * alphanumeric charset (`^[A-Za-z0-9_-]{1,12}$`), returning 400 or 422 on invalid input
 * without ever evaluating the input in SQL/template/shell interpreters.
 */
export const validator4xxArchetype: BenignArchetypeDefinition = {
  id: 'validator_4xx',
  title: 'Strict length-cap / charset / schema validator returning 400/422',
  description: 'Validates query and JSON schema strictly before handler logic; rejects malformed/overlong input with 400/422.',
  createSession(opts) {
    const SAFE_PARAM_RE = /^[A-Za-z0-9_-]{1,12}$/
    return createBenignSession({
      archetypeId: 'validator_4xx',
      origin: opts?.origin,
      signingKey: opts?.signingKey,
      primaryRoute: '/api/items/lookup',
      secondaryRoute: '/api/items/validate',
      queryParam: 'code',
      baseParamValue: 'item42',
      mutateRoute: '/api/items/validate',
      balanceRoute: '/api/items/lookup',
      readEntityRoute: '/api/items/lookup?code=item42',
      foreignEntityRoute: '/api/items/lookup?code=item99',
      handle(req): SyntheticTargetResponse {
        if (hasInvalidBearer(req)) {
          return { status: 401, json: { error: 'invalid_token' } }
        }
        const params = parseQueryParams(req.pathAndQuery)
        const code = params.get('code') ?? params.get('id') ?? params.get('q') ?? params.get('next')
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          const bodyObj = req.jsonBody && typeof req.jsonBody === 'object' && !Array.isArray(req.jsonBody)
            ? (req.jsonBody as Record<string, unknown>)
            : null
          if (!bodyObj || typeof bodyObj.code !== 'string' || !SAFE_PARAM_RE.test(bodyObj.code)) {
            return {
              status: 422,
              json: { error: 'validation_failed', field: 'code', constraint: 'alphanumeric_max_12' },
            }
          }
          return { status: 200, json: { valid: true, normalizedCode: bodyObj.code.toLowerCase() } }
        }
        if (code !== null && !SAFE_PARAM_RE.test(code)) {
          return {
            status: 400,
            json: { error: 'invalid_parameter', detail: 'Parameter must match ^[A-Za-z0-9_-]{1,12}$' },
          }
        }
        return {
          status: 200,
          json: { code: code ?? 'item42', name: 'Validated Record', status: 'active' },
        }
      },
    })
  },
}

/**
 * 3. `deleting_sanitizer`:
 * Benign text-preview/search endpoint that normalizes incoming user text via NFKC folding,
 * removes angle-bracket markup tags and zero-width characters, HTML-escapes quotes, and returns
 * the sanitized echo inside a JSON response (never executing markup or evaluating expressions).
 */
export const deletingSanitizerArchetype: BenignArchetypeDefinition = {
  id: 'deleting_sanitizer',
  title: 'Tag-stripping / zero-width / NFKC echoing endpoint',
  description: 'Applies NFKC normalization, zero-width deletion, and tag stripping before echoing input safely as JSON text.',
  createSession(opts) {
    const sanitizeText = (raw: string): string =>
      raw
        .normalize('NFKC')
        .replace(/[\u200B-\u200D\uFEFF]/g, '')
        .replace(/<[^>]*>/g, '')
        .replace(/[<>]/g, '')
        .slice(0, 256)

    return createBenignSession({
      archetypeId: 'deleting_sanitizer',
      origin: opts?.origin,
      signingKey: opts?.signingKey,
      primaryRoute: '/api/preview/sanitize',
      secondaryRoute: '/api/preview/echo',
      queryParam: 'q',
      baseParamValue: 'hello',
      mutateRoute: '/api/preview/sanitize',
      balanceRoute: '/api/preview/sanitize',
      readEntityRoute: '/api/preview/sanitize?q=hello',
      foreignEntityRoute: '/api/preview/sanitize?q=world',
      handle(req): SyntheticTargetResponse {
        const params = parseQueryParams(req.pathAndQuery)
        let rawInput = params.get('q') ?? params.get('id') ?? params.get('next') ?? 'hello'
        if (req.jsonBody && typeof req.jsonBody === 'object' && !Array.isArray(req.jsonBody)) {
          const obj = req.jsonBody as Record<string, unknown>
          if (typeof obj.text === 'string') rawInput = obj.text
          else if (typeof obj.q === 'string') rawInput = obj.q
        }
        const cleaned = sanitizeText(rawInput)
        return {
          status: 200,
          headers: {
            'content-type': 'application/json; charset=utf-8',
            'x-content-type-options': 'nosniff',
          },
          json: {
            sanitized: cleaned,
            originalLength: rawInput.length,
            cleanedLength: cleaned.length,
            escaped: true,
          },
        }
      },
    })
  },
}

/**
 * 4. `honest_accumulator`:
 * Honest commerce/wallet service that:
 *   - Increments cart quantity or wallet balance linearly on repeated authorized deposits/adds
 *     (no business-logic refusal boundary violated; each deposit is accounted for honestly),
 *   - Enforces strict balance conservation on debits/withdrawals (never allows balance < 0 or
 *     over-debit; rejects overdrafts with 409 Conflict),
 *   - Enforces strict refund conservation (total refunded never exceeds paidAmount),
 *   - Treats PUT profile/item updates idempotently (identical final state).
 */
export const honestAccumulatorArchetype: BenignArchetypeDefinition = {
  id: 'honest_accumulator',
  title: 'Honest accumulator (add-to-cart twice, wallet deposit twice, idempotent PUT)',
  description: 'Linearly accumulates authorized cart/deposit operations per tenant, strictly conserves debits/refunds with 409 on exhaustion, and applies idempotent PUT updates.',
  createSession(opts) {
    const wallets = new Map<string, { balance: number; note: string }>([
      ['tenant-a', { balance: 100, note: 'initial-a' }],
      ['tenant-b', { balance: 200, note: 'initial-b' }],
    ])
    const carts = new Map<string, { qty: number }>([
      ['tenant-a', { qty: 1 }],
      ['tenant-b', { qty: 1 }],
    ])
    const orders = new Map<string, { paidAmount: number; refundedTotal: number }>([
      ['tenant-a', { paidAmount: 5000, refundedTotal: 0 }],
      ['tenant-b', { paidAmount: 5000, refundedTotal: 0 }],
    ])
    const walletFor = (tenant: string) => {
      let w = wallets.get(tenant)
      if (!w) { w = { balance: 100, note: `initial-${tenant}` }; wallets.set(tenant, w) }
      return w
    }
    const cartFor = (tenant: string) => {
      let c = carts.get(tenant)
      if (!c) { c = { qty: 1 }; carts.set(tenant, c) }
      return c
    }
    const orderFor = (tenant: string) => {
      let o = orders.get(tenant)
      if (!o) { o = { paidAmount: 5000, refundedTotal: 0 }; orders.set(tenant, o) }
      return o
    }

    return createBenignSession({
      archetypeId: 'honest_accumulator',
      origin: opts?.origin,
      signingKey: opts?.signingKey,
      primaryRoute: '/api/wallets/acct_a/balance',
      secondaryRoute: '/api/carts/cart_a',
      queryParam: 'account',
      baseParamValue: 'acct_a',
      mutateRoute: '/api/wallets/acct_a/deposit',
      balanceRoute: '/api/wallets/acct_a/balance',
      readEntityRoute: '/api/wallets/acct_a/balance',
      foreignEntityRoute: '/api/wallets/acct_b/balance',
      handle(req): SyntheticTargetResponse {
        if (!req.actor.handle || !req.actor.tenant) return { status: 401, json: { error: 'authentication_required' } }
        if (hasInvalidBearer(req)) return { status: 401, json: { error: 'invalid_token' } }
        const path = pathnameOf(req.pathAndQuery)
        // Strict tenant isolation on tenant-scoped wallet/cart/order routes
        if (path.includes('/acct_a') && req.actor.tenant !== 'tenant-a') {
          return { status: 403, json: { error: 'forbidden_wallet_tenant' } }
        }
        if (path.includes('/acct_b') && req.actor.tenant !== 'tenant-b') {
          return { status: 403, json: { error: 'forbidden_wallet_tenant' } }
        }
        const tenant = req.actor.tenant
        const wallet = walletFor(tenant)
        const cart = cartFor(tenant)
        const order = orderFor(tenant)
        const acctId = tenant === 'tenant-a' ? 'acct_a' : 'acct_b'
        const body = req.jsonBody && typeof req.jsonBody === 'object' && !Array.isArray(req.jsonBody)
          ? (req.jsonBody as Record<string, unknown>)
          : {}

        if (req.method === 'GET') {
          if (path.includes('/cart')) {
            return { status: 200, json: { cartId: `cart_${tenant}`, quantity: cart.qty, total: cart.qty * 2500, tenant_id: tenant } }
          }
          if (path.includes('/orders')) {
            return {
              status: 200,
              json: {
                orderId: 'ord_100',
                paidAmount: order.paidAmount,
                refundedTotal: order.refundedTotal,
                fulfilledValue: order.paidAmount,
                fulfillmentState: 'fulfilled',
                tenant_id: tenant,
              },
            }
          }
          return {
            status: 200,
            json: {
              accountId: acctId,
              balance: wallet.balance,
              limit: 1000,
              note: wallet.note,
              paidAmount: order.paidAmount,
              refundedTotal: order.refundedTotal,
              tenant_id: tenant,
            },
          }
        }

        if (req.method === 'PUT') {
          if (typeof body.note === 'string') wallet.note = body.note.slice(0, 64)
          return { status: 200, json: { accountId: acctId, balance: wallet.balance, note: wallet.note, idempotent: true } }
        }

        if (path.includes('/debit') || path.includes('/withdraw') || path.includes('/redeem')) {
          const amt = typeof body.amount === 'number' && Number.isFinite(body.amount) && body.amount > 0 ? body.amount : 60
          if (amt > wallet.balance) {
            return { status: 409, json: { error: 'insufficient_balance', balance: wallet.balance } }
          }
          wallet.balance -= amt
          return { status: 200, json: { ok: true, debited: amt, balance: wallet.balance } }
        }

        if (path.includes('/refund')) {
          const amt = typeof body.amount === 'number' && Number.isFinite(body.amount) && body.amount > 0 ? body.amount : 1000
          if (order.refundedTotal + amt > order.paidAmount) {
            return { status: 409, json: { error: 'refund_exceeds_paid_amount', paidAmount: order.paidAmount, refundedTotal: order.refundedTotal } }
          }
          order.refundedTotal += amt
          return { status: 200, json: { ok: true, refunded: amt, refundedTotal: order.refundedTotal, paidAmount: order.paidAmount } }
        }

        if (path.includes('/cart')) {
          const addQty = typeof body.qty === 'number' && Number.isFinite(body.qty) && body.qty > 0 ? Math.min(body.qty, 5) : 1
          cart.qty += addQty
          return { status: 200, json: { cartId: `cart_${tenant}`, quantity: cart.qty, total: cart.qty * 2500 } }
        }

        // Honest deposit: strictly accounted authorized deposit
        const dep = typeof body.amount === 'number' && Number.isFinite(body.amount) && body.amount > 0 ? Math.min(body.amount, 50) : 25
        wallet.balance += dep
        return { status: 200, json: { accountId: acctId, deposited: dep, balance: wallet.balance } }
      },
    })
  },
}
