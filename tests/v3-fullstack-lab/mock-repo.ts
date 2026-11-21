import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

/**
 * Materializes a deterministic local repository tree for Suite B testing.
 * Contains representative backend routes, frontend components, and configuration files
 * matching the 12 Suite B test cases + 3 safe control routes.
 */
export function createSuiteBMockRepo(rootDir: string): string {
  const repoDir = join(rootDir, 'northstar-app')
  const files: Record<string, string> = {
    'package.json': JSON.stringify({
      name: 'northstar-suite-b-app',
      version: '1.0.0',
      private: true,
      dependencies: {
        next: '14.2.20',
        express: '4.19.2',
        ws: '8.18.0',
      },
    }, null, 2),

    // Case 1: Next.js Server Action missing ownership check
    'app/actions/invoice.ts': [
      "'use server'",
      'export interface InvoiceRecord { id: string; ownerId: string; totalCents: number; notes: string }',
      'export async function getInvoiceAction(invoiceId: string, db: Map<string, InvoiceRecord>, _sessionUserId: string) {',
      '  const invoice = db.get(invoiceId)',
      '  if (!invoice) return { ok: false, error: "not_found" }',
      '  // BUG: missing ownership check comparing invoice.ownerId === _sessionUserId',
      '  return { ok: true, invoice }',
      '}',
      '',
    ].join('\n'),

    // Case 2: DELETE /api/orgs/:id/members/:memberId missing tenant check
    'src/routes/org-members.ts': [
      'export interface OrgMember { orgId: string; memberId: string; role: string }',
      'export function deleteOrgMemberHandler(orgId: string, memberId: string, callerOrgId: string, store: Map<string, OrgMember>) {',
      '  const key = `${orgId}:${memberId}`',
      '  if (!store.has(key)) return { status: 404, body: { error: "not_found" } }',
      '  // BUG: does not verify callerOrgId === orgId before deleting member record',
      '  void callerOrgId',
      '  store.delete(key)',
      '  return { status: 200, body: { deleted: true, orgId, memberId } }',
      '}',
      '',
    ].join('\n'),

    // Case 3: Webhook verification failing open when secret is unset
    'src/routes/billing-webhook.ts': [
      'import { createHmac } from "node:crypto"',
      'export function verifyWebhookSignature(rawBody: string, headerSig: string | undefined, secret: string | undefined): boolean {',
      '  // BUG: fails open when signing secret is unset',
      '  if (!secret) return true',
      '  if (!headerSig) return false',
      '  const expected = createHmac("sha256", secret).update(rawBody).digest("hex")',
      '  return headerSig === expected',
      '}',
      '',
    ].join('\n'),

    // Case 4: Unparameterized search query filter
    'src/routes/search.ts': [
      'export function buildProductSearchQuery(filter: string): string {',
      '  // BUG: string interpolation in SQL WHERE clause',
      '  const sql = `SELECT id, title FROM products WHERE category = \'${filter}\'`',
      '  return sql',
      '}',
      '',
    ].join('\n'),

    // Case 5: Template expression evaluation
    'src/routes/preview-template.ts': [
      'export function renderGreetingTemplate(template: string): string {',
      '  // BUG: evaluates untrusted {{expr}} arithmetic blocks directly',
      '  return template.replace(/\\{\\{\\s*(\\d+)\\s*\\*\\s*(\\d+)\\s*\\}\\}/g, (_, a, b) => String(Number(a) * Number(b)))',
      '}',
      '',
    ].join('\n'),

    // Case 6: Outbound webhook URL fetch without host allowlist
    'src/routes/webhook-preview.ts': [
      'export async function fetchWebhookPreview(targetUrl: string) {',
      '  // BUG: fetches user-supplied URL without domain allowlist or egress filtering',
      '  return fetch(targetUrl, { method: "GET" })',
      '}',
      '',
    ].join('\n'),

    // Case 7: WebSocket upgrade missing Origin header check
    'src/routes/ws-notifications.ts': [
      'export function shouldAcceptWebSocket(originHeader: string | undefined, allowedOrigin: string): boolean {',
      '  // BUG: ignores Origin header on cookie-authenticated WebSocket handshake',
      '  void originHeader',
      '  void allowedOrigin',
      '  return true',
      '}',
      '',
    ].join('\n'),

    // Case 8: Browser message handler writing directly to innerHTML
    'src/client/preview-frame.ts': [
      'export function attachPreviewListener(target: HTMLElement) {',
      '  window.addEventListener("message", (event) => {',
      '    // BUG: does not validate event.origin and writes unsanitized HTML',
      '    if (event.data && typeof event.data.html === "string") {',
      '      target.innerHTML = event.data.html',
      '    }',
      '  })',
      '}',
      '',
    ].join('\n'),

    // Case 9: Non-atomic coupon redemption check-then-act
    'src/routes/coupons.ts': [
      'export async function redeemSingleUseCoupon(code: string, redeemed: Set<string>, persist: () => Promise<void>) {',
      '  if (redeemed.has(code)) return { status: 409, body: { error: "already_redeemed" } }',
      '  // BUG: async gap between check and mark allows concurrent double-redemption',
      '  await persist()',
      '  redeemed.add(code)',
      '  return { status: 200, body: { redeemed: true, code } }',
      '}',
      '',
    ].join('\n'),

    // Case 10: File upload served inline with image/svg+xml
    'src/routes/uploads.ts': [
      'export function uploadResponseHeaders(contentType: string): Record<string, string> {',
      '  // BUG: serves user-uploaded SVG inline without Content-Disposition: attachment',
      '  return { "Content-Type": contentType }',
      '}',
      '',
    ].join('\n'),

    // Case 11: Credentialed dynamic CORS reflecting arbitrary Origin
    'src/middleware/cors.ts': [
      'export function buildCorsHeaders(requestOrigin: string | undefined): Record<string, string> {',
      '  if (!requestOrigin) return {}',
      '  // BUG: reflects any Origin alongside Access-Control-Allow-Credentials: true',
      '  return {',
      '    "Access-Control-Allow-Origin": requestOrigin,',
      '    "Access-Control-Allow-Credentials": "true",',
      '  }',
      '}',
      '',
    ].join('\n'),

    // Case 12: Middleware trusting external x-middleware-subrequest header
    'middleware.ts': [
      'export function shouldBypassAuthMiddleware(headers: Record<string, string | undefined>): boolean {',
      '  // BUG: CVE-2025-29927 pattern - trusts external x-middleware-subrequest header',
      '  return Boolean(headers["x-middleware-subrequest"])',
      '}',
      '',
    ].join('\n'),

    // Synthetic config file for secret masking check (strictly synthetic test fixture value)
    'config/sample.env.example': [
      '# Synthetic test fixture for secret masking validation',
      'STRIPE_TEST_KEY=sk_live_TESTFIXTURE000000000000000000',
      'AWS_TEST_KEY=AKIAIOSFODNN7EXAMPLE',
      '',
    ].join('\n'),
  }

  for (const [relPath, content] of Object.entries(files)) {
    const absPath = join(repoDir, relPath)
    mkdirSync(join(absPath, '..'), { recursive: true })
    writeFileSync(absPath, content, 'utf8')
  }

  return repoDir
}
