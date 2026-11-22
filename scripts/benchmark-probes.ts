/**
 * Generic hypothesis formation and probe execution for the recall benchmark.
 *
 * Nothing here knows about any benchmark challenge: hypotheses are derived only from the
 * endpoints/params Guardian's recon discovered (names, locations, path shapes, methods), then
 * handed to the real `probeDifferential` engine. Profile capabilities decide which discovery
 * strategies, parameter encodings and probe classes are available.
 */
import { BrokerApprovalRequired, BrokerDenied } from '../src/server/broker.ts'
import type { BrokerExchangeResult, Grant, RequestBroker } from '../src/server/broker.ts'
import type { CanaryBroker } from '../src/server/canary-broker.ts'
import { analyzeXssReflection, injectUniversalParam, probeDifferential, responseSimilarity } from '../src/server/surface-engine.ts'
import type { DifferentialProbeClass, DifferentialResult, ProbeDifferentialRequest, SurfaceParamLocation } from '../src/server/surface-engine.ts'
import type { Store } from '../src/server/store.ts'
import { mineBaselines, mineGraphqlQuery, mineJsonFieldValues, mineObservedIds, mineSeedQuery, mineXmlTemplate } from './benchmark-corpus.ts'
import type { Corpus } from './benchmark-corpus.ts'
import type { BenchmarkProfileMode } from './benchmark-core.ts'

export interface ProfileCaps {
  mode: BenchmarkProfileMode
  /** Phase-0 recon (spec/JS/HTML/GraphQL discovery) vs. plain wordlist probing. */
  phase0Recon: boolean
  locations: ReadonlySet<string>
  newProbeClasses: boolean
  sessionAndCsrf: boolean
  authMutation: boolean
  timeDiff: boolean
  inlineRetries: number
  tier: 2 | 3
}

export function profileCaps(mode: BenchmarkProfileMode): ProfileCaps {
  if (mode === 'v3-baseline') {
    return {
      mode, phase0Recon: false, locations: new Set(['query', 'json']), newProbeClasses: false,
      sessionAndCsrf: false, authMutation: false, timeDiff: false, inlineRetries: 0, tier: 2,
    }
  }
  return {
    mode, phase0Recon: true, locations: new Set(['query', 'json', 'form', 'path', 'header', 'xml', 'graphql_var']), newProbeClasses: true,
    sessionAndCsrf: true, authMutation: true, timeDiff: true, inlineRetries: 2, tier: 3,
  }
}

export interface DiscoveredParam { name: string; location: string; isObjectId: boolean; isCsrf: boolean }
export interface DiscoveredEndpoint { method: string; path: string; params: DiscoveredParam[]; source: string }

export type HypothesisClass = DifferentialProbeClass | 'race_burst' | 'dom_xss_url'
export interface Hypothesis {
  key: string
  endpoint: DiscoveredEndpoint
  probeClass: HypothesisClass
  param?: DiscoveredParam
  location?: SurfaceParamLocation
  /** Method used for the probe/replay (body locations imply a write method). */
  method: 'GET' | 'POST' | 'PUT' | 'PATCH'
  /** Plant on a write endpoint, then re-read listing/detail routes for stored reflection. */
  secondOrder?: boolean
  readPaths?: string[]
  /** GET page whose XSS probe may need DOM interaction through the persisted browser. */
  browserEligible?: boolean
  /** Write endpoint with a URL parameter: verify by re-triggering delivery afterwards. */
  secondOrderSsrf?: boolean
  /** Workflow step-skip: creator route and the body it expects. */
  createPath?: string
  quantityField?: string
  producerBody?: Record<string, unknown>
  /** Race: sibling producer route that mints a single-use value for the consume parameter. */
  raceProducerPath?: string
  /** Server action invoked through a framework RPC route with a positional/JSON body. */
  serverAction?: boolean
  /** Test URL-query-driven DOM sinks on a rendered page (no form interaction needed). */
  urlDomSink?: boolean
  /** Extend authz_matrix with a safe cross-tenant write + owner read-back for PATCH/PUT objects. */
  writePathRead?: boolean
}

export interface HypothesisPlan {
  hypotheses: Hypothesis[]
  /** Endpoint paths where a param was skipped because the profile cannot emit its encoding. */
  encodingSkips: Array<{ path: string; location: string }>
}

const idName = /(^|[_-])(id|uid|uuid|sku|slug|key|ref)$/i
const urlName = /(url|uri|link|callback|webhook|redirect|next|dest|target|feed|image|src|endpoint)/i
const accountPath = /(profile|account|\/me\b|settings|user|org|tenant|team|member)/i
// Union of the M7B and discovery vocabularies; discovery's ranking + cap still decides the shortlist.
const cacheablePath = /(cache|static|asset|public|catalog|account|profile|\/me\b|settings|dashboard|billing|home|page|news|docs|content|media|banner|promo|shop|store|product|comment|css|js|export|summary|landing|index)/i
const oauthPath = /(oauth|authorize|\/auth\b|openid|oidc|sso|login\/callback)/i
const xmlPath = /(xml|import|soap|upload|feed|sitemap|saml|parse|svg|rss|wsdl)/i
const graphqlPath = /graphql/i
const workflowPath = /(order|checkout|cart|payment|workflow|step|confirm|refund|invoice)/i
const authishPath = /(oauth|authorize|openid|token|jwt|auth|session|login|sso|well-known|partner|ledger|credential|apikey|api-key)/i
/** Routes whose mutating verb usually requires an elevated role/function (BFLA candidates). */
const privilegedPath = /(admin|internal|manage|staff|superuser|privileged|permission|feature[-_]?flag|backoffice)/i
/** Parameters that name a file or path handled by a download/export/serve route. */
const fileParam = /^(?:file|filename|filepath|file_name|name|path|download|export|doc|document|attachment|resource|target)$/i
/** Parameters that plausibly reach a shell/OS command interpreter. */
const shellParam = /(host|hostname|ip|addr|domain|target|cmd|command|exec|shell|run|ping|diag|lookup|resolve|nslookup|whois)/i
const shellPath = /(ping|diagnostic|exec|command|shell|health|resolve|lookup|whois|dns|system)/i
/** Single-use value parameters (voucher/coupon/token style) for race testing. */
const singleUseParam = /^(?:code|voucher|coupon|token|key|secret|invite|promo|gift|redeem|nonce|otp|passcode|ticket)$/i
/** Later-step workflow verbs (must not run before the prerequisite step). */
const actionStepPath = /(confirm|approve|complete|finalize|fulfil|ship|activate|publish|accept|settle)/i
const serverActionPath = /(?:^|\/)(?:_actions|_next\/action)\//i
const templateishParam = /(template|message|subject|body|content|text|comment|title|html|email|name|greeting|preview|render|note|snippet)/i
/**
 * OAuth/OIDC/session protocol control parameters are not user-data sinks; running injection
 * matrices over them only burns budget. They stay recorded as surface, just not as inject targets.
 */
const protocolParam = /^(?:client[_-]?id|client[_-]?secret|redirect[_-]?uri|response[_-]?type|grant[_-]?type|scope|state|nonce|code|code[_-]?challenge|code[_-]?challenge[_-]?method|audience|prompt|login[_-]?hint|access[_-]?token|refresh[_-]?token|id[_-]?token|assertion|signature|sig|continue|return_to)$/i
const placeholderSeg = /^(:[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\])$/
const maxInjectionParamsPerEndpoint = 8
const maxCacheEndpoints = 5
/** Cookie-authenticated state-change candidates (CSRF) and their observable read routes. */
const csrfActionPath = /(settings|profile|account|tenant|org|team|refund|job|trigger|approve|confirm|transfer|invite|subscribe|billing|payment|grant)/i
const csrfSkipPath = /(^|\/)(login|logout|2fa|csrf|token|session|oauth|authorize|callback|graphql)(\/|$)/i
/** Inbound webhook receiver routes (not management/list routes). */
const webhookReceiverPath = /(^|\/)(?:receive|receive-webhook|callback|callbacks|inbound|deliver|delivery|events)(\/|$)/i
/** Navigation/callback parameter names used by open-redirect sinks. */
const redirectParamName = /^(?:next|nextUrl|next_url|returnTo|return_to|returnUrl|return_url|redirect|redirectUri|redirect_uri|url|uri|continue|continueUrl|callback|callbackUrl|dest|destination|target|go)$/i
const redirectPathHint = /(sso|oauth|authorize|callback|redirect|return|login|logout|checkout|download|export|continue|resume)/i
const maxCsrfHypotheses = 6
const maxWebhookHypotheses = 4
const maxRedirectHypotheses = 10

/** True for concrete path segments that look like resource identifiers (not route words). */
export function looksLikeIdSegment(seg: string): boolean {
  // Prefixed ids are a short prefix + separator + a value that contains a digit (`p_acme_1`,
  // `ord_1234`, `inv-1001`). This deliberately rejects dashed route words such as
  // `openid-configuration` that parse as identifier-shaped without the digit requirement.
  return /^(?:[A-Za-z]{1,6}[-_][A-Za-z0-9_.:-]*\d[A-Za-z0-9_.:-]*|\d{2,}|[0-9a-f]{8}-[0-9a-f-]{8,}|\d+[A-Za-z][A-Za-z0-9]*)$/.test(seg)
}

export function hasPathPlaceholder(path: string): boolean {
  return path.split('/').some(seg => placeholderSeg.test(seg))
}

/** Replace path placeholders: the last one becomes `lastValue`, earlier ones become `otherValue`. */
export function fillPlaceholders(path: string, lastValue: string, otherValue = '1'): string {
  const segs = path.split('/')
  let last = -1
  segs.forEach((s, i) => { if (placeholderSeg.test(s)) last = i })
  return segs.map((s, i) => (placeholderSeg.test(s) ? (i === last ? lastValue : otherValue) : s)).join('/')
}

function writeMethod(ep: DiscoveredEndpoint): 'POST' | 'PUT' | 'PATCH' {
  const m = ep.method.toUpperCase()
  return m === 'PUT' || m === 'PATCH' ? m : 'POST'
}

function lastPathSegment(path: string): string {
  const parts = path.split('?')[0].split('/').filter(Boolean)
  return parts[parts.length - 1] ?? ''
}

/**
 * Observable GET route for a CSRF state change: the same route when it is also readable, otherwise
 * a parent resource route (an action verb such as `/trigger` is stripped).
 */
function csrfReadPathFor(path: string, getPaths: readonly string[]): string | null {
  if (getPaths.includes(path)) return path
  const segs = path.split('?')[0].split('/').filter(Boolean)
  if (segs.length < 2) return null
  const parent = `/${segs.slice(0, -1).join('/')}`
  if (getPaths.includes(parent)) return parent
  return null
}

/** Plausible navigation parameter names for a route shape (no app-specific literals). */
function redirectCandidateParams(path: string): string[] {
  const p = path.toLowerCase()
  if (/(sso|oauth|authorize|openid|login)/.test(p)) return ['next', 'returnTo', 'returnUrl']
  if (/(checkout|return)/.test(p)) return ['returnUrl', 'returnTo', 'redirect']
  if (/(download|export)/.test(p)) return ['url', 'returnTo', 'redirect']
  return ['url', 'next', 'redirect']
}

/**
 * Candidate read routes for a stored/second-order check, derived only from the discovered surface:
 * the same path as a GET, sibling GET routes with the same resource tail, and prefix-stripped variants
 * (e.g. a write at /api/comments surfaces on /comments). Prefers short, non-API routes.
 */
function secondOrderReadPaths(writePath: string, getPaths: readonly string[]): string[] {
  const tail = lastPathSegment(writePath)
  const out = new Set<string>()
  if (getPaths.includes(writePath)) out.add(writePath)
  if (tail) {
    for (const p of getPaths) {
      if (lastPathSegment(p) === tail) out.add(p)
    }
  }
  const segs = writePath.split('/').filter(Boolean)
  for (let drop = 1; drop < Math.min(3, segs.length); drop += 1) {
    const variant = `/${segs.slice(drop).join('/')}`
    if (getPaths.includes(variant)) out.add(variant)
  }
  return [...out]
    .filter(p => p !== writePath || getPaths.includes(p))
    .sort((a, b) => {
      const api = (p: string) => (/^\/api\//i.test(p) ? 1 : 0)
      return api(a) - api(b) || a.split('/').filter(Boolean).length - b.split('/').filter(Boolean).length || a.localeCompare(b)
    })
    .slice(0, 3)
}

export function formHypotheses(endpoints: readonly DiscoveredEndpoint[], caps: ProfileCaps): HypothesisPlan {
  const hypotheses: Hypothesis[] = []
  const encodingSkips: Array<{ path: string; location: string }> = []
  const seen = new Set<string>()
  const add = (h: Omit<Hypothesis, 'key'>) => {
    const key = `${h.probeClass}|${h.endpoint.method}|${h.endpoint.path}|${h.param?.name ?? ''}|${h.location ?? ''}`
    if (seen.has(key)) return
    seen.add(key)
    hypotheses.push({ ...h, key })
  }

  const getPaths = [...new Set(endpoints.filter(e => e.method.toUpperCase() === 'GET' || e.method.toUpperCase() === 'HEAD').map(e => e.path))]
  const writeProbeSeen = new Set<string>()
  const cacheCandidates: DiscoveredEndpoint[] = []
  let csrfHypotheses = 0
  let webhookHypotheses = 0
  let redirectHypotheses = 0

  for (const ep of endpoints) {
    const method = ep.method.toUpperCase()
    const isGet = method === 'GET' || method === 'HEAD'
    const pathHasPlaceholder = hasPathPlaceholder(ep.path)
    const params = ep.params.filter(p => !p.isCsrf && p.location !== 'cookie')
    const injectParams = params.filter(p => !protocolParam.test(p.name)).slice(0, maxInjectionParamsPerEndpoint)
    const readPaths = !isGet ? secondOrderReadPaths(ep.path, getPaths) : []
    const idParam = params.find(p => p.isObjectId || idName.test(p.name))
    // A write that carries an object id can surface the stored marker on any read page that renders a
    // resource: templated pages, and concrete pages whose path already contains an id segment
    // (e.g. a project activity page linked from the landing page).
    const idBearingRead = (p: string): boolean =>
      hasPathPlaceholder(p) || p.split('?')[0].split('/').some(s => s && looksLikeIdSegment(s))
    const templatedReads = !isGet && idParam
      ? getPaths.filter(p => idBearingRead(p) && !p.includes(ep.path.split('?')[0]) && !/\.(?:js|css|json|xml)$/i.test(p))
        .sort((a, b) => Number(/^\/api\//i.test(a)) - Number(/^\/api\//i.test(b)) || a.localeCompare(b))
        .slice(0, 3)
      : []
    const storedReads = [...new Set([...readPaths, ...templatedReads])].slice(0, 3)

    // Object-level authorization: id-bearing paths or id-named parameters. Framework RPC ids are
    // not resource identifiers, so placeholder action routes are handled by the server-action probe.
    if ((pathHasPlaceholder && !serverActionPath.test(ep.path)) || (idParam && idParam.location === 'query')) {
      add({
        endpoint: ep, probeClass: 'authz_matrix', method: isGet ? 'GET' : writeMethod(ep),
        ...(!isGet && (method === 'PATCH' || method === 'PUT') && pathHasPlaceholder ? { writePathRead: true } : {}),
      })
    }
    // Function-level authorization: a privileged mutating verb invoked by a lower-privilege actor.
    // Placeholder server-action ids (framework RPC ids that are not on the surface) cannot be invoked
    // meaningfully; only concrete action routes are probed.
    const concreteServerAction = serverActionPath.test(ep.path) && !pathHasPlaceholder
    if (caps.newProbeClasses && !isGet && (privilegedPath.test(ep.path) || concreteServerAction)) {
      add({ endpoint: ep, probeClass: 'authz_matrix', method: writeMethod(ep), ...(concreteServerAction ? { serverAction: true } : {}) })
    }

    for (const p of injectParams) {
      if (!caps.locations.has(p.location)) {
        encodingSkips.push({ path: ep.path, location: p.location })
        continue
      }
      const location = p.location as SurfaceParamLocation
      const pMethod: Hypothesis['method'] = location === 'query' || location === 'path' || location === 'header' ? (isGet ? 'GET' : writeMethod(ep)) : writeMethod(ep)
      add({ endpoint: ep, probeClass: 'sqli_boolean', param: p, location, method: pMethod })
      if (caps.timeDiff) add({ endpoint: ep, probeClass: 'sqli_time_diff', param: p, location, method: pMethod })
      if (location === 'xml' || xmlPath.test(ep.path)) {
        if (caps.newProbeClasses) add({ endpoint: ep, probeClass: 'xxe_canary', param: p, location, method: writeMethod(ep) })
      }
      if (caps.newProbeClasses && (shellParam.test(p.name) || shellPath.test(ep.path)) && !idName.test(p.name)) {
        add({ endpoint: ep, probeClass: 'command_injection', param: p, location, method: pMethod })
      }
      if (idName.test(p.name) || p.isObjectId) continue
      // Template evaluation only matters for text-ish sinks; probing every parameter burns budget.
      if (templateishParam.test(p.name) || (isGet && location === 'query' && p.name.length <= 12)) {
        add({ endpoint: ep, probeClass: 'ssti_math', param: p, location, method: pMethod })
      }
      if (caps.newProbeClasses) {
        add({
          endpoint: ep, probeClass: 'xss_context', param: p, location, method: pMethod,
          ...(!isGet && (location === 'json' || location === 'form' || location === 'xml') && storedReads.length > 0
            ? { secondOrder: true, readPaths: storedReads }
            : {}),
          ...(isGet && !pathHasPlaceholder && location === 'query' ? { browserEligible: true, urlDomSink: true } : {}),
        })
      }
      if (urlName.test(p.name)) {
        add({ endpoint: ep, probeClass: 'ssrf_canary', param: p, location, method: pMethod, ...(!isGet ? { secondOrderSsrf: true } : {}) })
      }
    }

    // Traversal needs a genuine file/path parameter; path-shape probing alone cannot prove a jail escape.
    const fileP = params.find(p => fileParam.test(p.name) && (p.location === 'query' || p.location === 'json' || p.location === 'form'))
    if (isGet && fileP && !hasPathPlaceholder(ep.path)) {
      add({ endpoint: ep, probeClass: 'path_traversal_benign', param: fileP, location: fileP.location as SurfaceParamLocation, method: 'GET' })
    }
    if (graphqlPath.test(ep.path) || ep.source === 'graphql') {
      const key = `graphql_audit|${ep.path}`
      if (!writeProbeSeen.has(key)) {
        writeProbeSeen.add(key)
        add({ endpoint: ep, probeClass: 'graphql_audit', method: 'POST' })
      }
    }
    // Step-skip: a later transition verb on an object id whose creator route is a sibling POST.
    if (!isGet && pathHasPlaceholder && actionStepPath.test(ep.path)) {
      const parent = ep.path.split('/').filter(Boolean)
        .slice(0, ep.path.split('/').filter(Boolean).findIndex(seg => placeholderSeg.test(seg)))
        .join('/')
      const creatorPath = `/${parent}`
      const creator = endpoints.find(e => e.method.toUpperCase() === 'POST' && e.path === creatorPath)
      if (creator) {
        const producerBody: Record<string, unknown> = {}
        for (const p of creator.params.filter(x => x.location === 'json' || x.location === 'form')) {
          producerBody[p.name] = p.isObjectId || idName.test(p.name) ? '1' : /(qty|quantity|count|amount|price|total)/i.test(p.name) ? 1 : 'guardian'
        }
        add({ endpoint: ep, probeClass: 'workflow_invariant', method: writeMethod(ep), createPath: creatorPath, producerBody })
      }
    }
    if (workflowPath.test(ep.path)) add({ endpoint: ep, probeClass: 'workflow_invariant', method: isGet ? 'GET' : writeMethod(ep) })
    // Race: a single-use value parameter consumed by this write. Prefer a sibling producer route.
    // Restrict to consumption semantics so credential/account writes are never raced.
    const raceablePath = /(redeem|claim|consume|spend|credit|voucher|coupon|apply|activate|transfer|withdraw|checkout|order|purchase|grant)/i
    if (!isGet && raceablePath.test(ep.path)) {
      const consume = params.find(p => singleUseParam.test(p.name) && (p.location === 'json' || p.location === 'form' || p.location === 'query'))
      if (consume) {
        const segs = ep.path.split('/').filter(Boolean)
        const parentPath = `/${segs.slice(0, -1).join('/')}`
        const siblings = endpoints.filter(e => e.method.toUpperCase() === 'POST' && e.path !== ep.path &&
          e.path.split('/').filter(Boolean).slice(0, -1).join('/') === segs.slice(0, -1).join('/'))
        const producer = siblings.find(e => /(voucher|coupon|mint|create|issue|generate|invite|token|credit|key)s?$/i.test(e.path)) ?? siblings[0]
        add({
          endpoint: ep, probeClass: 'race_burst', param: consume, location: consume.location as SurfaceParamLocation,
          method: writeMethod(ep), ...(producer ? { raceProducerPath: producer.path } : { raceProducerPath: parentPath }),
        })
      }
    }

    if (caps.newProbeClasses) {
      if (accountPath.test(ep.path) && !pathHasPlaceholder) {
        const key = `mass_assignment|${ep.path}|${writeMethod(ep)}`
        if (!writeProbeSeen.has(key)) {
          writeProbeSeen.add(key)
          add({ endpoint: ep, probeClass: 'mass_assignment', method: isGet ? 'PATCH' : writeMethod(ep) })
        }
      }
      // Cache probes: parameterless GETs plus cacheable GETs that carry query parameters (an
      // unkeyed query string is itself a deception/poisoning vector). Still bounded below.
      const paramlessGet = isGet && !pathHasPlaceholder && params.length === 0
      const cacheableGet = isGet && !pathHasPlaceholder && cacheablePath.test(ep.path)
      if ((paramlessGet || cacheableGet) && !graphqlPath.test(ep.path) && !/\.well-known\//i.test(ep.path)) {
        cacheCandidates.push(ep)
      }
      // JWT/OAuth protocol auditing only runs on auth-shaped routes; running it on every parameterless
      // GET burns a large fraction of the request budget with no new evidence.
      if (!pathHasPlaceholder && caps.authMutation && (isGet || method === 'POST') && (authishPath.test(ep.path) || oauthPath.test(ep.path))) {
        add({ endpoint: ep, probeClass: 'auth_protocol_audit', method: isGet ? 'GET' : 'POST' })
      }
      if (xmlPath.test(ep.path) && !isGet && !params.some(p => p.location === 'xml')) {
        add({ endpoint: ep, probeClass: 'xxe_canary', method: writeMethod(ep) })
      }

      // CSRF state-change: a session-authenticated mutation whose read route exposes the field.
      if (
        !isGet && method !== 'DELETE' && csrfHypotheses < maxCsrfHypotheses &&
        !serverActionPath.test(ep.path) && !csrfSkipPath.test(ep.path) && !graphqlPath.test(ep.path) &&
        csrfActionPath.test(ep.path)
      ) {
        const readPath = csrfReadPathFor(ep.path, getPaths)
        const hasCsrfParam = ep.params.some(p => p.isCsrf)
        const actionish = /(trigger|approve|confirm|transfer|invite|refund|redeem|accept|settings|profile)/i.test(ep.path)
        const stateBody = params.some(p =>
          (p.location === 'json' || p.location === 'form') &&
          /name|title|label|note|description|status|state|value|amount|tier|plan|enabled|active/i.test(p.name))
        if (readPath && (hasCsrfParam || actionish) && (hasCsrfParam || stateBody || actionish)) {
          add({ endpoint: ep, probeClass: 'csrf_state_change', method: writeMethod(ep) })
          csrfHypotheses += 1
        }
      }

      // Inbound webhook signature: receiver-shaped routes only (never management/list verbs).
      if (
        !isGet && method !== 'DELETE' && webhookHypotheses < maxWebhookHypotheses &&
        (webhookReceiverPath.test(lastPathSegment(ep.path)) || /webhook|callback/i.test(ep.path))
      ) {
        add({ endpoint: ep, probeClass: 'webhook_signature_bypass', method: writeMethod(ep) })
        webhookHypotheses += 1
      }

      // Open redirect: navigation-shaped GET routes plus any discovered URL-ish parameter.
      if (isGet && redirectHypotheses < maxRedirectHypotheses && (redirectPathHint.test(ep.path) || params.some(p => redirectParamName.test(p.name)))) {
        const discovered = params.filter(p => redirectParamName.test(p.name))
        const candidates = discovered.length > 0
          ? discovered
          : redirectCandidateParams(ep.path).map(name => ({ name, location: 'query', isObjectId: false, isCsrf: false }))
        for (const cand of candidates.slice(0, 3)) {
          if (redirectHypotheses >= maxRedirectHypotheses) break
          add({
            endpoint: ep, probeClass: 'open_redirect_differential',
            param: cand, location: cand.location as SurfaceParamLocation,
            method: cand.location === 'json' || cand.location === 'form' ? writeMethod(ep) : 'GET',
          })
          redirectHypotheses += 1
        }
      }
    }
  }

  if (caps.newProbeClasses) {
    // Cache probes are expensive (control + header matrix + victim verifies), so rank candidate
    // routes by cache-ish semantics and take a bounded top slice. Response cache headers are not
    // available at hypothesis-formation time, so this stays a heuristic.
    const ranked = [...cacheCandidates].sort((a, b) => {
      const score = (e: DiscoveredEndpoint) => (cacheablePath.test(e.path) ? 2 : 0) + (e.path.split('/').filter(Boolean).length >= 2 ? 1 : 0)
      return score(b) - score(a) || a.path.length - b.path.length || a.path.localeCompare(b.path)
    })
    for (const ep of ranked.slice(0, maxCacheEndpoints)) {
      add({ endpoint: ep, probeClass: 'cache_poison_deception', method: 'GET' })
    }
  }
  const prioritized = hypotheses
    .map((h, i) => ({ h, i }))
    .sort((a, b) => (a.h.probeClass === 'sqli_time_diff' ? 1 : 0) - (b.h.probeClass === 'sqli_time_diff' ? 1 : 0) || a.i - b.i)
    .map(x => x.h)
  return { hypotheses: prioritized, encodingSkips }
}

// ---------------------------------------------------------------------------
// Probe execution
// ---------------------------------------------------------------------------

export interface ProbeEnv {
  origin: string
  broker: RequestBroker
  grant: Grant
  canaryBroker?: CanaryBroker
  storage: Store
  runId: string
  assignmentId?: string
  signal: AbortSignal
  caps: ProfileCaps
  owner?: string
  other?: string
  admin?: string
  viewer?: string
  /** Persona handle whose credential is a 3-segment JWT (for broker authMutation). */
  jwtPersona?: string
  personaUserIds: string[]
  session: string
  slowProbesLeft: number
  corpus?: Corpus
  ctxCache?: Map<string, ResolvedContext>
  /** Session jar ids already primed for cookies/CSRF tokens in this run. */
  primedSessions?: Set<string>
  /** Remaining persisted-browser attempts (SPA/DOM XSS chains). */
  browserAttemptsLeft?: number
  /** Persona user ids used to interpret ownership in authz/GraphQL evidence. */
  ownerUserId?: string
  otherUserId?: string
  /** Cached identifier pools harvested from collection routes. */
  idCache?: Map<string, string[]>
  /** Endpoints discovered in this run (used to resolve body field values from the surface). */
  endpoints?: readonly DiscoveredEndpoint[]
  /** Cached GET-response field harvests keyed by path. */
  fieldCache?: Map<string, JsonHarvest>
}

/** Target-observed context (baseline value, XML/GraphQL shape, seed query) resolved for a hypothesis. */
export interface ResolvedContext { baseline?: string; xmlTemplate?: string; graphqlQuery?: string; seedQuery?: string }

export interface HypothesisOutcome {
  hyp: Hypothesis
  verdict: 'signal' | 'no_signal' | 'inconclusive' | 'error'
  anomalies: Array<Record<string, unknown>>
  details: Record<string, unknown>
  csrfRejected: boolean
  contextReset: boolean
  tierBlocked: boolean
  requests: number
  summary?: string
  error?: string
  ctx?: ResolvedContext
  /** Personas actually used for an authz_matrix probe (owner = privileged/control, other = probe). */
  pair?: { owner?: string; other?: string }
}

const csrfBody = /(csrf|xsrf|anti-?forgery|invalid token|token (missing|required|mismatch))/i
const sessionBody = /(session (expired|required|invalid|not found)|login required|please (log|sign) ?in|not authenticated|unauthenticated)/i

/**
 * Value for a sibling request field. Real APIs validate writes, so values are format-aware and prefer
 * values observed on the target's own surface; `guardian` is only the last resort for free text.
 */
export function siblingValue(name: string, env?: ProbeEnv): string | number | boolean {
  const lower = name.toLowerCase()
  if (/(?:^|_)(?:is|has)_|enabled|active|verified|admin|paid|approved|marketing|optin|boolean|flag$/.test(lower)) return true
  if (/(uuid|guid)/.test(lower)) return '00000000-0000-4000-8000-000000000001'
  if (/email/.test(lower)) return 'guardian@example.test'
  if (/(date|time|timestamp|_at)$/.test(lower)) return '2026-01-01T00:00:00Z'
  if (/(qty|quantity|count|limit|amount|price|total|number|num|page|size|offset|age)/.test(lower)) return 1
  if (/(url|uri|link|callback|webhook|redirect|target)$/.test(lower)) return 'http://guardian-control.invalid/'
  if (env?.corpus) {
    const mined = mineJsonFieldValues(env.corpus, name, 2)
    if (mined.length > 0) return mined[0]
  }
  if (idName.test(name) || /(id|uuid|key|ref|code|token)$/.test(lower)) {
    if (env?.corpus) {
      const ids = mineObservedIds(env.corpus, 4)
      if (ids.length > 0) return ids[0]
    }
    return '1'
  }
  return 'guardian'
}

function siblingBody(h: Hypothesis, env?: ProbeEnv): Record<string, unknown> | undefined {
  if (h.location !== 'json' && h.location !== 'form' && h.location !== 'graphql_var') return undefined
  const body: Record<string, unknown> = {}
  for (const p of h.endpoint.params) {
    if (p.name === h.param?.name || p.location !== h.location || p.isCsrf) continue
    body[p.name] = siblingValue(p.name, env)
  }
  return body
}

export function probePathFor(h: Hypothesis): string {
  if (h.location === 'path') return h.endpoint.path.replace(/\{[^}]+\}|:[A-Za-z0-9_]+|\[[^\]]+\]/, '{{val}}')
  return hasPathPlaceholder(h.endpoint.path) ? fillPlaceholders(h.endpoint.path, '1') : h.endpoint.path
}

export function needsCsrf(h: Hypothesis): boolean {
  return h.endpoint.params.some(p => p.isCsrf)
}

export function buildProbeRequest(h: Hypothesis, env: ProbeEnv, extras: Partial<ProbeDifferentialRequest> = {}): ProbeDifferentialRequest {
  const body = siblingBody(h, env)
  const req: ProbeDifferentialRequest = {
    probeClass: h.probeClass as DifferentialProbeClass,
    origin: env.origin,
    pathAndQuery: probePathFor(h),
    method: h.method,
    persona: env.owner,
    runId: env.runId,
    storage: env.storage,
    ...(env.assignmentId ? { assignmentId: env.assignmentId } : {}),
    ...(h.param ? { param: h.param.name, paramLocation: h.location } : {}),
    ...(h.param && h.location === 'json' && body ? { jsonBody: body } : {}),
    ...(h.param && h.location === 'form' && body ? { formBody: Object.fromEntries(Object.entries(body).map(([k, v]) => [k, String(v)])) } : {}),
    ...(h.param && h.location === 'graphql_var' && body ? { jsonBody: { variables: body } } : {}),
    ...(env.caps.sessionAndCsrf ? { session: env.session, csrfBind: needsCsrf(h) ? true : undefined } : {}),
    ...extras,
  }
  if (req.csrfBind === undefined) delete req.csrfBind
  return req
}

function idShaped(values: readonly string[]): string[] {
  return [...new Set(values)].filter(i => /^[A-Za-z0-9_.:-]{1,128}$/.test(i))
}

interface JsonHarvest { ids: string[]; fields: Map<string, string[]> }

/** Extract id-shaped scalars and named scalar fields from a JSON response. */
function harvestJson(body: string): JsonHarvest {
  const ids: string[] = []
  const fields = new Map<string, string[]>()
  let parsed: unknown
  try { parsed = JSON.parse(body) } catch { return { ids, fields } }
  const walk = (node: unknown, depth: number): void => {
    if (depth > 5 || !node) return
    if (Array.isArray(node)) { for (const item of node.slice(0, 40)) walk(item, depth + 1); return }
    if (typeof node !== 'object') return
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      if (typeof value === 'string' || typeof value === 'number') {
        const s = String(value)
        if (/(?:^|_)(?:id|uuid|uid|sku|slug|key|ref|code|token)$/i.test(key) && s.length <= 128 && s.length > 0) ids.push(s)
        const bucket = fields.get(key) ?? []
        if (bucket.length < 6) bucket.push(s)
        fields.set(key, bucket)
      } else if (value && typeof value === 'object') {
        walk(value, depth + 1)
      }
    }
  }
  walk(parsed, 0)
  return { ids: idShaped(ids), fields }
}

/**
 * Identifier pool for object-level probes: personas, values observed on the target's own surface, and
 * ids read back from the sibling collection route (`/api/v1/invoices/{id}` -> GET `/api/v1/invoices`).
 * Collection responses are fetched once per route and cached for the run.
 */
export async function idPool(env: ProbeEnv, pathTemplate?: string): Promise<string[]> {
  const cache = (env.idCache ??= new Map())
  // Interleave raw persona ids with their numeric suffixes: some routes key on the user id
  // (user-1001) and others on the numeric object id (1001), and the id matrix is bounded.
  const derived = env.personaUserIds
    .map(id => id.replace(/^[A-Za-z]+[-_]/, ''))
    .filter((id, i) => id.length > 0 && id !== env.personaUserIds[i])
  const interleaved: string[] = []
  for (let i = 0; i < Math.max(env.personaUserIds.length, derived.length); i += 1) {
    if (env.personaUserIds[i]) interleaved.push(env.personaUserIds[i])
    if (derived[i]) interleaved.push(derived[i])
  }
  const seeds = [...interleaved, ...(env.corpus ? mineObservedIds(env.corpus) : [])]
  const collection = pathTemplate
    ? (() => {
        const segs = pathTemplate.split('?')[0].split('/').filter(Boolean)
        const idx = segs.findIndex(seg => placeholderSeg.test(seg))
        return idx > 0 ? `/${segs.slice(0, idx).join('/')}` : null
      })()
    : null
  if (collection) {
    let harvested = cache.get(collection)
    if (!harvested) {
      harvested = []
      try {
        const ex = await env.broker.executeHttp({
          origin: env.origin, method: 'GET', pathAndQuery: collection, persona: env.owner,
          followRedirects: false, timeoutMs: 8_000,
        }, env.grant, env.signal)
        if (ex.status >= 200 && ex.status < 300) harvested = harvestJson(ex.body).ids
      } catch { /* collection may not exist */ }
      cache.set(collection, harvested)
    }
    seeds.unshift(...harvested)
  }
  return idShaped([...seeds, '1', '2', '3']).slice(0, 12)
}

/** Plausible value for a request field, derived from its name and (optionally) observed data. */
function semanticValue(name: string, env: ProbeEnv, observed?: string[]): string | number | boolean {
  if (observed && observed.length > 0) return observed[0]
  const lower = name.toLowerCase()
  if (/(?:^|_)(?:is|has)_|enabled|active|verified|admin|paid|approved|marketing|optin|boolean/.test(lower)) return true
  if (/(qty|quantity|count|limit|amount|price|total|number|num|page|size|offset|age)/.test(lower)) return 1
  if (/email/.test(lower)) return 'guardian@example.test'
  if (/(url|uri|link|callback|webhook|redirect)/.test(lower)) return 'http://guardian-control.invalid/'
  if (/(date|time|timestamp|at)$/.test(lower)) return '2026-01-01T00:00:00Z'
  if (/(id|ref|key|code|token)$/.test(lower)) {
    if (env.corpus) {
      const mined = mineJsonFieldValues(env.corpus, name, 2)
      if (mined.length > 0) return mined[0]
      const observed = mineObservedIds(env.corpus, 6)
      if (observed.length > 0) return observed[0]
    }
    return '1'
  }
  if (env.corpus) {
    const mined = mineJsonFieldValues(env.corpus, name, 2)
    if (mined.length > 0) return mined[0]
  }
  return 'guardian'
}

/**
 * Body for a write probe, using the endpoint's declared fields. Nested dotted names are expanded so
 * `filter.name` becomes `{ filter: { name } }`.
 */
function writeBodyFor(ep: DiscoveredEndpoint, env: ProbeEnv, location: 'json' | 'form'): Record<string, unknown> {
  const body: Record<string, unknown> = {}
  for (const p of ep.params) {
    if (p.isCsrf || p.location !== location) continue
    const value = semanticValue(p.name, env)
    const parts = p.name.split('.')
    let cur = body
    for (let i = 0; i < parts.length - 1; i += 1) {
      const next = cur[parts[i]]
      if (!next || typeof next !== 'object' || Array.isArray(next)) cur[parts[i]] = {}
      cur = cur[parts[i]] as Record<string, unknown>
    }
    cur[parts[parts.length - 1]] = value
  }
  return body
}

/**
 * Server-action request body. Client bundles invoke actions either positionally (`[orgId, plan]`) or
 * with a keyed object. Field names come from the action name tokens, values from the target's own
 * surface (id-bearing GET routes and their responses).
 */
/** Resolve a token like `org` to a real value read from a matching id-bearing GET route. */
async function surfaceValueFor(token: string, env: ProbeEnv): Promise<string | null> {
  const cache = (env.fieldCache ??= new Map())
  const candidates = (env.endpoints ?? []).filter(e =>
    e.method.toUpperCase() === 'GET' && !hasPathPlaceholder(e.path) && new RegExp(`(?:^|[/_-])${token}(?:$|[/_-])`, 'i').test(e.path),
  ).slice(0, 2)
  for (const ep of candidates) {
    let harvest = cache.get(ep.path)
    if (!harvest) {
      try {
        const ex = await env.broker.executeHttp({
          origin: env.origin, method: 'GET', pathAndQuery: ep.path, persona: env.owner, followRedirects: false, timeoutMs: 8_000,
        }, env.grant, env.signal)
        harvest = ex.status >= 200 && ex.status < 300 ? harvestJson(ex.body) : { ids: [], fields: new Map() }
      } catch {
        harvest = { ids: [], fields: new Map() }
      }
      cache.set(ep.path, harvest)
    }
    const named = harvest.fields.get('id')?.[0] ?? harvest.fields.get(token)?.[0]
    if (named) return named
  }
  return null
}

async function serverActionBodies(h: Hypothesis, env: ProbeEnv): Promise<unknown[]> {
  const tokens = lastPathSegment(h.endpoint.path).replace(/([a-z0-9])([A-Z])/g, '$1 $2').split(/[^A-Za-z0-9]+/)
    .filter(t => t.length > 1 && !/^(update|create|make|set|get|do|handle|save|change|toggle|the|for|with)$/i.test(t))
  const fields = tokens.map(t => t.toLowerCase())
  const positional: unknown[] = []
  const objectBody: Record<string, unknown> = {}
  for (const token of fields.slice(0, 4)) {
    let value: string | number | boolean = 'guardian'
    if (/(org|tenant|team|group|account|company|workspace)/i.test(token)) {
      value = (await surfaceValueFor(token, env)) ?? (await idPool(env))[0] ?? '1'
    } else if (/(plan|tier)/i.test(token)) {
      value = (await surfaceValueFor(token, env)) ?? 'guardian'
    } else if (/(id|ref|key)$/i.test(token)) {
      value = (await idPool(env))[0] ?? '1'
    }
    positional.push(value)
    objectBody[token] = value
    objectBody[`${token}Id`] = value
  }
  return [positional, objectBody]
}

export async function authzRequest(h: Hypothesis, env: ProbeEnv, owner = env.owner, other = env.other): Promise<ProbeDifferentialRequest> {
  const idSlot = hasPathPlaceholder(h.endpoint.path)
  const idParam = h.endpoint.params.find(p => (p.isObjectId || idName.test(p.name)) && p.location === 'query')
  const functionLevel = !idSlot && !idParam
  const pathAndQuery = idSlot
    ? fillPlaceholders(h.endpoint.path, '{{id}}')
    : idParam
      ? `${h.endpoint.path}?${idParam.name}={{id}}`
      : h.endpoint.path
  const mutating = h.method !== 'GET'
  let functionBody: unknown
  if (functionLevel && mutating) {
    if (h.serverAction) {
      functionBody = (await serverActionBodies(h, env))[0]
    } else {
      const jsonLoc = h.endpoint.params.some(p => p.location === 'json')
      functionBody = jsonLoc ? writeBodyFor(h.endpoint, env, 'json') : (() => {
        const form = writeBodyFor(h.endpoint, env, 'form')
        return Object.keys(form).length > 0 ? form : {}
      })()
    }
  }
  const requestBody = functionLevel ? undefined : (mutating ? writeBodyFor(h.endpoint, env, 'json') : undefined)
  return {
    probeClass: 'authz_matrix',
    origin: env.origin,
    pathAndQuery,
    method: mutating ? h.method : 'GET',
    persona: owner,
    ownerPersona: owner,
    otherPersona: other,
    includeAnonymous: true,
    includeHeaderBypass: false,
    resourceIds: functionLevel ? [''] : await idPool(env, h.endpoint.path),
    ...(functionBody !== undefined ? { functionBody } : {}),
    ...(requestBody && Object.keys(requestBody).length > 0 ? { jsonBody: requestBody } : {}),
    runId: env.runId,
    storage: env.storage,
    ...(env.caps.sessionAndCsrf ? { session: env.session } : {}),
  }
}

const sqliClasses = new Set<string>(['sqli_boolean', 'sqli_time_diff'])

async function resolveContext(h: Hypothesis, env: ProbeEnv): Promise<ResolvedContext> {
  const cache = (env.ctxCache ??= new Map())
  // Probe class is part of the key: different classes on the same endpoint need different context
  // (e.g. a path-traversal pass must not pre-populate an empty context for the auth-protocol pass).
  const key = `${h.probeClass}|${h.endpoint.method}|${h.endpoint.path}|${h.param?.name ?? ''}|${h.location ?? ''}`
  const hit = cache.get(key)
  if (hit) return hit
  const ctx: ResolvedContext = {}
  cache.set(key, ctx)
  const corpus = env.corpus
  if (!corpus) return ctx
  if (h.param && h.location === 'xml') ctx.xmlTemplate = mineXmlTemplate(corpus, h.param.name) ?? undefined
  if (h.param && h.location === 'graphql_var') ctx.graphqlQuery = mineGraphqlQuery(corpus, h.param.name) ?? undefined
  if (h.probeClass === 'auth_protocol_audit') {
    // OAuth/OIDC authorize URLs are discovered as links/JS literals; the query seed carries the
    // registered client_id/redirect_uri/scope the endpoint actually expects.
    const seed = mineSeedQuery(corpus, h.endpoint.path.split('?')[0])
    if (seed) ctx.seedQuery = seed
  }
  if (h.param && sqliClasses.has(h.probeClass)) {
    const candidates = mineBaselines(corpus, h.param.name, h.endpoint.path).slice(0, 5)
    if (candidates.length > 0) {
      const body = siblingBody(h, env)
      const send = async (value: string): Promise<BrokerExchangeResult | null> => {
        try {
          const inj = injectUniversalParam({
            pathAndQuery: probePathFor(h), param: h.param!.name, paramLocation: h.location!, value, method: h.method,
            ...(h.location === 'json' && body ? { jsonBody: body } : {}),
            ...(h.location === 'form' && body ? { formBody: Object.fromEntries(Object.entries(body).map(([k, v]) => [k, String(v)])) } : {}),
            ...(h.location === 'graphql_var' ? { jsonBody: { variables: body ?? {} } } : {}),
            ...(ctx.xmlTemplate ? { xmlTemplate: ctx.xmlTemplate } : {}),
            ...(ctx.graphqlQuery ? { graphqlQuery: ctx.graphqlQuery } : {}),
            ...(env.caps.sessionAndCsrf ? { session: env.session, csrfBind: needsCsrf(h) ? true : undefined } : {}),
          })
          return await env.broker.executeHttp({ origin: env.origin, persona: env.owner, followRedirects: false, ...inj }, env.grant, env.signal)
        } catch { return null }
      }
      const bogus = await send('zzguardianzz')
      for (const value of candidates) {
        const ex = await send(value)
        if (!ex || ex.status >= 500) continue
        if (!bogus || ex.status !== bogus.status || responseSimilarity(ex.body, bogus.body) < 0.9) { ctx.baseline = value; break }
      }
    }
  }
  return ctx
}

function shortToken(chars = 8): string {
  return Math.random().toString(36).slice(2, 2 + chars)
}

interface RawSendOptions {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH'
  pathAndQuery: string
  body?: string
  headers?: Record<string, string>
  persona?: string
  session?: string
  csrfBind?: boolean
}

/** Broker-routed raw request used by multi-step (second-order / browser) checks. */
async function sendRaw(env: ProbeEnv, req: RawSendOptions): Promise<BrokerExchangeResult | null> {
  try {
    return await env.broker.executeHttp({
      origin: env.origin,
      method: req.method,
      pathAndQuery: req.pathAndQuery,
      ...(req.body !== undefined ? { body: req.body } : {}),
      ...(req.headers ? { headers: req.headers } : {}),
      ...(req.persona ? { persona: req.persona } : {}),
      ...(req.session ? { session: req.session } : {}),
      ...(req.csrfBind ? { csrfBind: true } : {}),
      ...(env.runId ? { runId: env.runId } : {}),
      ...(env.assignmentId ? { assignmentId: env.assignmentId } : {}),
      followRedirects: false,
      timeoutMs: 8_000,
    }, env.grant, env.signal)
  } catch {
    return null
  }
}

/**
 * CSRF/session priming: fetch the entry page (and the GET-able target) through the same broker session
 * jar before the first write probe, so Set-Cookie and hidden/meta/JSON CSRF tokens are bound.
 */
async function primeSessionOnce(h: Hypothesis, env: ProbeEnv): Promise<number> {
  if (!env.caps.sessionAndCsrf) return 0
  env.primedSessions ??= new Set<string>()
  if (env.primedSessions.has(env.session)) return 0
  env.primedSessions.add(env.session)
  const paths = new Set<string>(['/'])
  if (h.method === 'GET') paths.add(h.endpoint.path)
  let sent = 0
  for (const p of paths) {
    if (env.signal.aborted) break
    const ex = await sendRaw(env, {
      method: 'GET', pathAndQuery: p,
      persona: env.owner, session: env.session, csrfBind: needsCsrf(h),
    })
    if (ex) sent += 1
  }
  return sent
}

interface MultiStepResult {
  hit: boolean
  anomalies: Array<Record<string, unknown>>
  details: Record<string, unknown>
  requests: number
  summary?: string
}

/** Plant a marker through the write endpoint, then re-read candidate listing/detail routes. */
async function runSecondOrderCheck(
  h: Hypothesis,
  env: ProbeEnv,
  watch: (ex: BrokerExchangeResult) => void,
): Promise<MultiStepResult> {
  const result: MultiStepResult = { hit: false, anomalies: [], details: {}, requests: 0 }
  const param = h.param
  if (!param || !h.location || !h.readPaths?.length) return result
  const marker = `gxss${shortToken(8)}`
  const payload = `${marker}"'<b>`
  const body = h.location === 'json' ? writeBodyFor(h.endpoint, env, 'json') : h.location === 'form' ? writeBodyFor(h.endpoint, env, 'form') : siblingBody(h, env)
  const injected = injectUniversalParam({
    pathAndQuery: probePathFor(h),
    param: param.name,
    paramLocation: h.location,
    value: payload,
    method: h.method,
    jsonBody: h.location === 'json' ? body : undefined,
    formBody: h.location === 'form' ? Object.fromEntries(Object.entries(body ?? {}).map(([k, v]) => [k, String(v)])) : undefined,
    session: env.caps.sessionAndCsrf ? env.session : undefined,
    csrfBind: env.caps.sessionAndCsrf && needsCsrf(h) ? true : undefined,
    runId: env.runId,
    ...(env.assignmentId ? { assignmentId: env.assignmentId } : {}),
  })
  const writeEx = await sendRaw(env, {
    method: (injected.method === 'GET' ? 'POST' : injected.method) as RawSendOptions['method'],
    pathAndQuery: injected.pathAndQuery,
    ...(injected.body !== undefined ? { body: injected.body } : {}),
    ...(injected.headers ? { headers: injected.headers } : {}),
    persona: env.owner,
    ...(injected.session ? { session: injected.session } : {}),
    ...(injected.csrfBind ? { csrfBind: true } : {}),
  })
  result.requests += 1
  if (writeEx) watch(writeEx)
  result.details.writeStatus = writeEx?.status ?? null

  const reads: Array<Record<string, unknown>> = []
  const reflectedOnly: Array<Record<string, unknown>> = []
  // Templated read pages are filled with ids observed on the surface (and the value used for an
  // id-bearing write field), so a stored marker is looked up on the object it was attached to.
  const fillIds = [
    ...h.endpoint.params.filter(p => idName.test(p.name) && body && typeof body[p.name] === 'string').map(p => String(body![p.name])),
    ...(await idPool(env)),
  ]
  const readTargets: string[] = []
  for (const rp of h.readPaths.slice(0, 3)) {
    if (hasPathPlaceholder(rp)) {
      for (const idv of [...new Set(fillIds)].slice(0, 3)) readTargets.push(fillPlaceholders(rp, encodeURIComponent(idv)))
      continue
    }
    const segs = rp.split('?')[0].split('/')
    const idIdx = segs.findIndex(s => s && looksLikeIdSegment(s))
    if (idIdx < 0) { readTargets.push(rp); continue }
    // Prefer the value the write actually used, then other observed ids.
    const orderedIds = [...new Set([...fillIds.filter(v => v === segs[idIdx]), ...fillIds])].slice(0, 3)
    for (const idv of orderedIds) {
      const next = [...segs]
      next[idIdx] = encodeURIComponent(idv)
      readTargets.push(next.join('/') + (rp.includes('?') ? `?${rp.split('?')[1]}` : ''))
    }
  }
  for (const readPath of readTargets.slice(0, 4)) {
    if (env.signal.aborted) break
    const readEx = await sendRaw(env, {
      method: 'GET', pathAndQuery: readPath,
      persona: env.owner,
      session: env.caps.sessionAndCsrf ? env.session : undefined,
    })
    result.requests += 1
    if (!readEx) continue
    watch(readEx)
    const analysis = analyzeXssReflection(readEx.body, readEx.mediaType, marker)
    reads.push({
      readPath, status: readEx.status, reflected: analysis.reflected,
      context: analysis.context, unencodedChars: analysis.unencodedChars,
      mediaType: analysis.mediaType, exploitable: analysis.exploitable,
    })
    if (analysis.exploitable) {
      result.hit = true
      result.anomalies.push({
        type: 'second_order_xss',
        plantPath: h.endpoint.path,
        plantParam: param.name,
        plantLocation: h.location,
        readPath,
        context: analysis.context,
        unencodedChars: analysis.unencodedChars,
        mediaType: analysis.mediaType,
        suggestedReplayKind: 'http_chain',
      })
      break
    }
    if (analysis.reflected) {
      reflectedOnly.push({ readPath, context: analysis.context, mediaType: analysis.mediaType })
    }
  }
  result.details.reads = reads
  if (!result.hit && reflectedOnly.length > 0) result.details.storedReflection = reflectedOnly
  return result
}

/**
 * Persisted-browser fallback for DOM XSS: only launched when the rendered page actually contains a
 * DOM sink plus fillable controls, then fill + click through the page's own handlers while the sink
 * hook watches for the canary. Uses the existing ScopedBrowser backend.
 */
async function runBrowserChainCheck(
  h: Hypothesis,
  env: ProbeEnv,
  watch: (ex: BrokerExchangeResult) => void,
): Promise<MultiStepResult> {
  const result: MultiStepResult = { hit: false, anomalies: [], details: {}, requests: 0 }
  if ((env.browserAttemptsLeft ?? 3) <= 0) {
    result.details.skipped = 'browser_budget'
    return result
  }
  const pageEx = await sendRaw(env, {
    method: 'GET', pathAndQuery: h.endpoint.path,
    persona: env.owner,
    session: env.caps.sessionAndCsrf ? env.session : undefined,
  })
  result.requests += 1
  if (!pageEx) return result
  watch(pageEx)
  const html = pageEx.body
  if (!/<input\b/i.test(html) || !/<button\b[^>]*\bid\s*=/i.test(html) || !/\b(?:innerHTML|outerHTML|document\.write)\b/i.test(html)) {
    result.details.skipped = 'not_interactive_dom'
    return result
  }
  const attr = (attrs: string, name: string): string | null => {
    const m = new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(attrs)
    return (m?.[1] ?? m?.[2] ?? m?.[3] ?? null)
  }
  const marker = `gxss${shortToken(8)}`
  const fillValue = `${marker}<b>`
  const fills: Array<{ type: 'fill'; selector: string; value: string }> = []
  for (const m of html.matchAll(/<input\b([^>]*)>/gi)) {
    const attrs = m[1]
    const type = (attr(attrs, 'type') ?? '').toLowerCase()
    if (/^(?:hidden|submit|button|reset|checkbox|radio|file|image)$/.test(type)) continue
    const id = attr(attrs, 'id')
    const name = attr(attrs, 'name')
    const selector = id ? `#${id.trim()}` : name ? `[name="${name.trim()}"]` : null
    if (!selector) continue
    fills.push({ type: 'fill', selector, value: fillValue })
    if (fills.length >= 2) break
  }
  const clicks: Array<{ type: 'click'; selector: string }> = []
  for (const m of html.matchAll(/<button\b([^>]*)>/gi)) {
    const id = attr(m[1], 'id')
    if (id) clicks.push({ type: 'click', selector: `#${id.trim()}` })
    if (clicks.length >= 4) break
  }
  if (fills.length === 0 || clicks.length === 0) {
    result.details.skipped = 'no_actions'
    return result
  }
  env.browserAttemptsLeft = (env.browserAttemptsLeft ?? 3) - 1
  try {
    const { ScopedBrowser } = await import('../src/server/scoped-browser.ts')
    const browser = new ScopedBrowser(env.broker, { storage: env.storage })
    const visit = await browser.visitPage({
      origin: env.origin,
      pathAndQuery: h.endpoint.path,
      persona: env.owner,
      ...(env.caps.sessionAndCsrf ? { session: env.session } : {}),
      ...(env.runId ? { runId: env.runId } : {}),
      ...(env.assignmentId ? { assignmentId: env.assignmentId } : {}),
      canaryToken: marker,
      enableSinkHook: true,
      checkKind: 'dom_xss',
      actions: [...fills, ...clicks],
      waitAfterLoadMs: 800,
      timeoutMs: 20_000,
    }, env.grant, AbortSignal.any([env.signal, AbortSignal.timeout(25_000)]))
    result.requests += visit.exchanges.length
    for (const ex of visit.exchanges) watch(ex)
    const sinkHit = visit.domSinkTraces.find(t => t.containsCanary)
    result.details = {
      actions: [...fills.map(f => `fill ${f.selector}`), ...clicks.map(c => `click ${c.selector}`)],
      canaryTriggered: visit.canaryCheck.triggered,
      canaryDetail: visit.canaryCheck.detail,
      sink: sinkHit?.sink ?? null,
      sinkPreview: sinkHit?.preview?.slice(0, 160) ?? null,
    }
    if (visit.canaryCheck.triggered || sinkHit) {
      result.hit = true
      result.anomalies.push({
        type: 'dom_xss_sink',
        path: h.endpoint.path,
        sink: sinkHit?.sink ?? 'dom',
        actions: result.details.actions,
        canaryTriggered: true,
        suggestedReplayKind: 'browser_chain',
      })
    }
  } catch (err) {
    result.details.browserError = err instanceof Error ? err.message.slice(0, 200) : String(err)
  }
  return result
}

/**
 * Race/TOCTOU check: mint a single-use value from the sibling producer, then fire the consumer
 * concurrently. Multiple 2xx acceptances for one stored value prove a check-then-act window.
 */
async function runRaceCheck(h: Hypothesis, env: ProbeEnv, watch: (ex: BrokerExchangeResult) => void): Promise<MultiStepResult> {
  const result: MultiStepResult = { hit: false, anomalies: [], details: {}, requests: 0 }
  const param = h.param
  const producerPath = h.raceProducerPath
  if (!param || !producerPath) return result
  const consumeBody = (value: string): Record<string, unknown> => {
    const body: Record<string, unknown> = {}
    for (const p of h.endpoint.params) {
      if (p.isCsrf) continue
      body[p.name] = p.name === param.name ? value : semanticValue(p.name, env)
    }
    if (!(param.name in body)) body[param.name] = value
    return body
  }
  const mint = async (): Promise<{ code: string; value: number } | null> => {
    const ex = await sendRaw(env, {
      method: 'POST', pathAndQuery: producerPath, body: '{}',
      headers: { 'Content-Type': 'application/json' }, persona: env.owner,
      session: env.caps.sessionAndCsrf ? env.session : undefined,
    })
    result.requests += 1
    if (!ex) return null
    watch(ex)
    const harvest = harvestJson(ex.body)
    const code = harvest.fields.get(param.name)?.[0] ?? harvest.ids[0]
    if (!code) return null
    const value = Number(harvest.fields.get('value')?.[0] ?? harvest.fields.get('amount')?.[0] ?? 0)
    return { code, value: Number.isFinite(value) ? value : 0 }
  }
  // Validate the happy path once so a burst failure is not misread as "no race".
  const single = await mint()
  if (!single) { result.details.skipped = 'producer_unavailable'; return result }
  const singleEx = await sendRaw(env, {
    method: h.method, pathAndQuery: probePathFor(h), body: JSON.stringify(consumeBody(single.code)),
    headers: { 'Content-Type': 'application/json' }, persona: env.owner,
    session: env.caps.sessionAndCsrf ? env.session : undefined,
  })
  result.requests += 1
  if (singleEx) watch(singleEx)
  result.details.singleStatus = singleEx?.status ?? null
  if (!singleEx || singleEx.status < 200 || singleEx.status >= 300) {
    result.details.skipped = 'consume_baseline_failed'
    return result
  }
  const target = await mint()
  if (!target) { result.details.skipped = 'producer_unavailable'; return result }
  const parent = `/${h.endpoint.path.split('/').filter(Boolean).slice(0, -1).join('/')}`
  const balanceBefore = await sendRaw(env, { method: 'GET', pathAndQuery: parent, persona: env.owner, session: env.caps.sessionAndCsrf ? env.session : undefined })
  result.requests += 1
  if (balanceBefore) watch(balanceBefore)
  const burstSize = 4
  const burstReqs = Array.from({ length: burstSize }, () => ({
    origin: env.origin, method: h.method, pathAndQuery: probePathFor(h),
    headers: { 'Content-Type': 'application/json' }, persona: env.owner,
    ...(env.caps.sessionAndCsrf ? { session: env.session } : {}),
    body: JSON.stringify(consumeBody(target.code)),
  }))
  let statuses: number[] = []
  try {
    const burst = await env.broker.executeRaceBurst(burstReqs, env.grant, env.signal)
    statuses = burst.results.map(r => r.status)
    for (const ex of burst.results) watch(ex)
    result.requests += burst.results.length
  } catch (err) {
    result.details.burstError = err instanceof Error ? err.message.slice(0, 160) : String(err)
    return result
  }
  const successes = statuses.filter(s => s >= 200 && s < 300).length
  const balanceAfter = await sendRaw(env, { method: 'GET', pathAndQuery: parent, persona: env.owner, session: env.caps.sessionAndCsrf ? env.session : undefined })
  result.requests += 1
  if (balanceAfter) watch(balanceAfter)
  const balanceOf = (ex: BrokerExchangeResult | null): number | null => {
    if (!ex) return null
    const fields = harvestJson(ex.body).fields
    for (const key of ['balance', 'credits', 'total', 'count']) {
      const v = Number(fields.get(key)?.[0])
      if (Number.isFinite(v)) return v
    }
    return null
  }
  const before = balanceOf(balanceBefore)
  const after = balanceOf(balanceAfter)
  result.details = {
    ...result.details, burstSize, statuses, successes, value: target.value,
    balanceBefore: before, balanceAfter: after, parentPath: parent, producerPath,
  }
  if (successes >= 2) {
    result.hit = true
    result.anomalies.push({
      type: 'race_double_spend', path: probePathFor(h), producerPath, param: param.name,
      consumeBody: consumeBody('{{code}}'), successes, statuses, burstSize,
      value: target.value, balanceBefore: before, balanceAfter: after,
      suggestedReplayKind: 'race_burst',
    })
  }
  return result
}

/** URL-query-driven DOM sink: source in location.* flowing into an executable sink in page scripts. */
async function runUrlDomSinkCheck(h: Hypothesis, env: ProbeEnv, watch: (ex: BrokerExchangeResult) => void): Promise<MultiStepResult> {
  const result: MultiStepResult = { hit: false, anomalies: [], details: {}, requests: 0 }
  if ((env.browserAttemptsLeft ?? 3) <= 0) { result.details.skipped = 'browser_budget'; return result }
  const pageEx = await sendRaw(env, { method: 'GET', pathAndQuery: h.endpoint.path, persona: env.owner, session: env.caps.sessionAndCsrf ? env.session : undefined })
  result.requests += 1
  if (!pageEx || pageEx.status >= 400) return result
  watch(pageEx)
  const html = pageEx.body
  const scriptBodies: string[] = []
  for (const m of html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)) {
    const src = m[1]
    if (!src.startsWith('/') || scriptBodies.length >= 3) continue
    const ex = await sendRaw(env, { method: 'GET', pathAndQuery: src, persona: env.owner })
    result.requests += 1
    if (ex) { watch(ex); scriptBodies.push(ex.body) }
  }
  for (const m of html.matchAll(/<script\b[^>]*>([\s\S]{0,20000}?)<\/script>/gi)) scriptBodies.push(m[1])
  const combined = scriptBodies.join('\n')
  const source = /location\.(?:search|hash)|document\.(?:URL|documentURI|referrer)|URLSearchParams\s*\(\s*(?:window\.)?location/i.test(combined)
  const sink = /\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write|eval\s*\(|new\s+Function\s*\(/.test(combined)
  if (!source || !sink) { result.details.skipped = 'no_url_sink_flow'; return result }
  const paramName = /URLSearchParams\s*\([^)]*\)\s*\.\s*get\s*\(\s*['"]([^'"]+)['"]/.exec(combined)?.[1] ?? h.param?.name ?? 'q'
  if (!/^[A-Za-z_][A-Za-z0-9_.-]{0,40}$/.test(paramName)) { result.details.skipped = 'no_param_name'; return result }
  const marker = `gxss${shortToken(8)}`
  const payload = `<img src=x onerror="document.title='${marker}'">`
  const url = new URL(`${h.endpoint.path}${h.endpoint.path.includes('?') ? '&' : '?'}${encodeURIComponent(paramName)}=${encodeURIComponent(payload)}`, env.origin)
  env.browserAttemptsLeft = (env.browserAttemptsLeft ?? 3) - 1
  try {
    const { ScopedBrowser } = await import('../src/server/scoped-browser.ts')
    const browser = new ScopedBrowser(env.broker, { storage: env.storage })
    const visit = await browser.visitPage({
      origin: env.origin,
      pathAndQuery: url.pathname + url.search,
      persona: env.owner,
      ...(env.caps.sessionAndCsrf ? { session: env.session } : {}),
      ...(env.runId ? { runId: env.runId } : {}),
      ...(env.assignmentId ? { assignmentId: env.assignmentId } : {}),
      canaryToken: marker,
      enableSinkHook: true,
      checkKind: 'dom_xss',
      waitAfterLoadMs: 900,
      timeoutMs: 20_000,
    }, env.grant, AbortSignal.any([env.signal, AbortSignal.timeout(25_000)]))
    result.requests += visit.exchanges.length
    for (const ex of visit.exchanges) watch(ex)
    const sinkHit = visit.domSinkTraces.find(t => t.containsCanary)
    result.details = {
      param: paramName, canaryTriggered: visit.canaryCheck.triggered, sink: sinkHit?.sink ?? null,
      title: visit.title ?? null, scriptCount: scriptBodies.length,
    }
    if (visit.canaryCheck.triggered || sinkHit) {
      result.hit = true
      result.anomalies.push({
        type: 'dom_xss_url_sink', path: h.endpoint.path, urlParam: paramName,
        sink: sinkHit?.sink ?? 'dom', payload, canaryTriggered: true,
        suggestedReplayKind: 'browser_chain',
      })
    }
  } catch (err) {
    result.details.browserError = err instanceof Error ? err.message.slice(0, 200) : String(err)
  }
  return result
}

/**
 * Second-order SSRF: store a canary URL through the write route, then trigger the product's own
 * fetch/delivery step. The callback is correlated to the canary minted for this probe.
 */
async function runSecondOrderSsrfCheck(h: Hypothesis, env: ProbeEnv, watch: (ex: BrokerExchangeResult) => void): Promise<MultiStepResult> {
  const result: MultiStepResult = { hit: false, anomalies: [], details: {}, requests: 0 }
  const param = h.param
  if (!param || !env.canaryBroker) return result
  const info = env.canaryBroker.listenerInfo()
  if (!info.running) { try { await env.canaryBroker.startListener() } catch { return result } }
  const minted = env.canaryBroker.mintCanary(env.runId, `second_order_ssrf:${h.endpoint.path}`, env.origin, { storage: env.storage, ...(env.assignmentId ? { assignmentId: env.assignmentId } : {}) })
  const body: Record<string, unknown> = {}
  for (const p of h.endpoint.params) {
    if (p.isCsrf) continue
    body[p.name] = p.name === param.name ? minted.httpUrl : semanticValue(p.name, env)
  }
  const regEx = await sendRaw(env, {
    method: h.method, pathAndQuery: probePathFor(h), body: JSON.stringify(body),
    headers: { 'Content-Type': 'application/json' }, persona: env.owner,
    session: env.caps.sessionAndCsrf ? env.session : undefined,
  })
  result.requests += 1
  if (regEx) watch(regEx)
  result.details.registerStatus = regEx?.status ?? null
  if (!regEx || regEx.status < 200 || regEx.status >= 300) return result
  const harvest = harvestJson(regEx.body)
  const id = harvest.ids[0] ?? null
  result.details.resourceId = id
  const segs = h.endpoint.path.split('/').filter(Boolean)
  const base = `/${segs.join('/')}`
  const triggerCandidates = new Set<string>()
  if (id) {
    for (const verb of ['ping', 'test', 'deliver', 'trigger', 'verify', 'preview', 'send', 'retry', 'invoke', 'dispatch']) {
      triggerCandidates.add(`${base}/${encodeURIComponent(id)}/${verb}`)
    }
  }
  // Prefer routes the app itself surfaced (same prefix + id slot + action verb).
  for (const ep of env.endpoints ?? []) {
    if (ep.method.toUpperCase() !== 'POST' || !hasPathPlaceholder(ep.path)) continue
    if (!ep.path.startsWith(`${base}/`) || ep.path === h.endpoint.path) continue
    if (id) triggerCandidates.add(fillPlaceholders(ep.path, id))
  }
  const tried: Array<Record<string, unknown>> = []
  for (const path of [...triggerCandidates].slice(0, 5)) {
    if (env.signal.aborted) break
    const ex = await sendRaw(env, {
      method: 'POST', pathAndQuery: path, body: '{}', headers: { 'Content-Type': 'application/json' },
      persona: env.owner, ...(env.caps.sessionAndCsrf ? { session: env.session } : {}),
    })
    result.requests += 1
    if (ex) watch(ex)
    tried.push({ path, status: ex?.status ?? null })
  }
  result.details.triggers = tried
  let hit = false
  for (let attempt = 0; attempt < 12 && !hit; attempt += 1) {
    const check = env.canaryBroker.checkCanary(minted.token, { storage: env.storage, runId: env.runId })
    if (check.hit) hit = true
    else await new Promise<void>(resolve => setTimeout(resolve, 150))
  }
  if (hit) {
    result.hit = true
    const triggerPath = tried.find(t => typeof t.status === 'number' && (t.status as number) < 500)?.path ?? [...triggerCandidates][0]
    result.anomalies.push({
      type: 'second_order_ssrf_callback', path: h.endpoint.path, param: param.name,
      registerPath: probePathFor(h), resourceId: id, triggerPaths: tried.map(t => t.path),
      triggerPattern: id && triggerPath ? String(triggerPath).replace(encodeURIComponent(id), '{{id}}').replace(id, '{{id}}') : null,
      token: minted.token, variant: 'http', suggestedReplayKind: 'http_chain',
    })
  }
  return result
}

interface WebhookDelivery {
  body: Record<string, unknown>
  readPath: string
  stateField: string
  stateValue: number
  header: string
}

/**
 * Discover an inbound receiver's sibling management/list route, harvest an endpoint identifier and a
 * scalar/array state that only advances when a delivery is processed.
 */
async function webhookDeliveryFor(h: Hypothesis, env: ProbeEnv): Promise<WebhookDelivery | null> {
  const getPaths = (env.endpoints ?? []).filter(e => e.method.toUpperCase() === 'GET').map(e => e.path)
  const segs = h.endpoint.path.split('?')[0].split('/').filter(Boolean)
  const parent = segs.length > 1 ? `/${segs.slice(0, -1).join('/')}` : null
  const candidates = [...new Set([
    parent,
    ...getPaths.filter(p => !hasPathPlaceholder(p) && /(hook|webhook|event|deliver|callback|audit|log)/i.test(p)),
  ].filter((p): p is string => Boolean(p)))].slice(0, 3)
  for (const path of candidates) {
    const ex = await sendRaw(env, { method: 'GET', pathAndQuery: path, persona: env.owner, session: env.caps.sessionAndCsrf ? env.session : undefined })
    if (!ex || ex.status < 200 || ex.status >= 300) continue
    let parsed: unknown
    try { parsed = JSON.parse(ex.body) } catch { continue }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) continue
    const rec = parsed as Record<string, unknown>
    const harvest = harvestJson(ex.body)
    const id = harvest.fields.get('endpoint')?.[0] ?? harvest.fields.get('id')?.[0] ??
      harvest.fields.get('hookId')?.[0] ?? harvest.fields.get('webhookId')?.[0] ?? harvest.ids[0]
    if (!id) continue
    for (const key of ['events', 'items', 'deliveries', 'runs', 'records', 'logs']) {
      const value = rec[key]
      if (Array.isArray(value)) {
        return {
          body: {
            endpoint: id, id, hookId: id, webhookId: id,
            event: { type: 'guardian.probe', id: `gwh${shortToken(8)}` }, type: 'guardian.probe',
          },
          readPath: path, stateField: key, stateValue: value.length + 1,
          header: 'x-webhook-signature',
        }
      }
    }
    for (const key of ['count', 'total', 'received', 'processed']) {
      const value = Number(rec[key])
      if (Number.isFinite(value)) {
        return {
          body: {
            endpoint: id, id, hookId: id, webhookId: id,
            event: { type: 'guardian.probe', id: `gwh${shortToken(8)}` }, type: 'guardian.probe',
          },
          readPath: path, stateField: key, stateValue: value + 1,
          header: 'x-webhook-signature',
        }
      }
    }
  }
  return null
}

export async function runHypothesis(h: Hypothesis, env: ProbeEnv, onExchange: (ex: BrokerExchangeResult) => void): Promise<HypothesisOutcome> {
  const out: HypothesisOutcome = {
    hyp: h, verdict: 'inconclusive', anomalies: [], details: {}, csrfRejected: false, contextReset: false, tierBlocked: false, requests: 0,
  }
  const watch = (ex: BrokerExchangeResult) => {
    onExchange(ex)
    if ((ex.status === 403 || ex.status === 400 || ex.status === 419) && csrfBody.test(ex.body)) out.csrfRejected = true
    if ((ex.status === 401 || ex.status === 403 || ex.status === 440) && sessionBody.test(ex.body)) out.contextReset = true
  }

  // Prime the session jar before write probes so cookies + CSRF tokens discovered on the entry page
  // are available to the broker's csrfBind injection.
  if (h.method !== 'GET') out.requests += await primeSessionOnce(h, env)

  if (h.probeClass === 'race_burst') {
    const race = await runRaceCheck(h, env, watch)
    out.requests += race.requests
    out.details = race.details
    if (race.hit) {
      out.verdict = 'signal'
      out.anomalies = race.anomalies
      out.summary = 'Concurrent duplicate consume requests on one single-use value were accepted more than once.'
    } else {
      out.verdict = 'no_signal'
      out.summary = 'Race burst did not accept the same single-use value twice.'
    }
    return out
  }
  if (h.probeClass === 'dom_xss_url') {
    const dom = await runUrlDomSinkCheck(h, env, watch)
    out.requests += dom.requests
    out.details = dom.details
    if (dom.hit) {
      out.verdict = 'signal'
      out.anomalies = dom.anomalies
      out.summary = 'A URL query parameter reached an executable DOM sink in the page script.'
    } else {
      out.verdict = 'no_signal'
      out.summary = 'No URL-driven DOM sink flow was observed.'
    }
    return out
  }

  const ctx = await resolveContext(h, env)
  out.ctx = ctx
  let req: ProbeDifferentialRequest
  switch (h.probeClass) {
    case 'authz_matrix': {
      let owner = env.owner
      let other = env.other
      if ((/(admin|internal|manage|staff|flag|role|permission)/i.test(h.endpoint.path) || serverActionPath.test(h.endpoint.path)) && env.admin && (env.viewer ?? env.other)) { owner = env.admin; other = env.viewer ?? env.other }
      out.pair = { owner, other }
      req = await authzRequest(h, env, owner, other)
      if (h.writePathRead) req.writePathRead = true
      break
    }
    case 'ssrf_canary':
      req = buildProbeRequest(h, env, { ssrfParams: h.param ? [h.param.name] : [], waitMs: 2500 }); break
    case 'xxe_canary': req = buildProbeRequest(h, env, { waitMs: 2500 }); break
    case 'mass_assignment': req = buildProbeRequest(h, env, { paramLocation: 'json', jsonBody: {} }); break
    case 'graphql_audit': {
      req = buildProbeRequest(h, env)
      req.ownerPersona = env.owner
      req.otherPersona = env.other
      req.resourceIds = [...new Set([...env.personaUserIds, ...(env.corpus ? mineObservedIds(env.corpus, 6) : [])])].slice(0, 6)
      if (env.ownerUserId) req.ownerUserId = env.ownerUserId
      if (env.otherUserId) req.otherUserId = env.otherUserId
      break
    }
    case 'workflow_invariant': {
      req = buildProbeRequest(h, env)
      delete req.param; delete req.paramLocation
      if (h.createPath) {
        req.createPath = h.createPath
        req.producerBody = h.producerBody ?? {}
        if (hasPathPlaceholder(h.endpoint.path)) req.pathAndQuery = fillPlaceholders(h.endpoint.path, '{{id}}')
        const qty = h.endpoint.params.find(p => /(qty|quantity|count|amount)/i.test(p.name))
        if (qty) req.quantityField = qty.name
      }
      break
    }
    case 'cache_poison_deception': case 'auth_protocol_audit':
      req = buildProbeRequest(h, env); delete req.param; delete req.paramLocation; break
    case 'path_traversal_benign':
      req = buildProbeRequest(h, env); break
    case 'csrf_state_change': {
      const getPaths = (env.endpoints ?? []).filter(e => e.method.toUpperCase() === 'GET').map(e => e.path)
      const idSlot = hasPathPlaceholder(h.endpoint.path)
      const ids = idSlot ? await idPool(env, h.endpoint.path) : []
      const id = ids[0] ?? '1'
      const writePath = idSlot ? fillPlaceholders(h.endpoint.path, encodeURIComponent(id)) : h.endpoint.path
      const parent = `/${h.endpoint.path.split('?')[0].split('/').filter(Boolean).slice(0, -1).join('/')}`
      const segs = h.endpoint.path.split('?')[0].split('/').filter(Boolean)
      const placeholderIdx = segs.findIndex(s => /^(:[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\])$/.test(s))
      const collection = placeholderIdx > 0 ? `/${segs.slice(0, placeholderIdx).join('/')}` : null
      const readTemplate = getPaths.includes(h.endpoint.path)
        ? h.endpoint.path
        : getPaths.includes(parent) || parent !== '/'
          ? parent
          : null
      req = buildProbeRequest(h, env)
      req.method = h.method
      req.pathAndQuery = writePath
      req.readPathCandidates = [...new Set([
        ...(readTemplate ? [readTemplate] : []),
        ...(collection ? [collection] : []),
      ])].map(tpl => hasPathPlaceholder(tpl) ? fillPlaceholders(tpl, encodeURIComponent(id)) : tpl)
      if (req.readPathCandidates.length > 0) req.readPath = req.readPathCandidates[0]
      req.stateRecordId = id
      const bodyNames = h.endpoint.params.filter(p => (p.location === 'json' || p.location === 'form') && !p.isCsrf).map(p => p.name)
      const stateHint = bodyNames.find(n => /^(?:status|state)$/i.test(n)) ??
        bodyNames.find(n => /^(?:name|title|label|display_?name)$/i.test(n)) ??
        (/(trigger|confirm|approve|complete|activate|publish|status|state|workflow)/i.test(h.endpoint.path) ? 'status'
          : /(settings|profile|account)/i.test(h.endpoint.path) ? 'name' : undefined)
      if (stateHint) req.stateField = stateHint
      req.csrfPrimePaths = [
        ...(env.endpoints ?? [])
          .filter(e => e.method.toUpperCase() === 'GET' && /(?:^|[/_-])(?:csrf|xsrf|token|session|nonce)(?:$|[/_-])/i.test(e.path))
          .map(e => e.path)
          .slice(0, 2),
        ...(req.readPath ? [req.readPath] : []),
      ]
      const bodyParams = h.endpoint.params.filter(p => (p.location === 'json' || p.location === 'form') && !p.isCsrf)
      if (bodyParams.some(p => /^field$/i.test(p.name)) && bodyParams.some(p => /^value$/i.test(p.name))) {
        req.writeBody = { field: '', value: '' }
      }
      break
    }
    case 'webhook_signature_bypass': {
      req = buildProbeRequest(h, env)
      const delivery = await webhookDeliveryFor(h, env)
      if (delivery) {
        req.webhookBody = delivery.body
        req.readPath = delivery.readPath
        req.readStateField = delivery.stateField
        req.readStateValue = delivery.stateValue
        req.webhookHeader = delivery.header
      }
      break
    }
    case 'open_redirect_differential': {
      req = buildProbeRequest(h, env)
      if (h.param && env.corpus) {
        req.redirectBaseTargets = mineBaselines(env.corpus, h.param.name, h.endpoint.path)
          .filter(v => /^https?:\/\//i.test(v) || v.startsWith('//'))
          .slice(0, 4)
      }
      break
    }
    default: req = buildProbeRequest(h, env)
  }
  if (h.param) {
    if (ctx.baseline && sqliClasses.has(h.probeClass)) req.baselineValue = ctx.baseline
    if (ctx.xmlTemplate && h.location === 'xml') req.xmlTemplate = ctx.xmlTemplate
    if (ctx.graphqlQuery && h.location === 'graphql_var') req.graphqlQuery = ctx.graphqlQuery
  }
  if (h.probeClass === 'auth_protocol_audit') {
    req.persona = env.jwtPersona ?? env.owner
    // Authorize-style flows are GET redirects; token/introspection endpoints keep their discovered method.
    req.method = oauthPath.test(h.endpoint.path) ? 'GET' : h.method
    if (ctx.seedQuery) req.pathAndQuery = `${h.endpoint.path.split('?')[0]}?${ctx.seedQuery}`
  }
  if (h.probeClass === 'graphql_audit') req.method = 'POST'
  req.onExchange = ex => { watch(ex) }
  try {
    const res: DifferentialResult = await probeDifferential(req, env.broker, env.grant, env.canaryBroker, env.signal)
    out.verdict = res.verdict
    out.anomalies = res.anomalies
    out.details = res.details
    out.requests += res.requestsSent
    out.summary = res.summary
    if (res.stoppedReason === 'approval_required' || res.stoppedReason === 'denied') out.tierBlocked = true
  } catch (err) {
    if (err instanceof BrokerApprovalRequired) out.tierBlocked = true
    else if (err instanceof BrokerDenied && /tier/i.test(err.message)) out.tierBlocked = true
    out.verdict = 'error'
    out.error = err instanceof Error ? err.message : String(err)
  }

  // Second-order (stored) verification: only after an inconclusive/negative first-order probe.
  if (h.secondOrder && !out.tierBlocked && out.verdict !== 'signal' && !env.signal.aborted) {
    const stored = await runSecondOrderCheck(h, env, watch)
    out.requests += stored.requests
    out.details = { ...out.details, secondOrder: stored.details }
    if (stored.hit) {
      out.verdict = 'signal'
      out.anomalies = [...out.anomalies, ...stored.anomalies]
      out.summary = 'Stored marker planted via the write endpoint surfaced unencoded on a downstream read route.'
    }
  }

  // Second-order SSRF: the URL was stored but not fetched during the write, so trigger delivery.
  if (h.secondOrderSsrf && h.probeClass === 'ssrf_canary' && !out.tierBlocked && out.verdict !== 'signal' && !env.signal.aborted) {
    const stored = await runSecondOrderSsrfCheck(h, env, watch)
    out.requests += stored.requests
    out.details = { ...out.details, secondOrderSsrf: stored.details }
    if (stored.hit) {
      out.verdict = 'signal'
      out.anomalies = [...out.anomalies, ...stored.anomalies]
      out.summary = 'Stored webhook URL was fetched by the delivery agent (correlated OOB callback).'
    }
  }

  // URL-query-driven DOM XSS: source->sink flow found in page scripts, no form interaction needed.
  if (h.urlDomSink && h.probeClass === 'xss_context' && !out.tierBlocked && out.verdict !== 'signal' && !env.signal.aborted) {
    const urlDom = await runUrlDomSinkCheck(h, env, watch)
    out.requests += urlDom.requests
    out.details = { ...out.details, urlDomSink: urlDom.details }
    if (urlDom.hit) {
      out.verdict = 'signal'
      out.anomalies = [...out.anomalies, ...urlDom.anomalies]
      out.summary = 'A URL query parameter reached an executable DOM sink in the page script.'
    }
  }

  // Browser-dependent DOM XSS: only when a GET page reflection probe did not already signal.
  if (h.browserEligible && h.probeClass === 'xss_context' && !out.tierBlocked && out.verdict !== 'signal' && !env.signal.aborted) {
    const dom = await runBrowserChainCheck(h, env, watch)
    out.requests += dom.requests
    out.details = { ...out.details, browserChain: dom.details }
    if (dom.hit) {
      out.verdict = 'signal'
      out.anomalies = [...out.anomalies, ...dom.anomalies]
      out.summary = 'Canary reached an executable DOM sink after scripted interaction on a rendered page.'
    }
  }
  return out
}
