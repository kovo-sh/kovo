/**
 * Generic hypothesis formation and probe execution for the recall benchmark.
 *
 * Nothing here knows about any benchmark challenge: hypotheses are derived only from the
 * endpoints/params Kovo's recon discovered (names, locations, path shapes, methods), then
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
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  /** DELETE endpoints keep `method` POST for spec compatibility but probe the real verb. */
  deleteMethod?: boolean
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
  /** Workflow quantity/counter: read-back route whose JSON exposes the conserved value. */
  workflowReadPath?: string
  /** Workflow transition: collection list used to resolve a seeded target and read its state. */
  workflowListPath?: string
  /** Workflow transition: performing the same transition twice must be rejected the second time. */
  repeatTransition?: boolean
  /** Workflow: client-supplied price update on a route with a sibling read-back. */
  priceTrust?: boolean
  /** Workflow: repeat a money/single-use mutation twice (aggregate cap). */
  repeatMutation?: boolean
  /** Race: sibling producer route that mints a single-use value for the consume parameter. */
  raceProducerPath?: string
  /** Race: `single_use` mints a value; `balance` overspends a read-then-write balance/stock. */
  raceMode?: 'single_use' | 'balance'
  /** Race: collection/detail route that exposes the balance/stock being spent. */
  raceResourcePath?: string
  /** Race: create route used to mint a fresh resource (cart) before the burst. */
  raceCreatePath?: string
  /** CSRF: create-style mutation whose read-back is the created object's detail route. */
  csrfCreate?: boolean
  /** Full merged surface used to form this hypothesis (detail/config routes may be surface extras). */
  knownEndpoints?: readonly DiscoveredEndpoint[]
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
const authishPath = /(oauth|authorize|openid|token|jwt|auth|session|login|sso|well-known|partner|ledger|credential|apikey|api-key|whoami|userinfo|identity|reports?\/(?:sales|summary|analytics)|internal|export)/i
/** Routes whose mutating verb usually requires an elevated role/function (BFLA candidates). */
const privilegedPath = /(admin|internal|manage|staff|superuser|privileged|permission|feature[-_]?flag|backoffice)/i
/** Parameters that name a file or path handled by a download/export/serve route. */
const fileParam = /^(?:file|filename|filepath|file_name|logfile|log_file|log|name|path|download|export|doc|document|attachment|resource|target)$/i
/** Parameters that plausibly reach a shell/OS command interpreter. */
const shellParam = /\b(?:host|hostname|ip|addr|domain|target|cmd|command|exec|shell|run|ping|diag|lookup|resolve|nslookup|whois)\b/i
const shellPath = /(ping|diagnostic|exec|command|shell|health|resolve|lookup|whois|dns|system)/i
/** Single-use value parameters (voucher/coupon/token style) for race testing. */
const singleUseParam = /^(?:code|voucher|coupon|token|key|secret|invite|promo|gift|redeem|nonce|otp|passcode|ticket)$/i
/** Later-step workflow verbs (must not run before the prerequisite step). */
const actionStepPath = /(confirm|approve|complete|finalize|fulfil|ship|activate|publish|accept|settle)/i
const serverActionPath = /(?:^|\/)(?:_actions|_next\/action)\//i
const templateishParam = /(template|layout|source|message|subject|body|content|text|comment|title|html|email|name|greeting|preview|render|note|snippet)/i
/**
 * OAuth/OIDC/session protocol control parameters are not user-data sinks; running injection
 * matrices over them only burns budget. They stay recorded as surface, just not as inject targets.
 */
const protocolParam = /^(?:client[_-]?id|client[_-]?secret|redirect[_-]?uri|response[_-]?type|grant[_-]?type|scope|state|nonce|code|code[_-]?challenge|code[_-]?challenge[_-]?method|audience|prompt|login[_-]?hint|access[_-]?token|refresh[_-]?token|id[_-]?token|assertion|signature|sig|continue|return_to)$/i
const placeholderSeg = /^(:[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\])$/
const maxInjectionParamsPerEndpoint = 8
const maxCacheEndpoints = 5
/** Cookie-authenticated state-change candidates (CSRF) and their observable read routes. */
const csrfActionPath = /(settings|profile|account|tenant|org|team|refund|reversal|payout|disburse|charge|credit|withdraw|job|trigger|approve|confirm|transfer|invite|subscribe|billing|payment|grant|reimburse)/i
const csrfSkipPath = /(^|\/)(login|logout|2fa|csrf|token|session|oauth|authorize|callback|graphql)(\/|$)/i
/** Inbound webhook receiver routes (not management/list routes). */
const webhookReceiverPath = /(^|\/)(?:receive|receive-webhook|callback|callbacks|inbound|deliver|delivery|events|event[-_]?hooks?|webhooks?|receivers?)(\/|$)/i
/** Navigation/callback parameter names used by open-redirect sinks. */
const redirectParamName = /^(?:next|nextUrl|next_url|returnTo|return_to|returnUrl|return_url|redirect|redirectUri|redirect_uri|url|uri|continue|continueUrl|callback|callbackUrl|dest|destination|target|go)$/i
const redirectPathHint = /(sso|oauth|authorize|callback|redirect|return|login|logout|checkout|download|export|continue|resume)/i
const maxCsrfHypotheses = 8
const maxWebhookHypotheses = 4
const maxRedirectHypotheses = 16
const maxRaceHypotheses = 8
const maxGraphqlHypotheses = 5

/**
 * Query/body parameters for routes whose parameter names the surface did not expose (server-rendered
 * pages, hidden API routes listed only as paths). Candidate names are derived from route semantics and
 * the vocabulary applications actually use for that shape; every candidate is still verified by a
 * differential, so a wrong guess costs a bounded request and never produces a signal on its own.
 */
export type InferredPurpose = 'search' | 'file' | 'url' | 'command' | 'text' | 'template' | 'number'
export interface InferredParam extends DiscoveredParam { purpose?: InferredPurpose }

const searchRouteHint = /(?:^|[/_.-])(?:search|searches|lookup|find|filter|query|queries|saved-?views?)(?:$|[/_.-])/i
const searchSeg = /^(?:search|query|find|lookup|filter|run)$/i
const fileServeSeg = /^(?:download|downloads|view|serve|file|files|asset|assets|receipt|receipts|invoice|invoices|billing[-_]?docs?|label|labels|document|documents|attachment|attachments|media|raw|content|archive|archives|backup|backups|log|logs|journal|journals)$/i
const downloadPathHint = /(?:^|[/_.-])(?:download|downloads|export|exports)(?:$|[/_.-])/i
const importRouteHint = /(?:^|[/_.-])(?:import|imports|feeds?|upload|uploads|parse|xml|saml|soap|svg|rss|wsdl|manifests?|descriptor|labels?|backups?|archives?)(?:$|[/_.-])/i
const urlRouteHint = /(?:^|[/_.-])(?:avatar|avatars|image|images|photo|photos|logo|logos|media|thumbnail|webhooks?|hooks?|callbacks?|integrations?|connectors?|proxy|proxies|fetch|remote|links?)(?:$|[/_.-])/i
const commandRouteHint = /(?:^|[/_.-])(?:diag|diagnostics?|exec|execute|shell|commands?|ping|resolve|whois|nslookup|exports?|archives?|backups?|reports?)(?:$|[/_.-])/i
const numericParam = /(?:^|_)(?:id|uid|ref|count|qty|quantity|limit|offset|page|since|amount|price|total|num|number)$/i
/** Parameter names that plausibly reach a SQL string/branch in real applications. */
const sqlSinkName = /(?:^|[_-])(?:q|query|search|term|keyword|filter|expr|clause|sort|order|where|id|uid|ref|sku|slug|name|title|category|type|status|state|email|user|account|member|host|target|page|limit|since|amount|price|total|number|code|token|text|body|comment|note)$/i
const sqlSinkPath = /(?:search|lookup|filter|query|find|list|items|products|orders|accounts|catalog|reports|logs|journals|graphql|xml|export)/i
const textSinkRoute = /(?:^|[/_.-])(?:reviews?|ratings?|feedback|comments?|notes?|messages?|posts?|replies|tickets?|threads?|announcements?)(?:$|[/_.-])/i
const templateRouteHint = /(?:^|[/_.-])(?:render|preview|templates?|layouts?|reports?|docs?|pages?|emails?|snippets?)(?:$|[/_.-])/i
const maxInferredParamGroups = 12
const maxBrowserPageHypotheses = 4

function fileNamesFor(path: string): string[] {
  if (/(?:^|[/_.-])(?:logs?|journals?|audit|stream|view)(?:$|[/_.-])/i.test(path)) return ['file', 'logFile', 'name']
  if (/(?:receipt|invoice|statement|label|manifest|export|report)/i.test(path)) return ['file', 'document', 'name']
  return ['path', 'file', 'name']
}

function urlNamesFor(path: string): string[] {
  if (/(?:avatar|image|photo|logo|picture|thumbnail|media)/i.test(path)) return ['avatarUrl', 'imageUrl', 'src', 'pictureUrl', 'source']
  if (/(?:webhook|hook|callback)/i.test(path)) return ['url', 'callbackUrl', 'endpoint']
  if (/(?:integration|connector|fetch|proxy|remote|link)/i.test(path)) return ['url', 'endpoint', 'target']
  return ['url', 'target', 'endpoint']
}

function commandNamesFor(path: string): string[] {
  if (/(?:export|archive|backup|report|download|label|manifest)/i.test(path)) return ['name', 'filename', 'file', 'label', 'title', 'path']
  return ['host', 'target', 'command', 'cmd', 'endpointHost']
}

/** Common editable text fields on an update route whose body shape the surface did not expose. */
function textFieldNamesFor(path: string): string[] {
  if (/(?:ticket|comment|review|note|thread|message|post|issue)/i.test(path)) return ['body', 'note', 'text', 'comment']
  if (/(?:profile|member|user|account|person|staff)/i.test(path)) return ['name', 'title', 'bio', 'description']
  return ['name', 'description', 'title', 'label']
}

/** Query candidates for a GET whose surface exposed no parameters. */
export function inferredQueryParams(ep: DiscoveredEndpoint): InferredParam[] {
  const path = ep.path.split('?')[0]
  const segs = path.split('/').filter(Boolean)
  const last = segs[segs.length - 1] ?? ''
  const out: InferredParam[] = []
  const push = (purpose: InferredPurpose, names: string[]) => {
    for (const name of names) out.push({ name, location: 'query', isObjectId: false, isCsrf: false, purpose })
  }
  if (searchRouteHint.test(path) || searchSeg.test(last)) push('search', ['q', 'query', 'term', 'keyword'])
  else if (fileServeSeg.test(last) || downloadPathHint.test(path)) {
    // Plain collection routes (`/assets`, `/logs`) do not take a file name; only serving-shaped
    // routes and download/export paths do. This keeps the 17-request traversal oracle focused.
    const collectionOnly = !hasPathPlaceholder(path) && /s$/i.test(last) && !downloadPathHint.test(path) && !/(?:downloads?|exports?|serve|view)/i.test(path)
    if (!collectionOnly) push('file', fileNamesFor(path))
  }
  return out.slice(0, 4)
}

/** Body candidates for a write whose surface exposed no JSON/form fields. */
export function inferredBodyParams(ep: DiscoveredEndpoint): InferredParam[] {
  const path = ep.path.split('?')[0]
  const segs = path.split('/').filter(Boolean)
  const last = segs[segs.length - 1] ?? ''
  const out: InferredParam[] = []
  const push = (purpose: InferredPurpose, names: string[]) => {
    for (const name of names) out.push({ name, location: 'json', isObjectId: false, isCsrf: false, purpose })
  }
  if (urlRouteHint.test(path)) push('url', urlNamesFor(path))
  else if (commandRouteHint.test(path)) push('command', commandNamesFor(path))
  else if (searchRouteHint.test(path) || /^(?:run|filter|search|query)$/i.test(last)) {
    push('search', ['filter', 'expr', 'clause', 'q', 'query', 'term', 'since'])
  } else if (/(?:refund|credit|payment|payout|charge|withdraw|spend|redeem|transfer)/i.test(path)) {
    // Money-moving writes read a numeric amount from the body even when recon never exposed fields.
    push('number', ['amount', 'amountCents', 'value', 'total', 'price'])
  } else if (/(?:checkout|order|cart|purchase|reserve|inventory|stock)/i.test(path)) {
    push('number', ['quantity', 'qty', 'itemQty', 'productId', 'amount'])
  } else if (textSinkRoute.test(path)) push('text', ['body', 'text', 'content', 'message', 'note', 'comment', 'author'])
  else if (templateRouteHint.test(path)) push('template', ['template', 'layout', 'source'])
  else if (/^(?:PATCH|PUT)$/i.test(ep.method)) push('text', textFieldNamesFor(path))
  return out.slice(0, 4)
}

/** XML import-shaped mutating routes: the body itself is the probe surface (no parameter needed). */
export function isXmlImportRoute(ep: DiscoveredEndpoint): boolean {
  return ep.method.toUpperCase() !== 'GET' && importRouteHint.test(ep.path.split('?')[0])
}

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
  if (/(checkout|return)/.test(p)) return ['returnUrl', 'returnTo', 'next', 'redirect']
  if (/(download|export)/.test(p)) return ['url', 'next', 'returnTo', 'redirect']
  return ['url', 'next', 'redirect', 'returnTo']
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
  const segs = writePath.split('?')[0].split('/').filter(Boolean)
  // Routes nested under the written resource: a project description renders on the project card,
  // ticket notes render in the ticket view, orders appear on receipts. The resource anchor is the
  // path up to and including its last identifier segment (or the collection itself for create routes).
  const lastIdIdx = (() => {
    for (let i = segs.length - 1; i >= 0; i -= 1) if (placeholderSeg.test(segs[i])) return i
    return -1
  })()
  const anchor = lastIdIdx >= 0 ? `/${segs.slice(0, lastIdIdx + 1).join('/')}` : `/${segs.join('/')}`
  for (const p of getPaths) {
    if (p === writePath) continue
    if (p.startsWith(`${anchor}/`) && !/\.(?:js|css|json|xml)$/i.test(p)) out.add(p)
  }
  for (let drop = 1; drop < Math.min(3, segs.length); drop += 1) {
    const variant = `/${segs.slice(drop).join('/')}`
    if (getPaths.includes(variant)) out.add(variant)
  }
  return [...out]
    .filter(p => p !== writePath || getPaths.includes(p))
    .sort((a, b) => {
      const api = (p: string) => (/^\/api\//i.test(p) ? 1 : 0)
      // Prefer HTML-rendering read routes (admin/moderation views, card/page/preview) over raw JSON.
      const render = (p: string) => (/\/(?:view|render|card|page|preview|show|display|html|admin|moderation|queue|thread)(?:\/|$)/i.test(p) ? -1 : 0)
      return render(a) - render(b) || api(a) - api(b) || a.split('/').filter(Boolean).length - b.split('/').filter(Boolean).length || a.localeCompare(b)
    })
    .slice(0, 4)
}

export function formHypotheses(endpoints: readonly DiscoveredEndpoint[], caps: ProfileCaps): HypothesisPlan {
  const hypotheses: Hypothesis[] = []
  const encodingSkips: Array<{ path: string; location: string }> = []
  const seen = new Set<string>()
  const add = (h: Omit<Hypothesis, 'key'>) => {
    const key = `${h.probeClass}|${h.endpoint.method}|${h.endpoint.path}|${h.param?.name ?? ''}|${h.location ?? ''}`
    if (seen.has(key)) return
    seen.add(key)
    hypotheses.push({ ...h, key, knownEndpoints: endpoints })
  }

  const getPaths = [...new Set(endpoints.filter(e => e.method.toUpperCase() === 'GET' || e.method.toUpperCase() === 'HEAD').map(e => e.path))]
  const writeProbeSeen = new Set<string>()
  const cacheCandidates: DiscoveredEndpoint[] = []
  let redirectHypotheses = 0
  let inferredGroups = 0
  let textFieldHypotheses = 0
  let massHypotheses = 0
  let filterAuthzHypotheses = 0
  let secretHypotheses = 0
  let workflowReadHypotheses = 0
  let workflowTransitionHypotheses = 0
  let workflowRepeatHypotheses = 0
  let priceTrustHypotheses = 0
  const massProbePaths = new Set<string>()
  const pageCandidates: Array<{ ep: DiscoveredEndpoint; score: number }> = []
  const csrfCandidates: Array<{ ep: DiscoveredEndpoint; readPath: string | null; create: boolean; score: number }> = []
  const webhookCandidates: Array<{ ep: DiscoveredEndpoint; score: number }> = []
  const raceCandidates: Array<{ ep: DiscoveredEndpoint; param: DiscoveredParam; createPath?: string; resourcePath?: string; mode: 'single_use' | 'balance'; score: number }> = []
  const graphqlCandidates: DiscoveredEndpoint[] = []
  const inferredPurpose = (p: DiscoveredParam): InferredPurpose | undefined => (p as InferredParam).purpose

  for (const ep of endpoints) {
    const method = ep.method.toUpperCase()
    const isGet = method === 'GET' || method === 'HEAD'
    const pathHasPlaceholder = hasPathPlaceholder(ep.path)
    const params = ep.params.filter(p => !p.isCsrf && p.location !== 'cookie')
    // Routes whose names the surface never exposed (server-rendered pages, path-only API listings)
    // still get semantically plausible candidates; each one is confirmed or discarded by the probe.
    const inferred: InferredParam[] = []
    if (isGet && !params.some(p => p.location === 'query')) inferred.push(...inferredQueryParams(ep))
    if (!isGet && !params.some(p => p.location === 'json' || p.location === 'form' || p.location === 'xml' || p.location === 'graphql_var')) inferred.push(...inferredBodyParams(ep))
    // Rendered-resource updates often expose only some fields; the descriptive field that feeds the
    // downstream card is frequently omitted. Add one text candidate so stored XSS can be tested.
    const inferredText: InferredParam[] = []
    if (!isGet && (method === 'PATCH' || method === 'PUT') && textFieldHypotheses < 12 &&
        !params.some(p => /(?:description|content|note|text|body|comment|message)/i.test(p.name))) {
      const candidate = textFieldNamesFor(ep.path).find(name => !params.some(p => p.name === name))
      if (candidate) {
        inferredText.push({ name: candidate, location: 'json', isObjectId: false, isCsrf: false, purpose: 'text' })
        textFieldHypotheses += 1
      }
    }
    // Action-shaped routes (money, checkout, settings) need body-field inference even after the
    // generic inferred-parameter budget is spent: they are the inputs for CSRF/race probes.
    const actionShaped = /(refund|credit|payment|payout|charge|withdraw|spend|redeem|transfer|checkout|cart|order|settings|profile|account|webhook|invite|approve|confirm|trigger|avatar|photos?|images?|integrations?|import|fetch)/i.test(ep.path)
    const allowInferred = caps.newProbeClasses && (inferredGroups < maxInferredParamGroups || actionShaped)
    const effectiveParams: DiscoveredParam[] = [...params, ...inferredText, ...(allowInferred ? inferred : [])]
    if (allowInferred && inferred.length > 0) inferredGroups += 1
    const injectParams = effectiveParams.filter(p => !protocolParam.test(p.name)).slice(0, maxInjectionParamsPerEndpoint)
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

    // Parameterless rendered pages: a page that ships interactive controls can carry a DOM sink even
    // when no query parameter was ever discovered. The browser check itself bails unless the page
    // really contains a fillable input plus a button/JS sink, so this stays a cheap, bounded probe.
    const pageEligible = caps.newProbeClasses && isGet && !pathHasPlaceholder && params.length === 0 &&
      !/\.(?:json|js|mjs|css|xml|txt|map|svg|ico|png|jpe?g|gif|webp|woff2?)$/i.test(ep.path.split('?')[0]) &&
      !/\.well-known\//i.test(ep.path) && !graphqlPath.test(ep.path) &&
      ep.path.split('?')[0].split('/').filter(Boolean).length <= 2
    if (pageEligible) {
      const p = ep.path.split('?')[0]
      const score = p === '/' ? 0 : /(?:page|view|profile|account|settings|form|wizard|dashboard|home|search|edit|new|create|preview|comments?|reports?|shop|store)/i.test(p) ? 1 : 2
      pageCandidates.push({ ep, score })
    }

    // Object-level authorization: id-bearing paths or id-named parameters. Framework RPC ids are
    // not resource identifiers, so placeholder action routes are handled by the server-action probe.
    if ((pathHasPlaceholder && !serverActionPath.test(ep.path)) || (idParam && idParam.location === 'query')) {
      add({
        endpoint: ep, probeClass: 'authz_matrix', method: isGet ? 'GET' : (method === 'DELETE' ? 'DELETE' : writeMethod(ep)),
        ...(!isGet && method === 'DELETE' ? { deleteMethod: true } : {}),
        ...(!isGet && (method === 'PATCH' || method === 'PUT') && pathHasPlaceholder ? { writePathRead: true } : {}),
      })
    }
    // Role/permission transition routes: any authenticated member reaching a privileged role change is
    // an authorization failure; probe with a privileged value and compare actors.
    if (caps.newProbeClasses && !isGet && pathHasPlaceholder && /(?:role|grant|permission|privilege|promote|assign)(?:\/|$)/i.test(ep.path) &&
        !params.some(p => /^(?:role|grant|level)$/i.test(p.name))) {
      const roleParam: DiscoveredParam = { name: 'role', location: 'json', isObjectId: false, isCsrf: false }
      add({
        endpoint: { ...ep, params: [...ep.params, roleParam] },
        probeClass: 'authz_matrix', param: roleParam, location: 'json', method: writeMethod(ep),
      })
    }
    const recordCollection = /(?:^|[/_.-])(?:files?|assets?|documents?|attachments?|records?|entries|items?|notes?|comments?|listings?|media|logs?|events?)(?:$|[/_.-])/i
    if (isGet && !pathHasPlaceholder && recordCollection.test(ep.path) && !params.some(p => p.location === 'query') && filterAuthzHypotheses < 2) {
      for (const name of ['projectId', 'projId', 'workspaceId', 'ownerId']) {
        const filterParam: DiscoveredParam = { name, location: 'query', isObjectId: true, isCsrf: false }
        add({
          endpoint: { ...ep, params: [...ep.params, filterParam] },
          probeClass: 'authz_matrix', param: filterParam, location: 'query', method: 'GET',
        })
      }
      filterAuthzHypotheses += 1
    }
    // Non-entitled secret exposure: auth-ish collection/detail reads are scanned for tenant secret
    // markers by a viewer-role actor while an anonymous control proves the route is guarded.
    if (caps.newProbeClasses && isGet && secretHypotheses < 12 &&
        /(?:api[-_]?keys?|apikeys|secret|tokens?|credential|audit|settings|config|billing|integration|connectors?|links?|hooks?|webhooks?|providers?|connections?|accounts?)/i.test(ep.path) &&
        !graphqlPath.test(ep.path)) {
      const key = `secret_scan|${ep.path}`
      if (!writeProbeSeen.has(key)) {
        writeProbeSeen.add(key)
        add({ endpoint: ep, probeClass: 'authz_matrix', method: 'GET' })
        secretHypotheses += 1
      }
    }
    // Function-level authorization: a privileged mutating verb invoked by a lower-privilege actor.
    // Placeholder server-action ids (framework RPC ids that are not on the surface) cannot be invoked
    // meaningfully; only concrete action routes are probed.
    const concreteServerAction = serverActionPath.test(ep.path) && !pathHasPlaceholder
    if (caps.newProbeClasses && !isGet && (privilegedPath.test(ep.path) || concreteServerAction)) {
      add({ endpoint: ep, probeClass: 'authz_matrix', method: writeMethod(ep), ...(method === 'DELETE' ? { deleteMethod: true } : {}), ...(concreteServerAction ? { serverAction: true } : {}) })
    }

    for (const p of injectParams) {
      if (!caps.locations.has(p.location)) {
        encodingSkips.push({ path: ep.path, location: p.location })
        continue
      }
      // Numeric amount/quantity candidates exist for race budgeting, not as injection sinks.
      if (inferredPurpose(p) === 'number') continue
      const location = p.location as SurfaceParamLocation
      const purpose = inferredPurpose(p)
      const pMethod: Hypothesis['method'] = location === 'query' || location === 'path' || location === 'header' ? (isGet ? 'GET' : writeMethod(ep)) : writeMethod(ep)
      const isSearch = purpose === 'search' || /^(?:q|query|term|keyword|filter|expr|clause|since)$/i.test(p.name)
      const isFile = purpose === 'file'
      const isUrl = purpose === 'url' || urlName.test(p.name)
      const camelWords = p.name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase()
      const isCommand = purpose === 'command' || shellParam.test(p.name) ||
        /(?:^|_)(?:host|hostname|ip|addr|domain|target|cmd|command|exec|shell|run|ping|diag|lookup|resolve|nslookup|whois)(?:_|$)/.test(camelWords)
      const isText = purpose === 'text'
      const isTemplate = purpose === 'template'
      const isIdLike = idName.test(p.name) || p.isObjectId
      const sqlPlausible = purpose ? true : (sqlSinkName.test(p.name) || sqlSinkPath.test(ep.path))
      if (!isFile && !isUrl && !isCommand && !isText && !isTemplate && sqlPlausible) {
        add({ endpoint: ep, probeClass: 'sqli_boolean', param: p, location, method: pMethod })
        // Time-based confirmation is slow; keep it for query/body sinks and skip path/header/XML ids.
        const timeEligible = location === 'query' || location === 'json' || location === 'form' || location === 'graphql_var'
        if (caps.timeDiff && timeEligible && (purpose ? (isSearch || numericParam.test(p.name)) : true)) {
          add({ endpoint: ep, probeClass: 'sqli_time_diff', param: p, location, method: pMethod })
        }
      }
      if (isTemplate) {
        add({ endpoint: ep, probeClass: 'ssti_math', param: p, location, method: pMethod })
        continue
      }
      if (location === 'xml' || xmlPath.test(ep.path)) {
        if (caps.newProbeClasses) add({ endpoint: ep, probeClass: 'xxe_canary', param: p, location, method: writeMethod(ep) })
      }
      if (caps.newProbeClasses && isCommand && !isIdLike) {
        add({ endpoint: ep, probeClass: 'command_injection', param: p, location, method: pMethod })
      }
      if (isIdLike) continue
      // Template evaluation only matters for text-ish sinks; probing every parameter burns budget.
      if (!isFile && !isUrl && !isCommand && !isText && (templateishParam.test(p.name) || (isGet && location === 'query' && p.name.length <= 12))) {
        add({ endpoint: ep, probeClass: 'ssti_math', param: p, location, method: pMethod })
      }
      if (caps.newProbeClasses && !isFile && !isCommand) {
        add({
          endpoint: ep, probeClass: 'xss_context', param: p, location, method: pMethod,
          ...(!isGet && (location === 'json' || location === 'form' || location === 'xml') && storedReads.length > 0
            ? { secondOrder: true, readPaths: storedReads }
            : {}),
          ...(isGet && !pathHasPlaceholder && location === 'query' ? { browserEligible: true, urlDomSink: true } : {}),
        })
      }
      if (isUrl) {
        add({ endpoint: ep, probeClass: 'ssrf_canary', param: p, location, method: pMethod, ...(!isGet ? { secondOrderSsrf: true } : {}) })
      }
    }

    // Traversal needs a genuine file/path parameter; path-shape probing alone cannot prove a jail escape.
    // Inferred names are all tried, each gated by a cheap single-payload jail-escape pre-check.
    const fileRouteHint = /(?:download|downloads|export|exports|file|files|asset|assets|document|documents|attachment|attachments|receipt|receipts|invoice|invoices|label|labels|statement|statements|media|raw|content|logs?|journals?|view|read|serve|backup|backups|archive|archives)/i
    const fileParams = effectiveParams
      .filter(p => (inferredPurpose(p) === 'file' || (fileParam.test(p.name) && fileRouteHint.test(ep.path))) && (p.location === 'query' || p.location === 'json' || p.location === 'form'))
      .slice(0, inferred.length > 0 ? 3 : 1)
    for (const fileP of isGet ? fileParams : []) {
      add({ endpoint: ep, probeClass: 'path_traversal_benign', param: fileP, location: fileP.location as SurfaceParamLocation, method: 'GET' })
    }
    if (graphqlPath.test(ep.path) || ep.source === 'graphql') {
      const key = `graphql|${ep.path}`
      if (!writeProbeSeen.has(key) && graphqlCandidates.length < maxGraphqlHypotheses) {
        writeProbeSeen.add(key)
        graphqlCandidates.push(ep)
      }
    }
    // Structural action shapes. Path nouns are randomized by realistic apps, so state-changing
    // routes are recognised from their stable shape: a collection creator (POST), a collection
    // list/detail GET, and a terminal action verb (accept/confirm/complete/approve/...).
    const pathSegs = ep.path.split('?')[0].split('/').filter(Boolean)
    const placeholderIdx = pathSegs.findIndex(seg => placeholderSeg.test(seg))
    const singlePlaceholder = placeholderIdx >= 0 && pathSegs.slice(placeholderIdx + 1).every(seg => !placeholderSeg.test(seg))
    const collectionPath = placeholderIdx > 0 ? `/${pathSegs.slice(0, placeholderIdx).join('/')}` : null
    const prefixSegs = placeholderIdx > 0 ? pathSegs.slice(0, placeholderIdx) : []
    const detailGet = placeholderIdx > 0
      ? getPaths.find(g => {
          const gs = g.split('?')[0].split('/').filter(Boolean)
          return gs.length === placeholderIdx + 1 && placeholderSeg.test(gs[placeholderIdx]) &&
            gs.slice(0, placeholderIdx).join('/') === prefixSegs.join('/')
        })
      : undefined
    const collectionGet = collectionPath && getPaths.includes(collectionPath) ? collectionPath : undefined
    const collectionCreator = collectionPath
      ? endpoints.find(e => e.method.toUpperCase() === 'POST' && !hasPathPlaceholder(e.path) && e.path === collectionPath)
      : undefined
    const lastSeg = pathSegs[pathSegs.length - 1] ?? ''
    const actionVerb = actionStepPath.test(lastSeg) || /^(?:reapply|reset|rotate)$/i.test(lastSeg)
    const skipTransitionVerb = /^(?:cancel|logout|signout|revoke|delete|remove|reset|forgot)$/i.test(lastSeg)
    const creatorBody = (creator: DiscoveredEndpoint): Record<string, unknown> => {
      const body: Record<string, unknown> = {}
      for (const p of creator.params.filter(x => x.location === 'json' || x.location === 'form')) {
        body[p.name] = p.isObjectId || idName.test(p.name) ? '1' : /(qty|quantity|count|amount|price|total)/i.test(p.name) ? 1 : 'kovo'
      }
      return body
    }
    // Step-skip: a later transition accepted for a fresh/seeded object whose prerequisite is unmet.
    if (!isGet && method === 'POST' && actionVerb && !skipTransitionVerb &&
        workflowTransitionHypotheses < 8) {
      if (pathHasPlaceholder) {
        if (singlePlaceholder && (collectionCreator || collectionGet || detailGet)) {
          add({
            endpoint: ep, probeClass: 'workflow_invariant', method: writeMethod(ep),
            repeatTransition: true,
            ...(collectionCreator ? { createPath: collectionCreator.path, producerBody: creatorBody(collectionCreator) } : {}),
            ...(collectionGet ? { workflowListPath: collectionGet } : {}),
            ...(detailGet ? { workflowReadPath: detailGet } : {}),
          })
          workflowTransitionHypotheses += 1
        }
      } else if (pathSegs.length >= 2) {
        const parentPath = `/${pathSegs.slice(0, -1).join('/')}`
        const creator = endpoints.find(e => e.method.toUpperCase() === 'POST' && !hasPathPlaceholder(e.path) && e.path === parentPath)
        const list = getPaths.includes(parentPath) ? parentPath : undefined
        if (creator || list) {
          add({
            endpoint: ep, probeClass: 'workflow_invariant', method: writeMethod(ep),
            repeatTransition: true,
            ...(creator ? { createPath: creator.path, producerBody: creatorBody(creator) } : {}),
            ...(list ? { workflowListPath: list } : {}),
          })
          workflowTransitionHypotheses += 1
        }
      }
    }
    // Quantity/counter invariant: a write whose numeric body field feeds a readable resource state.
    // Create-shaped line/cart writes get their creator and detail read-back so the probe can prove
    // the conserved value (e.g. subtotal) left its bound.
    if (!isGet && workflowReadHypotheses < 6 &&
        (workflowPath.test(ep.path) ||
          (singlePlaceholder && Boolean(collectionCreator) && Boolean(detailGet)) ||
          /(?:qty|quantity|seat|license|licence|wallet|credit|stock|inventory|amount|price|subtotal|total)/i.test(ep.path))) {
      const bodyParams = effectiveParams.filter(p => p.location === 'json' || p.location === 'form')
      const qtyField = bodyParams.find(p => /^(?:qty|quantity|itemQty|count|seats?|amount)$/i.test(p.name))
      const numericIntent = Boolean(qtyField) ||
        /(?:cart|bag|basket|order|line|item|qty|quantity|seat|license|licence|wallet|credit|stock|inventory|amount|price|subtotal|total)/i.test(ep.path)
      if (numericIntent && (qtyField || (singlePlaceholder && collectionCreator && detailGet))) {
        add({
          endpoint: ep, probeClass: 'workflow_invariant', method: writeMethod(ep),
          quantityField: qtyField?.name ?? 'qty',
          ...(singlePlaceholder && collectionCreator ? { createPath: collectionCreator.path, producerBody: creatorBody(collectionCreator) } : {}),
          ...(singlePlaceholder && detailGet ? { workflowReadPath: detailGet } : {}),
        })
        workflowReadHypotheses += 1
      }
    }
    // Client-trusted numeric value: a write that shares its path with a readable summary. The probe
    // compares the summary before/after a price-bearing write, so a server that ignores the field
    // (the hardened twin) never signals.
    if (!isGet && (method === 'PATCH' || method === 'PUT') && priceTrustHypotheses < 3 &&
        getPaths.includes(ep.path) &&
        /(?:subscription|billing|plan|price|wallet|payment|invoice|license|licence|seat|account|tenant)/i.test(ep.path)) {
      add({ endpoint: ep, probeClass: 'workflow_invariant', method: writeMethod(ep), priceTrust: true, workflowReadPath: ep.path })
      priceTrustHypotheses += 1
    }
    // Aggregate cap: repeating a settled money mutation creates a second settled record. Only
    // eligible when the same resource family exposes a terminal action route (approve/confirm/...)
    // or the route is explicitly money-shaped, which keeps ordinary creates out of the probe.
    if (!isGet && method === 'POST' && !pathHasPlaceholder && workflowRepeatHypotheses < 4 && pathSegs.length >= 2) {
      const familyRoot = `/${pathSegs.slice(0, 2).join('/')}`
      const familyHasAction = endpoints.some(e =>
        e.method.toUpperCase() === 'POST' && hasPathPlaceholder(e.path) && e.path.startsWith(`${familyRoot}/`) &&
        actionStepPath.test(lastPathSegment(e.path)))
      const moneyShaped = /(refund|reversal|credit|payout|withdraw|settle|charge|payment|deposit|reimburse)/i.test(ep.path) ||
        /(?:lines?|items?)$/i.test(ep.path) && familyHasAction
      if (familyHasAction || moneyShaped) {
        add({ endpoint: ep, probeClass: 'workflow_invariant', method: writeMethod(ep), repeatMutation: true })
        workflowRepeatHypotheses += 1
      }
    }
    // Race: a single-use value or a read-then-write balance/stock consumed by this write. Prefer a
    // sibling producer (mint) route; balance mode reads the resource/detail route instead.
    const raceablePath = /(redeem|claim|consume|spend|credit|voucher|coupon|apply|activate|transfer|withdraw|checkout|purchase|refund|reserve|oversell|overspend)/i
    if (!isGet && method === 'POST' && raceablePath.test(ep.path)) {
      const singleUse = effectiveParams.find(p => singleUseParam.test(p.name) && (p.location === 'json' || p.location === 'form' || p.location === 'query'))
      const numeric = effectiveParams.find(p => /^(?:amount|amount_?cents|qty|quantity|count|value|total|price)$/i.test(p.name) &&
        (p.location === 'json' || p.location === 'form' || p.location === 'query'))
      const consume = singleUse ?? numeric
      if (consume) {
        const segs = ep.path.split('?')[0].split('/').filter(Boolean)
        const parentPath = segs.length > 1 ? `/${segs.slice(0, -1).join('/')}` : null
        const siblings = endpoints.filter(e => e.method.toUpperCase() === 'POST' && e.path !== ep.path &&
          e.path.split('?')[0].split('/').filter(Boolean).slice(0, -1).join('/') === segs.slice(0, -1).join('/'))
        const producer = siblings.find(e => /(voucher|coupon|mint|create|issue|generate|invite|token|credit|key|cart)s?$/i.test(e.path))
        const resource = parentPath ? getPaths.filter(p => p === parentPath || (hasPathPlaceholder(p) && p.split('/').slice(0, -1).join('/') === parentPath)).sort((a, b) => Number(hasPathPlaceholder(b)) - Number(hasPathPlaceholder(a)))[0] : undefined
        const mode: 'single_use' | 'balance' = singleUse ? 'single_use' : 'balance'
        const balanceEligible = mode === 'single_use' || !/(?:voucher|coupon|apply|reapply|grant|invite)/i.test(ep.path)
        const creator = siblings
          .filter(e => !hasPathPlaceholder(e.path) && /(voucher|coupon|mint|create|issue|generate|invite|token|credit|key|cart|bag|order)s?$/i.test(e.path))
          .map(e => e.path)[0]
          ?? (segs.length > 2
            ? endpoints.find(e => e.method.toUpperCase() === 'POST' && !hasPathPlaceholder(e.path) && e.path === `/${segs.slice(0, -2).join('/')}`)?.path
            : undefined)
        if (balanceEligible && (mode === 'single_use' ? Boolean(producer) : Boolean(resource || numeric))) {
          raceCandidates.push({
            ep, param: consume, mode,
            ...(producer && mode === 'single_use' ? { createPath: producer.path } : creator ? { createPath: creator } : {}),
            ...(resource ? { resourcePath: resource } : {}),
            score: (singleUse ? 3 : 1) + (producer ? 1 : 0) + (resource ? 1 : 0),
          })
        }
      }
    }

    if (caps.newProbeClasses) {
      // Object updates: overpost privileged fields and prove persistence with a read-back. This
      // covers per-object records whose field names the surface never exposed.
      if (!isGet && (method === 'PATCH' || method === 'PUT') && pathHasPlaceholder &&
          !params.some(p => p.location === 'json' || p.location === 'form') && massHypotheses < 10) {
        const key = `mass_assignment|${ep.path}|${method}`
        if (!writeProbeSeen.has(key)) {
          writeProbeSeen.add(key)
          add({ endpoint: ep, probeClass: 'mass_assignment', method: writeMethod(ep) })
          massProbePaths.add(ep.path)
          massHypotheses += 1
        }
      }
      if (accountPath.test(ep.path) && !pathHasPlaceholder) {
        const key = `mass_assignment|${ep.path}|${writeMethod(ep)}`
        if (!writeProbeSeen.has(key)) {
          writeProbeSeen.add(key)
          add({ endpoint: ep, probeClass: 'mass_assignment', method: isGet ? 'PATCH' : writeMethod(ep) })
        }
      }
      // Cache probes: parameterless GETs plus cacheable GETs that carry query parameters (an
      // unkeyed query string is itself a deception/poisoning vector). Templated public/share views
      // are included (their id is resolved before probing) because cross-actor cache reuse lives
      // there. Still bounded below.
      const paramlessGet = isGet && !pathHasPlaceholder && params.length === 0
      const cacheableGet = isGet && (!pathHasPlaceholder || /(?:public|share|cache|preview|store|product|catalog|report|account|profile|dashboard|billing|settings|\/me\b)/i.test(ep.path)) && cacheablePath.test(ep.path)
      if ((paramlessGet || cacheableGet) && !graphqlPath.test(ep.path) && !/\.well-known\//i.test(ep.path)) {
        cacheCandidates.push(ep)
      }
      // JWT/OAuth protocol auditing only runs on auth-shaped routes; running it on every parameterless
      // GET burns a large fraction of the request budget with no new evidence.
      if (!pathHasPlaceholder && caps.authMutation && (isGet || method === 'POST') && (authishPath.test(ep.path) || oauthPath.test(ep.path)) &&
          !/(?:logout|signout|revoke|delete|reset|forgot)/i.test(ep.path)) {
        add({ endpoint: ep, probeClass: 'auth_protocol_audit', method: isGet ? 'GET' : 'POST' })
      }
      if ((xmlPath.test(ep.path) || isXmlImportRoute(ep)) && !isGet && !params.some(p => p.location === 'xml')) {
        const key = `xxe_canary|${ep.path}`
        if (!writeProbeSeen.has(key)) {
          writeProbeSeen.add(key)
          add({ endpoint: ep, probeClass: 'xxe_canary', method: writeMethod(ep) })
        }
      }

      // CSRF state-change: a session-authenticated mutation whose read route exposes the field.
      // Create-shaped form posts (refunds, charge creation) have no list route; their read-back is the
      // created object's detail route (response id), so they are collected and ranked with the rest.
      if (
        !isGet && method !== 'DELETE' &&
        !serverActionPath.test(ep.path) && !csrfSkipPath.test(ep.path) && !graphqlPath.test(ep.path) &&
        csrfActionPath.test(ep.path)
      ) {
        const readPath = csrfReadPathFor(ep.path, getPaths)
        const hasCsrfParam = ep.params.some(p => p.isCsrf)
        const actionish = /(trigger|approve|confirm|transfer|invite|refund|redeem|accept|settings|profile)/i.test(ep.path)
        const stateBody = effectiveParams.some(p =>
          (p.location === 'json' || p.location === 'form') &&
          /name|title|label|note|description|status|state|value|amount|tier|plan|enabled|active/i.test(p.name))
        const createCandidate = !readPath && !pathHasPlaceholder && (method === 'POST' || method === 'PUT')
        const detailRead = createCandidate
          ? getPaths.find(p => hasPathPlaceholder(p) && p.split('/').filter(Boolean).slice(0, -1).join('/') === ep.path.split('?')[0].split('/').filter(Boolean).join('/'))
          : undefined
        const moneyShaped = /(refund|reversal|payout|disburse|charge|credit|withdraw|transfer|payment|settle|reimburse)/i.test(ep.path)
        if ((readPath || detailRead) && (
          (moneyShaped && Boolean(detailRead)) ||
          ((hasCsrfParam || actionish) && (hasCsrfParam || stateBody || actionish))
        )) {
          csrfCandidates.push({ ep, readPath: readPath ?? null, create: Boolean(!readPath && detailRead), score: (hasCsrfParam ? 2 : 0) + (stateBody ? 2 : 0) + (actionish ? 1 : 0) + (detailRead ? 1 : 0) + (moneyShaped ? 3 : 0) })
        }
      }

      // Inbound webhook signature: receiver-shaped routes only (never management/list verbs).
      const whSegs = ep.path.split('?')[0].split('/').filter(Boolean)
      const whLast = whSegs[whSegs.length - 1] ?? ''
      const whPrev = whSegs[whSegs.length - 2] ?? ''
      const receiverShaped = webhookReceiverPath.test(whLast) || (whPrev !== '' && webhookReceiverPath.test(whPrev))
      if (!isGet && method !== 'DELETE' && receiverShaped) {
        webhookCandidates.push({ ep, score: (webhookReceiverPath.test(whLast) ? 2 : 1) + (/(receive|inbound)/i.test(ep.path) ? 1 : 0) })
      }

      // Open redirect: navigation-shaped GET routes plus any discovered URL-ish parameter.
      if (isGet && redirectHypotheses < maxRedirectHypotheses && (redirectPathHint.test(ep.path) || params.some(p => redirectParamName.test(p.name)))) {
        const discovered = params.filter(p => redirectParamName.test(p.name))
        const candidates = discovered.length > 0
          ? discovered
          : redirectCandidateParams(ep.path).map(name => ({ name, location: 'query', isObjectId: false, isCsrf: false }))
        for (const cand of candidates.slice(0, 4)) {
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
    // Collected writes are ranked and capped per class so early surface order cannot starve the
    // endpoints with the strongest state-change evidence.
    for (const c of csrfCandidates.sort((a, b) => b.score - a.score || a.ep.path.length - b.ep.path.length).slice(0, maxCsrfHypotheses)) {
      add({ endpoint: c.ep, probeClass: 'csrf_state_change', method: writeMethod(c.ep), ...(c.create ? { csrfCreate: true } : {}) })
    }
    for (const c of webhookCandidates.sort((a, b) => b.score - a.score || a.ep.path.length - b.ep.path.length).slice(0, maxWebhookHypotheses)) {
      add({ endpoint: c.ep, probeClass: 'webhook_signature_bypass', method: writeMethod(c.ep) })
    }
    for (const c of raceCandidates.sort((a, b) => b.score - a.score || a.ep.path.length - b.ep.path.length).slice(0, maxRaceHypotheses)) {
      add({
        endpoint: c.ep, probeClass: 'race_burst', param: c.param, location: c.param.location as SurfaceParamLocation,
        method: writeMethod(c.ep), raceMode: c.mode,
        ...(c.createPath && c.mode === 'single_use' ? { raceProducerPath: c.createPath } : c.createPath ? { raceCreatePath: c.createPath } : {}),
        ...(c.resourcePath ? { raceResourcePath: c.resourcePath } : {}),
      })
    }
    for (const ep of graphqlCandidates) add({ endpoint: ep, probeClass: 'graphql_audit', method: 'POST' })

    // Cache probes are expensive (control + header matrix + victim verifies), so rank candidate
    // routes by cache-ish semantics and take a bounded top slice. Response cache headers are not
    // available at hypothesis-formation time, so this stays a heuristic.
    const ranked = [...cacheCandidates].sort((a, b) => {
      const score = (e: DiscoveredEndpoint) =>
        (cacheablePath.test(e.path) ? 2 : 0) +
        (/(?:public|share|cache|report|product|catalog|storefront|preview|account|profile|dashboard|billing)/i.test(e.path) ? 4 : 0) +
        (hasPathPlaceholder(e.path) ? 1 : 0) +
        (e.path.split('/').filter(Boolean).length >= 2 ? 1 : 0)
      return score(b) - score(a) || a.path.length - b.path.length || a.path.localeCompare(b.path)
    })
    for (const ep of ranked.slice(0, maxCacheEndpoints)) {
      add({ endpoint: ep, probeClass: 'cache_poison_deception', method: 'GET' })
    }
    // Rendered pages without a discovered parameter: arm the persisted browser only for the most
    // page-like candidates (root, profile/wizard/search-shaped, then shortest paths).
    const pages = [...pageCandidates]
      .sort((a, b) => a.score - b.score || a.ep.path.length - b.ep.path.length || a.ep.path.localeCompare(b.ep.path))
      .slice(0, maxBrowserPageHypotheses)
    for (const { ep } of pages) {
      add({ endpoint: ep, probeClass: 'xss_context', method: 'GET', browserEligible: true })
    }
  }
  // A self-profile PATCH is a mass-assignment surface; the authz matrix on the same route reads the
  // same generic success body and would bind to the wrong class (unattributed FP). Keep the
  // mass-assignment probe for those routes and drop the duplicate authz hypothesis.
  const selfProfilePath = /(?:^|\/)(?:users?|members?|staff|people|persons?|employees?|profile|operators?|agents?)(?:\/|$)/i
  const filteredHypotheses = hypotheses.filter(h =>
    !(h.probeClass === 'authz_matrix' && h.method !== 'GET' &&
      selfProfilePath.test(h.endpoint.path) && massProbePaths.has(h.endpoint.path)))
  const prioritized = filteredHypotheses
    .map((h, i) => ({ h, i }))
    .sort((a, b) => {
      // Workflow/state-changing probes must run while the owner session still has its original
      // role; auth-protocol audits (legacy login, token minting) can rotate/overwrite the session
      // identity, so they run last. Mass-assignment probes deliberately change their own profile.
      const phase = (h: Hypothesis): number =>
        h.probeClass === 'workflow_invariant' ? 0
          : h.probeClass === 'auth_protocol_audit' ? 1
            : h.probeClass === 'mass_assignment' ? 2
              : 3
      return phase(a.h) - phase(b.h) ||
        (a.h.probeClass === 'sqli_time_diff' ? 1 : 0) - (b.h.probeClass === 'sqli_time_diff' ? 1 : 0) ||
        a.i - b.i
    })
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
  /** The low-privileged (viewer) and elevated (admin) persona user ids, when the lab exposes them. */
  viewerUserId?: string
  adminUserId?: string
  /** Cached identifier pools harvested from collection routes. */
  idCache?: Map<string, string[]>
  /** Endpoints discovered in this run (used to resolve body field values from the surface). */
  endpoints?: readonly DiscoveredEndpoint[]
  /** Cached GET-response field harvests keyed by path. */
  fieldCache?: Map<string, JsonHarvest>
  /** Cached identity/session claims (email, id, tenant/store) for forged-token audits. */
  identityCache?: Map<string, string[]>
  /** Loopback service origins harvested from config/discovery routes (in-band SSRF proof). */
  internalTargetCache?: Map<string, string[]>
}

/** Target-observed context (baseline value, XML/GraphQL shape, seed query) resolved for a hypothesis. */
export interface ResolvedContext {
  baseline?: string
  xmlTemplate?: string
  graphqlQuery?: string
  seedQuery?: string
  /** For an inferred parameter name: true/false once a differential proved whether the app reads it. */
  paramActive?: boolean
  /** Explicit anti-CSRF header learned from a token-issuing route (bound to the persona session). */
  csrfHeader?: Record<string, string>
}

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
 * values observed on the target's own surface; `kovo` is only the last resort for free text.
 */
export function siblingValue(name: string, env?: ProbeEnv): string | number | boolean {
  const lower = name.toLowerCase()
  if (/(?:^|_)(?:is|has)_|enabled|active|verified|admin|paid|approved|marketing|optin|boolean|flag$/.test(lower)) return true
  if (/(uuid|guid)/.test(lower)) return '00000000-0000-4000-8000-000000000001'
  if (/email/.test(lower)) return 'kovo@example.test'
  if (/(date|time|timestamp|_at)$/.test(lower)) return '2026-01-01T00:00:00Z'
  if (/(qty|quantity|count|limit|amount|price|total|number|num|page|size|offset|age)/.test(lower)) return 1
  if (/(url|uri|link|callback|webhook|redirect|target)$/.test(lower)) return 'http://kovo-control.invalid/'
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
  return 'kovo'
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
        const idKey = /(?:^|_)(?:id|uuid|uid|sku|slug|key|ref|code|token)$/i.test(key)
        const ownerKey = /(?:^|_)(?:project|owner|tenant|team|org|account|parent|user|member)$/i.test(key)
        if ((idKey || (ownerKey && looksLikeIdSegment(s))) && s.length <= 128 && s.length > 0) ids.push(s)
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
/**
 * A money-shaped body for aggregate-cap probes: harvest a numeric total/amount from the target's
 * own readable collections (orders, payments, invoices) so a second settlement actually exceeds the
 * captured total. Returns null when no monetary value is exposed — the probe then stays silent
 * instead of submitting a finding without a real bound.
 */
export async function harvestMoneyBody(env: ProbeEnv, routePath: string): Promise<Record<string, unknown> | null> {
  const segs = routePath.split('?')[0].split('/').filter(Boolean)
  const root = segs.length > 1 ? `/${segs.slice(0, 2).join('/')}` : `/${segs[0] ?? ''}`
  const ranked = (env.endpoints ?? [])
    .filter(e => e.method.toUpperCase() === 'GET' && !hasPathPlaceholder(e.path) &&
      !/\.(?:js|css|json|xml|txt|map|svg|ico|png|jpe?g|gif|webp)$/i.test(e.path.split('?')[0]) &&
      !/(?:openapi|swagger|docs|spec)/i.test(e.path))
    .filter(e => e.path === root || e.path.startsWith(`${root}/`) ||
      /(?:orders?|purchases?|payments?|invoices?|billing|charges?|transactions?|refunds?)/i.test(e.path))
    .sort((a, b) =>
      Number(/(?:orders?|purchases?|payments?|invoices?|billing|charges?|transactions?)/i.test(b.path)) -
      Number(/(?:orders?|purchases?|payments?|invoices?|billing|charges?|transactions?)/i.test(a.path)) ||
      a.path.length - b.path.length)
    .slice(0, 3)
  const maxByField = new Map<string, number>()
  const walk = (node: unknown, depth: number): void => {
    if (depth > 5 || !node || typeof node !== 'object') return
    if (Array.isArray(node)) { for (const item of node.slice(0, 20)) walk(item, depth + 1); return }
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      if (typeof value === 'number' && Number.isFinite(value) && value > 0 && value <= 1_000_000_000 &&
          /^(?:amount|amountCents|amount_cents|total|totalCents|total_cents|price|priceCents|value|cents|sum)$/i.test(key)) {
        const current = maxByField.get(key) ?? 0
        if (value > current) maxByField.set(key, value)
      } else if (value && typeof value === 'object') {
        walk(value, depth + 1)
      }
    }
  }
  for (const candidate of ranked) {
    try {
      const ex = await env.broker.executeHttp({
        origin: env.origin, method: 'GET', pathAndQuery: candidate.path, persona: env.owner,
        followRedirects: false, timeoutMs: 8_000,
      }, env.grant, env.signal)
      if (ex.status < 200 || ex.status >= 300) continue
      let parsed: unknown
      try { parsed = JSON.parse(ex.body) } catch { continue }
      walk(parsed, 0)
    } catch { /* readable collections are best-effort */ }
    if (maxByField.size > 0) break
  }
  if (maxByField.size === 0) return null
  const [field, value] = [...maxByField.entries()].sort((a, b) => b[1] - a[1])[0]!
  return { [field]: Math.floor(value) }
}

export async function idPool(env: ProbeEnv, pathTemplate?: string, persona = env.owner): Promise<string[]> {  const cache = (env.idCache ??= new Map())
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
        // A templated detail route harvests from its collection; a pathless collection route
        // harvests from itself (its records carry the owner/tenant ids filters expect).
        if (idx > 0) return `/${segs.slice(0, idx).join('/')}`
        return hasPathPlaceholder(pathTemplate) ? null : pathTemplate.split('?')[0]
      })()
    : null
  if (collection) {
    const cacheKey = `${persona ?? ''}|${collection}`
    let harvested = cache.get(cacheKey)
    if (!harvested) {
      harvested = []
      try {
        const ex = await env.broker.executeHttp({
          origin: env.origin, method: 'GET', pathAndQuery: collection, persona,
          followRedirects: false, timeoutMs: 8_000,
        }, env.grant, env.signal)
        if (ex.status >= 200 && ex.status < 300) harvested = harvestJson(ex.body).ids
      } catch { /* collection may not exist */ }
      cache.set(cacheKey, harvested)
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
  if (/email/.test(lower)) return 'kovo@example.test'
  if (/(url|uri|link|callback|webhook|redirect)/.test(lower)) return 'http://kovo-control.invalid/'
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
  return 'kovo'
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

/**
 * Learn an anti-CSRF token bound to the persona's own session. Some apps issue the token from a
 * dedicated GET while the persona authenticates with a vault cookie; the broker's jar-level bind
 * then targets a different session, so the explicit header is needed for authorized write probes.
 */
async function csrfHeaderFor(env: ProbeEnv): Promise<Record<string, string> | undefined> {
  if (!env.caps.sessionAndCsrf) return undefined
  const cache = (env.ctxCache ??= new Map())
  const cached = cache.get('csrf-header')
  if (cached) return cached.csrfHeader
  const route = (env.endpoints ?? []).find(e =>
    e.method.toUpperCase() === 'GET' && !hasPathPlaceholder(e.path) &&
    /(?:^|[/_-])(?:csrf|xsrf|session|token)(?:$|[/_-])/i.test(e.path),
  )
  if (!route) return undefined
  const out: ResolvedContext = {}
  try {
    const ex = await env.broker.executeHttp({
      origin: env.origin, method: 'GET', pathAndQuery: route.path, persona: env.owner,
      followRedirects: false, timeoutMs: 8_000,
    }, env.grant, env.signal)
    if (ex.status >= 200 && ex.status < 300) {
      const m = /"(?:csrfToken|csrf_token|csrf|xsrfToken|xsrf_token)"\s*:\s*"([A-Za-z0-9._~+/-]{8,256})"/.exec(ex.body)
      if (m) out.csrfHeader = { 'x-csrf-token': m[1] }
    }
  } catch { /* no token route reachable */ }
  cache.set('csrf-header', out)
  return out.csrfHeader
}

/**
 * Identity claims observed on the target's own session/me routes. Used to build a *forged* token
 * payload (subject/tenant) without ever reading persona credentials; only scalar JSON values are
 * harvested and the values stay inside the probe.
 */
async function identityClaims(env: ProbeEnv, persona = env.owner): Promise<Record<string, string>> {
  const cache = (env.identityCache ??= new Map<string, string[]>())
  const cacheKey = `claims:${persona ?? ''}`
  const cached = cache.get(cacheKey)
  if (cached) return Object.fromEntries(cached.map(v => v.split('=', 2) as [string, string]))
  const routes = (env.endpoints ?? []).filter(e =>
    e.method.toUpperCase() === 'GET' && !hasPathPlaceholder(e.path) &&
    /(?:^|[/_-])(?:me|session|whoami|userinfo|profile|identity|account)(?:$|[/_-])/i.test(e.path),
  ).slice(0, 3)
  const claims: Record<string, string> = {}
  const interesting = /^(?:email|mail|id|uid|userId|user_id|sub|actor|tenant|store|org|organization|workspace|team|role|scope)$/i
  const walk = (node: unknown, depth: number): void => {
    if (depth > 4 || !node || typeof node !== 'object' || Array.isArray(node)) return
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      if (v && typeof v === 'object') { walk(v, depth + 1); continue }
      if (!interesting.test(k) || (typeof v !== 'string' && typeof v !== 'number')) continue
      const s = String(v)
      if (s.length === 0 || s.length > 96 || /[\\\r\n]/.test(s)) continue
      if (!claims[k]) claims[k] = s
    }
  }
  for (const route of routes) {
    try {
      const ex = await env.broker.executeHttp({
        origin: env.origin, method: 'GET', pathAndQuery: route.path, persona,
        followRedirects: false, timeoutMs: 8_000,
      }, env.grant, env.signal)
      if (ex.status < 200 || ex.status >= 300) continue
      walk(JSON.parse(ex.body), 0)
    } catch { /* route may not be readable */ }
  }
  cache.set(cacheKey, Object.entries(claims).map(([k, v]) => `${k}=${v}`))
  return claims
}

/**
 * Loopback service origins published by the target's own configuration/discovery routes. These are
 * legitimate egress destinations for the app (service discovery), so a sink that fetches them proves
 * server-side reachability *in-band* when no OOB callback port is registered.
 */
async function harvestInternalTargets(env: ProbeEnv): Promise<string[]> {
  const cache = (env.internalTargetCache ??= new Map())
  const cached = cache.get('targets')
  if (cached) return cached
  const routes = (env.endpoints ?? []).filter(e =>
    e.method.toUpperCase() === 'GET' && !hasPathPlaceholder(e.path) &&
    /(?:^|[/_-])(?:config|settings|integration|metadata|services?|discovery|webhook|hooks|health|status|info|bootstrap|session)(?:$|[/_-])/i.test(e.path),
  ).slice(0, 6)
  const found = new Set<string>()
  const collect = (node: unknown, depth: number): void => {
    if (depth > 5 || node === null || node === undefined) return
    if (typeof node === 'string') {
      if (/^https?:\/\/(?:127\.0\.0\.1|localhost|\[::1\]):\d{2,5}(?:\/|$)/i.test(node) && node.length <= 256) found.add(node)
      return
    }
    if (Array.isArray(node)) { for (const v of node.slice(0, 20)) collect(v, depth + 1); return }
    if (typeof node === 'object') for (const v of Object.values(node as Record<string, unknown>)) collect(v, depth + 1)
  }
  for (const route of routes) {
    for (const persona of [env.owner, env.admin]) {
      if (!persona) continue
      try {
        const ex = await env.broker.executeHttp({
          origin: env.origin, method: 'GET', pathAndQuery: route.path, persona,
          followRedirects: false, timeoutMs: 8_000,
        }, env.grant, env.signal)
        if (ex.status !== 200) continue
        try { collect(JSON.parse(ex.body), 0) } catch { collect(ex.body, 0) }
      } catch { /* ignore */ }
      if (found.size >= 4) break
    }
    if (found.size >= 4) break
  }
  const out = [...found].slice(0, 4)
  cache.set('targets', out)
  return out
}

/**
 * Root field names and other-actor object ids for a GraphQL endpoint without SDL/introspection.
 * Roots come from the discovered collection nouns; ids are harvested from the same collections as
 * the *other* persona so a cross-persona read has an object the caller should not own.
 */
export async function graphqlDiscoverySeeds(env: ProbeEnv): Promise<{ roots: string[]; ids: string[]; byRoot: Record<string, string[]> }> {
  const collections = (env.endpoints ?? []).filter(e =>
    e.method.toUpperCase() === 'GET' && !hasPathPlaceholder(e.path) &&
    !/(?:search|find|filter|query|me|session|health|config|csrf|token)/i.test(e.path),
  )
  const roots = new Set<string>()
  const rootPaths = new Map<string, string>()
  for (const ep of collections.slice(0, 20)) {
    const tail = lastPathSegment(ep.path)
    if (!/^[a-z][a-z0-9-]{2,24}$/i.test(tail) || /^(?:items|list|all|data|stats)$/i.test(tail)) continue
    const singular = tail.replace(/ies$/i, 'y').replace(/s$/i, '')
    for (const name of [singular, tail]) {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) continue
      roots.add(name)
      if (!rootPaths.has(name)) rootPaths.set(name, ep.path)
    }
  }
  const ids: string[] = []
  const byRoot: Record<string, string[]> = {}
  const persona = env.other ?? env.owner
  for (const [root, path] of rootPaths) {
    try {
      const ex = await env.broker.executeHttp({
        origin: env.origin, method: 'GET', pathAndQuery: path, persona,
        followRedirects: false, timeoutMs: 8_000,
      }, env.grant, env.signal)
      if (ex.status >= 200 && ex.status < 300) {
        const found = harvestJson(ex.body).ids.slice(0, 2)
        if (found.length > 0) byRoot[root] = found
        ids.push(...found)
      }
    } catch { /* ignore */ }
    if (ids.length >= 6) break
  }
  return { roots: [...roots].slice(0, 8), ids: idShaped(ids).slice(0, 4), byRoot }
}

/**
 * Delivery body for a receiver that exposes no management/list route. Field names come from the
 * receiver's own parameters and generic event vocabulary; tenant/store values come from the target's
 * session claims. This is enough to exercise signature handling without guessing the secret.
 */
async function fallbackWebhookBody(h: Hypothesis, env: ProbeEnv): Promise<Record<string, unknown> | null> {
  const claims = await identityClaims(env)
  const tenant = claims.store ?? claims.tenant ?? claims.org ?? claims.workspace ?? claims.team ?? ''
  const paramNames = h.endpoint.params.filter(p => p.location === 'json' || p.location === 'form').map(p => p.name)
  const body: Record<string, unknown> = {}
  for (const name of paramNames) {
    if (/token|sig|signature|hmac/i.test(name)) continue
    if (/ts|timestamp|time/i.test(name)) body[name] = Math.floor(Date.now() / 1000)
    else if (/backup|job|run|event|order|id|ref|endpoint|hook/i.test(name)) body[name] = `gwh${shortToken(8)}`
    else if (/amount|total|value|price/i.test(name)) body[name] = 1
    else if (/store|tenant|org|account|team/i.test(name)) body[name] = tenant || `gwh${shortToken(4)}`
    else body[name] = 'kovo.probe'
  }
  if (tenant && !Object.keys(body).some(k => /store|tenant|org|account|team/i.test(k))) body.store = tenant
  if (!Object.keys(body).some(k => /event|type/i.test(k))) body.event = { type: 'kovo.probe', id: `gwh${shortToken(8)}` }
  body.ts = body.ts ?? Math.floor(Date.now() / 1000)
  return Object.keys(body).length > 0 ? body : null
}

async function serverActionBodies(h: Hypothesis, env: ProbeEnv): Promise<unknown[]> {
  const tokens = lastPathSegment(h.endpoint.path).replace(/([a-z0-9])([A-Z])/g, '$1 $2').split(/[^A-Za-z0-9]+/)
    .filter(t => t.length > 1 && !/^(update|create|make|set|get|do|handle|save|change|toggle|the|for|with)$/i.test(t))
  const fields = tokens.map(t => t.toLowerCase())
  const positional: unknown[] = []
  const objectBody: Record<string, unknown> = {}
  for (const token of fields.slice(0, 4)) {
    let value: string | number | boolean = 'kovo'
    if (/(org|tenant|team|group|account|company|workspace)/i.test(token)) {
      value = (await surfaceValueFor(token, env)) ?? (await idPool(env))[0] ?? '1'
    } else if (/(plan|tier)/i.test(token)) {
      value = (await surfaceValueFor(token, env)) ?? 'kovo'
    } else if (/(id|ref|key)$/i.test(token)) {
      value = (await idPool(env))[0] ?? '1'
    }
    positional.push(value)
    objectBody[token] = value
    objectBody[`${token}Id`] = value
  }
  return [positional, objectBody]
}

// ---------------------------------------------------------------------------
// Function-state readback inference
// ---------------------------------------------------------------------------

/**
 * Verbs carried by a function/server-action name. Only resource/state nouns remain after filtering,
 * so `updateOrgPlan` yields `org`,`plan` without any app-specific vocabulary.
 */
const functionVerbToken = /^(?:update|create|make|set|get|do|handle|save|change|toggle|the|for|with|new|add|edit|apply|enable|disable|remove|delete|reset|assign|invite|grant|revoke|submit|send|start|stop|run|test|trigger|verify|approve|reject|publish|archive|restore|move|rename|copy|sync|refresh|reload|clear|close|open|lock|unlock|validate|confirm|cancel|complete|finish|promote|demote|ban|unban|suspend|activate|deactivate|mark|patch|put|post|exec|invoke)$/i
/** Request fields that select *which* resource a function acts on (never the state under test). */
const selectorField = /^(?:id|ref|key|code|token|name|flag|field|type|kind|slug|resource|record|object|entity|uid|uuid|org|tenant|team|account|workspace|project|user|owner|target|selector|path|url|email)$/i
/** Request fields that carry the state a function changes. */
const stateField = /(?:enabled|active|status|state|plan|tier|role|value|amount|price|total|count|qty|quantity|mode|level|visibility|public|private|locked|verified|admin|feature|setting|config|seats?|credits?|balance)$/i
/** Values that legitimately change between two reads without proving a state mutation. */
const volatileField = /^(?:updated?at|updated?_?on|created?at|created?_?on|timestamp|ts|etag|last_?modified|request_?id|trace_?id|nonce|csrf|xsrf|expires?|exp|iat|jti|date|time|version|revision|hash|signature|token)$/i

/** Resource/state tokens carried by a function's own name (`updateOrgPlan` -> `org`, `plan`). */
export function actionStateTokens(actionPath: string): string[] {
  return lastPathSegment(actionPath)
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .map(token => token.toLowerCase())
    .filter(token => token.length > 1 && !functionVerbToken.test(token))
}

/**
 * Sibling GET routes that can expose the state a function mutates, derived only from the target's
 * own route map: the discovered reads whose path segments name the same resource/state as the
 * function name (`updateOrgPlan` -> `/api/v1/org`, `/api/v1/org/:id`). Collections rank before
 * deeper paths so a concrete status route wins over an unrelated nested listing.
 */
export function inferObservableReadRoutes(actionPath: string, getPaths: readonly string[]): string[] {
  const tokens = actionStateTokens(actionPath)
  if (tokens.length === 0) return []
  const scored: Array<{ path: string; score: number; depth: number }> = []
  const bare = actionPath.split('?')[0]
  for (const candidate of getPaths) {
    const candidatePath = candidate.split('?')[0]
    if (candidatePath === bare) continue
    const segments = candidatePath.split('/').filter(Boolean).map(segment => segment.toLowerCase())
    if (segments.length === 0) continue
    let score = 0
    for (const token of tokens) {
      const singular = token.replace(/s$/, '')
      if (segments.some(segment => segment === token || segment.replace(/s$/, '') === singular)) score += 2
    }
    if (score === 0) continue
    scored.push({ path: candidatePath, score, depth: segments.length })
  }
  return scored
    .sort((a, b) => b.score - a.score || a.depth - b.depth || a.path.length - b.path.length || a.path.localeCompare(b.path))
    .map(candidate => candidate.path)
}

/** Flatten a JSON value to scalar paths (NUL-joined) with their raw values (bounded). */
export function flattenScalars(value: unknown, prefix: string[] = [], out: Map<string, unknown> = new Map()): Map<string, unknown> {
  if (out.size >= 256 || prefix.length > 8) return out
  if (Array.isArray(value)) {
    value.slice(0, 16).forEach((child, index) => flattenScalars(child, [...prefix, String(index)], out))
    return out
  }
  if (value && typeof value === 'object') {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) flattenScalars(child, [...prefix, key], out)
    return out
  }
  if (value !== null && value !== undefined) out.set(prefix.join('\u0000'), value)
  return out
}

/** A distinct, format-preserving counterpart of a mutated value (never destructive). */
export function alternateStateValue(value: unknown, tag: string): unknown {
  const suffix = tag.replace(/[^a-z0-9]/gi, '').slice(0, 8) || 'alt'
  if (typeof value === 'boolean') return !value
  if (typeof value === 'number' && Number.isFinite(value)) return value === 0 ? 1 : Math.trunc(value) + 1
  if (typeof value === 'string') {
    if (/^\d{1,10}$/.test(value)) return String(Number(value) + 9_000_001).slice(0, 12)
    if (value.length > 0 && value.length <= 24 && /^[A-Za-z_][A-Za-z0-9_.-]*$/.test(value)) return `${value}_${suffix}`
    return `kovo_${suffix}`
  }
  return value
}

function isSelectorField(key: string): boolean {
  return selectorField.test(key) || /(?:Id|_id|ID)$/.test(key) || /^[a-z]+id$/i.test(key)
}

/**
 * Build a benign control body and the state-changing probe body from the observed write body.
 * Selectors (the resource the function targets) are preserved; state fields are alternated so the
 * control read and the post-probe read are guaranteed to differ. Returns null when no field can be
 * safely varied.
 */
export function buildStateVariants(
  body: unknown,
  readPaths: ReadonlySet<string>,
): { controlBody: unknown; probeBody: unknown } | null {
  const seenKey = new Set<string>()
  for (const path of readPaths) for (const part of path.split('\u0000')) seenKey.add(part.toLowerCase())
  const keep = (key: string, value: unknown): boolean =>
    isSelectorField(key) || (typeof value === 'string' && seenKey.has(value.toLowerCase()) && !stateField.test(key))
  if (Array.isArray(body)) {
    // RPC convention: the first positional argument names the target resource, the rest are state.
    if (body.length < 2) return null
    const [target, ...rest] = body
    if (rest.every(value => value === undefined)) return null
    return {
      controlBody: [target, ...rest.map(value => alternateStateValue(value, 'ctrl'))],
      probeBody: [...body],
    }
  }
  if (body && typeof body === 'object') {
    const entries = Object.entries(body as Record<string, unknown>)
    if (entries.length === 0) return null
    const controlBody: Record<string, unknown> = {}
    const probeBody: Record<string, unknown> = {}
    let varied = 0
    for (const [key, value] of entries) {
      probeBody[key] = value
      if (keep(key, value)) {
        controlBody[key] = value
        continue
      }
      controlBody[key] = alternateStateValue(value, 'ctrl')
      varied += 1
    }
    return varied > 0 ? { controlBody, probeBody } : null
  }
  return null
}

export interface FunctionStateReadback {
  /** Concrete GET route that reports the mutated function state. */
  path: string
  controlBody: unknown
  probeBody: unknown
  /** Scalar path inside the read body that changed (e.g. ["flags","kovo"]). */
  fieldPath: string[]
  controlValue?: unknown
  probeValue: unknown
  /** Identifier binding: a read-body field whose value is the function's target resource id. */
  bindingPath?: string[]
  bindingValue?: string
}

function selectorOf(body: unknown): string | null {
  if (Array.isArray(body)) {
    const first = body[0]
    return typeof first === 'string' && first.length > 0 && first.length <= 128 ? first : null
  }
  if (body && typeof body === 'object') {
    for (const [key, value] of Object.entries(body as Record<string, unknown>)) {
      if (!isSelectorField(key)) continue
      if (typeof value === 'string' && value.length > 0 && value.length <= 128) return value
    }
  }
  return null
}

/** First scalar path in the read body whose leaf names a resource id and equals the selector. */
function bindingFor(readJson: unknown, selector: string | null): { path: string[]; value: string } | null {
  if (!selector) return null
  for (const [flat, value] of flattenScalars(readJson)) {
    if (String(value) !== selector) continue
    const path = flat.split('\u0000')
    const leaf = path[path.length - 1] ?? ''
    if (/^(?:id|ref|key|code|uid|uuid|slug)$/i.test(leaf) || /(?:Id|_id)$/.test(leaf)) return { path, value: selector }
  }
  return null
}

interface ScalarDelta { path: string[]; before?: unknown; after?: unknown }

/** Scalars that differ between two reads, preferring explicit state fields over noisy metadata. */
export function scalarDeltas(before: unknown, after: unknown): ScalarDelta[] {
  const left = flattenScalars(before)
  const right = flattenScalars(after)
  const out: ScalarDelta[] = []
  for (const [flat, value] of right) {
    const path = flat.split('\u0000')
    if (volatileField.test(path[path.length - 1] ?? '')) continue
    if (!left.has(flat)) out.push({ path, after: value })
    else if (left.get(flat) !== value) out.push({ path, before: left.get(flat), after: value })
  }
  for (const [flat] of left) {
    if (right.has(flat)) continue
    const path = flat.split('\u0000')
    if (volatileField.test(path[path.length - 1] ?? '')) continue
    out.push({ path, before: left.get(flat) })
  }
  const rank = (delta: ScalarDelta): number => {
    const leaf = delta.path[delta.path.length - 1] ?? ''
    return (stateField.test(leaf) ? 0 : 2) + (delta.before !== undefined && delta.after !== undefined ? 0 : 1)
  }
  return out.sort((a, b) => rank(a) - rank(b) || a.path.length - b.path.length || a.path.join('.').localeCompare(b.path.join('.')))
}

/**
 * Observe a mutating function's own state: read its observable status route (or a sibling read
 * inferred from the function name), drive a benign control value, invoke the same function as the
 * lower-privileged actor, and read the state again. A non-empty delta is the persistence evidence a
 * mutation echo can never provide. Only GET reads are used for the checkpoints.
 */
async function observeFunctionStateReadback(
  h: Hypothesis,
  env: ProbeEnv,
  owner: string | undefined,
  other: string | undefined,
  anomalies: readonly Record<string, unknown>[],
  watch: (ex: BrokerExchangeResult) => void,
): Promise<FunctionStateReadback | null> {
  if (!owner || !other) return null
  const bodyTemplate = anomalies.find(anomaly => anomaly.type === 'unauthorized_access' && String(anomaly.method ?? '') !== 'GET')?.bodyTemplate
  if (bodyTemplate === undefined || bodyTemplate === null) return null
  const getPaths = [...new Set((env.endpoints ?? []).filter(endpoint => endpoint.method.toUpperCase() === 'GET').map(endpoint => endpoint.path))]
  const ownPath = h.endpoint.path.split('?')[0]
  const candidates = [ownPath, ...inferObservableReadRoutes(ownPath, getPaths)]
    .filter((candidate, index, all) => all.indexOf(candidate) === index && !candidate.startsWith('//'))
    .slice(0, 3)
  const selector = selectorOf(bodyTemplate)
  const stateWriteMethod: 'POST' | 'PUT' | 'PATCH' = h.method === 'PUT' || h.method === 'PATCH' ? h.method : 'POST'
  const send = async (method: 'GET' | 'POST' | 'PUT' | 'PATCH', pathAndQuery: string, persona: string, body?: unknown) => {
    const ex = await env.broker.executeHttp({
      origin: env.origin, method, pathAndQuery, persona,
      ...(body !== undefined ? { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : {}),
      ...(env.caps.sessionAndCsrf ? { session: env.session } : {}),
      followRedirects: false, timeoutMs: 8_000,
    }, env.grant, env.signal)
    watch(ex)
    return ex
  }
  for (const candidate of candidates) {
    const readPath = hasPathPlaceholder(candidate)
      ? (selector ? fillPlaceholders(candidate, encodeURIComponent(selector)) : null)
      : candidate
    if (!readPath) continue
    let initial: BrokerExchangeResult
    try { initial = await send('GET', readPath, owner) } catch { continue }
    if (process.env.KOVO_BENCH_DEBUG === '1') process.stderr.write(`[state-readback] ${h.endpoint.path} candidate=${candidate} initial=${initial.status}\n`)
    if (initial.status < 200 || initial.status >= 300) continue
    let initialJson: unknown
    try { initialJson = JSON.parse(initial.body) } catch { continue }
    if (!initialJson || typeof initialJson !== 'object') continue
    const readPaths = new Set(flattenScalars(initialJson).keys())
    const variants = buildStateVariants(bodyTemplate, readPaths)
    if (!variants) continue
    const binding = bindingFor(initialJson, selector)
    // Control write sets a distinct benign baseline, so the probe delta is attributable and the
    // post-probe read is never identical just because an earlier probe already wrote this value.
    try { await send(stateWriteMethod, ownPath, owner, variants.controlBody) } catch { continue }
    let before: BrokerExchangeResult
    try { before = await send('GET', readPath, owner) } catch { continue }
    if (before.status < 200 || before.status >= 300) continue
    let beforeJson: unknown
    try { beforeJson = JSON.parse(before.body) } catch { continue }
    let write: BrokerExchangeResult
    try { write = await send(stateWriteMethod, ownPath, other, variants.probeBody) } catch { continue }
    if (write.status < 200 || write.status >= 300) continue
    let after: BrokerExchangeResult
    try { after = await send('GET', readPath, owner) } catch { continue }
    if (after.status < 200 || after.status >= 300) continue
    let afterJson: unknown
    try { afterJson = JSON.parse(after.body) } catch { continue }
    const delta = scalarDeltas(beforeJson, afterJson)[0]
    if (process.env.KOVO_BENCH_DEBUG === '1') process.stderr.write(`[state-readback] ${h.endpoint.path} ${readPath} before=${before.status} probe=${write.status} after=${after.status} delta=${delta ? delta.path.join('.') : 'none'}\n`)
    if (!delta) continue
    return {
      path: readPath, controlBody: variants.controlBody, probeBody: variants.probeBody,
      fieldPath: delta.path, ...(delta.before !== undefined ? { controlValue: delta.before } : {}), probeValue: delta.after,
      ...(binding ? { bindingPath: binding.path, bindingValue: binding.value } : {}),
    }
  }
  return null
}

export async function authzRequest(h: Hypothesis, env: ProbeEnv, owner = env.owner, other = env.other): Promise<ProbeDifferentialRequest> {
  const idSlot = hasPathPlaceholder(h.endpoint.path)
  const idParam = h.endpoint.params.find(p => (p.isObjectId || idName.test(p.name)) && p.location === 'query')
  const functionLevel = !idSlot && !idParam
  // Anonymous-readable detail routes are normally rejected as public data. Tenant/owner-scoped
  // resources (orders, customers, files, accounts, …) are never public, even when the app forgot the
  // auth check too; keep the anonymous row only for explicitly public/preview/storefront surfaces.
  const publicSurface = /(?:public|shared|preview|storefront|catalog|embed|community|landing|products?|wares?|ratings?|testimonials?|listings?)/i
  const scopedResource = /(?:orders?|purchases?|customers?|invoices?|billing|files?|assets?|documents?|accounts?|tickets?|alerts?|notifications?|members?|users?|shipments?|payments?|refunds?|jobs?|logs?|audit|reports?)/i
  const includeAnonymous = !(idSlot && scopedResource.test(h.endpoint.path) && !publicSurface.test(h.endpoint.path))
  const pathAndQuery = idSlot
    ? fillPlaceholders(h.endpoint.path, '{{id}}')
    : idParam
      ? `${h.endpoint.path}?${idParam.name}={{id}}`
      : h.endpoint.path
  const wireMethod: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' = h.deleteMethod ? 'DELETE' : h.method
  const mutating = wireMethod !== 'GET'
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
  const requestBody = functionLevel ? undefined : (mutating && wireMethod !== 'DELETE' ? writeBodyFor(h.endpoint, env, 'json') : undefined)
  // Role-transition actions need a privileged value to prove the missing role check.
  if (mutating && /(?:role|grant|permission|privilege|promote|assign)(?:\/|$)/i.test(h.endpoint.path)) {
    const privileged = { role: 'admin', grant: 'admin', level: 'admin' }
    if (requestBody) Object.assign(requestBody, privileged)
    if (functionBody && typeof functionBody === 'object' && !Array.isArray(functionBody)) Object.assign(functionBody as Record<string, unknown>, privileged)
  }
  // Object ids from both sides: a cross-tenant read often keys on the *other* actor's object, whose
  // id never appears in the owner's own collection.
  const ownerIds = functionLevel ? [] : await idPool(env, h.endpoint.path, owner)
  const otherIds = functionLevel || !other ? [] : await idPool(env, h.endpoint.path, other)
  const resourceIds = functionLevel
    ? ['']
    : [...new Set([...ownerIds, ...otherIds])].slice(0, 12)
  return {
    probeClass: 'authz_matrix',
    origin: env.origin,
    pathAndQuery,
    method: mutating ? wireMethod : 'GET',
    persona: owner,
    ownerPersona: owner,
    otherPersona: other,
    includeAnonymous,
    includeHeaderBypass: false,
    resourceIds,
    ...(env.caps.sessionAndCsrf && mutating ? { csrfBind: true } : {}),
    ...(functionBody !== undefined ? { functionBody } : {}),
    ...(requestBody && Object.keys(requestBody).length > 0 ? { jsonBody: requestBody } : {}),
    runId: env.runId,
    storage: env.storage,
    ...(env.caps.sessionAndCsrf ? { session: env.session } : {}),
  }
}

const sqliClasses = new Set<string>(['sqli_boolean', 'sqli_time_diff'])

/**
 * Real values observed on the target's own collection routes, for search/filter baselines. A
 * LIKE-wrapped sink only yields a boolean differential when the baseline actually matches rows, and
 * generic terms may match nothing; the first record's own label always matches its own search.
 */
async function harvestedSeedValues(h: Hypothesis, env: ProbeEnv): Promise<string[]> {
  const endpoints = env.endpoints ?? []
  const segs = h.endpoint.path.split('?')[0].split('/').filter(Boolean)
  if (segs.length < 2) return []
  const apiRoot = `/${segs[0]}`
  const skipped = /^(?:session|csrf|health|settings|me|app-config|login|logout|token|graphql|search|query|filter|lookup|audit|stats|metrics)$/i
  const candidates = endpoints
    .filter(e => e.method.toUpperCase() === 'GET' && !hasPathPlaceholder(e.path) && e.path !== h.endpoint.path)
    .filter(e => {
      const parts = e.path.split('?')[0].split('/').filter(Boolean)
      return e.path.startsWith(`${apiRoot}/`) && parts.length >= 2 && parts.length <= 3 &&
        !skipped.test(parts[parts.length - 1]) && !/\.(?:js|css|json|xml|txt)$/i.test(e.path)
    })
    .sort((a, b) => a.path.length - b.path.length || a.path.localeCompare(b.path))
    .slice(0, 2)
  const out: string[] = []
  const pushValue = (value: string): void => {
    if (out.length >= 4) return
    const trimmed = value.trim()
    // Prefer a broad token (first word) so the baseline matches a set of rows, not one exact row:
    // a one-row true branch scores too close to the baseline for an echo-heavy JSON response.
    const broad = trimmed.split(/\s+/)[0] ?? ''
    if (broad.length >= 3 && broad.length <= 32 && !/[<>{}\\\u0000-\u001f]/.test(broad)) out.push(broad)
    if (trimmed.length >= 3 && trimmed.length <= 48 && trimmed !== broad && !/[<>{}\\\u0000-\u001f]/.test(trimmed)) out.push(trimmed)
  }
  for (const ep of candidates) {
    try {
      const ex = await env.broker.executeHttp({
        origin: env.origin, method: 'GET', pathAndQuery: ep.path, persona: env.owner, followRedirects: false, timeoutMs: 8_000,
      }, env.grant, env.signal)
      if (ex.status < 200 || ex.status >= 300) continue
      const parsed = JSON.parse(ex.body) as unknown
      const walk = (node: unknown, depth: number): void => {
        if (depth > 4 || !node || out.length >= 3) return
        if (Array.isArray(node)) { for (const item of node.slice(0, 5)) walk(item, depth + 1); return }
        if (typeof node !== 'object') return
        for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
          if (out.length >= 3) return
          if (typeof value === 'string' && /^(?:name|title|label|slug|subject|description|email|text)$/i.test(key) &&
              value.length >= 3 && value.length <= 48 && !/[<>{}\\]/.test(value)) {
            pushValue(value)
          } else if (value && typeof value === 'object') walk(value, depth + 1)
        }
      }
      walk(parsed, 0)
    } catch { /* collection may be absent or non-JSON */ }
    if (out.length > 0) break
  }
  return out
}

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
  const inferredPurpose = (h.param as InferredParam | undefined)?.purpose
  if (h.param && inferredPurpose && inferredPurpose !== 'text' && (h.location === 'query' || h.location === 'json' || h.location === 'form')) {
    // The name was inferred, not observed. A request with the candidate and a request with a random
    // parameter name decide cheaply whether the app reads this name at all before the full matrix runs.
    const body = siblingBody(h, env)
    const sendFor = async (name: string, value: string): Promise<BrokerExchangeResult | null> => {
      try {
        const inj = injectUniversalParam({
          pathAndQuery: probePathFor(h), param: name, paramLocation: h.location!, value, method: h.method === 'DELETE' ? 'POST' : h.method,
          ...(h.location === 'json' && body ? { jsonBody: body } : {}),
          ...(h.location === 'form' && body ? { formBody: Object.fromEntries(Object.entries(body).map(([k, v]) => [k, String(v)])) } : {}),
          ...(h.location === 'json' ? { headers: { 'Content-Type': 'application/json' } } : h.location === 'form' ? { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } } : {}),
          ...(env.caps.sessionAndCsrf ? { session: env.session, csrfBind: needsCsrf(h) ? true : undefined } : {}),
        })
        return await env.broker.executeHttp({ origin: env.origin, persona: env.owner, followRedirects: false, ...inj }, env.grant, env.signal)
      } catch { return null }
    }
    const fake = await sendFor(`gxprobe${shortToken(5)}`, 'gxprobe')
    if (inferredPurpose === 'file') {
      // A file parameter is active when it reads a valid in-jail name, or when it reads outside the
      // served root. One passwd-shaped payload (and a suffix-preserving log path) decides the latter.
      const passwd = /^[A-Za-z0-9_.-]+:[^:\n]*:\d+:\d+:[^:\n]*:[^:\n]*:[^\n]*$/m
      ctx.paramActive = false
      for (const validName of mineBaselines(corpus, h.param.name, h.endpoint.path).filter(v => /^[A-Za-z0-9_. -]{1,60}$/.test(v) && !/[\\/]/.test(v)).slice(0, 2)) {
        const ex = await sendFor(h.param.name, validName)
        if (ex && ex.status >= 200 && ex.status < 300 && ex.body.trim().length > 0 &&
            (!fake || ex.status !== fake.status || responseSimilarity(ex.body, fake.body) < 0.9)) { ctx.paramActive = true; break }
      }
      const payloads = ['../../../../etc/passwd', '../../../../var/log/system/audit.log']
      for (const payload of ctx.paramActive ? [] : payloads) {
        const real = await sendFor(h.param.name, payload)
        if (!real) continue
        if (passwd.test(real.body)) { ctx.paramActive = true; break }
        if (fake && real.status >= 200 && real.status < 300 && real.body.trim().length > 0 &&
            (real.status !== fake.status || responseSimilarity(real.body, fake.body) < 0.9)) { ctx.paramActive = true; break }
      }
    } else if (fake) {
      const values = inferredPurpose === 'url' ? ['http://kovo-control.invalid/'] : ['a', 'test', 'gxprobe']
      ctx.paramActive = false
      for (const value of values) {
        const ex = await sendFor(h.param.name, value)
        if (ex && (ex.status !== fake.status || responseSimilarity(ex.body, fake.body) < 0.97)) { ctx.paramActive = true; break }
      }
    }
    if (ctx.paramActive === false) return ctx
  }
  if (h.param && h.probeClass === 'path_traversal_benign') {
    const mined = mineBaselines(corpus, h.param.name, h.endpoint.path)
      .filter(v => /^[A-Za-z0-9_. -]{1,60}$/.test(v) && !/[\\/]/.test(v))
    // Pick a value the endpoint actually serves; a valid in-jail name is what proves a handler
    // strips `../` before resolving (and therefore needs an encoded variant to test).
    for (const value of mined.slice(0, 4)) {
      try {
        const ex = await env.broker.executeHttp({ origin: env.origin, persona: env.owner, followRedirects: false, ...injectUniversalParam({
          pathAndQuery: probePathFor(h), param: h.param.name, paramLocation: h.location!, value, method: h.method === 'DELETE' ? 'POST' : h.method,
        }) }, env.grant, env.signal)
        if (ex.status >= 200 && ex.status < 300 && ex.body.trim().length > 0) { ctx.baseline = value; break }
      } catch { /* keep trying */ }
    }
  }
  if (h.param && sqliClasses.has(h.probeClass)) {
    const mined = mineBaselines(corpus, h.param.name, h.endpoint.path)
    const searchish = inferredPurpose === 'search' || /^(?:q|query|term|keyword|filter|expr|clause|since)$/i.test(h.param.name) ||
      /(?:search|lookup|filter|query|find)/i.test(h.endpoint.path)
    // A matching value read from the target's own collection beats a generic term: a LIKE sink only
    // differentiates when the baseline row set is non-empty.
    const observed = searchish ? await harvestedSeedValues(h, env) : []
    const seeds = searchish ? ['a', '0', '1', 'test'] : []
    const candidates = [...new Set([...observed, ...mined, ...seeds])].slice(0, 8)
    if (candidates.length > 0) {
      const body = siblingBody(h, env)
      const send = async (value: string): Promise<BrokerExchangeResult | null> => {
        try {
          const inj = injectUniversalParam({
            pathAndQuery: probePathFor(h), param: h.param!.name, paramLocation: h.location!, value, method: h.method === 'DELETE' ? 'POST' : h.method,
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
      const bogus = await send('zzkovozz')
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
  // Token-issuing read routes: the session jar must hold a CSRF token before a mutating probe.
  if (h.method !== 'GET') {
    for (const ep of (env.endpoints ?? []).filter(e => e.method.toUpperCase() === 'GET')) {
      if (paths.size >= 3) break
      if (/(?:^|[/_-])(?:me|csrf|session|settings|token|nonce|xsrf)(?:$|[/_-])/i.test(ep.path) && !hasPathPlaceholder(ep.path)) paths.add(ep.path)
    }
  }
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
  // Active markup (not just a tag): the benchmark's impact monitor requires an executable handler,
  // and a real stored-XSS in a rich-text field is exactly this. `<script>` is stripped by naive
  // filters, so the event-handler form is what survives and proves impact.
  const payload = `${marker}"'<img src=x onerror="${marker}">`
  const body = h.location === 'json' ? writeBodyFor(h.endpoint, env, 'json') : h.location === 'form' ? writeBodyFor(h.endpoint, env, 'form') : siblingBody(h, env)
  // A write to a templated resource must address a real object, and the read-back must use the same
  // object; otherwise the marker lands on `<id=1>` while the reader looks at another record.
  const writeIds = hasPathPlaceholder(h.endpoint.path) ? await idPool(env, h.endpoint.path) : []
  const writePath = writeIds.length > 0 ? fillPlaceholders(h.endpoint.path, encodeURIComponent(writeIds[0])) : probePathFor(h)
  const injected = injectUniversalParam({
    pathAndQuery: writePath,
    param: param.name,
    paramLocation: h.location,
    value: payload,
    method: h.method === 'DELETE' ? 'POST' : h.method,
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
  // A create-style write returns the new object id; the downstream page needs that exact object.
  const createdIds = writeEx && writeEx.status >= 200 && writeEx.status < 300
    ? idShaped(harvestJson(writeEx.body).ids)
    : []
  const concretePlantPath = injected.pathAndQuery.split('?')[0]

  const reads: Array<Record<string, unknown>> = []
  const reflectedOnly: Array<Record<string, unknown>> = []
  // Templated read pages are filled with ids observed on the surface (and the value used for an
  // id-bearing write field), so a stored marker is looked up on the object it was attached to.
  const fillIds = [
    ...writeIds.slice(0, 1),
    ...createdIds,
    ...h.endpoint.params.filter(p => idName.test(p.name) && body && typeof body[p.name] === 'string').map(p => String(body![p.name])),
    ...(await idPool(env)),
  ]
  const readTargets: Array<{ path: string; fromCreated: boolean }> = []
  for (const rp of h.readPaths.slice(0, 3)) {
    if (hasPathPlaceholder(rp)) {
      for (const idv of [...new Set(fillIds)].slice(0, 3)) readTargets.push({ path: fillPlaceholders(rp, encodeURIComponent(idv)), fromCreated: createdIds.includes(idv) })
      continue
    }
    const segs = rp.split('?')[0].split('/')
    const idIdx = segs.findIndex(s => s && looksLikeIdSegment(s))
    if (idIdx < 0) { readTargets.push({ path: rp, fromCreated: false }); continue }
    // Prefer the value the write actually used, then other observed ids.
    const orderedIds = [...new Set([...fillIds.filter(v => v === segs[idIdx]), ...fillIds])].slice(0, 3)
    for (const idv of orderedIds) {
      const next = [...segs]
      next[idIdx] = encodeURIComponent(idv)
      readTargets.push({ path: next.join('/') + (rp.includes('?') ? `?${rp.split('?')[1]}` : ''), fromCreated: createdIds.includes(idv) })
    }
  }
  for (const { path: readPath, fromCreated } of readTargets.slice(0, 5)) {
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
      // A create-only write returns an id the replay spec cannot reference (the stored-XSS
      // synthesizer replays the observed read path verbatim). Reads of the *created* object are
      // therefore unconfirmable; a parent/container page (e.g. the project's activity feed) is fine.
      const createOnly = h.method === 'POST' && !hasPathPlaceholder(h.endpoint.path)
      if (createOnly && fromCreated) {
        result.details.storedOnNewObject = { readPath, context: analysis.context }
        continue
      }
      result.hit = true
      result.anomalies.push({
        type: 'second_order_xss',
        plantPath: concretePlantPath,
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
  if (!param) return result
  const mode = h.raceMode ?? (h.raceProducerPath ? 'single_use' : 'balance')
  const productScoped = /(?:checkout|cart|bag|order|purchase|product|ware|inventory|stock)/i.test(h.endpoint.path)
  const send = async (method: 'GET' | 'POST' | 'PUT' | 'PATCH', pathAndQuery: string, body?: Record<string, unknown>) => {
    const ex = await sendRaw(env, {
      method, pathAndQuery, ...(body ? { body: JSON.stringify(body) } : {}),
      headers: { 'Content-Type': 'application/json' }, persona: env.owner,
      session: env.caps.sessionAndCsrf ? env.session : undefined,
      ...(env.caps.sessionAndCsrf && method !== 'GET' ? { csrfBind: true } : {}),
    })
    result.requests += 1
    if (ex) watch(ex)
    return ex
  }
  const numeric = (body: string | undefined): Record<string, number> => {
    const out: Record<string, number> = {}
    const fields = body ? harvestJson(body).fields : new Map<string, string[]>()
    for (const key of ['balance', 'credits', 'stock', 'available', 'remaining', 'inventory', 'quantity', 'count', 'total']) {
      const values = (fields.get(key) ?? []).map(Number).filter(Number.isFinite)
      if (values.length > 0) out[key] = Math.max(...values)
    }
    return out
  }
  const stateFieldPriority = ['balance', 'credits', 'stock', 'available', 'remaining', 'inventory', 'quantity']
  const pickState = (values: Record<string, number>): { field: string; value: number } | null => {
    for (const field of stateFieldPriority) if (values[field] !== undefined) return { field, value: values[field]! }
    return null
  }
  const numericAliases = (name: string): string[] => {
    if (/(?:amount|value|total|price|cents)/i.test(name)) return [...new Set([name, 'amount', 'value', 'cents', 'total', 'price'])]
    if (/(?:qty|quantity|count|number)/i.test(name)) return [...new Set([name, 'qty', 'quantity', 'count', 'itemQty'])]
    return [name]
  }
  const bodySiblings = (value: number | string): Record<string, unknown> => {
    const body: Record<string, unknown> = {}
    for (const p of h.endpoint.params) {
      if (p.isCsrf || p.name === param.name) continue
      if (p.location !== 'json' && p.location !== 'form') continue
      body[p.name] = semanticValue(p.name, env)
    }
    if (typeof value === 'number') {
      for (const alias of numericAliases(param.name)) body[alias] = value
    } else {
      body[param.name] = value
    }
    if (productScoped) {
      for (const alias of ['productId', 'product_id', 'product', 'item', 'itemId', 'sku']) body[alias] = '1'
    }
    return body
  }
  let catalogIds: string[] | null = null
  const ensureCatalogIds = async (): Promise<string[]> => {
    if (catalogIds) return catalogIds
    const route = (env.endpoints ?? []).find(e =>
      e.method.toUpperCase() === 'GET' && !hasPathPlaceholder(e.path) && /(?:products?|wares?|catalog|items?|stock|inventory)$/i.test(lastPathSegment(e.path)),
    )
    catalogIds = route ? await idPool(env, route.path) : []
    return catalogIds
  }
  // Resolve the concrete consume path (and mint a disposable resource where a create route exists).
  const setupSteps: Array<Record<string, unknown>> = []
  let consumePath = probePathFor(h)
  let resolvedId: string | null = null
  let resolvedIds: string[] = []
  if (hasPathPlaceholder(h.endpoint.path)) {
    if (h.raceCreatePath) {
      const created = await send('POST', h.raceCreatePath, {})
      const id = created ? harvestJson(created.body).ids[0] ?? null : null
      if (id) {
        resolvedId = id
        consumePath = fillPlaceholders(h.endpoint.path, encodeURIComponent(id))
        setupSteps.push({ method: 'POST', pathAndQuery: h.raceCreatePath, jsonBody: {} })
      }
    }
    if (!resolvedId) {
      const ids = await idPool(env, h.endpoint.path)
      resolvedIds = ids
      if (!ids[0]) { result.details.skipped = 'resource_unavailable'; return result }
      resolvedId = ids[0]
      consumePath = fillPlaceholders(h.endpoint.path, encodeURIComponent(ids[0]))
    }
  }
  // Resolve body references (product ids) and the resource value the burst is meant to overspend.
  let baseline: number | null = null
  let baselineField: string | null = null
  let readPath: string | null = null
  let productId: string | null = null
  let catalogRows: Array<{ id: string; value: number }> = []
  const catalogRoute = (env.endpoints ?? []).find(e =>
    e.method.toUpperCase() === 'GET' && !hasPathPlaceholder(e.path) && /(?:products?|wares?|catalog|items?|stock|inventory)$/i.test(lastPathSegment(e.path)),
  )?.path
  const readCandidates: string[] = []
  if (h.raceResourcePath) {
    readCandidates.push(hasPathPlaceholder(h.raceResourcePath)
      ? (resolvedId ? fillPlaceholders(h.raceResourcePath, encodeURIComponent(resolvedId)) : '')
      : h.raceResourcePath)
  }
  if (mode === 'balance' && /(?:checkout|cart|order|purchase|inventory|stock)/i.test(h.endpoint.path) && catalogRoute) readCandidates.push(catalogRoute)
  for (const read of readCandidates.filter(Boolean)) {
    const ex = await send('GET', read)
    const values = numeric(ex?.body)
    const picked = pickState(values)
    if (!picked) continue
    baseline = picked.value
    baselineField = picked.field
    readPath = read
    // Pick the catalog row that owns the largest stock so qty*burst actually exceeds it.
    if (!productScoped) continue
    try {
      const parsed = JSON.parse(ex!.body) as unknown
      const rows: Array<Record<string, unknown>> = []
      const walk = (node: unknown, depth: number): void => {
        if (depth > 4 || !node || typeof node !== 'object') return
        if (Array.isArray(node)) { for (const item of node) walk(item, depth + 1); return }
        const rec = node as Record<string, unknown>
        if (picked.field in rec) rows.push(rec)
        for (const v of Object.values(rec)) if (v && typeof v === 'object') walk(v, depth + 1)
      }
      walk(parsed, 0)
      const rowsWithValue = rows
        .map(r => {
          const v = Number(r[picked.field])
          const id = ['id', 'external_id', 'externalId', 'uuid'].map(k => r[k]).find(x => typeof x === 'string' || typeof x === 'number')
          return Number.isFinite(v) && id !== undefined ? { id: String(id), value: v } : null
        })
        .filter((r): r is { id: string; value: number } => r !== null)
        .sort((a, b) => b.value - a.value)
      catalogRows = rowsWithValue
      const best = rowsWithValue[0]
      if (best) productId = best.id
    } catch { /* non-JSON read */ }
    break
  }
  if (mode === 'single_use') {
    const producerPath = h.raceProducerPath
    if (!producerPath) { result.details.skipped = 'producer_unavailable'; return result }
    const producerEp = (env.endpoints ?? []).find(e => e.path === producerPath && e.method.toUpperCase() === 'POST')
    const producerBody: Record<string, unknown> = {}
    for (const p of producerEp?.params ?? []) {
      if (p.location === 'json' || p.location === 'form') producerBody[p.name] = /product(Id)?$/i.test(p.name) ? (await ensureCatalogIds())[0] ?? '1' : semanticValue(p.name, env)
    }
    const mint = async (): Promise<string | null> => {
      const ex = await send('POST', producerPath, producerBody)
      if (!ex || ex.status < 200 || ex.status >= 300) return null
      const harvest = harvestJson(ex.body)
      return harvest.fields.get(param.name)?.[0] ?? harvest.ids[0] ?? null
    }
    const first = await mint()
    if (!first) { result.details.skipped = 'producer_unavailable'; return result }
    const singleEx = await send(h.method === 'DELETE' ? 'POST' : h.method, consumePath, bodySiblings(first))
    result.details.singleStatus = singleEx?.status ?? null
    if (!singleEx || singleEx.status < 200 || singleEx.status >= 300) { result.details.skipped = 'consume_baseline_failed'; return result }
    const target = await mint()
    if (!target) { result.details.skipped = 'producer_unavailable'; return result }
    setupSteps.push({
      id: 's1', method: 'POST', path: producerPath, body: producerBody,
      extract: [{ varName: 'code', from: 'json', selector: param.name }],
    })
    const value = target
    const replayBody: Record<string, unknown> = bodySiblings(value)
    for (const alias of numericAliases(param.name)) replayBody[alias] = `{{code}}`
    const burstReqs = Array.from({ length: 4 }, () => ({
      origin: env.origin, method: h.method, pathAndQuery: consumePath,
      headers: { 'Content-Type': 'application/json' }, persona: env.owner,
      ...(env.caps.sessionAndCsrf ? { session: env.session } : {}),
      body: JSON.stringify(bodySiblings(value)),
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
    result.details = { ...result.details, mode, burstSize: 4, statuses, successes, value, baseline, baselineField, readPath, consumePath, producerPath, setupSteps }
    if (successes >= 2) {
      result.hit = true
      result.anomalies.push({
        type: 'race_double_spend', mode, path: consumePath, producerPath, param: param.name,
        consumeBody: replayBody, successes, statuses, burstSize: 4,
        ...(readPath ? { parentPath: readPath } : {}), setupSteps,
        suggestedReplayKind: 'race_burst',
      })
    }
    return result
  }

  // Balance/stock mode: derive the per-request value from the observed balance, then overspend it
  // with concurrent read-then-write requests (2+ acceptances for a value > half the balance).
  if (baseline === null || baselineField === null) {
    // No read route: one inexpensive consume exposes the post-state balance in its response.
    const probe = await send(h.method === 'DELETE' ? 'POST' : h.method, consumePath, bodySiblings(1))
    const picked = pickState(numeric(probe?.body))
    if (picked) { baseline = picked.value + (probe?.status && probe.status >= 200 && probe.status < 300 ? 1 : 0); baselineField = picked.field }
  }
  if (baseline === null || baselineField === null || baseline < 2) {
    result.details.skipped = 'balanceless'
    return result
  }
  const value = Math.max(1, Math.floor(baseline * 0.75))
  // Product-scoped stock (cart checkout) must target a real catalog item.
  const body = bodySiblings(value)
  if ('productId' in body || 'product_id' in body) {
    const id = productId ?? (await ensureCatalogIds())[0]
    if (id) for (const alias of ['productId', 'product_id', 'product', 'item', 'itemId', 'sku']) body[alias] = id
  }
  // Prefer the specific record's detail route for the post-burst read so an unrelated row with a
  // larger balance cannot mask the decrement.
  if (productId && catalogRoute && productScoped) {
    const detailTemplate = (env.endpoints ?? []).find(e =>
      e.method.toUpperCase() === 'GET' && hasPathPlaceholder(e.path) &&
      e.path.split('?')[0].split('/').filter(Boolean).slice(0, -1).join('/') === catalogRoute.split('/').filter(Boolean).join('/'),
    )?.path
    if (detailTemplate) readPath = fillPlaceholders(detailTemplate, encodeURIComponent(productId))
  }
  // Replay must run against a resource the probe did not exhaust. Pick a second untouched catalog
  // row / card and build setup steps that address it (fresh cart where a create route exists).
  let replayPath = consumePath
  let replayBody: Record<string, unknown> = body
  let replayRead: string | null = readPath
  let replayValue = value
  const replaySetup: Array<Record<string, unknown>> = []
  const productField = 'productId' in body ? 'productId' : 'product_id' in body ? 'product_id' : null
  const detailTemplateFor = (collectionPath: string): string | undefined => (env.endpoints ?? []).find(e =>
    e.method.toUpperCase() === 'GET' && hasPathPlaceholder(e.path) &&
    e.path.split('?')[0].split('/').filter(Boolean).slice(0, -1).join('/') === collectionPath.split('/').filter(Boolean).join('/'),
  )?.path
  if (productField && catalogRows.length > 0) {
    const replayRow = catalogRows.find(r => r.id !== productId && r.value >= 2) ?? catalogRows[0]
    if (replayRow) {
      replayValue = Math.max(1, Math.floor(replayRow.value * 0.75))
      replayBody = { ...bodySiblings(replayValue), [productField]: replayRow.id }
      const detailTemplate = catalogRoute ? detailTemplateFor(catalogRoute) : undefined
      if (detailTemplate) {
        const readForReplay = fillPlaceholders(detailTemplate, encodeURIComponent(replayRow.id))
        replayRead = readForReplay
        replaySetup.push({
          id: 's2', method: 'GET', path: readForReplay,
          extract: [{ varName: 'balance0', from: 'json', selector: baselineField }],
        })
      }
    }
    if (h.raceCreatePath) {
      replayPath = h.endpoint.path.replace(/(?::[A-Za-z0-9_]+|\{[A-Za-z0-9_]+\}|\[[A-Za-z0-9_]+\])/g, '{{resource_id}}')
      replaySetup.unshift({
        id: 's1', method: 'POST', path: h.raceCreatePath, body: {},
        extract: [{ varName: 'resource_id', from: 'json', selector: 'id' }],
      })
    }
  } else if (hasPathPlaceholder(h.endpoint.path) && resolvedIds.length > 1) {
    const template = h.endpoint.path
    const detailTemplate = detailTemplateFor(`/${template.split('?')[0].split('/').filter(Boolean).slice(0, -1).join('/')}`)
    const candidates = resolvedIds.filter(id => id !== resolvedId).slice(0, 4)
    for (const replayId of candidates) {
      const readForReplay = detailTemplate
        ? fillPlaceholders(detailTemplate, encodeURIComponent(replayId))
        : fillPlaceholders(template, encodeURIComponent(replayId))
      const fresh = await send('GET', readForReplay)
      if (!fresh || fresh.status < 200 || fresh.status >= 300) continue
      const picked = pickState(numeric(fresh.body))
      if (!picked || picked.value < 2) continue
      replayValue = Math.max(1, Math.floor(picked.value * 0.75))
      replayBody = bodySiblings(replayValue)
      replayPath = fillPlaceholders(template, encodeURIComponent(replayId))
      replayRead = readForReplay
      replaySetup.push({
        id: 's1', method: 'GET', path: readForReplay,
        extract: [{ varName: 'balance0', from: 'json', selector: picked.field }],
      })
      break
    }
  }
  if (replaySetup.length === 0 && readPath) {
    replaySetup.push({
      id: 's1', method: 'GET', path: readPath,
      extract: [{ varName: 'balance0', from: 'json', selector: baselineField }],
    })
  }
  const before = baseline
  const burstReqs = Array.from({ length: 4 }, () => ({
    origin: env.origin, method: h.method, pathAndQuery: consumePath,
    headers: { 'Content-Type': 'application/json' }, persona: env.owner,
    ...(env.caps.sessionAndCsrf ? { session: env.session } : {}),
    body: JSON.stringify(body),
  }))
  let statuses: number[] = []
  let burstBodies: string[] = []
  try {
    const burst = await env.broker.executeRaceBurst(burstReqs, env.grant, env.signal)
    statuses = burst.results.map(r => r.status)
    burstBodies = burst.results.map(r => r.body)
    for (const ex of burst.results) watch(ex)
    result.requests += burst.results.length
  } catch (err) {
    result.details.burstError = err instanceof Error ? err.message.slice(0, 160) : String(err)
    return result
  }
  const successes = statuses.filter(s => s >= 200 && s < 300).length
  let after: number | null = null
  if (readPath) {
    const ex = await send('GET', readPath)
    const values = numeric(ex?.body)
    after = values[baselineField] ?? null
  } else {
    for (const body of burstBodies) {
      const values = numeric(body)
      if (values[baselineField] !== undefined) after = Math.min(after ?? Infinity, values[baselineField]!)
    }
  }
  const overspent = after !== null && after < before - value
  result.details = { ...result.details, mode, burstSize: 4, statuses, successes, value, baseline: before, baselineField, after, readPath, consumePath, setupSteps }
  if (successes >= 2 && overspent) {
    result.hit = true
    result.anomalies.push({
      type: 'race_double_spend', mode, path: replayPath, param: param.name,
      consumeBody: replayBody, successes, statuses, burstSize: 4,
      value: replayValue, baseline: before, after, balanceField: baselineField,
      ...(replayRead ? { parentPath: replayRead, balancePath: replayRead, readPath: replayRead } : {}),
      setupSteps: replaySetup,
      cleanupSteps: [],
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
    method: h.method === 'DELETE' ? 'POST' : h.method, pathAndQuery: probePathFor(h), body: JSON.stringify(body),
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
            event: { type: 'kovo.probe', id: `gwh${shortToken(8)}` }, type: 'kovo.probe',
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
            event: { type: 'kovo.probe', id: `gwh${shortToken(8)}` }, type: 'kovo.probe',
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

  // The merged surface (variant routes + grey-box API reference) can include detail/config routes
  // that Phase-0 did not link. Helpers resolve read-backs and service origins against that surface.
  if (h.knownEndpoints?.length) env.endpoints = h.knownEndpoints

  // Prime the session jar before write probes so cookies + CSRF tokens discovered on the entry page
  // are available to the broker's csrfBind injection.
  if (h.method !== 'GET') out.requests += await primeSessionOnce(h, env)

  // Path/query probes on a templated route: resolve the route to a real object first, and record
  // that concrete path on the hypothesis so the replay spec addresses the same object.
  if ((h.probeClass === 'path_traversal_benign' || h.probeClass === 'mass_assignment') && hasPathPlaceholder(h.endpoint.path)) {
    const ids = await idPool(env, h.endpoint.path)
    // Hypotheses share the discovered endpoint object; clone before substituting a concrete id so
    // other probes on the same route still see its path template.
    if (ids.length > 0) h.endpoint = { ...h.endpoint, path: fillPlaceholders(h.endpoint.path, encodeURIComponent(ids[0])) }
  }
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
  // Effect-level probes (OOB callbacks, state diffs, auth protocol) prove themselves through the
  // target's side effects; a constant response body must not suppress them.
  const effectProbe = ['ssrf_canary', 'xxe_canary', 'csrf_state_change', 'cache_poison_deception', 'webhook_signature_bypass', 'auth_protocol_audit', 'command_injection'].includes(h.probeClass)
  if (ctx.paramActive === false && !effectProbe) {
    out.verdict = 'no_signal'
    out.summary = 'Inferred parameter name does not affect the response (not read by the endpoint).'
    return out
  }
  let req: ProbeDifferentialRequest
  switch (h.probeClass) {
    case 'authz_matrix': {
      let owner = env.owner
      let other = env.other
      if ((/(admin|internal|manage|staff|flag|role|permission)/i.test(h.endpoint.path) || serverActionPath.test(h.endpoint.path)) && env.admin && (env.viewer ?? env.other)) { owner = env.admin; other = env.viewer ?? env.other }
      out.pair = { owner, other }
      req = await authzRequest(h, env, owner, other)
      if (h.writePathRead) req.writePathRead = true
      if (h.method !== 'GET') {
        // A mutating matrix needs the session jar to already hold the anti-CSRF token issued by the
        // app's own read routes; otherwise every actor write is rejected and the role check is never
        // observed. Priming is memoized per session, so this is one bounded preflight per run.
        if (env.caps.sessionAndCsrf) await primeSessionOnce(h, env)
        const csrf = await csrfHeaderFor(env)
        if (csrf) req.headers = { ...(req.headers ?? {}), ...csrf }
      }
      if (h.method === 'GET' && env.viewer && !hasPathPlaceholder(h.endpoint.path) &&
          /(?:keys?|secret|tokens?|credential|audit|settings|config|billing|integration|connectors?|links?|hooks?|webhooks?|providers?|connections?)/i.test(h.endpoint.path)) {
        req.secretScan = true
        req.viewerPersona = env.viewer
      }
      break
    }
    case 'ssrf_canary':
      req = buildProbeRequest(h, env, { ssrfParams: h.param ? [h.param.name] : [], waitMs: 2500, internalTargets: await harvestInternalTargets(env) }); break
    case 'xxe_canary': req = buildProbeRequest(h, env, { waitMs: 2500 }); break
    case 'mass_assignment': {
      req = buildProbeRequest(h, env, { paramLocation: 'json', jsonBody: {} })
      // Role/team escalation is only observable as an impact event when a non-admin performs it;
      // probe as the low-privilege persona while the replay still runs as the owner.
      if (env.viewer && /(?:user|member|people|staff|profile|account)/i.test(h.endpoint.path)) req.persona = env.viewer
      break
    }
    case 'graphql_audit': {
      req = buildProbeRequest(h, env)
      req.ownerPersona = env.owner
      req.otherPersona = env.other
      const seeds = await graphqlDiscoverySeeds(env)
      // Persona user ids first: a nested resolver BOLA needs a node owned by the *other* actor, and
      // those ids are the ones a cross-persona replay can reproduce.
      req.resourceIds = [...new Set([...env.personaUserIds, ...seeds.ids, ...(env.corpus ? mineObservedIds(env.corpus, 6) : [])])].slice(0, 8)
      if (seeds.roots.length > 0) req.graphqlRoots = seeds.roots
      if (Object.keys(seeds.byRoot).length > 0) req.graphqlSeedsByRoot = seeds.byRoot
      if (env.ownerUserId) req.ownerUserId = env.ownerUserId
      if (env.otherUserId) req.otherUserId = env.otherUserId
      break
    }
    case 'workflow_invariant': {
      req = buildProbeRequest(h, env)
      delete req.param; delete req.paramLocation
      if (h.quantityField) req.quantityField = h.quantityField
      if (hasPathPlaceholder(h.endpoint.path) && !h.createPath) {
        if (h.repeatTransition && h.workflowListPath) {
          // The transition probe resolves a seeded object from its own collection below; keeping the
          // placeholder lets it pick a record that still has the prerequisite state.
          req.pathAndQuery = fillPlaceholders(h.endpoint.path, '{{id}}')
        } else {
        const segs = h.endpoint.path.split('?')[0].split('/').filter(Boolean)
        const collection = segs.length > 2 ? `/${segs.slice(0, -2).join('/')}` : null
        const creator = collection
          ? (env.endpoints ?? []).find(e => e.method.toUpperCase() === 'POST' && !hasPathPlaceholder(e.path) && e.path === collection)
          : undefined
        let id: string | undefined
        if (creator) {
          try {
            const created = await env.broker.executeHttp({
              origin: env.origin, method: 'POST', pathAndQuery: creator.path, persona: env.owner,
              headers: { 'Content-Type': 'application/json' }, body: '{}', followRedirects: false, timeoutMs: 8_000,
            }, env.grant, env.signal)
            if (created.status >= 200 && created.status < 300) id = harvestJson(created.body).ids[0]
          } catch { /* creator may reject an empty body */ }
        }
        if (!id) id = (await idPool(env, h.endpoint.path))[0]
        if (id) req.pathAndQuery = fillPlaceholders(h.endpoint.path, encodeURIComponent(id))
        }
        // Cart/order lines need a real catalog reference as well as the quantity under test.
        if (req.quantityField && /(?:cart|bag|order|line|item)/i.test(h.endpoint.path)) {
          const catalog = (env.endpoints ?? []).find(e =>
            e.method.toUpperCase() === 'GET' && !hasPathPlaceholder(e.path) && /(?:products?|wares?|catalog|items?)$/i.test(lastPathSegment(e.path)),
          )
          const productId = catalog ? (await idPool(env, catalog.path))[0] : undefined
          if (productId) req.jsonBody = { ...(req.jsonBody ?? {}), productId }
        }
      }
      if (h.createPath) {
        req.createPath = h.createPath
        req.producerBody = h.producerBody ?? {}
        if (hasPathPlaceholder(h.endpoint.path)) req.pathAndQuery = fillPlaceholders(h.endpoint.path, '{{id}}')
      }
      if (h.workflowReadPath) req.workflowReadPath = h.workflowReadPath
      if (h.workflowListPath) req.workflowListPath = h.workflowListPath
      req.workflowTargetTemplate = h.endpoint.path
      if (env.caps.sessionAndCsrf) req.csrfBind = true
      if (h.repeatTransition) req.repeatTransition = true
      if (h.priceTrust) req.priceTrust = true
      if (h.repeatMutation) {
        req.repeatMutation = true
        const money = await harvestMoneyBody(env, h.endpoint.path)
        if (money) {
          // The body field name is randomized per seed; send the value under every common amount
          // alias so the route parses the same authoritative total.
          const value = Object.values(money)[0]
          req.jsonBody = {
            ...(req.jsonBody ?? {}),
            amount: value, amountCents: value, value, total: value, price: value, cents: value,
          }
        }
      }
      if (!req.quantityField && !req.repeatTransition && !req.priceTrust && !req.repeatMutation) {
        const qty = h.endpoint.params.find(p => /^(?:qty|quantity|itemQty|count|seats?|amount)$/i.test(p.name))
        if (qty) req.quantityField = qty.name
      }
      // Workflow probes mix owner/other/viewer actors. The broker's per-session cookie jar is shared
      // across personas, and a rotated jar cookie can shadow the Vault credential; use a
      // persona-scoped session so each actor keeps its own jar and the owner write stays owner.
      if (env.caps.sessionAndCsrf && req.persona) {
        // Per-hypothesis jar: workflow probes mutate state, and a shared jar can carry a rotated or
        // consumed session into later writes. A fresh jar + token-issuing GET keeps the owner's
        // credential authoritative for exactly this probe.
        const scopedSession = `${env.session}-${req.persona}-${shortToken(4)}`
        const scopedEnv: ProbeEnv = { ...env, session: scopedSession }
        out.requests += await primeSessionOnce(h, scopedEnv)
        req.session = scopedSession
        req.csrfPrimePaths = (env.endpoints ?? [])
          .filter(e => e.method.toUpperCase() === 'GET' && !hasPathPlaceholder(e.path) &&
            /(?:^|[/_-])(?:me|csrf|session|token|nonce|xsrf)(?:$|[/_-])/i.test(e.path))
          .map(e => e.path)
          .slice(0, 2)
      }
      break
    }
    case 'cache_poison_deception': {
      req = buildProbeRequest(h, env)
      delete req.param; delete req.paramLocation
      const cacheShaped = /(?:public|share|preview|storefront|stores?\/|shops?\/|sellers?\/|vendors?\/|catalog)/i.test(h.endpoint.path)
      const placeholderCount = h.endpoint.path.split('?')[0].split('/').filter(seg => /^(:[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\])$/.test(seg)).length
      if (placeholderCount === 1) {
        const ownerIds = await idPool(env, h.endpoint.path, env.owner)
        const otherIds = env.other ? await idPool(env, h.endpoint.path, env.other) : []
        const ownerId = ownerIds[0]
        const otherId = otherIds.find(id => id !== ownerId) ?? otherIds[0]
        if (ownerId) req.pathAndQuery = fillPlaceholders(h.endpoint.path, encodeURIComponent(ownerId))
        if (otherId && otherId !== ownerId) req.crossControlPath = fillPlaceholders(h.endpoint.path, encodeURIComponent(otherId))
        req.crossActorSeeds = { ...(ownerId ? { owner: ownerId } : {}), ...(otherId ? { other: otherId } : {}) }
      } else if (placeholderCount >= 2 && cacheShaped && env.other) {
        const ownerClaims = await identityClaims(env, env.owner)
        const otherClaims = await identityClaims(env, env.other)
        const markerOf = (claims: Record<string, string>) => claims.store ?? claims.tenant ?? claims.org ?? claims.workspace ?? claims.team
        const ownerStore = markerOf(ownerClaims)
        const otherStore = markerOf(otherClaims)
        const catalog = (env.endpoints ?? []).find(e =>
          e.method.toUpperCase() === 'GET' && !hasPathPlaceholder(e.path) && /(?:wares?|products?|items?|catalog)/i.test(lastPathSegment(e.path)),
        )
        const productIds = catalog ? await idPool(env, catalog.path) : []
        if (ownerStore && otherStore && productIds[0]) {
          const fillTwo = (store: string): string => {
            const segs = h.endpoint.path.split('?')[0].split('/').map(seg => {
              if (!/^(:[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\])$/.test(seg)) return seg
              return null
            })
            const lastIdx = segs.reduce((last, seg, i) => (seg === null ? i : last), -1)
            return segs.map((seg, i) => seg === null ? encodeURIComponent(i === lastIdx ? productIds[0]! : store) : seg).join('/')
          }
          req.pathAndQuery = fillTwo(ownerStore)
          req.crossControlPath = fillTwo(otherStore)
        }
      } else if (hasPathPlaceholder(h.endpoint.path)) {
        const ids = await idPool(env, h.endpoint.path)
        const id = ids[0]
        if (id) req.pathAndQuery = fillPlaceholders(h.endpoint.path, encodeURIComponent(id))
      }
      if (cacheShaped) {
        req.ownerPersona = env.owner
        req.otherPersona = env.other
        const ownerClaims = await identityClaims(env, env.owner)
        const otherClaims = env.other ? await identityClaims(env, env.other) : {}
        const markerOf = (claims: Record<string, string>) => claims.store ?? claims.tenant ?? claims.org ?? claims.workspace ?? claims.team
        const ownerMarker = markerOf(ownerClaims)
        const otherMarker = markerOf(otherClaims)
        if (ownerMarker || otherMarker) req.actorMarkers = { ...(ownerMarker ? { owner: ownerMarker } : {}), ...(otherMarker ? { other: otherMarker } : {}) }
      }
      break
    }
    case 'auth_protocol_audit': {
      req = buildProbeRequest(h, env)
      delete req.param; delete req.paramLocation
      const tokenFields = h.endpoint.params
        .filter(p => (p.location === 'json' || p.location === 'form') && /token|jwt|assertion|access/i.test(p.name))
        .map(p => p.name)
      const pathHint = /token|refresh|jwt|session/i.test(h.endpoint.path)
      req.tokenFields = [...new Set([...tokenFields, ...(pathHint ? ['token', 'refreshToken', 'refresh_token', 'access_token'] : ['token'])])].slice(0, 4)
      req.identityClaims = await identityClaims(env)
      // Login/token routes can overwrite the caller's session identity (legacy login, self-mint).
      // Run them anonymously in an isolated jar so later owner probes keep their authorization.
      if (/(?:login|signin|token|refresh|oauth|sso)/i.test(h.endpoint.path)) {
        req.persona = undefined
      }
      if (env.caps.sessionAndCsrf) req.session = `${env.session}-a-${shortToken(4)}`
      break
    }
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
      const csrfBodyLocations = new Set(h.endpoint.params.filter(p => !p.isCsrf).map(p => p.location))
      // Try the encoding the surface advertised first, then the other one: some routes declare
      // JSON fields while their handler only parses form bodies (and vice versa).
      req.bodyEncodings = csrfBodyLocations.has('form') && !csrfBodyLocations.has('json') ? ['form', 'json'] : ['json', 'form']
      // Create-shaped writes read the object they just created back through its detail route.
      const createReadTemplate = h.csrfCreate
        ? getPaths.find(p => {
            if (!hasPathPlaceholder(p)) return false
            const parts = p.split('?')[0].split('/').filter(Boolean)
            return parts.slice(0, -1).join('/') === segs.join('/')
          })
        : undefined
      req.readPathCandidates = [...new Set([
        ...(idSlot ? (env.endpoints ?? [])
          .filter(e => e.method.toUpperCase() === 'GET' && hasPathPlaceholder(e.path))
          .filter(e => e.path.startsWith(`${parent}/`) && e.path.split('/').filter(Boolean).length === parent.split('/').filter(Boolean).length + 1)
          .slice(0, 1)
          .map(e => fillPlaceholders(e.path, encodeURIComponent(id))) : []),
        ...(readTemplate ? [readTemplate] : []),
        ...(collection ? [collection] : []),
      ])].map(tpl => hasPathPlaceholder(tpl) ? fillPlaceholders(tpl, encodeURIComponent(id)) : tpl)
      if (req.readPathCandidates.length > 0) req.readPath = req.readPathCandidates[0]
      if (idSlot && !createReadTemplate) req.stateRecordId = id
      if (createReadTemplate) req.createReadTemplate = createReadTemplate
      const bodyNames = h.endpoint.params.filter(p => (p.location === 'json' || p.location === 'form') && !p.isCsrf).map(p => p.name)
      const stateHint = bodyNames.find(n => /^(?:status|state)$/i.test(n)) ??
        bodyNames.find(n => /^(?:name|title|label|display_?name|amount|amount_?cents|value|total)$/i.test(n)) ??
        (/(trigger|confirm|approve|complete|activate|publish|status|state|workflow)/i.test(h.endpoint.path) ? 'status'
          : /(refund|credit|payment|payout|charge|transfer)/i.test(h.endpoint.path) ? 'amount'
            : /(settings|profile|account)/i.test(h.endpoint.path) ? 'name' : undefined)
      if (stateHint) {
        req.stateField = stateHint
        if (bodyNames.includes(stateHint) || /^(?:amount|status|name)$/.test(stateHint)) req.bodyField = stateHint
      }
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
      } else {
        const body = await fallbackWebhookBody(h, env)
        if (body) {
          req.webhookBody = body
          req.webhookHeader = h.endpoint.params.some(p => /signature|sig$|hmac/i.test(p.name)) ? 'x-webhook-signature' : 'x-hub-signature-256'
        }
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
    if (ctx.baseline && h.probeClass === 'path_traversal_benign') req.baselineValue = ctx.baseline
    if (ctx.xmlTemplate && h.location === 'xml') req.xmlTemplate = ctx.xmlTemplate
    if (ctx.graphqlQuery && h.location === 'graphql_var') req.graphqlQuery = ctx.graphqlQuery
  }
  if (h.probeClass === 'auth_protocol_audit') {
    req.persona = env.jwtPersona ?? env.owner
    // Only authorize-style flows are GET redirects; token/introspection endpoints keep their method.
    req.method = /(?:authorize|oauth|openid|\/sso\/)/i.test(h.endpoint.path) ? 'GET' : h.method
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
    // A proven write-path BOLA gets its own concrete object path so the write finding is not
    // deduplicated against the read finding on the same templated route (dedupe ignores the verb).
    if (h.writePathRead && hasPathPlaceholder(h.endpoint.path) &&
        res.anomalies.some(a => a.type === 'write_path_bola' || a.type === 'unauthorized_write')) {
      const ids = await idPool(env, h.endpoint.path)
      const writeId = ids[1] ?? ids[0]
      if (writeId) h.endpoint = { ...h.endpoint, path: fillPlaceholders(h.endpoint.path, encodeURIComponent(writeId)) }
    }
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

  // Function-level mutation (BFLA / server action): the mutation response is an echo, so observe the
  // function's own status route (or a sibling read inferred from its name) across a controlled state
  // transition. Only a real readback delta can support a persistence claim.
  const functionLevelMutation = h.probeClass === 'authz_matrix' && h.method !== 'GET' && !h.deleteMethod &&
    !hasPathPlaceholder(h.endpoint.path) &&
    !h.endpoint.params.some(p => (p.isObjectId || idName.test(p.name)) && p.location === 'query')
  if (functionLevelMutation && out.verdict === 'signal' && !out.tierBlocked && !env.signal.aborted) {
    const stateReadback = await observeFunctionStateReadback(h, env, out.pair?.owner, out.pair?.other, out.anomalies, watch)
    if (stateReadback) {
      out.details = { ...out.details, functionState: stateReadback }
    }
  }
  return out
}
