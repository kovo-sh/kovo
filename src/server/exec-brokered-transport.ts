import { randomUUID } from 'node:crypto'
import type { RequestHttpArgs, RequestHttpRaceArgs, WorkerToolHandlers } from './agent-session.ts'
import { computeStateChangeBodyHash, hasDeclaredMultipartContentType } from './approval-judge.ts'
import {
  BrokerApprovalRequired,
  BrokerDenied,
  websocketResultToExchange,
  type BrokerExchangeResult,
  type BrokerHttpRequest,
  type Grant,
  type RequestBroker,
} from './broker.ts'
import { scanSecondOrderMarkers, type CanaryBroker } from './canary-broker.ts'
import { templateIdsForCves } from './cve-broker.ts'
import { extractCreatedId, tagStagingEntityBody } from './deterministic-engine.ts'
import type { ExecBoardManager } from './exec-board.ts'
import { createExchangeRecorder, recordBrokerExchange, type ExecActiveJob } from './exec-exchange.ts'
import type { ExecBrokeredTransportContext } from './exec-worker-runner.ts'
import { BudgetExceededError } from './provider.ts'
import type { RunTier3ApprovalCoordinator } from './run-actor.ts'
import { tenantTagForRun } from './scope-policy.ts'
import type { ScopedBrowser } from './scoped-browser.ts'
import type { BoardMessageRow, Run, Store } from './store.ts'
import { runSafeTemplates } from './surface-engine.ts'
import type { RecordedRequestExchange } from './trace-proof-compiler.ts'

function tryParseJsonBody(raw?: string): unknown {
  if (!raw) return undefined
  const t = raw.trim()
  if (!t || (t[0] !== '{' && t[0] !== '[')) return undefined
  try { return JSON.parse(t) } catch { return undefined }
}

function emitRecordedExchange(
  cb: ((ex: RecordedRequestExchange) => void) | undefined,
  exchangeId: string,
  req: { headers?: Record<string, string>; body?: string; jsonBody?: unknown; persona?: string; followRedirects?: boolean },
  res: BrokerExchangeResult,
): void {
  if (!cb) return
  const rawSc = Object.entries(res.respHeaders ?? {}).find(([k]) => k.toLowerCase() === 'set-cookie')?.[1]
  const setCookies = rawSc
    ? rawSc.split(/\r?\n/).flatMap(ln => ln.split(/,\s*(?=[!#$%&'*+\-.^_`|~0-9A-Za-z]+=)/)).map(s => s.trim()).filter(Boolean)
    : undefined
  const reqJson = req.jsonBody !== undefined ? req.jsonBody : tryParseJsonBody(req.body)
  const respJson = tryParseJsonBody(res.body)
  const persona = res.personaHandle ?? req.persona ?? undefined
  cb({
    exchangeId,
    origin: res.origin,
    method: res.method,
    pathAndQuery: res.pathAndQuery,
    ...(persona ? { persona } : {}),
    requestHeaders: { ...(res.reqHeaders ?? {}), ...(req.headers ?? {}) },
    ...(req.body !== undefined ? { requestBody: req.body } : {}),
    ...(reqJson !== undefined ? { requestJson: reqJson } : {}),
    ...(req.followRedirects !== undefined ? { followRedirects: req.followRedirects } : {}),
    status: res.status,
    mediaType: res.mediaType,
    responseHeaders: res.respHeaders,
    ...(setCookies?.length ? { setCookies } : {}),
    responseBody: res.body,
    ...(respJson !== undefined ? { responseJson: respJson } : {}),
    timestampMs: Date.now(),
  })
}

export interface ExecBrokeredTransportHost {
  storage: Store
  broker: RequestBroker
  browser: ScopedBrowser
  canaryBroker: CanaryBroker
  stagingCreatedEntities: Map<string, Set<string>>
  check: (job: ExecActiveJob) => Run
  approvedOriginsSet: (run: Run) => Set<string>
  parseOriginForRun: (run: Run, raw: string) => string
  markEndpointCoverage: (run: Run, origin: string, method: string, pathAndQuery: string, testedClass: string) => void
  scanSecondOrderExchange: (
    run: Run,
    assignmentId: string,
    res: Pick<BrokerExchangeResult, 'origin' | 'pathAndQuery' | 'personaHandle' | 'mediaType' | 'respHeaders' | 'body'>,
    exchangeId: string | null,
    mediaTypeOverride?: string,
  ) => void
  postCanaryLead: (run: Run, input: Parameters<ExecBoardManager['postCanaryLead']>[1]) => BoardMessageRow | null
  stagingTagAgentRequest: (input: {
    runId: string
    grant: Grant
    mode: 'prod_readonly' | 'staging_isolated' | 'ephemeral_lab'
    entityTag: string
    method: string
    pathAndQuery: string
    probeClass?: string
    jsonBody?: unknown
  }) => { headers: Record<string, string>; jsonBody?: unknown; skipped?: string }
  stageAgentRaceBurst: (
    runId: string,
    grant: Grant,
    mode: 'prod_readonly' | 'staging_isolated' | 'ephemeral_lab',
    entityTag: string | null,
    requests: readonly BrokerHttpRequest[],
  ) => BrokerHttpRequest[]
  waitForTier3Approval: (
    ...a: Parameters<RunTier3ApprovalCoordinator['waitForTier3Approval']>
  ) => ReturnType<RunTier3ApprovalCoordinator['waitForTier3Approval']>
  executeApprovedRaceBurst: (
    ...a: Parameters<RunTier3ApprovalCoordinator['executeApprovedRaceBurst']>
  ) => ReturnType<RunTier3ApprovalCoordinator['executeApprovedRaceBurst']>
  executeApprovedBatch: (
    ...a: Parameters<RunTier3ApprovalCoordinator['executeApprovedBatch']>
  ) => ReturnType<RunTier3ApprovalCoordinator['executeApprovedBatch']>
}

export function buildBrokeredTransportHandlers(
  host: ExecBrokeredTransportHost,
  ctx: ExecBrokeredTransportContext,
): Partial<WorkerToolHandlers> {
  const {
    job, step, session, grant, currentSecrets, boardTools, sharedHandlers,
    trackPersonaResources, prepareBudgetedProbe, stageJsonArtifact, onExchangeRecorded,
  } = ctx

  const executeBrokerRequest = async (args: RequestHttpArgs, signal: AbortSignal): Promise<{
    exchangeId: string
    stagedPath: string | null
    result: BrokerExchangeResult
  }> => {
    const curRun = host.check(job)
    if (host.storage.checkBudgetExceeded(curRun.id)) {
      throw new BudgetExceededError('Run spend or request budget exceeded.')
    }
    const headers = { ...(args.headers ?? {}) }
    let jsonBody: unknown = args.jsonBody
    let body: string | undefined
    const scopePolicy = host.storage.scopePolicy(curRun)
    const stagingEntityTag = scopePolicy.mode === 'staging_isolated' ? tenantTagForRun(curRun.id) : null
    if (stagingEntityTag) {
      const tagged = host.stagingTagAgentRequest({
        runId: curRun.id, grant, mode: scopePolicy.mode, entityTag: stagingEntityTag,
        method: args.method, pathAndQuery: args.pathAndQuery,
        ...(args.probeClass ? { probeClass: args.probeClass } : {}),
        ...(jsonBody !== undefined ? { jsonBody } : {}),
      })
      if (tagged.skipped) {
        throw new BrokerDenied(`staging_isolated cannot safely tag this mutation (${tagged.skipped}); skipped without sending.`)
      }
      Object.assign(headers, tagged.headers)
      if (tagged.jsonBody !== undefined) jsonBody = tagged.jsonBody
    }
    if (args.textBody !== undefined) {
      body = args.textBody
      if (headers['x-kovo-tenant-tag'] && jsonBody === undefined) {
        try {
          const parsed = JSON.parse(args.textBody) as unknown
          if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
            body = JSON.stringify(tagStagingEntityBody(parsed as Record<string, unknown>, stagingEntityTag!))
          }
        } catch { /* non-JSON text bodies stay byte-identical; headers still carry the tag */ }
      }
    } else if (jsonBody !== undefined) {
      body = JSON.stringify(jsonBody)
      if (!headers['Content-Type'] && !headers['content-type']) headers['Content-Type'] = 'application/json'
    }

    const runHttp = () => host.broker.executeHttp({
      origin: args.origin,
      method: args.method,
      pathAndQuery: args.pathAndQuery,
      headers,
      body,
      multipartParts: args.multipartParts,
      persona: args.persona,
      session: args.session,
      csrfBind: args.csrfBind,
      authMutation: args.authMutation,
      probeClass: args.probeClass,
      traceId: args.traceId,
      runId: curRun.id,
      assignmentId: job.assignment.id,
      scopeRevision: curRun.scopeRevision,
      followRedirects: args.followRedirects ?? false,
    }, grant, signal)

    let res: BrokerExchangeResult
    try {
      res = await runHttp()
    } catch (err) {
      if (err instanceof BrokerApprovalRequired) {
        const approval = await host.waitForTier3Approval(job, {
          origin: err.origin,
          method: err.method,
          pathAndQuery: err.pathAndQuery,
          personaHandle: args.persona ?? null,
          rationale: args.rationale ?? `Tier 3 probe during step "${step.title}"`,
          requestPreview: JSON.stringify({
            method: args.method, origin: args.origin, pathAndQuery: args.pathAndQuery,
            persona: args.persona, headers, bodyPreview: body?.slice(0, 500),
            ...(args.multipartParts?.length ? { multipartPartsCount: args.multipartParts.length } : {}),
          }, null, 2),
          bodyPreview: body,
          bodyHash: computeStateChangeBodyHash(body, args.multipartParts),
          headers,
          hasMultipart: Boolean(args.multipartParts?.length) || hasDeclaredMultipartContentType(headers),
          secrets: currentSecrets(),
        }, signal)
        if (!approval.approved) {
          throw new BrokerDenied(
            approval.deniedReason
              ? `Tier 3 Safety Judge denied probe: ${approval.deniedReason}`
              : 'Tier 3 request was denied or expired.',
          )
        }
        res = await runHttp()
      } else {
        throw err
      }
    }

    const saved = recordBrokerExchange(host.storage, curRun, job.assignment.id, res, currentSecrets())
    emitRecordedExchange(onExchangeRecorded, saved.id, { headers, body, jsonBody, persona: args.persona, followRedirects: args.followRedirects ?? false }, res)
    trackPersonaResources(curRun, res, saved.id); boardTools.noteEvidence()
    host.markEndpointCoverage(curRun, res.origin, res.method, res.pathAndQuery, 'http_exchange')
    host.scanSecondOrderExchange(curRun, job.assignment.id, res, saved.id)
    if (stagingEntityTag && /^(?:POST|PUT|PATCH)$/i.test(args.method) && res.status >= 200 && res.status < 300) {
      const created = extractCreatedId(res.body)
      if (created) {
        const set = host.stagingCreatedEntities.get(curRun.id) ?? new Set<string>()
        set.add(created)
        host.stagingCreatedEntities.set(curRun.id, set)
      }
    }

    let stagedPath: string | null = null
    try {
      stagedPath = await session.stage(`exchanges/${saved.id}.json`, JSON.stringify({
        exchangeId: saved.id, origin: res.origin, finalOrigin: res.finalOrigin,
        redirectOrigins: res.redirectOrigins, method: res.method, pathAndQuery: res.pathAndQuery,
        status: res.status, mediaType: res.mediaType, reqHeaders: res.reqHeaders,
        respHeaders: res.respHeaders, setCookies: res.setCookies, bodySha256: res.bodySha256, body: res.body,
      }, null, 2), signal)
    } catch { /* ignore stage error */ }
    return { exchangeId: saved.id, stagedPath, result: res }
  }

  const buildNormalizedBrokerBody = (r: { headers?: Record<string, string>; textBody?: string; jsonBody?: unknown }) => {
    const headers = { ...(r.headers ?? {}) }
    let body: string | undefined
    if (r.textBody !== undefined) body = r.textBody
    else if (r.jsonBody !== undefined) {
      body = JSON.stringify(r.jsonBody)
      if (!headers['Content-Type'] && !headers['content-type']) headers['Content-Type'] = 'application/json'
    }
    return { headers, body }
  }
  const recordTrackedBatchExchange = (curRun: Run, res: BrokerExchangeResult) =>
    recordBrokerExchange(host.storage, curRun, job.assignment.id, res, currentSecrets(), {
      markCoverage: (r, o, m, p) => host.markEndpointCoverage(r, o, m, p, 'http_exchange'),
      onSaved: (r, e, id) => {
        trackPersonaResources(r, e, id)
        host.scanSecondOrderExchange(r, job.assignment.id, e, id)
      },
    })

  const executeRaceBurstTool = async (args: RequestHttpRaceArgs, signal: AbortSignal) => {
    const curRun = host.check(job)
    if (curRun.capabilityTier < 2) throw new BrokerDenied('Race-condition burst testing requires Capability Tier 2 or Tier 3.')
    if (host.storage.checkBudgetExceeded(curRun.id)) throw new BudgetExceededError('Run spend or request budget exceeded.')
    if (curRun.budgetRequests > 0 && curRun.spentRequests + args.requests.length > curRun.budgetRequests) {
      throw new BudgetExceededError('Race burst would exceed run request budget.')
    }
    const racePolicy = host.storage.scopePolicy(curRun)
    const raceEntityTag = racePolicy.mode === 'staging_isolated' ? tenantTagForRun(curRun.id) : null
    const brokerReqs: BrokerHttpRequest[] = args.requests.map(r => {
      const { headers, body } = buildNormalizedBrokerBody(r)
      return {
        origin: r.origin, method: r.method, pathAndQuery: r.pathAndQuery,
        headers, body, persona: r.persona, session: r.session,
        csrfBind: r.csrfBind, authMutation: r.authMutation, probeClass: r.probeClass,
        traceId: r.traceId, runId: curRun.id, assignmentId: job.assignment.id,
        scopeRevision: curRun.scopeRevision, followRedirects: r.followRedirects ?? false,
      }
    })
    const stagedReqs = host.stageAgentRaceBurst(curRun.id, grant, racePolicy.mode, raceEntityTag, brokerReqs)
    const burst = await host.executeApprovedRaceBurst(job, stagedReqs, grant, signal, {
      stepTitle: step.title,
      rationale: args.rationale,
      secrets: currentSecrets(),
      execute: () => host.broker.executeRaceBurst(stagedReqs, grant, signal),
    })
    const summaries = burst.results.map((res, idx) => {
      const id = recordTrackedBatchExchange(curRun, res).id
      const r = stagedReqs[idx]
      emitRecordedExchange(onExchangeRecorded, id, { headers: r?.headers, body: r?.body, persona: r?.persona, followRedirects: r?.followRedirects }, res)
      return { exchangeId: id, origin: res.origin, method: res.method, pathAndQuery: res.pathAndQuery, personaHandle: res.personaHandle, status: res.status, durationMs: res.durationMs, bodySha256: res.bodySha256, bodyPreview: res.bodyPreview.slice(0, 800) }
    })
    const stagedPath = await session.stage(`exchanges/race-${randomUUID().slice(0, 8)}.json`,
      JSON.stringify({ summary: burst.summary, results: summaries }, null, 2), signal).catch(() => null)
    boardTools.noteEvidence()
    return { count: summaries.length, summary: burst.summary, stagedPath, results: summaries }
  }

  return {
    request_http: async (args, signal) => {
      const { exchangeId, stagedPath, result } = await executeBrokerRequest(args, signal)
      return {
        exchangeId, stagedPath, origin: result.origin, finalOrigin: result.finalOrigin,
        redirectOrigins: result.redirectOrigins, status: result.status, mediaType: result.mediaType,
        respHeaders: result.respHeaders, setCookies: result.setCookies, bodyBytes: result.bodyBytes,
        bodySha256: result.bodySha256, bodyPreview: result.bodyPreview.slice(0, 6000), durationMs: result.durationMs,
      }
    },

    request_http_batch: async (args, signal) => {
      const curRun = host.check(job)
      if (host.storage.checkBudgetExceeded(curRun.id)) throw new BudgetExceededError('Budget exceeded.')
      const brokerReqs = args.requests.map(r => {
        const { headers, body } = buildNormalizedBrokerBody(r)
        return {
          origin: r.origin, method: r.method, pathAndQuery: r.pathAndQuery,
          headers, body, persona: r.persona, session: r.session,
          multipartParts: r.multipartParts,
          csrfBind: r.csrfBind, authMutation: r.authMutation, probeClass: r.probeClass,
          traceId: r.traceId, runId: curRun.id, assignmentId: job.assignment.id,
          scopeRevision: curRun.scopeRevision,
          followRedirects: r.followRedirects ?? false,
        }
      })
      const results = await host.executeApprovedBatch(job, brokerReqs, grant, signal, {
        stepTitle: step.title,
        rationale: args.rationale,
        secrets: currentSecrets(),
        execute: () => host.broker.executeBatch(brokerReqs, grant, signal),
      })
      const summaries = results.map((res, idx) => {
        const id = recordTrackedBatchExchange(curRun, res).id; const r = brokerReqs[idx]
        emitRecordedExchange(onExchangeRecorded, id, { headers: r?.headers, body: r?.body, persona: r?.persona, followRedirects: r?.followRedirects }, res)
        return { exchangeId: id, status: res.status, durationMs: res.durationMs, bodySha256: res.bodySha256, bodyPreview: res.bodyPreview.slice(0, 800) }
      })
      const stagedPath = await session.stage(`exchanges/batch-${randomUUID().slice(0, 8)}.json`,
        JSON.stringify(summaries, null, 2), signal).catch(() => null)
      boardTools.noteEvidence()
      return { count: summaries.length, stagedPath, results: summaries }
    },

    requestHttpRace: executeRaceBurstTool,
    request_http_race: executeRaceBurstTool,

    browser_visit: async (args, signal) => {
      const curRun = host.check(job)
      if (host.storage.checkBudgetExceeded(curRun.id)) throw new BudgetExceededError('Budget exceeded.')
      const res = await host.browser.visitPage({
        origin: args.origin, pathAndQuery: args.pathAndQuery,
        persona: args.persona, session: args.session,
        runId: curRun.id, assignmentId: job.assignment.id, traceId: randomUUID(),
        checkKind: args.domCheck && args.domCheck !== 'none' ? args.domCheck : undefined,
        actions: args.actions, enableSinkHook: args.enableSinkHook,
        waitAfterLoadMs: args.waitAfterLoadMs, secrets: currentSecrets(),
        onExchange: ex => {
          const saved = recordBrokerExchange(host.storage, curRun, job.assignment.id, ex, currentSecrets())
          host.scanSecondOrderExchange(curRun, job.assignment.id, ex, saved.id)
          return saved.id
        },
      }, grant, signal)
      const summaryObj = {
        origin: res.origin, finalUrl: res.finalUrl, title: res.title, status: res.status,
        links: res.links.slice(0, 60), forms: res.forms.slice(0, 30),
        xhrRequests: res.xhrRequests.slice(0, 80), blockedOrigins: res.blockedOrigins,
        consoleMessages: res.consoleMessages.slice(0, 40), postMessageListeners: res.postMessageListeners,
        cookieNames: res.cookieNames, localStorageKeys: res.localStorageKeys,
        sessionStorageKeys: res.sessionStorageKeys, canaryCheck: res.canaryCheck,
        actionResults: res.actionResults, builtinResults: res.builtinResults,
        domSinkTraces: res.domSinkTraces, exchangeIds: res.exchangeIds,
        domSnippet: res.domSnippet.slice(0, 6000), durationMs: res.durationMs,
      }
      const staged = await stageJsonArtifact(
        curRun, 'browser', `Browser visit · ${args.origin}${args.pathAndQuery.slice(0, 60)}`,
        'browser-{id}.json', summaryObj, signal,
      )
      boardTools.noteEvidence()
      return { ...staged, ...summaryObj }
    },

    run_sast_scan: async (args, signal) => {
      const curRun = host.check(job)
      const res = await sharedHandlers.run_sast_scan!(args, signal)
      const scaCves = new Map<string, { file: string; severity: string }>()
      for (const finding of res.findings) {
        if (finding.engine !== 'trivy-fs') continue
        for (const match of `${finding.ruleId} ${finding.message}`.matchAll(/CVE-\d{4}-\d{4,}/gi)) {
          const cve = match[0].toUpperCase()
          if (!scaCves.has(cve)) scaCves.set(cve, { file: finding.file, severity: finding.severity })
        }
      }
      if (scaCves.size > 0) {
        const targetOrigin = [...host.approvedOriginsSet(curRun)][0]
        const existingCves = new Set(
          host.storage.listFacts(curRun.id, { includeTainted: false, kind: 'cve_hypothesis', limit: 100 })
            .map(f => (typeof f.data?.cveId === 'string' ? f.data.cveId.toUpperCase() : '')),
        )
        for (const [cve, meta] of [...scaCves.entries()].slice(0, 40)) {
          if (!targetOrigin || existingCves.has(cve)) continue
          existingCves.add(cve)
          host.storage.addFact(curRun, job.assignment, {
            kind: 'cve_hypothesis',
            origin: targetOrigin,
            summary: `trivy-fs flagged ${cve} (${meta.severity}) in ${res.repo}/${meta.file}. Hypothesis only: verify runtime reachability with a non-destructive Replay Spec.`,
            data: {
              cveId: cve, repo: res.repo, file: meta.file, severity: meta.severity, source: 'trivy-fs',
              templateIds: templateIdsForCves([cve]), confidence: 'low',
            },
            sourceOrigins: [targetOrigin],
            secrets: currentSecrets(),
          })
        }
      }
      return res
    },

    run_safe_templates: async (args, signal) => {
      const { curRun, cleanOrigin, remainingReqs } = prepareBudgetedProbe(args.origin, undefined, 150)
      const techFactTags = host.storage.listFacts(curRun.id, { includeTainted: false, origin: cleanOrigin, kind: 'tech_fingerprint', limit: 30 })
        .flatMap(f => {
          const tags = f.data?.tags
          return Array.isArray(tags) ? tags.filter((t): t is string => typeof t === 'string') : []
        })
      const techFingerprint = [...new Set([...(args.techTags ?? []), ...techFactTags])]
      const cveIds = [...new Set(
        host.storage.listFacts(curRun.id, { includeTainted: false, kind: 'cve_hypothesis', limit: 40 })
          .map(f => (typeof f.data?.cveId === 'string' ? f.data.cveId.trim().toUpperCase() : ''))
          .filter(cve => /^CVE-\d{4}-\d{4,}$/i.test(cve)),
      )]
      const liveOrigins = host.approvedOriginsSet(curRun)
      const runEndpoints = host.storage.listEndpoints(curRun.id).filter(ep => liveOrigins.has(ep.origin))
      const protectedPaths = [...new Set(
        runEndpoints.map(ep => ep.pathTemplate.split('?')[0])
          .filter(path => /(admin|account|billing|settings|invoice|dashboard)/i.test(path)),
      )].slice(0, 6)
      const apiPaths = [...new Set(
        runEndpoints.map(ep => ep.pathTemplate.split('?')[0])
          .filter(path => /^\/(api|graphql|trpc)/i.test(path)),
      )].slice(0, 6)
      const res = await runSafeTemplates({
        origin: cleanOrigin,
        techFingerprint: techFingerprint.length ? techFingerprint : undefined,
        ...(templateIdsForCves(cveIds).length || args.templateIds?.length
          ? { templateIds: [...new Set([...(args.templateIds ?? []), ...templateIdsForCves(cveIds)])] }
          : {}),
        ...(cveIds.length ? { cveIds } : {}),
        ...(protectedPaths.length || apiPaths.length ? { discoveredPaths: { protectedPaths, apiPaths } } : {}),
        maxTemplates: args.maxTemplates,
        maxRequests: Math.min(150, remainingReqs),
        persona: args.persona,
        runId: curRun.id,
        assignmentId: job.assignment.id,
        storage: host.storage,
        onExchange: createExchangeRecorder(host.storage, () => curRun, job.assignment.id, currentSecrets),
      }, host.broker, grant, host.canaryBroker, signal)
      host.storage.recordSurfaceProbe({
        runId: curRun.id, assignmentId: job.assignment.id, scopeRevision: curRun.scopeRevision,
        origin: res.origin, probeKind: 'safe_templates',
        requestsSent: res.requestsSent, anomaliesFound: res.matches.length, baselineSignature: res.baselineSignature,
      })
      for (const match of res.matches) {
        host.storage.addFact(curRun, job.assignment, {
          kind: match.factKind === 'cve_hypothesis' ? 'cve_hypothesis' : 'note',
          origin: res.origin,
          summary: `[Safe template ${match.templateId}] ${match.name} (${match.severity}) on ${match.method} ${match.path} (HTTP ${match.status})`,
          data: {
            templateId: match.templateId, cve: match.cve ?? null, cwe: match.cwe ?? null,
            severity: match.severity, evidence: match.evidence, controlStatus: match.controlStatus, confidence: 'low',
          },
          exchangeIds: match.exchangeId ? [match.exchangeId] : [],
          sourceOrigins: [res.origin],
          secrets: currentSecrets(),
        })
      }
      const staged = await stageJsonArtifact(
        curRun, 'surface', `Safe templates · ${res.origin} (${res.matches.length} matches)`,
        'templates-{id}.json', res, signal,
      )
      return { ...staged, ...res }
    },

    probe_websocket: async (args, signal) => {
      const curRun = host.check(job)
      if (host.storage.checkBudgetExceeded(curRun.id)) throw new BudgetExceededError('Run spend or request budget exceeded.')
      const cleanOrigin = host.parseOriginForRun(curRun, args.origin)
      const wsRes = await host.broker.probeWebsocket({
        origin: cleanOrigin, pathAndQuery: args.pathAndQuery, originHeader: args.spoofOrigin,
        persona: args.persona, subprotocols: args.subprotocols, sendMessages: args.messages,
        maxFrames: args.maxFrames, timeoutMs: args.timeoutMs, secrets: currentSecrets(),
      }, grant, signal)
      const syntheticEx = websocketResultToExchange(wsRes)
      const saved = recordBrokerExchange(host.storage, curRun, job.assignment.id, syntheticEx, currentSecrets())
      const wsScanText = [
        ...Object.entries(wsRes.upgradeHeaders ?? {}).map(([k, v]) => `${k}: ${v}`),
        ...wsRes.frames.map(frame => frame.data),
      ].join('\n')
      if (wsScanText.includes('gn2o_')) {
        const surfaced = scanSecondOrderMarkers({
          text: wsScanText, runId: curRun.id, assignmentId: job.assignment.id,
          origin: wsRes.origin, endpoint: wsRes.pathAndQuery, persona: wsRes.personaHandle,
          mediaType: 'websocket', exchangeId: saved.id, storage: host.storage,
        })
        for (const record of surfaced) {
          host.postCanaryLead(curRun, {
            marker: record.marker, origin: wsRes.origin, endpoint: wsRes.pathAndQuery,
            persona: wsRes.personaHandle, exchangeId: saved.id, mediaType: 'websocket',
          })
        }
      }
      const staged = await stageJsonArtifact(
        curRun, 'ws', `WebSocket probe · ${wsRes.origin}${wsRes.pathAndQuery.slice(0, 60)}`,
        'ws-{id}.json', { exchangeId: saved.id, ...wsRes }, signal,
      )
      return { exchangeId: saved.id, ...staged, ...wsRes }
    },
  }
}
