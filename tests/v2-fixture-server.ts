import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'

export const E2E_CREDENTIAL = 'guardian-v2-e2e-fixture-key-99182'
export const E2E_COOKIE_SECRET = 'e2e-synthetic-session-cookie-77123'

type ResponsesToolCall = { name: string; args: Record<string, unknown> }

function sseMessage(text: string, toolCalls: ResponsesToolCall[] = []): string {
  const responseId = 'resp_' + randomUUID().slice(0, 12)
  const events: Record<string, unknown>[] = [
    { type: 'response.created', response: { id: responseId, status: 'in_progress', output: [] } },
  ]
  const output: Record<string, unknown>[] = []
  let idx = 0

  if (text) {
    const msgId = 'msg_' + randomUUID().slice(0, 8)
    events.push(
      { type: 'response.output_item.added', output_index: idx, item: { id: msgId, type: 'message', status: 'in_progress', role: 'assistant', content: [] } },
      { type: 'response.output_text.delta', output_index: idx, item_id: msgId, content_index: 0, delta: text },
      { type: 'response.output_text.done', output_index: idx, item_id: msgId, content_index: 0, text },
      { type: 'response.output_item.done', output_index: idx, item: { id: msgId, type: 'message', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text }] } },
    )
    output.push({ id: msgId, type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text }] })
    idx += 1
  }

  for (const call of toolCalls) {
    const fcId = 'fc_' + randomUUID().slice(0, 8)
    const callId = 'call_' + randomUUID().slice(0, 8)
    const serialized = JSON.stringify(call.args)
    events.push(
      { type: 'response.output_item.added', output_index: idx, item: { id: fcId, type: 'function_call', status: 'in_progress', call_id: callId, name: call.name, arguments: '' } },
      { type: 'response.function_call_arguments.delta', output_index: idx, item_id: fcId, delta: serialized },
      { type: 'response.function_call_arguments.done', output_index: idx, item_id: fcId, name: call.name, arguments: serialized },
      { type: 'response.output_item.done', output_index: idx, item: { id: fcId, type: 'function_call', status: 'completed', call_id: callId, name: call.name, arguments: serialized } },
    )
    output.push({ id: fcId, type: 'function_call', status: 'completed', call_id: callId, name: call.name, arguments: serialized })
    idx += 1
  }

  events.push({
    type: 'response.completed',
    response: {
      id: responseId,
      status: 'completed',
      output,
      usage: { input_tokens: 400, output_tokens: 120, total_tokens: 520 },
    },
  })

  return events.map(ev => `data: ${JSON.stringify(ev)}\n\n`).join('') + 'data: [DONE]\n\n'
}

export interface V2FixtureOptions {
  scenario: 'chain_cve' | 'tier3_approval' | 'two_host_revoke'
  holdTargetPath?: string
}

export async function createV2FixtureServer(options: V2FixtureOptions) {
  let patched = false
  let holdTargetPath = options.holdTargetPath
  const targetRequests: Array<{ method: string; target: string; headers: Record<string, string | string[] | undefined> }> = []
  const modelCalls: string[] = []
  const heldTargetResponses: ServerResponse[] = []
  let targetHeld = Promise.withResolvers<void>()

  const cveReplaySpec = {
    version: 1,
    kind: 'http_chain',
    origin: 'https://northstar.example',
    title: 'Next.js Middleware Auth Bypass (CVE-2025-29927)',
    category: 'broken-access-control',
    cwe: 'CWE-287',
    severity: 'critical',
    severityRationale: 'Unauthenticated callers can bypass middleware auth on /api/admin/bypass via x-middleware-subrequest.',
    impact: 'Full unauthorized access to administrative API endpoints.',
    remediation: 'Upgrade Next.js to >= 14.2.25 and strip external x-middleware-subrequest headers at the edge.',
    recheckInstructions: 'Re-run the declarative replay spec to confirm HTTP 401 on both control and probe requests.',
    spaCatchallControl: true,
    steps: [
      {
        id: 'control',
        role: 'control',
        description: 'Clean GET /api/admin/bypass without spoofed header returns 401.',
        request: {
          origin: 'https://northstar.example',
          method: 'GET',
          pathAndQuery: '/api/admin/bypass',
          followRedirects: false,
        },
      },
      {
        id: 'probe',
        role: 'probe',
        description: 'GET /api/admin/bypass with x-middleware-subrequest header.',
        request: {
          origin: 'https://northstar.example',
          method: 'GET',
          pathAndQuery: '/api/admin/bypass',
          headers: { 'x-middleware-subrequest': 'middleware:middleware:middleware:middleware:middleware' },
          followRedirects: false,
        },
      },
    ],
    assertionsJq: `{
      controlPassed: (.steps.control.status == 401),
      confirmed: (.steps.probe.status == 200 and (.steps.probe.body | contains("admin_bypass_confirmed")) and ((.spaCatchall.allProbesMatchedCatchall // false) | not)),
      observed: ("control=" + (.steps.control.status | tostring) + ", probe=" + (.steps.probe.status | tostring)),
      expected: "HTTP 401 on both control and probe"
    }`,
  }

  function handleTarget(req: IncomingMessage, res: ServerResponse, targetHref: string) {
    const url = new URL(targetHref)
    if (url.pathname === '/app.js') {
      res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' })
        .end('/* bundle */\nfetch("/api/admin/bypass").then(r => r.json());\n')
      return
    }
    if (url.pathname === '/api/admin/bypass') {
      const hasSubreq = Boolean(req.headers['x-middleware-subrequest'])
      if (hasSubreq && !patched) {
        res.writeHead(200, { 'Content-Type': 'application/json' })
          .end(JSON.stringify({ ok: true, marker: 'admin_bypass_confirmed' }))
      } else {
        res.writeHead(401, { 'Content-Type': 'application/json' })
          .end(JSON.stringify({ error: patched ? 'patched_unauthorized' : 'unauthorized' }))
      }
      return
    }
    if (url.pathname === '/api/state-eval' && req.method === 'POST') {
      res.writeHead(200, { 'Content-Type': 'application/json' })
        .end(JSON.stringify({ stateProbeOk: true, status: 'verified' }))
      return
    }
    if (url.pathname.startsWith('/.guardian-nonexistent-')) {
      res.writeHead(404, { 'Content-Type': 'text/plain' }).end('Not Found')
      return
    }
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Powered-By': 'Next.js 14.2.20',
      'Set-Cookie': `sid=${E2E_COOKIE_SECRET}; Path=/`,
    }).end('<!doctype html><html><head><title>Northstar</title></head><body><script src="/app.js"></script></body></html>')
  }

  async function handleModel(req: IncomingMessage, res: ServerResponse) {
    const auth = req.headers.authorization
    if (auth !== `Bearer ${E2E_CREDENTIAL}` && req.headers['x-api-key'] !== E2E_CREDENTIAL) {
      res.writeHead(401, { 'Content-Type': 'application/json' }).end('{"error":{"message":"Invalid key"}}')
      return
    }
    const chunks: Buffer[] = []
    for await (const c of req) chunks.push(Buffer.from(c))
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as {
      tools?: Array<{ name?: string }>
      input?: Array<Record<string, unknown>>
    }
    const toolNames = new Set((body.tools ?? []).map(t => t.name ?? ''))
    const serializedInput = JSON.stringify(body.input ?? [])

    let sseBody: string

    if (toolNames.has('guardian_connection')) {
      modelCalls.push('connection')
      sseBody = sseMessage('', [{ name: 'guardian_connection', args: { status: 'ready' } }])
    } else if (toolNames.has('request_http') && toolNames.has('complete_intent')) {
      // Worker investigation turn! Count how many function_call_output entries are in input
      const outputs = (body.input ?? []).filter(item => item.type === 'function_call_output')
      const alreadyCompleted = (body.input ?? []).some(
        item => item.type === 'function_call' && item.name === 'complete_intent',
      )
      if (alreadyCompleted) {
        modelCalls.push('worker:final_text')
        sseBody = sseMessage('Investigation summary committed.')
      } else if (options.scenario === 'tier3_approval') {
        if (outputs.length === 0) {
          modelCalls.push('worker:tier3_post')
          sseBody = sseMessage('', [{
            name: 'request_http',
            args: {
              origin: 'https://northstar.example',
              method: 'POST',
              pathAndQuery: '/api/state-eval',
              jsonBody: { probe: 'benign-tier3-check' },
              rationale: 'Verify Tier 3 HITL-approved benign state probe on /api/state-eval.',
            },
          }])
        } else {
          modelCalls.push('worker:tier3_complete')
          sseBody = sseMessage('', [
            {
              name: 'record_fact',
              args: {
                kind: 'endpoint',
                origin: 'https://northstar.example',
                summary: 'Tier 3 approved POST /api/state-eval succeeded cleanly.',
              },
            },
            {
              name: 'complete_intent',
              args: {
                status: 'proved',
                summary: 'Executed operator-approved Tier 3 probe on /api/state-eval.',
              },
            },
          ])
        }
      } else {
        // chain_cve or two_host_revoke
        const targetHost = serializedInput.includes('api.northstar.example') && !serializedInput.includes('northstar.example/app.js')
          ? 'https://api.northstar.example'
          : 'https://northstar.example'
        if (outputs.length === 0) {
          modelCalls.push('worker:harvest_js')
          sseBody = sseMessage('', [{
            name: 'request_http',
            args: {
              origin: targetHost,
              method: 'GET',
              pathAndQuery: '/app.js',
              followRedirects: true,
              rationale: 'Harvest SPA bundle for hidden API endpoints.',
            },
          }])
        } else {
          modelCalls.push('worker:propose_and_complete')
          const calls: ResponsesToolCall[] = [
            {
              name: 'record_fact',
              args: {
                kind: 'endpoint',
                origin: targetHost,
                summary: 'Harvested hidden admin endpoint /api/admin/bypass from /app.js.',
              },
            },
            {
              name: 'record_coverage',
              args: {
                origin: targetHost,
                category: 'broken-access-control',
                status: targetHost === 'https://northstar.example' ? 'reported' : 'no_issue_found',
                summary: 'Checked middleware auth bypass on /api/admin/bypass.',
              },
            },
          ]
          if (targetHost === 'https://northstar.example') {
            calls.push({
              name: 'propose_chain_finding',
              args: { replaySpec: cveReplaySpec },
            })
          }
          calls.push({
            name: 'complete_intent',
            args: {
              status: targetHost === 'https://northstar.example' ? 'proved' : 'ruled_out',
              summary: 'Completed JS harvest and proposed CVE-2025-29927 replay spec.',
            },
          })
          sseBody = sseMessage('', calls)
        }
      }
    } else if (serializedInput.includes('initialSteps') || serializedInput.includes('Threat Model') || serializedInput.includes('surfaceTags')) {
      modelCalls.push('threat_model')
      const hasApi = serializedInput.includes('https://api.northstar.example')
      const entries = [
        { origin: 'https://northstar.example', riskTier: 'critical', surfaceTags: ['web', 'nextjs'], rationale: 'Next.js primary app with lockfile CVE-2025-29927 hypothesis.' },
        ...(hasApi ? [{ origin: 'https://api.northstar.example', riskTier: 'high', surfaceTags: ['api'], rationale: 'Secondary API host.' }] : []),
      ]
      const initialSteps = [
        {
          title: 'Investigate northstar.example JS & CVE-2025-29927',
          hypothesis: 'Harvest /app.js and test /api/admin/bypass for middleware bypass.',
          category: 'broken-access-control',
          priority: 95,
          origins: ['https://northstar.example'],
          skills: ['recon-modern-spa', 'cve-runtime-correlation'],
        },
        ...(hasApi ? [{
          title: 'Inspect api.northstar.example endpoints',
          hypothesis: 'Check API surface on api.northstar.example.',
          category: 'broken-access-control',
          priority: 80,
          origins: ['https://api.northstar.example'],
          skills: ['api-rest-graphql'],
        }] : []),
      ]
      sseBody = sseMessage(JSON.stringify({ summary: 'Prioritized northstar.example critical Next.js surface.', entries, initialSteps }))
    } else if (serializedInput.includes('newSteps') && serializedInput.includes('cancelStepIds')) {
      modelCalls.push('chain_planner')
      sseBody = sseMessage(JSON.stringify({ summary: 'All investigation steps complete.', newSteps: [], cancelStepIds: [], done: true }))
    } else if (serializedInput.includes('checks')) {
      modelCalls.push('review_plan')
      sseBody = sseMessage(JSON.stringify({ checks: ['hsts', 'nosniff', 'referrer-policy', 'content-security-policy', 'frame-protection', 'server-disclosure'] }))
    } else {
      modelCalls.push('coordinator_chat')
      sseBody = sseMessage('Guardian coordinator status: active assessment progressing under approved scope.')
    }

    res.writeHead(200, { 'Content-Type': 'text/event-stream' })
    res.end(sseBody)
  }

  const server = createServer((req, res) => {
    if (req.method === 'POST' && (req.url ?? '').startsWith('/api/v1/')) {
      void handleModel(req, res).catch(() => {
        if (!res.headersSent) res.writeHead(500)
        res.end()
      })
      return
    }
    const targetHref = req.headers['x-guardian-fixture-target']
    if (typeof targetHref !== 'string') {
      res.writeHead(400).end('Missing x-guardian-fixture-target')
      return
    }
    targetRequests.push({ method: req.method ?? 'GET', target: targetHref, headers: req.headers })
    const url = new URL(targetHref)
    if (holdTargetPath && url.pathname === holdTargetPath) {
      heldTargetResponses.push(res)
      targetHeld.resolve()
      return
    }
    handleTarget(req, res, targetHref)
  }).listen(0, '127.0.0.1')

  await once(server, 'listening')
  const addr = server.address()
  if (!addr || typeof addr === 'string') throw new Error('Could not bind v2 fixture server.')

  return {
    origin: `http://127.0.0.1:${addr.port}`,
    targetRequests,
    modelCalls,
    get targetHeld() { return targetHeld.promise },
    setPatched(value: boolean) { patched = value },
    releaseTargetHold() {
      holdTargetPath = undefined
      for (const res of heldTargetResponses.splice(0)) {
        if (!res.destroyed) {
          res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' })
            .end('/* released bundle */\nfetch("/api/admin/bypass").then(r => r.json());\n')
        }
      }
    },
    dropTargetHold() {
      holdTargetPath = undefined
      for (const res of heldTargetResponses.splice(0)) {
        res.destroy()
      }
    },
    close() {
      server.closeAllConnections()
      return new Promise<void>(resolve => server.close(() => resolve()))
    },
  }
}
