/**
 * Isolated worker_threads entrypoint for untrusted CPU/memory-bound parsing tasks (H-33..H-39).
 *
 * Runs inside a V8 isolate bounded by `resourceLimits` and terminated on wall-clock timeout by
 * `UntrustedComputePool`. Never reads host `process.env` or executes dynamic code.
 */
import { isMainThread, parentPort } from 'node:worker_threads'
import {
  ComposeParseError,
  parseComposeDocument,
  parseComposeEnvFile,
  type ComposeParseOptions,
} from './compose-parse.ts'
import type { StaticWorkspaceSnapshot } from './static-workspace-snapshot.ts'
import {
  extractHtmlLinksAndScripts,
  parseJsonOrYaml,
  type WorkerTaskRequest,
  type WorkerTaskResponse,
} from './untrusted-compute-pool.ts'

const MAX_JSON_BYTES = 2 * 1024 * 1024
const MAX_HTML_BYTES = 2 * 1024 * 1024
const MAX_JS_BYTES = 2 * 1024 * 1024
const MAX_PROGRAM_GRAPH_BYTES = 24 * 1024 * 1024

interface ParseComposePayload {
  yamlText: string
  options?: ComposeParseOptions
}

interface ParseComposeEnvPayload {
  content: string
}

interface ParseJsonPayload {
  text: string
  maxBytes?: number
}

interface JsHarvestPayload {
  content: string
  sourceName?: string
  options?: Record<string, unknown>
}

interface ExtractHtmlPayload {
  html: string
  origin: string
  maxBytes?: number
}

interface ExtractProgramGraphPayload {
  files?: ReadonlyArray<{ path: string; content: string }>
  repo?: string
  maxFileBytes?: number
  staticSnapshot?: StaticWorkspaceSnapshot
}

async function executeTask(kind: string, payload: unknown): Promise<unknown> {
  switch (kind) {
    case 'parse_compose': {
      const req = (payload ?? {}) as ParseComposePayload
      if (typeof req.yamlText !== 'string') {
        throw new ComposeParseError('yamlText must be a string')
      }
      const safeOptions: ComposeParseOptions = {
        ...(req.options?.maxServices !== undefined ? { maxServices: req.options.maxServices } : {}),
        ...(req.options?.maxBytes !== undefined ? { maxBytes: req.options.maxBytes } : {}),
        env: req.options?.env && typeof req.options.env === 'object' ? req.options.env : {},
      }
      return parseComposeDocument(req.yamlText, safeOptions)
    }
    case 'parse_compose_env': {
      const req = (payload ?? {}) as ParseComposeEnvPayload
      if (typeof req.content !== 'string') {
        throw new ComposeParseError('compose env content must be a string')
      }
      return parseComposeEnvFile(req.content)
    }
    case 'parse_json': {
      const req = (payload ?? {}) as ParseJsonPayload
      if (typeof req.text !== 'string') {
        throw new Error('JSON input text must be a string')
      }
      const maxBytes = typeof req.maxBytes === 'number' && Number.isFinite(req.maxBytes) && req.maxBytes > 0
        ? Math.min(req.maxBytes, MAX_JSON_BYTES)
        : MAX_JSON_BYTES
      if (Buffer.byteLength(req.text, 'utf8') > maxBytes) {
        throw new Error(`JSON input exceeds maximum size of ${maxBytes} bytes`)
      }
      return JSON.parse(req.text) as unknown
    }
    case 'parse_json_or_yaml': {
      const req = (payload ?? {}) as ParseJsonPayload
      if (typeof req.text !== 'string') {
        throw new Error('Document input text must be a string')
      }
      const maxBytes = typeof req.maxBytes === 'number' && Number.isFinite(req.maxBytes) && req.maxBytes > 0
        ? Math.min(req.maxBytes, MAX_JSON_BYTES)
        : MAX_JSON_BYTES
      if (Buffer.byteLength(req.text, 'utf8') > maxBytes) {
        throw new Error(`Document input exceeds maximum size of ${maxBytes} bytes`)
      }
      return parseJsonOrYaml(req.text)
    }
    case 'js_harvest': {
      const req = (payload ?? {}) as JsHarvestPayload
      if (typeof req.content !== 'string') {
        throw new Error('js_harvest content must be a string')
      }
      if (Buffer.byteLength(req.content, 'utf8') > MAX_JS_BYTES) {
        throw new Error(`JS input exceeds maximum size of ${MAX_JS_BYTES} bytes`)
      }
      const { jsHarvest } = await import('../../worker/analyzers.ts')
      return jsHarvest(req.content, typeof req.sourceName === 'string' ? req.sourceName : '', req.options)
    }
    case 'extract_html': {
      const req = (payload ?? {}) as ExtractHtmlPayload
      if (typeof req.html !== 'string' || typeof req.origin !== 'string') {
        throw new Error('extract_html requires html and origin strings')
      }
      const maxBytes = typeof req.maxBytes === 'number' && Number.isFinite(req.maxBytes) && req.maxBytes > 0
        ? Math.min(req.maxBytes, MAX_HTML_BYTES)
        : MAX_HTML_BYTES
      if (Buffer.byteLength(req.html, 'utf8') > maxBytes) {
        throw new Error(`HTML input exceeds maximum size of ${maxBytes} bytes`)
      }
      return extractHtmlLinksAndScripts(req.html, req.origin)
    }
    case 'extract_program_graph':
    case 'build_program_graph': {
      const req = (payload ?? {}) as ExtractProgramGraphPayload
      if (!req || (!Array.isArray(req.files) && !req.staticSnapshot)) {
        throw new Error('extract_program_graph requires files or staticSnapshot')
      }
      if (Array.isArray(req.files)) {
        let totalBytes = 0
        for (const file of req.files) {
          if (!file || typeof file.path !== 'string' || typeof file.content !== 'string') {
            throw new Error('extract_program_graph files entries must have string path and content')
          }
          totalBytes += Buffer.byteLength(file.content, 'utf8')
          if (totalBytes > MAX_PROGRAM_GRAPH_BYTES) {
            throw new Error(`extract_program_graph input exceeds maximum size of ${MAX_PROGRAM_GRAPH_BYTES} bytes`)
          }
        }
      }
      const { extractProgramGraph } = await import('./program-graph.ts')
      return extractProgramGraph(req)
    }
    default:
      throw new Error(`Unsupported untrusted compute task kind: ${String(kind)}`)
  }
}

function serializeWorkerError(err: unknown): NonNullable<WorkerTaskResponse['error']> {
  if (err instanceof ComposeParseError) {
    return {
      name: err.name,
      message: err.message,
      ...(err.lineNumber !== undefined ? { lineNumber: err.lineNumber } : {}),
    }
  }
  if (err instanceof Error) {
    return {
      name: err.name || 'Error',
      message: err.message,
    }
  }
  return {
    name: 'Error',
    message: String(err),
  }
}

if (!isMainThread && parentPort) {
  const port = parentPort
  port.on('message', (msg: WorkerTaskRequest) => {
    void (async () => {
      try {
        const result = await executeTask(msg.kind, msg.payload)
        const response: WorkerTaskResponse = { id: msg.id, ok: true, result }
        port.postMessage(response)
      } catch (err) {
        const response: WorkerTaskResponse = {
          id: msg.id,
          ok: false,
          error: serializeWorkerError(err),
        }
        port.postMessage(response)
      }
    })()
  })
} else if (isMainThread && typeof process.send === 'function') {
  // Disposable child_process.fork IPC mode (`R2-H-23`): isolates native crashes (e.g. SIGSEGV)
  // and OOMs completely from the host Kovo process.
  process.on('message', (raw: unknown) => {
    const msg = raw as WorkerTaskRequest | null | undefined
    if (!msg || typeof msg.id !== 'string' || typeof msg.kind !== 'string') return
    void (async () => {
      try {
        const result = await executeTask(msg.kind, msg.payload)
        const response: WorkerTaskResponse = { id: msg.id, ok: true, result }
        if (process.connected) process.send?.(response)
      } catch (err) {
        const response: WorkerTaskResponse = {
          id: msg.id,
          ok: false,
          error: serializeWorkerError(err),
        }
        if (process.connected) process.send?.(response)
      }
    })()
  })
}
