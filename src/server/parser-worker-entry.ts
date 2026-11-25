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
import type {
  WorkerTaskRequest,
  WorkerTaskResponse,
} from './untrusted-compute-pool.ts'

const MAX_JSON_BYTES = 2 * 1024 * 1024

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
    case 'extract_program_graph':
    case 'build_program_graph': {
      const req = (payload ?? {}) as ExtractProgramGraphPayload
      if (!req || (!Array.isArray(req.files) && !req.staticSnapshot)) {
        throw new Error('extract_program_graph requires files or staticSnapshot')
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
}
