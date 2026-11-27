import type { ChildProcess } from 'node:child_process'
import { randomBytes, randomUUID } from 'node:crypto'
import { chmodSync, chownSync, copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync, rmSync } from 'node:fs'
import { createConnection, createServer, type Server, type Socket } from 'node:net'
import { join } from 'node:path'
import { registerRunDisposer } from './run-disposers.ts'
import {
  VERIFY_RPC_CONTEXT_ENV, VERIFY_RPC_CONTEXT_NAME, VERIFY_RPC_SOCKET_ENV,
  VERIFY_RPC_SOCKET_NAME, VERIFY_RPC_TOKEN_ENV, VERIFY_RPC_TOKEN_NAME,
} from './verify-claims.ts'

/** Container mount point for per-run warm `kovo_verify` RPC roots (readonly bind mount). */
export const VERIFY_ROOT_CONTAINER_DIR = '/kovo-verify-root'

/** Long-lived minimal keepalive for `--entrypoint node` inside a per-run warm verify container. */
export const RUN_VERIFY_KEEPALIVE_SCRIPT =
  'const stop=()=>process.exit(0);process.on("SIGTERM",stop);process.on("SIGINT",stop);setInterval(()=>{},60000)'

export interface RunVerifyResourceOptions { memoryMb?: number; cpus?: number; pidsLimit?: number; tmpfsMb?: number }

export interface RunVerifyAttemptLease {
  readonly runKey: string
  readonly containerName: string
  readonly attemptId: string
  readonly hostAttemptDir: string
  readonly containerSocketPath: string
  readonly containerTokenFile: string
  readonly containerContextFile: string
  readonly reusedContainer: boolean
  spawnBridge(): ChildProcess
  release(): Promise<void>
}

export interface RunContainerPoolStats {
  readonly activeRuns: number
  readonly verifyContainersCreated: number
  readonly verifyAttemptsServed: number
  readonly verifyAttemptsReused: number
  readonly verifyContainersRemoved: number
}

export interface RunContainerPoolOptions {
  readonly maxRuns: number
  readonly docker: (args: string[], signal: AbortSignal, input?: string) => Promise<string>
  readonly buildVerifyCreateArgs: (input: { name: string; runKey: string; verifyRootHostDir: string; options?: RunVerifyResourceOptions }) => string[]
  readonly spawnExec: (containerName: string, execArgs: string[]) => ChildProcess
  readonly allocateVerifyRootDir: (runKey: string) => string
  readonly disposeVerifyRootDir: (dir: string) => void
  readonly trackContainer: (name: string) => void
  readonly untrackContainer: (name: string) => void
  readonly onRunDisposed?: (runId: string) => void
}

interface RunVerifySlot {
  readonly key: string
  readonly runKey: string
  readonly containerName: string
  readonly verifyRootHostDir: string
  readyPromise: Promise<void>
  ready: boolean
  retired: boolean
  activeAttempts: number
  attemptsServed: number
}

const liveRunContainerPools = new Set<WeakRef<RunContainerPool>>()
registerRunDisposer('run-container-pool:run-verify', (runId: string) => {
  for (const ref of [...liveRunContainerPools]) {
    const pool = ref.deref()
    if (!pool) liveRunContainerPools.delete(ref)
    else pool.handleRunDisposed(runId)
  }
})

/** Extract a non-empty `runId` from a `VerifyRpcServer` `context.json` file when present. */
export function readVerifyContextRunId(rpcMountDir: string): string | undefined {
  try {
    const contextPath = join(rpcMountDir, VERIFY_RPC_CONTEXT_NAME)
    if (!existsSync(contextPath)) return undefined
    const parsed = JSON.parse(readFileSync(contextPath, 'utf8')) as { runId?: unknown }
    return typeof parsed.runId === 'string' && parsed.runId.trim() ? parsed.runId.trim() : undefined
  } catch { return undefined }
}

function setAttemptMode(targetPath: string, mode: number, hostUid: number): void {
  chmodSync(targetPath, mode)
  if (hostUid === 0) { try { chownSync(targetPath, 10001, 10001) } catch { /* ignore */ } }
}

async function startUnixSocketProxy(targetSocketPath: string, listenSocketPath: string, sockMode: number, hostUid: number): Promise<() => Promise<void>> {
  const openSockets = new Set<Socket>()
  const server: Server = createServer(client => {
    const upstream = createConnection(targetSocketPath)
    openSockets.add(client); openSockets.add(upstream)
    const tearDown = () => {
      openSockets.delete(client); openSockets.delete(upstream)
      if (!client.destroyed) client.destroy()
      if (!upstream.destroyed) upstream.destroy()
    }
    client.on('error', tearDown); upstream.on('error', tearDown)
    client.on('close', () => { openSockets.delete(client); if (!upstream.destroyed) upstream.end() })
    upstream.on('close', () => { openSockets.delete(upstream); if (!client.destroyed) client.end() })
    client.pipe(upstream); upstream.pipe(client)
  })
  await new Promise<void>((resolve, reject) => {
    const onError = (err: Error) => { server.off('listening', onListen); reject(err) }
    const onListen = () => { server.off('error', onError); resolve() }
    server.once('error', onError); server.once('listening', onListen); server.listen(listenSocketPath)
  })
  setAttemptMode(listenSocketPath, sockMode, hostUid)
  return async () => {
    for (const sock of [...openSockets]) { try { sock.destroy() } catch { /* ignore */ } }
    openSockets.clear()
    await new Promise<void>(resolve => server.close(() => resolve()))
  }
}

async function bridgeAttemptRpcDir(sourceRpcDir: string, hostAttemptDir: string): Promise<() => Promise<void>> {
  const hostUid = typeof process.getuid === 'function' ? process.getuid() : -1
  const ownerOnly = hostUid === 10001 || hostUid === 0
  const [dirMode, fileMode, sockMode] = ownerOnly ? [0o700, 0o600, 0o600] : [0o750, 0o640, 0o660]
  mkdirSync(hostAttemptDir, { recursive: true, mode: dirMode })
  setAttemptMode(hostAttemptDir, dirMode, hostUid)
  for (const fileName of [VERIFY_RPC_TOKEN_NAME, VERIFY_RPC_CONTEXT_NAME]) {
    const src = join(sourceRpcDir, fileName)
    if (!existsSync(src) || !lstatSync(src).isFile()) continue
    const dst = join(hostAttemptDir, fileName)
    copyFileSync(src, dst); setAttemptMode(dst, fileMode, hostUid)
  }
  let closeProxy: (() => Promise<void>) | undefined
  const srcSocket = join(sourceRpcDir, VERIFY_RPC_SOCKET_NAME)
  if (existsSync(srcSocket)) {
    const sockStat = lstatSync(srcSocket)
    const dstSocket = join(hostAttemptDir, VERIFY_RPC_SOCKET_NAME)
    if (sockStat.isSocket()) closeProxy = await startUnixSocketProxy(srcSocket, dstSocket, sockMode, hostUid)
    else if (sockStat.isFile()) { copyFileSync(srcSocket, dstSocket); setAttemptMode(dstSocket, sockMode, hostUid) }
  }
  let releasePromise: Promise<void> | undefined
  return () => (releasePromise ??= (async () => {
    if (closeProxy) await closeProxy().catch(() => undefined)
    try { rmSync(hostAttemptDir, { recursive: true, force: true }) } catch { /* ignore */ }
  })())
}

/**
 * Per-run long-lived warm container pool for Layer-3 `kovo_verify` attempts.
 * Each run owns at most one hardened `--network none` verify container with `/kovo-verify-root/rpc`
 * mounted readonly; each attempt gets a fresh disjoint `<attemptId>` RPC dir & `docker exec` process.
 */
export class RunContainerPool {
  private readonly opts: RunContainerPoolOptions
  private readonly runSlots = new Map<string, RunVerifySlot>()
  private verifyContainersCreated = 0
  private verifyAttemptsServed = 0
  private verifyAttemptsReused = 0
  private verifyContainersRemoved = 0

  constructor(opts: RunContainerPoolOptions) {
    this.opts = opts
    liveRunContainerPools.add(new WeakRef(this))
  }

  get stats(): RunContainerPoolStats {
    return {
      activeRuns: this.runSlots.size, verifyContainersCreated: this.verifyContainersCreated,
      verifyAttemptsServed: this.verifyAttemptsServed, verifyAttemptsReused: this.verifyAttemptsReused,
      verifyContainersRemoved: this.verifyContainersRemoved,
    }
  }

  ownsContainer(name: string): boolean {
    for (const slot of this.runSlots.values()) if (slot.containerName === name) return true
    return false
  }

  private async destroySlotResources(slot: RunVerifySlot): Promise<void> {
    this.opts.untrackContainer(slot.containerName)
    await this.opts.docker(['container', 'rm', '--force', slot.containerName], AbortSignal.timeout(5_000)).catch(() => undefined)
    this.verifyContainersRemoved += 1
    this.opts.disposeVerifyRootDir(slot.verifyRootHostDir)
  }

  private retireSlot(slot: RunVerifySlot, force = false): Promise<void> {
    slot.retired = true
    if (this.runSlots.get(slot.key) === slot) this.runSlots.delete(slot.key)
    return !force && slot.activeAttempts > 0 ? Promise.resolve() : this.destroySlotResources(slot)
  }

  private evictExcessIdleRuns(): void {
    if (this.runSlots.size <= this.opts.maxRuns) return
    for (const candidate of [...this.runSlots.values()]) {
      if (this.runSlots.size <= this.opts.maxRuns) break
      if (candidate.activeAttempts === 0) void this.retireSlot(candidate)
    }
  }

  private createSlot(key: string, runKey: string, options?: RunVerifyResourceOptions): RunVerifySlot {
    while (this.runSlots.size >= this.opts.maxRuns) {
      const idle = [...this.runSlots.values()].find(s => s.activeAttempts === 0)
      if (!idle) break
      void this.retireSlot(idle)
    }
    const containerName = 'kovo-' + randomUUID()
    const verifyRootHostDir = this.opts.allocateVerifyRootDir(runKey)
    const slot: RunVerifySlot = {
      key, runKey, containerName, verifyRootHostDir,
      readyPromise: Promise.resolve(), ready: false, retired: false, activeAttempts: 0, attemptsServed: 0,
    }
    this.runSlots.set(key, slot)
    this.opts.trackContainer(containerName)
    slot.readyPromise = (async () => {
      await this.opts.docker(this.opts.buildVerifyCreateArgs({ name: containerName, runKey, verifyRootHostDir, options }), AbortSignal.timeout(15_000))
      this.verifyContainersCreated += 1
      await this.opts.docker(['container', 'start', containerName], AbortSignal.timeout(10_000))
      slot.ready = true
    })().catch(async err => { await this.retireSlot(slot, true); throw err })
    return slot
  }

  async acquireVerifyAttempt(input: { runKey: string; rpcMountDir: string; signal: AbortSignal; options?: RunVerifyResourceOptions }): Promise<RunVerifyAttemptLease | null> {
    const cleanRunKey = input.runKey.trim()
    if (!cleanRunKey) return null
    input.signal.throwIfAborted()
    const o = input.options
    const key = `${cleanRunKey}\0${o?.memoryMb ?? ''}:${o?.cpus ?? ''}:${o?.pidsLimit ?? ''}:${o?.tmpfsMb ?? ''}`
    let slot = this.runSlots.get(key)
    if (slot && !slot.retired) { this.runSlots.delete(key); this.runSlots.set(key, slot) }
    else slot = this.createSlot(key, cleanRunKey, o)

    try { await slot.readyPromise } catch { return null }
    input.signal.throwIfAborted()
    if (slot.retired || !slot.ready) return null

    slot.activeAttempts += 1
    const attemptId = randomBytes(8).toString('hex')
    const hostAttemptDir = join(slot.verifyRootHostDir, attemptId)
    let releaseBridge: () => Promise<void>
    try { releaseBridge = await bridgeAttemptRpcDir(input.rpcMountDir, hostAttemptDir) }
    catch (error) {
      slot.activeAttempts = Math.max(0, slot.activeAttempts - 1)
      if (slot.retired && slot.activeAttempts === 0) void this.destroySlotResources(slot)
      throw error
    }

    const reusedContainer = slot.attemptsServed > 0
    slot.attemptsServed += 1; this.verifyAttemptsServed += 1
    if (reusedContainer) this.verifyAttemptsReused += 1

    const base = `${VERIFY_ROOT_CONTAINER_DIR}/rpc/${attemptId}`
    const containerSocketPath = `${base}/${VERIFY_RPC_SOCKET_NAME}`
    const containerTokenFile = `${base}/${VERIFY_RPC_TOKEN_NAME}`
    const containerContextFile = `${base}/${VERIFY_RPC_CONTEXT_NAME}`
    const execArgs = [
      '-e', `${VERIFY_RPC_SOCKET_ENV}=${containerSocketPath}`,
      '-e', `${VERIFY_RPC_TOKEN_ENV}=${containerTokenFile}`,
      '-e', `${VERIFY_RPC_CONTEXT_ENV}=${containerContextFile}`,
      slot.containerName, 'node', '--max-old-space-size=512', '/opt/kovo-worker/bridge.ts', '--session',
    ]
    let releasePromise: Promise<void> | undefined
    const activeSlot = slot
    return {
      runKey: cleanRunKey, containerName: activeSlot.containerName, attemptId, hostAttemptDir,
      containerSocketPath, containerTokenFile, containerContextFile, reusedContainer,
      spawnBridge: () => this.opts.spawnExec(activeSlot.containerName, execArgs),
      release: () => (releasePromise ??= (async () => {
        await releaseBridge()
        activeSlot.activeAttempts = Math.max(0, activeSlot.activeAttempts - 1)
        if (activeSlot.retired && activeSlot.activeAttempts === 0) await this.destroySlotResources(activeSlot)
        else this.evictExcessIdleRuns()
      })()),
    }
  }

  async evictContainer(containerName: string): Promise<void> {
    for (const slot of [...this.runSlots.values()]) if (slot.containerName === containerName) await this.retireSlot(slot, true)
  }

  async evictRun(runId: string): Promise<void> {
    const normalized = runId.trim()
    if (!normalized) return
    await Promise.all([...this.runSlots.values()].filter(s => s.runKey === normalized).map(s => this.retireSlot(s, true)))
  }

  handleRunDisposed(runId: string): void { void this.evictRun(runId); this.opts.onRunDisposed?.(runId) }

  async closeAll(): Promise<void> {
    const slots = [...this.runSlots.values()]
    this.runSlots.clear()
    await Promise.all(slots.map(slot => this.retireSlot(slot, true)))
  }
}
