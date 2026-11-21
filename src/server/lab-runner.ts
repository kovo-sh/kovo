import { spawn } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import {
  chmodSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { createServer as createTcpServer } from 'node:net'
import type { AddressInfo, Server as TcpServer } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'

export interface LabConfig {
  enabled?: boolean
  startCommand?: string
  dockerfile?: string
  dockerComposeFile?: string
  healthPath?: string
  internalPort?: number
  image?: string
  env?: Record<string, string>
  buildTimeoutMs?: number
  healthTimeoutMs?: number
  memoryLimit?: string
  cpus?: string
  pidsLimit?: number
}

export interface StartLabTargetParams {
  runId: string
  environment: 'public' | 'local-lab'
  repoDir: string
  labConfig?: LabConfig
  signal?: AbortSignal
}

export interface LabTargetHandle {
  runId: string
  networkName: string
  containerName: string
  containerIp: string
  imageName: string
  origin: string
  hostPort: number
  internalPort: number
  healthPath: string
  sanitizedRepoDir: string
  startedAt: number
}

interface InternalTargetState {
  handle: LabTargetHandle
  labConfig: LabConfig
  builtImage: boolean
  forwarder: TcpServer
  forwardTarget: { containerName: string; port: number }
}

const EXCLUDED_DIR_NAMES = new Set([
  '.git',
  '.aws',
  '.ssh',
  '.gnupg',
  '.kube',
])

const EXCLUDED_FILE_PATTERNS = [
  /^\.env(?:\..+)?$/i,
  /\.(?:pem|key|p12|pfx|jks|keystore)$/i,
  /^id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$/i,
  /^\.(?:npmrc|netrc|pypirc|dockercfg)$/i,
  /^(?:secrets|credentials)\.(?:json|ya?ml|toml|env|txt)$/i,
]

const SAFE_ENV_KEY = /^[A-Z_][A-Z0-9_]{0,63}$/

export function assertLocalLabAllowed(environment: string): void {
  if (environment !== 'local-lab') {
    throw new Error(
      `Local-lab app runner is forbidden on "${environment}" projects. Requires project.environment === 'local-lab'.`,
    )
  }
  if (process.env.GUARDIAN_ALLOW_LOCAL_LAB !== '1') {
    throw new Error('Local-lab app runner requires GUARDIAN_ALLOW_LOCAL_LAB=1.')
  }
}

function dockerHost(): string {
  const host = process.env.DOCKER_HOST || 'unix:///var/run/docker.sock'
  if (!/^unix:\/\/\/[^/?#\r\n][^?#\r\n]*$/.test(host)) {
    throw new Error('Guardian LabRunner requires a local Docker Unix socket.')
  }
  return host
}

function dockerEnv() {
  return {
    PATH: process.env.PATH,
    DOCKER_HOST: dockerHost(),
    XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR,
  }
}

function runDocker(args: string[], signal?: AbortSignal): Promise<string> {
  signal?.throwIfAborted()
  return new Promise((resolvePromise, reject) => {
    const proc = spawn('docker', args, {
      signal,
      env: dockerEnv(),
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    const stdoutChunks: Buffer[] = []
    const stderrChunks: Buffer[] = []
    proc.stdout.on('data', (chunk: Buffer) => stdoutChunks.push(chunk))
    proc.stderr.on('data', (chunk: Buffer) => stderrChunks.push(chunk))
    proc.once('error', err => reject(signal?.aborted ? signal.reason : err))
    proc.once('close', code => {
      if (code === 0) {
        resolvePromise(Buffer.concat(stdoutChunks).toString('utf8'))
      } else {
        const stderr = Buffer.concat(stderrChunks).toString('utf8').trim()
        reject(new Error(`Docker command failed (${args.slice(0, 3).join(' ')}): ${stderr || `exit ${code}`}`))
      }
    })
  })
}

function shouldSkipCopy(name: string, isDir: boolean): boolean {
  if (isDir) return EXCLUDED_DIR_NAMES.has(name)
  return EXCLUDED_FILE_PATTERNS.some(pattern => pattern.test(name))
}

function copySanitizedRepo(srcDir: string, destDir: string, rootReal: string): void {
  mkdirSync(destDir, { recursive: true, mode: 0o755 })
  // Ensure world-readable directory traversal so --cap-drop ALL (no CAP_DAC_OVERRIDE) containers can read /app.
  chmodSync(destDir, 0o755)
  const entries = readdirSync(srcDir)
  for (const entry of entries) {
    const srcPath = join(srcDir, entry)
    const dstPath = join(destDir, entry)
    const st = lstatSync(srcPath)
    if (st.isSymbolicLink()) {
      // Never follow symlinks that escape the repository root or point to secrets.
      try {
        const targetReal = realpathSync(srcPath)
        const rel = relative(rootReal, targetReal)
        if (rel.startsWith('..') || rel.includes(`${sep}..${sep}`)) continue
      } catch {
        continue
      }
      continue
    }
    if (st.isDirectory()) {
      if (shouldSkipCopy(entry, true)) continue
      copySanitizedRepo(srcPath, dstPath, rootReal)
    } else if (st.isFile()) {
      if (shouldSkipCopy(entry, false)) continue
      copyFileSync(srcPath, dstPath)
      chmodSync(dstPath, (st.mode & 0o111) ? 0o755 : 0o644)
    }
  }
}

function safeResolveUnderRoot(rootDir: string, relPath: string): string {
  const clean = relPath.replace(/^[ab]\//, '').replace(/\\/g, '/')
  if (!clean || clean.includes('\0') || clean.startsWith('/') || clean.split('/').some(seg => seg === '..')) {
    throw new Error(`Unsafe patch file path rejected: "${relPath}"`)
  }
  const rootReal = realpathSync(rootDir)
  const full = resolve(rootReal, clean)
  const rel = relative(rootReal, full)
  if (rel.startsWith('..') || rel === '') {
    throw new Error(`Patch path escapes repository root: "${relPath}"`)
  }
  return full
}

interface ParsedHunk {
  oldStart: number
  oldCount: number
  newStart: number
  newCount: number
  lines: string[]
}

interface ParsedFilePatch {
  oldPath: string
  newPath: string
  hunks: ParsedHunk[]
}

function parseUnifiedDiff(diffText: string): ParsedFilePatch[] {
  const rawLines = diffText.replace(/\r\n/g, '\n').split('\n')
  const patches: ParsedFilePatch[] = []
  let i = 0

  while (i < rawLines.length) {
    const line = rawLines[i]
    if (line.startsWith('--- ')) {
      const oldPath = line.slice(4).split('\t')[0].trim()
      const nextLine = rawLines[i + 1] ?? ''
      if (!nextLine.startsWith('+++ ')) {
        i++
        continue
      }
      const newPath = nextLine.slice(4).split('\t')[0].trim()
      i += 2
      const hunks: ParsedHunk[] = []

      while (i < rawLines.length) {
        const hLine = rawLines[i]
        if (hLine.startsWith('--- ') || hLine.startsWith('diff --git ')) break
        const match = hLine.match(/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/)
        if (!match) {
          i++
          continue
        }
        const oldStart = Number(match[1])
        const oldCount = match[2] !== undefined ? Number(match[2]) : 1
        const newStart = Number(match[3])
        const newCount = match[4] !== undefined ? Number(match[4]) : 1
        i++
        const hunkLines: string[] = []
        let seenOld = 0
        let seenNew = 0
        while (i < rawLines.length) {
          const contentLine = rawLines[i]
          if (contentLine.startsWith('@@ ') || contentLine.startsWith('diff --git ') || contentLine.startsWith('--- ')) {
            break
          }
          if (contentLine.startsWith('\\ No newline at end of file')) {
            i++
            continue
          }
          if (seenOld >= oldCount && seenNew >= newCount && contentLine === '') {
            i++
            break
          }
          if (contentLine.startsWith(' ')) {
            hunkLines.push(contentLine)
            seenOld++
            seenNew++
            i++
          } else if (contentLine.startsWith('-')) {
            hunkLines.push(contentLine)
            seenOld++
            i++
          } else if (contentLine.startsWith('+')) {
            hunkLines.push(contentLine)
            seenNew++
            i++
          } else if (contentLine === '' && (seenOld < oldCount || seenNew < newCount)) {
            hunkLines.push(' ')
            seenOld++
            seenNew++
            i++
          } else {
            break
          }
        }
        hunks.push({ oldStart, oldCount, newStart, newCount, lines: hunkLines })
      }

      if (hunks.length > 0) {
        patches.push({ oldPath, newPath, hunks })
      }
      continue
    }
    i++
  }

  return patches
}

export function applyUnifiedDiffToDirectory(rootDir: string, diffText: string): { filesModified: string[] } {
  const patches = parseUnifiedDiff(diffText)
  if (!patches.length) {
    throw new Error('Unified diff contains no valid file hunks.')
  }

  const backups = new Map<string, string | null>()
  const filesModified: string[] = []

  try {
    for (const patch of patches) {
      const isDelete = patch.newPath === '/dev/null'
      const isCreate = patch.oldPath === '/dev/null'
      const relTarget = isDelete ? patch.oldPath : patch.newPath
      const fullPath = safeResolveUnderRoot(rootDir, relTarget)
      const normalizedRel = relTarget.replace(/^[ab]\//, '')

      const existed = existsSync(fullPath)
      if (!backups.has(fullPath)) {
        backups.set(fullPath, existed ? readFileSync(fullPath, 'utf8') : null)
      }

      if (!existed && !isCreate) {
        throw new Error(`Target file does not exist for patch: ${normalizedRel}`)
      }

      const originalContent = existed ? readFileSync(fullPath, 'utf8') : ''
      const hadTrailingNewline = originalContent.endsWith('\n')
      const lines = originalContent === ''
        ? []
        : (hadTrailingNewline ? originalContent.slice(0, -1).split('\n') : originalContent.split('\n'))

      let lineOffset = 0
      for (const hunk of patch.hunks) {
        const expectedOld = hunk.lines
          .filter(l => l.startsWith(' ') || l.startsWith('-'))
          .map(l => l.slice(1))
        const replacement = hunk.lines
          .filter(l => l.startsWith(' ') || l.startsWith('+'))
          .map(l => l.slice(1))

        const nominalIdx = Math.max(0, hunk.oldStart - 1 + lineOffset)
        const matchesAt = (idx: number) => {
          if (idx < 0 || idx + expectedOld.length > lines.length) return false
          for (let k = 0; k < expectedOld.length; k++) {
            if (lines[idx + k] !== expectedOld[k]) return false
          }
          return true
        }

        let matchIdx = -1
        if (expectedOld.length === 0) {
          matchIdx = Math.min(nominalIdx, lines.length)
        } else if (matchesAt(nominalIdx)) {
          matchIdx = nominalIdx
        } else {
          // Allow small bounded offset drift (up to +/- 15 lines) while still requiring exact line text.
          for (let delta = 1; delta <= 15; delta++) {
            if (matchesAt(nominalIdx + delta)) {
              matchIdx = nominalIdx + delta
              break
            }
            if (matchesAt(nominalIdx - delta)) {
              matchIdx = nominalIdx - delta
              break
            }
          }
        }

        if (matchIdx === -1) {
          throw new Error(`Patch hunk failed to apply cleanly to ${normalizedRel} near line ${hunk.oldStart}.`)
        }

        lines.splice(matchIdx, expectedOld.length, ...replacement)
        lineOffset += replacement.length - expectedOld.length
      }

      if (isDelete) {
        if (existsSync(fullPath)) unlinkSync(fullPath)
      } else {
        mkdirSync(dirname(fullPath), { recursive: true, mode: 0o755 })
        const out = lines.length > 0 ? lines.join('\n') + '\n' : ''
        writeFileSync(fullPath, out, { encoding: 'utf8', mode: 0o644 })
        chmodSync(fullPath, 0o644)
      }
      filesModified.push(normalizedRel)
    }

    return { filesModified }
  } catch (err) {
    // Roll back any partial writes on failure.
    for (const [filePath, prev] of backups.entries()) {
      try {
        if (prev === null) {
          if (existsSync(filePath)) unlinkSync(filePath)
        } else {
          writeFileSync(filePath, prev, 'utf8')
        }
      } catch {
        // Best-effort rollback
      }
    }
    throw err
  }
}

function createLoopbackForwarder(
  targetRef: { containerName: string; port: number },
): Promise<{ server: TcpServer; port: number }> {
  // Uses `docker exec -i` stdio->loopback bridge inside the container so the container's
  // --internal network can set inhibit_ipv4=true (giving the host zero bridge IP, so the
  // container has ZERO route to host 0.0.0.0 services AND zero internet egress).
  const bridgeScript = [
    `if command -v node >/dev/null 2>&1; then`,
    `  exec node -e "const net=require('net');const s=net.connect(Number(process.argv[1]),'127.0.0.1');process.stdin.pipe(s);s.pipe(process.stdout);s.on('error',()=>process.exit(1));s.on('close',()=>process.exit(0));process.stdin.on('end',()=>s.end());" "$1"`,
    `elif command -v python3 >/dev/null 2>&1; then`,
    `  exec python3 -u -c "import os,select,socket,sys; s=socket.create_connection(('127.0.0.1',int(sys.argv[1]))); fds=[0,s.fileno()]` +
      `; \nwhile True:\n r,_,_=select.select(fds,[],[])\n if 0 in r:\n  d=os.read(0,65536)\n  if not d: s.shutdown(socket.SHUT_WR); fds.remove(0)\n  else: s.sendall(d)\n if s.fileno() in r:\n  d=s.recv(65536)\n  if not d: break\n  os.write(1,d)" "$1"`,
    `else`,
    `  exit 127`,
    `fi`,
  ].join('\n')

  return new Promise((resolvePromise, reject) => {
    const server = createTcpServer(clientSocket => {
      const proc = spawn(
        'docker',
        ['exec', '-i', targetRef.containerName, 'sh', '-c', bridgeScript, '_', String(targetRef.port)],
        { env: dockerEnv(), stdio: ['pipe', 'pipe', 'ignore'] },
      )
      clientSocket.pipe(proc.stdin)
      proc.stdout.pipe(clientSocket)

      const teardown = () => {
        try { clientSocket.destroy() } catch { /* ignore */ }
        try { proc.kill() } catch { /* ignore */ }
      }
      clientSocket.on('error', teardown)
      clientSocket.on('close', () => {
        try { proc.kill() } catch { /* ignore */ }
      })
      proc.stdin.on('error', () => { /* ignore EPIPE */ })
      proc.stdout.on('error', teardown)
      proc.once('error', teardown)
      proc.once('close', () => {
        try { clientSocket.end() } catch { /* ignore */ }
      })
    })
    server.once('error', reject)
    // Strictly bind ONLY to 127.0.0.1 ephemeral port (never 0.0.0.0).
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as AddressInfo | null
      if (!addr || typeof addr.port !== 'number') {
        server.close()
        reject(new Error('Failed to allocate loopback ephemeral port for lab target.'))
        return
      }
      resolvePromise({ server, port: addr.port })
    })
  })
}

async function waitForHealthCheck(origin: string, healthPath: string, timeoutMs: number, signal?: AbortSignal): Promise<void> {
  const path = healthPath.startsWith('/') ? healthPath : '/' + healthPath
  const url = `${origin}${path}`
  const deadline = Date.now() + timeoutMs
  let lastError = 'No response received'

  while (Date.now() < deadline) {
    signal?.throwIfAborted()
    try {
      const res = await fetch(url, {
        method: 'GET',
        redirect: 'manual',
        signal: AbortSignal.any([
          AbortSignal.timeout(2_500),
          ...(signal ? [signal] : []),
        ]),
      })
      if (res.status < 500) {
        await res.body?.cancel().catch(() => undefined)
        return
      }
      lastError = `HTTP ${res.status}`
      await res.body?.cancel().catch(() => undefined)
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err)
    }
    await delay(300, undefined, { signal }).catch(() => undefined)
  }

  throw new Error(`Lab target health check timed out after ${timeoutMs}ms at ${url} (${lastError}).`)
}

function buildSyntheticEnvArgs(internalPort: number, labConfig: LabConfig): string[] {
  const synthetic: Record<string, string> = {
    PORT: String(internalPort),
    HOST: '0.0.0.0',
    NODE_ENV: 'test',
    GUARDIAN_LAB: '1',
  }
  for (const [k, v] of Object.entries(labConfig.env ?? {})) {
    if (!SAFE_ENV_KEY.test(k)) continue
    // Never forward host secrets accidentally passed as env template references.
    synthetic[k] = String(v).slice(0, 1024)
  }
  const args: string[] = []
  for (const [k, v] of Object.entries(synthetic)) {
    args.push('-e', `${k}=${v}`)
  }
  return args
}

function resolveStartCommand(sanitizedRepoDir: string, labConfig: LabConfig): { image: string; cmd: string[] } {
  const image = labConfig.image || 'node:24-bookworm-slim'
  if (labConfig.startCommand?.trim()) {
    return { image, cmd: ['sh', '-c', labConfig.startCommand.trim()] }
  }
  if (existsSync(join(sanitizedRepoDir, 'server.ts'))) {
    return { image, cmd: ['node', '/app/server.ts'] }
  }
  if (existsSync(join(sanitizedRepoDir, 'server.js'))) {
    return { image, cmd: ['node', '/app/server.js'] }
  }
  if (existsSync(join(sanitizedRepoDir, 'index.js'))) {
    return { image, cmd: ['node', '/app/index.js'] }
  }
  if (existsSync(join(sanitizedRepoDir, 'package.json'))) {
    return { image, cmd: ['npm', 'start'] }
  }
  if (existsSync(join(sanitizedRepoDir, 'app.py'))) {
    return { image: labConfig.image || 'guardian-worker:local', cmd: ['python3', '/app/app.py'] }
  }
  throw new Error('Unable to infer lab start command. Specify labConfig.startCommand or labConfig.dockerfile.')
}

export class LabRunner {
  private readonly active = new Map<string, InternalTargetState>()

  getTarget(runId: string): LabTargetHandle | undefined {
    return this.active.get(runId)?.handle
  }

  listTargets(): LabTargetHandle[] {
    return [...this.active.values()].map(s => s.handle)
  }

  private async launchContainer(params: {
    runId: string
    networkName: string
    sanitizedRepoDir: string
    labConfig: LabConfig
    signal?: AbortSignal
  }): Promise<{ containerName: string; containerIp: string; imageName: string; builtImage: boolean }> {
    const { runId, networkName, sanitizedRepoDir, labConfig, signal } = params
    const shortId = createHash('sha256').update(`${runId}:${randomUUID()}`).digest('hex').slice(0, 10)
    const containerName = `guardian-lab-app-${shortId}`
    const internalPort = labConfig.internalPort ?? 8080
    const memoryLimit = labConfig.memoryLimit ?? '512m'
    const cpus = labConfig.cpus ?? '1.0'
    const pidsLimit = labConfig.pidsLimit ?? 128

    let imageName: string
    let builtImage = false
    let cmd: string[] = []
    let mountArgs: string[] = []

    const dockerfileRel = labConfig.dockerfile
      || (!labConfig.startCommand && !labConfig.image && existsSync(join(sanitizedRepoDir, 'Dockerfile')) ? 'Dockerfile' : undefined)

    if (dockerfileRel) {
      const dockerfileFull = safeResolveUnderRoot(sanitizedRepoDir, dockerfileRel)
      if (!existsSync(dockerfileFull)) {
        throw new Error(`Lab Dockerfile not found: ${dockerfileRel}`)
      }
      imageName = `guardian-lab-img-${shortId}:local`
      const buildSignal = AbortSignal.any([
        AbortSignal.timeout(labConfig.buildTimeoutMs ?? 120_000),
        ...(signal ? [signal] : []),
      ])
      await runDocker(
        ['build', '--pull=false', '--network', 'none', '-f', dockerfileFull, '-t', imageName, sanitizedRepoDir],
        buildSignal,
      )
      builtImage = true
      if (labConfig.startCommand?.trim()) {
        cmd = ['sh', '-c', labConfig.startCommand.trim()]
      }
    } else {
      const resolved = resolveStartCommand(sanitizedRepoDir, labConfig)
      imageName = resolved.image
      cmd = resolved.cmd
      mountArgs = ['--mount', `type=bind,source=${sanitizedRepoDir},target=/app,readonly`, '--workdir', '/app']
    }

    const runArgs = [
      'run', '-d',
      '--name', containerName,
      '--network', networkName,
      '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges',
      '--read-only',
      '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m',
      '--memory', memoryLimit,
      '--memory-swap', memoryLimit,
      '--cpus', cpus,
      '--pids-limit', String(pidsLimit),
      '--label', 'dev.guardian.lab=1',
      '--label', `dev.guardian.run=${runId}`,
      ...buildSyntheticEnvArgs(internalPort, labConfig),
      ...mountArgs,
      imageName,
      ...cmd,
    ]

    try {
      await runDocker(runArgs, signal)
      const rawIp = (await runDocker(
        ['inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', containerName],
        signal,
      )).trim()
      if (!rawIp || !/^\d+\.\d+\.\d+\.\d+$/.test(rawIp)) {
        throw new Error(`Failed to resolve internal bridge IP for lab container ${containerName}.`)
      }
      return { containerName, containerIp: rawIp, imageName, builtImage }
    } catch (err) {
      await runDocker(['container', 'rm', '--force', containerName], AbortSignal.timeout(5_000)).catch(() => undefined)
      if (builtImage) {
        await runDocker(['image', 'rm', '--force', imageName], AbortSignal.timeout(5_000)).catch(() => undefined)
      }
      throw err
    }
  }

  async startLabTarget(params: StartLabTargetParams): Promise<LabTargetHandle> {
    assertLocalLabAllowed(params.environment)
    params.signal?.throwIfAborted()

    if (!existsSync(params.repoDir) || !statSync(params.repoDir).isDirectory()) {
      throw new Error(`Lab repository directory does not exist: ${params.repoDir}`)
    }

    // Stop any previous lab target for this run before creating a new one.
    if (this.active.has(params.runId)) {
      await this.stopLabTarget(params.runId)
    }

    const labConfig: LabConfig = params.labConfig ?? {}
    const internalPort = labConfig.internalPort ?? 8080
    const healthPath = labConfig.healthPath ?? '/health'
    const shortId = createHash('sha256').update(`${params.runId}:${randomUUID()}`).digest('hex').slice(0, 12)
    const networkName = `guardian-lab-${shortId}`

    const sanitizedRepoDir = mkdtempSync(join(tmpdir(), 'guardian-lab-repo-'))
    const repoReal = realpathSync(params.repoDir)
    copySanitizedRepo(repoReal, sanitizedRepoDir, repoReal)

    let networkCreated = false
    let containerName: string | undefined
    let builtImageName: string | undefined
    let forwarder: TcpServer | undefined

    try {
      // Dedicated per-run Docker --internal bridge network with inhibit_ipv4=true:
      // zero internet egress AND zero host bridge gateway IP (blocks access to host 0.0.0.0 services!).
      await runDocker(
        [
          'network', 'create',
          '--driver', 'bridge',
          '--internal',
          '-o', 'com.docker.network.bridge.inhibit_ipv4=true',
          '--label', 'dev.guardian.lab=1',
          '--label', `dev.guardian.run=${params.runId}`,
          networkName,
        ],
        params.signal,
      )
      networkCreated = true

      const launched = await this.launchContainer({
        runId: params.runId,
        networkName,
        sanitizedRepoDir,
        labConfig,
        signal: params.signal,
      })
      containerName = launched.containerName
      if (launched.builtImage) builtImageName = launched.imageName

      const forwardTarget = { containerName: launched.containerName, port: internalPort }
      const proxy = await createLoopbackForwarder(forwardTarget)
      forwarder = proxy.server

      const origin = `http://127.0.0.1:${proxy.port}`
      await waitForHealthCheck(origin, healthPath, labConfig.healthTimeoutMs ?? 30_000, params.signal)

      const handle: LabTargetHandle = {
        runId: params.runId,
        networkName,
        containerName: launched.containerName,
        containerIp: launched.containerIp,
        imageName: launched.imageName,
        origin,
        hostPort: proxy.port,
        internalPort,
        healthPath,
        sanitizedRepoDir,
        startedAt: Date.now(),
      }

      this.active.set(params.runId, {
        handle,
        labConfig,
        builtImage: launched.builtImage,
        forwarder: proxy.server,
        forwardTarget,
      })

      return handle
    } catch (err) {
      if (forwarder) {
        await new Promise<void>(res => forwarder!.close(() => res())).catch(() => undefined)
      }
      if (containerName) {
        await runDocker(['container', 'rm', '--force', containerName], AbortSignal.timeout(5_000)).catch(() => undefined)
      }
      if (builtImageName) {
        await runDocker(['image', 'rm', '--force', builtImageName], AbortSignal.timeout(5_000)).catch(() => undefined)
      }
      if (networkCreated) {
        await runDocker(['network', 'rm', networkName], AbortSignal.timeout(5_000)).catch(() => undefined)
      }
      rmSync(sanitizedRepoDir, { recursive: true, force: true })
      throw err
    }
  }

  async rebuildWithPatch(runId: string, patchDiff: string, signal?: AbortSignal): Promise<LabTargetHandle> {
    assertLocalLabAllowed('local-lab')
    const state = this.active.get(runId)
    if (!state) {
      throw new Error(`No active local-lab target found for run ${runId}.`)
    }

    // Apply unified diff safely to the isolated sanitized repo copy (never touching original /repos).
    applyUnifiedDiffToDirectory(state.handle.sanitizedRepoDir, patchDiff)

    const prevContainer = state.handle.containerName
    const prevImage = state.builtImage ? state.handle.imageName : undefined

    const launched = await this.launchContainer({
      runId,
      networkName: state.handle.networkName,
      sanitizedRepoDir: state.handle.sanitizedRepoDir,
      labConfig: state.labConfig,
      signal,
    })

    // Switch loopback forwarder to the newly patched container while keeping the exact same 127.0.0.1:<port> origin.
    state.forwardTarget.containerName = launched.containerName
    state.forwardTarget.port = state.handle.internalPort

    try {
      await waitForHealthCheck(
        state.handle.origin,
        state.handle.healthPath,
        state.labConfig.healthTimeoutMs ?? 30_000,
        signal,
      )
    } catch (err) {
      await runDocker(['container', 'rm', '--force', launched.containerName], AbortSignal.timeout(5_000)).catch(() => undefined)
      if (launched.builtImage) {
        await runDocker(['image', 'rm', '--force', launched.imageName], AbortSignal.timeout(5_000)).catch(() => undefined)
      }
      throw err
    }

    state.handle = {
      ...state.handle,
      containerName: launched.containerName,
      containerIp: launched.containerIp,
      imageName: launched.imageName,
      startedAt: Date.now(),
    }
    state.builtImage = launched.builtImage

    // Clean up replaced container and old built image.
    await runDocker(['container', 'rm', '--force', prevContainer], AbortSignal.timeout(5_000)).catch(() => undefined)
    if (prevImage && prevImage !== launched.imageName) {
      await runDocker(['image', 'rm', '--force', prevImage], AbortSignal.timeout(5_000)).catch(() => undefined)
    }

    return state.handle
  }

  async stopLabTarget(runId: string): Promise<void> {
    const state = this.active.get(runId)
    if (!state) return
    this.active.delete(runId)

    await new Promise<void>(res => state.forwarder.close(() => res())).catch(() => undefined)
    await runDocker(['container', 'rm', '--force', state.handle.containerName], AbortSignal.timeout(5_000)).catch(() => undefined)
    if (state.builtImage) {
      await runDocker(['image', 'rm', '--force', state.handle.imageName], AbortSignal.timeout(5_000)).catch(() => undefined)
    }
    await runDocker(['network', 'rm', state.handle.networkName], AbortSignal.timeout(5_000)).catch(() => undefined)
    try {
      rmSync(state.handle.sanitizedRepoDir, { recursive: true, force: true })
    } catch {
      // Best-effort cleanup
    }
  }

  async stopAll(): Promise<void> {
    const ids = [...this.active.keys()]
    await Promise.all(ids.map(id => this.stopLabTarget(id)))
  }
}
