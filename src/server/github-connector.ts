import { execFileSync, spawn } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import {
  accessSync,
  chmodSync,
  constants,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { redact } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import { mineSecurityRelevantCommitDiffs, type CommitDiffSignal } from './program-graph.ts'

export const DEFAULT_GITHUB_PAT_PATH = join(homedir(), '.config', 'guardian-fixtures', 'github.pat')
export const DEFAULT_GITHUB_MAX_AUTO_SELECT = 10
export const DEFAULT_GITHUB_BASE_URL = 'https://github.com'
export const DEFAULT_GITHUB_API_BASE_URL = 'https://api.github.com'
const GITHUB_REFRESH_LEEWAY_MS = 5 * 60 * 1000
const MAX_PENDING_DEVICE_FLOWS = 32

export type GithubPatSource = 'vault' | 'fixture'
export type GithubPatKind = 'fine_grained' | 'classic' | 'github_app' | 'unknown'
export type GithubAuthKind = 'github_app_device' | 'pat'

export interface GithubPatStatus {
  configured: boolean
  source: GithubPatSource | null
  tokenKind: GithubPatKind | null
}

export interface GithubAppInstallationSummary {
  id: number
  accountLogin: string
  accountType: string
  repositorySelection: 'all' | 'selected' | 'unknown'
  htmlUrl?: string
}

export interface GithubAuthStatus extends GithubPatStatus {
  authKind: GithubAuthKind | null
  login: string | null
  expiresAt: string | null
  githubDeviceFlowConfigured: boolean
  clientIdSource: 'env' | 'vault' | null
  appSlug: string | null
  installUrl: string | null
  installations?: GithubAppInstallationSummary[]
  needsAppInstall?: boolean
  privateRepoCount?: number
}

export interface StoredGithubVaultCredential {
  accessToken: string
  refreshToken?: string
  expiresAt?: string
  refreshTokenExpiresAt?: string
  clientId?: string
  login?: string
  authKind: GithubAuthKind
}

export interface StartGithubDeviceFlowOptions {
  dataDir?: string
  clientId?: string
  githubBaseUrl?: string
  apiBaseUrl?: string
  fetchImpl?: typeof fetch
  signal?: AbortSignal
}

export interface StartGithubDeviceFlowResult {
  flowId: string
  userCode: string
  verificationUri: string
  expiresIn: number
  intervalSec: number
}

export interface PollGithubDeviceFlowOptions {
  dataDir?: string
  githubBaseUrl?: string
  apiBaseUrl?: string
  fetchImpl?: typeof fetch
  signal?: AbortSignal
}

export type PollGithubDeviceFlowResult =
  | { status: 'pending'; intervalSec: number }
  | { status: 'slow_down'; intervalSec: number }
  | { status: 'expired'; error: string }
  | { status: 'denied'; error: string }
  | { status: 'error'; error: string }
  | {
      status: 'authorized'
      login: string | null
      authKind: 'github_app_device'
      repoCount: number
      expiresAt: string | null
      accountStatus: GithubAuthStatus
    }

export interface AccessibleGithubRepo {
  fullName: string
  private: boolean
  defaultBranch: string
  updatedAt: string | null
  description: string | null
}

export interface ListAccessibleGithubReposOptions {
  dataDir?: string
  patPath?: string
  apiBaseUrl?: string
  githubBaseUrl?: string
  fetchImpl?: typeof fetch
  maxRepos?: number
  signal?: AbortSignal
}

export interface ListAccessibleGithubReposResult {
  repos: AccessibleGithubRepo[]
  tokenKind: GithubPatKind
  truncated: boolean
  installations: GithubAppInstallationSummary[]
  installUrl: string | null
  needsAppInstall: boolean
  privateRepoCount: number
}

export interface RepoDependency {
  ecosystem: string
  package: string
  version: string
  sourceFile: string
}

export interface SyncedRepoFile {
  path: string
  category: 'manifest' | 'lockfile' | 'openapi' | 'graphql' | 'route' | 'config'
  size: number
  truncated: boolean
  content: string
}

export interface SyncedRepoSpec {
  name: string
  kind: 'openapi' | 'graphql' | 'routes' | 'notes'
  content: string
}

export interface SyncedGithubRepo {
  fullName: string
  defaultBranch: string
  private: boolean
  description: string | null
  language: string | null
  treeCount: number
  files: SyncedRepoFile[]
  dependencies: RepoDependency[]
  specs: SyncedRepoSpec[]
  warnings: string[]
  mountPath?: string
  localPath?: string
  commitSha?: string
  topLevelDirs?: string[]
  /** Bounded git history retained for code-first regression mining. */
  gitHistory?: {
    depth: number
    commitsScanned: number
    commitDiffs: CommitDiffSignal[]
    metadataPreserved: boolean
  }
}

export interface GithubSyncOptions {
  dataDir?: string
  patPath?: string
  apiBaseUrl?: string
  githubBaseUrl?: string
  gitBaseUrl?: string
  cloneDir?: string
  fetchImpl?: typeof fetch
  maxFilesPerRepo?: number
  maxFileBytes?: number
  maxRepoBytes?: number
  cloneTimeoutMs?: number
  /** Bounded clone history depth (default 100). `.git` is preserved unless explicitly stripped. */
  historyDepth?: number
  /** Mine security-relevant diffs, then remove `.git` from the mounted checkout. */
  stripGitMetadata?: boolean
  /** Maximum commits inspected for diffs during sync (default 20). */
  maxCommitDiffs?: number
}

const repoFullNamePattern = /^[a-zA-Z0-9_.-]{1,100}\/[a-zA-Z0-9_.-]{1,100}$/
const safeSegmentPattern = /^[a-zA-Z0-9_.-]{1,128}$/
const defaultMaxFilesPerRepo = 40
const defaultMaxFileBytes = 512 * 1024
const defaultMaxRepoBytes = 2 * 1024 * 1024
const defaultMaxLockfileBytes = 8 * 1024 * 1024
const defaultCloneTimeoutMs = 120_000
const defaultHistoryDepth = 100
const defaultMaxCommitDiffs = 20

const skippedDirNames = new Set([
  '.git',
  'node_modules',
  'dist',
  'build',
  '.next',
  '.nuxt',
  '.vercel',
  'coverage',
  'vendor',
  '__pycache__',
  '.venv',
  'target',
])

const lockfileNames = new Set([
  'package-lock.json',
  'pnpm-lock.yaml',
  'bun.lock',
  'yarn.lock',
  'requirements.txt',
  'pyproject.toml',
  'go.sum',
  'cargo.lock',
  'uv.lock',
])

export function projectReposDir(dataDir: string, projectId: string): string {
  if (!dataDir || /[\0,\r\n]/.test(dataDir)) {
    throw new Error('Invalid workspace data directory.')
  }
  if (!safeSegmentPattern.test(projectId) || projectId === '.' || projectId === '..' || projectId.includes('..')) {
    throw new Error(`Invalid project ID for repository directory: "${projectId}".`)
  }
  return join(dataDir, 'repos', projectId)
}

export function listMountedRepos(reposDir: string): string[] {
  if (!reposDir || /[\0,\r\n]/.test(reposDir) || !existsSync(reposDir)) return []
  let rootStat
  try {
    rootStat = lstatSync(reposDir)
  } catch {
    return []
  }
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) return []

  const mounted: string[] = []
  let owners
  try {
    owners = readdirSync(reposDir, { withFileTypes: true })
  } catch {
    return []
  }
  for (const ownerEntry of owners) {
    if (ownerEntry.name.startsWith('.') || !safeSegmentPattern.test(ownerEntry.name)) continue
    if (!ownerEntry.isDirectory() || ownerEntry.isSymbolicLink()) continue
    const ownerPath = join(reposDir, ownerEntry.name)
    let repos
    try {
      repos = readdirSync(ownerPath, { withFileTypes: true })
    } catch {
      continue
    }
    for (const repoEntry of repos) {
      if (repoEntry.name.startsWith('.') || !safeSegmentPattern.test(repoEntry.name)) continue
      if (!repoEntry.isDirectory() || repoEntry.isSymbolicLink()) continue
      mounted.push(`/repos/${ownerEntry.name}/${repoEntry.name}`)
    }
  }
  return mounted.sort()
}

function parseRepoFullName(rawName: string): { fullName: string; owner: string; repo: string } {
  const fullName = rawName.trim()
  if (!repoFullNamePattern.test(fullName) || fullName.includes('..')) {
    throw new Error(`Invalid GitHub repository name: "${fullName}". Expected "owner/repo".`)
  }
  const [owner, repo] = fullName.split('/')
  if (
    !owner || !repo ||
    owner === '.' || owner === '..' || repo === '.' || repo === '..' ||
    owner.startsWith('-') || repo.startsWith('-')
  ) {
    throw new Error(`Invalid GitHub repository name: "${fullName}". Expected "owner/repo".`)
  }
  return { fullName, owner, repo }
}

function assertValidDataDir(dataDir: string): string {
  if (!dataDir || /[\0,\r\n]/.test(dataDir)) {
    throw new Error('Invalid workspace data directory.')
  }
  return dataDir
}

function vaultGithubPatPath(dataDir: string): string {
  return join(assertValidDataDir(dataDir), 'credentials', 'github.pat')
}

function vaultGithubAppConfigPath(dataDir: string): string {
  return join(assertValidDataDir(dataDir), 'credentials', 'github-app.json')
}

export function classifyGithubPatKind(token: string): GithubPatKind {
  const trimmed = token.trim()
  if (trimmed.startsWith('github_pat_')) return 'fine_grained'
  if (trimmed.startsWith('ghu_')) return 'github_app'
  if (/^gh[posr]_/.test(trimmed)) return 'classic'
  return 'unknown'
}

function writeAtomic0600(filePath: string, content: string): void {
  const dir = dirname(filePath)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  chmodSync(dir, 0o700)

  const tmpPath = join(dir, `.tmp-${randomUUID()}`)
  try {
    writeFileSync(tmpPath, content, { encoding: 'utf8', mode: 0o600 })
    chmodSync(tmpPath, 0o600)
    renameSync(tmpPath, filePath)
    chmodSync(filePath, 0o600)
  } finally {
    if (existsSync(tmpPath)) {
      try { rmSync(tmpPath, { force: true }) } catch { /* best-effort */ }
    }
  }
}

function validateTokenString(raw: string, label = 'GitHub token'): string {
  const token = raw.trim()
  if (!token || token.length < 10 || token.length > 512 || /[\s\0]/.test(token)) {
    throw new Error(`${label} must be a single non-empty token without whitespace.`)
  }
  return token
}

function validateGithubClientId(raw: string): string {
  const clientId = raw.trim()
  if (!clientId || clientId.length < 6 || clientId.length > 128 || !/^[a-zA-Z0-9._-]+$/.test(clientId)) {
    throw new Error('GitHub App Client ID must be 6–128 alphanumeric, dot, dash, or underscore characters.')
  }
  return clientId
}

function readOwnerOnlyFile(filePath: string, label: string): string {
  const stat = statSync(filePath)
  if (!stat.isFile() || stat.size === 0) {
    throw new Error(`${label} is missing or empty.`)
  }
  if ((stat.mode & 0o077) !== 0) {
    throw new Error(`${label} must have owner-only 0600 permissions.`)
  }
  accessSync(filePath, constants.R_OK)
  return readFileSync(filePath, 'utf8').trim()
}

const githubAppSlugPattern = /^[a-z0-9-]+$/

function normalizeGithubAppSlug(raw: unknown): string | null {
  if (typeof raw !== 'string') return null
  const trimmed = raw.trim()
  if (!trimmed || trimmed.length > 100 || !githubAppSlugPattern.test(trimmed)) {
    return null
  }
  return trimmed
}

function readVaultGithubAppConfig(dataDir?: string): { clientId?: string; appSlug?: string } {
  if (!dataDir) return {}
  const appConfigPath = vaultGithubAppConfigPath(dataDir)
  if (!existsSync(appConfigPath)) return {}
  try {
    const raw = readOwnerOnlyFile(appConfigPath, 'GitHub App config file')
    const parsed = JSON.parse(raw) as { clientId?: unknown; appSlug?: unknown }
    const out: { clientId?: string; appSlug?: string } = {}
    if (typeof parsed.clientId === 'string' && parsed.clientId.trim()) {
      try {
        out.clientId = validateGithubClientId(parsed.clientId)
      } catch {
        // Ignore malformed clientId
      }
    }
    const slug = normalizeGithubAppSlug(parsed.appSlug)
    if (slug) {
      out.appSlug = slug
    }
    return out
  } catch {
    return {}
  }
}

export function saveGithubClientId(dataDir: string, rawClientId: string): string {
  const clientId = validateGithubClientId(rawClientId)
  const existing = readVaultGithubAppConfig(dataDir)
  writeAtomic0600(
    vaultGithubAppConfigPath(dataDir),
    `${JSON.stringify({ ...existing, clientId }, null, 2)}\n`,
  )
  return clientId
}

export function resolveGithubAppSlug(dataDir?: string): string | null {
  const envRaw = process.env.GUARDIAN_GITHUB_APP_SLUG
  if (typeof envRaw === 'string' && envRaw.trim().length > 0) {
    return normalizeGithubAppSlug(envRaw)
  }
  const vaultConfig = readVaultGithubAppConfig(dataDir)
  return vaultConfig.appSlug ?? null
}

export function githubAppInstallUrl(
  slug: string | null | undefined,
  githubBaseUrl = DEFAULT_GITHUB_BASE_URL,
): string | null {
  const validSlug = normalizeGithubAppSlug(slug)
  if (!validSlug) return null
  const base = (githubBaseUrl || DEFAULT_GITHUB_BASE_URL).replace(/\/+$/, '')
  return `${base}/apps/${validSlug}/installations/new`
}

function readVaultGithubClientId(dataDir?: string): string | null {
  if (!dataDir) return null
  const patPath = vaultGithubPatPath(dataDir)
  if (existsSync(patPath)) {
    try {
      const cred = readGithubVaultCredential(patPath)
      if (cred.clientId) return validateGithubClientId(cred.clientId)
    } catch {
      // Fall through to github-app.json
    }
  }
  return readVaultGithubAppConfig(dataDir).clientId ?? null
}

export function resolveGithubClientId(
  dataDir?: string,
  explicitClientId?: string,
): { clientId: string | null; source: 'input' | 'env' | 'vault' | null } {
  if (typeof explicitClientId === 'string' && explicitClientId.trim()) {
    return { clientId: validateGithubClientId(explicitClientId), source: 'input' }
  }
  const envClientId = process.env.GUARDIAN_GITHUB_CLIENT_ID?.trim()
  if (envClientId) {
    try {
      return { clientId: validateGithubClientId(envClientId), source: 'env' }
    } catch {
      return { clientId: null, source: null }
    }
  }
  const vaultClientId = readVaultGithubClientId(dataDir)
  if (vaultClientId) {
    return { clientId: vaultClientId, source: 'vault' }
  }
  return { clientId: null, source: null }
}

/**
 * Resolve the active GitHub PAT path: prefers `<dataDir>/credentials/github.pat` when present,
 * falling back to `DEFAULT_GITHUB_PAT_PATH` only when the vault file is absent.
 */
export function resolveGithubPatPath(dataDir?: string): string {
  if (dataDir) {
    const vaultPath = vaultGithubPatPath(dataDir)
    if (existsSync(vaultPath)) return vaultPath
  }
  return DEFAULT_GITHUB_PAT_PATH
}

export function readGithubVaultCredential(patPath = DEFAULT_GITHUB_PAT_PATH): StoredGithubVaultCredential {
  const raw = readOwnerOnlyFile(patPath, 'GitHub PAT file')
  if (raw.startsWith('{')) {
    let parsed: Record<string, unknown>
    try {
      parsed = JSON.parse(raw) as Record<string, unknown>
    } catch {
      throw new Error('GitHub credential file contains malformed JSON.')
    }
    if (typeof parsed.accessToken !== 'string') {
      throw new Error('GitHub credential file does not contain a valid access token.')
    }
    const accessToken = validateTokenString(parsed.accessToken, 'GitHub access token')
    const refreshToken = typeof parsed.refreshToken === 'string' && parsed.refreshToken.trim()
      ? validateTokenString(parsed.refreshToken, 'GitHub refresh token')
      : undefined
    const expiresAt = typeof parsed.expiresAt === 'string' && Number.isFinite(Date.parse(parsed.expiresAt))
      ? parsed.expiresAt
      : undefined
    const refreshTokenExpiresAt = typeof parsed.refreshTokenExpiresAt === 'string' && Number.isFinite(Date.parse(parsed.refreshTokenExpiresAt))
      ? parsed.refreshTokenExpiresAt
      : undefined
    const clientId = typeof parsed.clientId === 'string' && parsed.clientId.trim()
      ? validateGithubClientId(parsed.clientId)
      : undefined
    const login = typeof parsed.login === 'string' && parsed.login.trim()
      ? parsed.login.trim().slice(0, 100)
      : undefined
    const authKind: GithubAuthKind = parsed.authKind === 'github_app_device' ? 'github_app_device' : 'pat'
    return {
      accessToken,
      ...(refreshToken ? { refreshToken } : {}),
      ...(expiresAt ? { expiresAt } : {}),
      ...(refreshTokenExpiresAt ? { refreshTokenExpiresAt } : {}),
      ...(clientId ? { clientId } : {}),
      ...(login ? { login } : {}),
      authKind,
    }
  }
  if (!raw || raw.length < 10) {
    throw new Error('GitHub PAT file does not contain a valid token.')
  }
  return {
    accessToken: raw,
    authKind: 'pat',
  }
}

function readGithubPat(patPath = DEFAULT_GITHUB_PAT_PATH): string {
  return readGithubVaultCredential(patPath).accessToken
}

interface ObservedGithubInstallations {
  tokenFingerprint: string
  installations: GithubAppInstallationSummary[]
  needsAppInstall: boolean
  privateRepoCount: number
}

const observedGithubInstallations = new Map<string, ObservedGithubInstallations>()

function fingerprintGithubToken(token: string): string {
  return createHash('sha256').update(token).digest('hex').slice(0, 16)
}

function clearObservedGithubInstallations(filePath: string): void {
  observedGithubInstallations.delete(resolve(filePath))
}

export function saveGithubVaultCredential(
  dataDir: string,
  credential: StoredGithubVaultCredential,
): GithubAuthStatus {
  const accessToken = validateTokenString(credential.accessToken, 'GitHub access token')
  const normalized: StoredGithubVaultCredential = {
    accessToken,
    ...(credential.refreshToken ? { refreshToken: validateTokenString(credential.refreshToken, 'GitHub refresh token') } : {}),
    ...(credential.expiresAt && Number.isFinite(Date.parse(credential.expiresAt)) ? { expiresAt: credential.expiresAt } : {}),
    ...(credential.refreshTokenExpiresAt && Number.isFinite(Date.parse(credential.refreshTokenExpiresAt))
      ? { refreshTokenExpiresAt: credential.refreshTokenExpiresAt }
      : {}),
    ...(credential.clientId ? { clientId: validateGithubClientId(credential.clientId) } : {}),
    ...(credential.login && credential.login.trim() ? { login: credential.login.trim().slice(0, 100) } : {}),
    authKind: credential.authKind === 'github_app_device' ? 'github_app_device' : 'pat',
  }
  const patPath = vaultGithubPatPath(dataDir)
  clearObservedGithubInstallations(patPath)
  writeAtomic0600(patPath, `${JSON.stringify(normalized, null, 2)}\n`)
  if (normalized.clientId) {
    saveGithubClientId(dataDir, normalized.clientId)
  }
  return getGithubAuthStatus(dataDir)
}

export function saveGithubPat(dataDir: string, rawToken: string): GithubPatStatus {
  const token = rawToken.trim()
  if (!token || token.length < 10 || token.length > 512 || /[\s\0]/.test(token)) {
    throw new Error('GitHub PAT must be a single non-empty token without whitespace.')
  }
  const patPath = vaultGithubPatPath(dataDir)
  clearObservedGithubInstallations(patPath)
  writeAtomic0600(patPath, `${token}\n`)
  return {
    configured: true,
    source: 'vault',
    tokenKind: classifyGithubPatKind(token),
  }
}

export function clearGithubPat(dataDir: string): { cleared: boolean; status: GithubPatStatus } {
  const patPath = vaultGithubPatPath(dataDir)
  clearObservedGithubInstallations(patPath)
  let cleared = false
  try {
    lstatSync(patPath)
    rmSync(patPath, { force: true })
    cleared = true
  } catch {
    cleared = false
  }
  return { cleared, status: getGithubPatStatus(dataDir) }
}

export function getGithubPatStatus(dataDir?: string, explicitPatPath?: string): GithubPatStatus {
  if (explicitPatPath) {
    try {
      const pat = readGithubPat(explicitPatPath)
      const source: GithubPatSource = resolve(explicitPatPath) === resolve(DEFAULT_GITHUB_PAT_PATH) ? 'fixture' : 'vault'
      return { configured: true, source, tokenKind: classifyGithubPatKind(pat) }
    } catch {
      return { configured: false, source: null, tokenKind: null }
    }
  }
  if (dataDir) {
    const vaultPath = vaultGithubPatPath(dataDir)
    if (existsSync(vaultPath)) {
      try {
        const pat = readGithubPat(vaultPath)
        return { configured: true, source: 'vault', tokenKind: classifyGithubPatKind(pat) }
      } catch {
        return { configured: false, source: null, tokenKind: null }
      }
    }
  }
  try {
    const pat = readGithubPat(DEFAULT_GITHUB_PAT_PATH)
    return { configured: true, source: 'fixture', tokenKind: classifyGithubPatKind(pat) }
  } catch {
    return { configured: false, source: null, tokenKind: null }
  }
}

export function getGithubAuthStatus(
  dataDir?: string,
  explicitPatPath?: string,
  githubBaseUrl?: string,
): GithubAuthStatus {
  const resolvedClient = resolveGithubClientId(dataDir)
  const clientIdSource = resolvedClient.source === 'env' || resolvedClient.source === 'vault'
    ? resolvedClient.source
    : null
  const appSlug = resolveGithubAppSlug(dataDir)
  const installUrl = githubAppInstallUrl(appSlug, githubBaseUrl)
  const baseUnconfigured: GithubAuthStatus = {
    configured: false,
    source: null,
    tokenKind: null,
    authKind: null,
    login: null,
    expiresAt: null,
    githubDeviceFlowConfigured: Boolean(resolvedClient.clientId),
    clientIdSource,
    appSlug,
    installUrl,
  }

  const readStatusFromPath = (targetPath: string, source: GithubPatSource): GithubAuthStatus => {
    const cred = readGithubVaultCredential(targetPath)
    const effectiveClient = cred.clientId
      ? { clientId: cred.clientId, source: (clientIdSource ?? 'vault') as 'env' | 'vault' }
      : { clientId: resolvedClient.clientId, source: clientIdSource }
    const observed = observedGithubInstallations.get(resolve(targetPath))
    const observedMatch = observed && observed.tokenFingerprint === fingerprintGithubToken(cred.accessToken)
      ? observed
      : null
    return {
      configured: true,
      source,
      tokenKind: classifyGithubPatKind(cred.accessToken),
      authKind: cred.authKind,
      login: cred.login ?? null,
      expiresAt: cred.expiresAt ?? null,
      githubDeviceFlowConfigured: Boolean(effectiveClient.clientId),
      clientIdSource: effectiveClient.source,
      appSlug,
      installUrl,
      ...(observedMatch
        ? {
            installations: observedMatch.installations.map(item => ({ ...item })),
            needsAppInstall: observedMatch.needsAppInstall,
            privateRepoCount: observedMatch.privateRepoCount,
          }
        : {}),
    }
  }

  if (explicitPatPath) {
    try {
      const source: GithubPatSource = resolve(explicitPatPath) === resolve(DEFAULT_GITHUB_PAT_PATH) ? 'fixture' : 'vault'
      return readStatusFromPath(explicitPatPath, source)
    } catch {
      return baseUnconfigured
    }
  }
  if (dataDir) {
    const vaultPath = vaultGithubPatPath(dataDir)
    if (existsSync(vaultPath)) {
      try {
        return readStatusFromPath(vaultPath, 'vault')
      } catch {
        return baseUnconfigured
      }
    }
  }
  try {
    return readStatusFromPath(DEFAULT_GITHUB_PAT_PATH, 'fixture')
  } catch {
    return baseUnconfigured
  }
}

interface PendingDeviceFlow {
  flowId: string
  deviceCode: string
  clientId: string
  intervalSec: number
  expiresAtMs: number
  createdAtMs: number
  githubBaseUrl: string
  apiBaseUrl: string
  dataDir?: string
}

const pendingDeviceFlows = new Map<string, PendingDeviceFlow>()
const inFlightTokenRefreshes = new Map<string, Promise<StoredGithubVaultCredential>>()

function prunePendingDeviceFlows(nowMs = Date.now()): void {
  for (const [id, flow] of pendingDeviceFlows) {
    if (flow.expiresAtMs <= nowMs) {
      pendingDeviceFlows.delete(id)
    }
  }
  while (pendingDeviceFlows.size >= MAX_PENDING_DEVICE_FLOWS) {
    let oldestId: string | undefined
    let oldestTime = Infinity
    for (const [id, flow] of pendingDeviceFlows) {
      if (flow.createdAtMs < oldestTime) {
        oldestTime = flow.createdAtMs
        oldestId = id
      }
    }
    if (!oldestId) break
    pendingDeviceFlows.delete(oldestId)
  }
}

async function resolveFreshGithubCredential(options: {
  dataDir?: string
  patPath?: string
  githubBaseUrl?: string
  fetchImpl?: typeof fetch
  signal?: AbortSignal
} = {}): Promise<StoredGithubVaultCredential> {
  const effectivePath = options.patPath ?? resolveGithubPatPath(options.dataDir)
  const cred = readGithubVaultCredential(effectivePath)
  if (!cred.expiresAt || !cred.refreshToken) {
    return cred
  }
  const expiresAtMs = Date.parse(cred.expiresAt)
  if (!Number.isFinite(expiresAtMs) || expiresAtMs - Date.now() > GITHUB_REFRESH_LEEWAY_MS) {
    return cred
  }

  const clientId = cred.clientId ?? resolveGithubClientId(options.dataDir).clientId
  if (!clientId) {
    return cred
  }

  const existing = inFlightTokenRefreshes.get(effectivePath)
  if (existing) return existing

  const refreshPromise = (async (): Promise<StoredGithubVaultCredential> => {
    const nowMs = Date.now()
    if (cred.refreshTokenExpiresAt) {
      const refreshExpMs = Date.parse(cred.refreshTokenExpiresAt)
      if (Number.isFinite(refreshExpMs) && refreshExpMs <= nowMs) {
        throw new Error('GitHub session refresh token expired. Please sign in with GitHub again.')
      }
    }

    const secrets: NamedSecret[] = [
      { value: cred.accessToken, placeholder: '[redacted]' },
      { value: cred.refreshToken!, placeholder: '[redacted]' },
    ]
    const githubBase = (options.githubBaseUrl ?? DEFAULT_GITHUB_BASE_URL).replace(/\/+$/, '')
    const fetchFn = options.fetchImpl ?? fetch
    const reqSignal = options.signal
      ? AbortSignal.any([options.signal, AbortSignal.timeout(20_000)])
      : AbortSignal.timeout(20_000)

    const res = await fetchFn(`${githubBase}/login/oauth/access_token`, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Guardian/2 read-only repo connector',
      },
      body: new URLSearchParams({
        client_id: clientId,
        grant_type: 'refresh_token',
        refresh_token: cred.refreshToken!,
      }).toString(),
      signal: reqSignal,
    })

    const rawText = await res.text().catch(() => '')
    let parsed: Record<string, unknown> = {}
    try {
      parsed = rawText ? JSON.parse(rawText) as Record<string, unknown> : {}
    } catch {
      parsed = {}
    }

    if (typeof parsed.access_token === 'string') {
      secrets.push({ value: parsed.access_token, placeholder: '[redacted]' })
    }
    if (typeof parsed.refresh_token === 'string') {
      secrets.push({ value: parsed.refresh_token, placeholder: '[redacted]' })
    }

    if (!res.ok || typeof parsed.error === 'string') {
      const detail = redact(
        String(parsed.error_description || parsed.error || rawText || `HTTP ${res.status}`),
        secrets,
      ).slice(0, 240)
      throw new Error(`GitHub token refresh failed (${res.status}): ${detail}. Please sign in with GitHub again.`)
    }

    if (typeof parsed.access_token !== 'string' || parsed.access_token.trim().length < 10) {
      throw new Error('GitHub token refresh response did not include a valid access token.')
    }

    const refreshedNowMs = Date.now()
    const newAccessToken = validateTokenString(parsed.access_token, 'GitHub access token')
    const newRefreshToken = typeof parsed.refresh_token === 'string' && parsed.refresh_token.trim()
      ? validateTokenString(parsed.refresh_token, 'GitHub refresh token')
      : cred.refreshToken
    const newExpiresAt = typeof parsed.expires_in === 'number' && Number.isFinite(parsed.expires_in) && parsed.expires_in > 0
      ? new Date(refreshedNowMs + parsed.expires_in * 1000).toISOString()
      : cred.expiresAt
    const newRefreshExpiresAt = typeof parsed.refresh_token_expires_in === 'number'
      && Number.isFinite(parsed.refresh_token_expires_in)
      && parsed.refresh_token_expires_in > 0
      ? new Date(refreshedNowMs + parsed.refresh_token_expires_in * 1000).toISOString()
      : cred.refreshTokenExpiresAt

    const updated: StoredGithubVaultCredential = {
      accessToken: newAccessToken,
      ...(newRefreshToken ? { refreshToken: newRefreshToken } : {}),
      ...(newExpiresAt ? { expiresAt: newExpiresAt } : {}),
      ...(newRefreshExpiresAt ? { refreshTokenExpiresAt: newRefreshExpiresAt } : {}),
      clientId,
      ...(cred.login ? { login: cred.login } : {}),
      authKind: cred.authKind,
    }

    writeAtomic0600(effectivePath, `${JSON.stringify(updated, null, 2)}\n`)
    return updated
  })()

  inFlightTokenRefreshes.set(effectivePath, refreshPromise)
  try {
    return await refreshPromise
  } finally {
    inFlightTokenRefreshes.delete(effectivePath)
  }
}

export async function startGithubDeviceFlow(
  input: StartGithubDeviceFlowOptions = {},
): Promise<StartGithubDeviceFlowResult> {
  input.signal?.throwIfAborted()
  const resolved = resolveGithubClientId(input.dataDir, input.clientId)
  if (!resolved.clientId) {
    throw new Error('GitHub App Client ID is required. Set GUARDIAN_GITHUB_CLIENT_ID or enter your GitHub App Client ID.')
  }
  const clientId = resolved.clientId
  if (input.clientId && input.dataDir) {
    saveGithubClientId(input.dataDir, clientId)
  }

  const githubBase = (input.githubBaseUrl ?? DEFAULT_GITHUB_BASE_URL).replace(/\/+$/, '')
  const apiBase = (input.apiBaseUrl ?? DEFAULT_GITHUB_API_BASE_URL).replace(/\/+$/, '')
  const fetchFn = input.fetchImpl ?? fetch
  const reqSignal = input.signal
    ? AbortSignal.any([input.signal, AbortSignal.timeout(20_000)])
    : AbortSignal.timeout(20_000)

  const res = await fetchFn(`${githubBase}/login/device/code`, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': 'Guardian/2 read-only repo connector',
    },
    body: new URLSearchParams({ client_id: clientId }).toString(),
    signal: reqSignal,
  })

  const rawText = await res.text().catch(() => '')
  let parsed: Record<string, unknown> = {}
  try {
    parsed = rawText ? JSON.parse(rawText) as Record<string, unknown> : {}
  } catch {
    parsed = {}
  }

  const secrets: NamedSecret[] = typeof parsed.device_code === 'string' && parsed.device_code
    ? [{ value: parsed.device_code, placeholder: '[redacted]' }]
    : []

  if (!res.ok || typeof parsed.error === 'string') {
    const detail = redact(
      String(parsed.error_description || parsed.error || rawText || `HTTP ${res.status}`),
      secrets,
    ).slice(0, 240)
    throw new Error(`GitHub device authorization failed to start (${res.status}): ${detail}`)
  }

  const deviceCode = typeof parsed.device_code === 'string' ? parsed.device_code.trim() : ''
  const userCode = typeof parsed.user_code === 'string' ? parsed.user_code.trim() : ''
  const verificationUri = typeof parsed.verification_uri === 'string' ? parsed.verification_uri.trim() : ''
  if (!deviceCode || !userCode || !verificationUri) {
    throw new Error('GitHub device authorization response was missing required fields.')
  }

  const expiresIn = typeof parsed.expires_in === 'number' && Number.isFinite(parsed.expires_in) && parsed.expires_in > 0
    ? Math.floor(parsed.expires_in)
    : 900
  const intervalSec = typeof parsed.interval === 'number' && Number.isFinite(parsed.interval) && parsed.interval >= 1
    ? Math.ceil(parsed.interval)
    : 5

  const nowMs = Date.now()
  prunePendingDeviceFlows(nowMs)
  const flowId = randomUUID()
  pendingDeviceFlows.set(flowId, {
    flowId,
    deviceCode,
    clientId,
    intervalSec,
    expiresAtMs: nowMs + expiresIn * 1000,
    createdAtMs: nowMs,
    githubBaseUrl: githubBase,
    apiBaseUrl: apiBase,
    dataDir: input.dataDir,
  })

  return {
    flowId,
    userCode,
    verificationUri,
    expiresIn,
    intervalSec,
  }
}

export async function pollGithubDeviceFlow(
  flowId: string,
  options: PollGithubDeviceFlowOptions = {},
): Promise<PollGithubDeviceFlowResult> {
  options.signal?.throwIfAborted()
  const flow = pendingDeviceFlows.get(flowId)
  if (!flow) {
    return { status: 'expired', error: 'GitHub sign-in session expired or was cancelled.' }
  }
  const nowMs = Date.now()
  if (nowMs >= flow.expiresAtMs) {
    pendingDeviceFlows.delete(flowId)
    return { status: 'expired', error: 'GitHub device code expired. Start sign-in again.' }
  }

  const githubBase = (options.githubBaseUrl ?? flow.githubBaseUrl).replace(/\/+$/, '')
  const apiBase = (options.apiBaseUrl ?? flow.apiBaseUrl).replace(/\/+$/, '')
  const fetchFn = options.fetchImpl ?? fetch
  const reqSignal = options.signal
    ? AbortSignal.any([options.signal, AbortSignal.timeout(20_000)])
    : AbortSignal.timeout(20_000)

  const secrets: NamedSecret[] = [{ value: flow.deviceCode, placeholder: '[redacted]' }]

  const res = await fetchFn(`${githubBase}/login/oauth/access_token`, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': 'Guardian/2 read-only repo connector',
    },
    body: new URLSearchParams({
      client_id: flow.clientId,
      device_code: flow.deviceCode,
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    }).toString(),
    signal: reqSignal,
  })

  const rawText = await res.text().catch(() => '')
  let parsed: Record<string, unknown> = {}
  try {
    parsed = rawText ? JSON.parse(rawText) as Record<string, unknown> : {}
  } catch {
    parsed = {}
  }

  if (typeof parsed.access_token === 'string' && parsed.access_token) {
    secrets.push({ value: parsed.access_token, placeholder: '[redacted]' })
  }
  if (typeof parsed.refresh_token === 'string' && parsed.refresh_token) {
    secrets.push({ value: parsed.refresh_token, placeholder: '[redacted]' })
  }

  if (!res.ok) {
    const detail = redact(
      String(parsed.error_description || parsed.error || rawText || `HTTP ${res.status}`),
      secrets,
    ).slice(0, 240)
    return { status: 'error', error: `GitHub token polling failed (${res.status}): ${detail}` }
  }

  const errCode = typeof parsed.error === 'string' ? parsed.error : ''
  if (errCode === 'authorization_pending') {
    return { status: 'pending', intervalSec: flow.intervalSec }
  }
  if (errCode === 'slow_down') {
    const suggested = typeof parsed.interval === 'number' && Number.isFinite(parsed.interval)
      ? Math.ceil(parsed.interval)
      : flow.intervalSec + 5
    flow.intervalSec = Math.max(flow.intervalSec + 1, suggested)
    return { status: 'slow_down', intervalSec: flow.intervalSec }
  }
  if (errCode === 'expired_token') {
    pendingDeviceFlows.delete(flowId)
    return {
      status: 'expired',
      error: redact(String(parsed.error_description || 'GitHub device code expired. Start sign-in again.'), secrets).slice(0, 240),
    }
  }
  if (errCode === 'access_denied') {
    pendingDeviceFlows.delete(flowId)
    return {
      status: 'denied',
      error: redact(String(parsed.error_description || 'GitHub authorization was denied.'), secrets).slice(0, 240),
    }
  }
  if (errCode) {
    pendingDeviceFlows.delete(flowId)
    return {
      status: 'error',
      error: redact(String(parsed.error_description || errCode), secrets).slice(0, 240),
    }
  }

  if (typeof parsed.access_token !== 'string' || parsed.access_token.trim().length < 10) {
    pendingDeviceFlows.delete(flowId)
    return { status: 'error', error: 'GitHub did not return a valid access token.' }
  }

  const accessToken = validateTokenString(parsed.access_token, 'GitHub access token')
  const refreshToken = typeof parsed.refresh_token === 'string' && parsed.refresh_token.trim()
    ? validateTokenString(parsed.refresh_token, 'GitHub refresh token')
    : undefined
  const authNowMs = Date.now()
  const expiresAt = typeof parsed.expires_in === 'number' && Number.isFinite(parsed.expires_in) && parsed.expires_in > 0
    ? new Date(authNowMs + parsed.expires_in * 1000).toISOString()
    : undefined
  const refreshTokenExpiresAt = typeof parsed.refresh_token_expires_in === 'number'
    && Number.isFinite(parsed.refresh_token_expires_in)
    && parsed.refresh_token_expires_in > 0
    ? new Date(authNowMs + parsed.refresh_token_expires_in * 1000).toISOString()
    : undefined

  // Best-effort lookup of GitHub username for UI badge
  let login: string | null = null
  try {
    const userRes = await fetchFn(`${apiBase}/user`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'Guardian/2 read-only repo connector',
      },
      signal: options.signal
        ? AbortSignal.any([options.signal, AbortSignal.timeout(10_000)])
        : AbortSignal.timeout(10_000),
    })
    if (userRes.ok) {
      const userJson = await userRes.json() as { login?: unknown }
      if (typeof userJson.login === 'string' && userJson.login.trim()) {
        login = userJson.login.trim().slice(0, 100)
      }
    }
  } catch {
    // Non-fatal: login badge is optional
  }

  const effectiveDataDir = options.dataDir ?? flow.dataDir
  if (!effectiveDataDir) {
    pendingDeviceFlows.delete(flowId)
    throw new Error('Workspace data directory is required to store GitHub credentials.')
  }

  let accountStatus = saveGithubVaultCredential(effectiveDataDir, {
    accessToken,
    ...(refreshToken ? { refreshToken } : {}),
    ...(expiresAt ? { expiresAt } : {}),
    ...(refreshTokenExpiresAt ? { refreshTokenExpiresAt } : {}),
    clientId: flow.clientId,
    ...(login ? { login } : {}),
    authKind: 'github_app_device',
  })

  pendingDeviceFlows.delete(flowId)

  let repoCount = 0
  try {
    const listed = await listAccessibleGithubRepos({
      dataDir: effectiveDataDir,
      apiBaseUrl: apiBase,
      githubBaseUrl: githubBase,
      fetchImpl: fetchFn,
      signal: options.signal,
    })
    repoCount = listed.repos.length
    accountStatus = getGithubAuthStatus(effectiveDataDir, undefined, githubBase)
  } catch {
    // Non-fatal: token is stored; caller can refresh repo list separately
  }

  return {
    status: 'authorized',
    login,
    authKind: 'github_app_device',
    repoCount,
    expiresAt: expiresAt ?? null,
    accountStatus,
  }
}

export function cancelGithubDeviceFlow(flowId: string): { cancelled: boolean } {
  return { cancelled: pendingDeviceFlows.delete(flowId) }
}

export function hasGithubPat(patPathOrOptions?: string | { dataDir?: string; patPath?: string }): boolean {
  if (typeof patPathOrOptions === 'object' && patPathOrOptions !== null) {
    return getGithubPatStatus(patPathOrOptions.dataDir, patPathOrOptions.patPath).configured
  }
  if (typeof patPathOrOptions === 'string') {
    try {
      if (statSync(patPathOrOptions).isDirectory()) {
        return getGithubPatStatus(patPathOrOptions).configured
      }
    } catch {
      // May be a nonexistent dataDir or file path; try direct file read below.
    }
    try {
      readGithubPat(patPathOrOptions)
      return true
    } catch {
      return false
    }
  }
  return getGithubPatStatus().configured
}

/**
 * Pure helper for pre-selecting discovered repositories in the UI:
 * - Fine-grained PATs typically expose <= 10 scoped repos, so all are pre-checked.
 * - Broad classic PATs / large org accounts expose > maxAutoSelect repos, so none are pre-checked.
 */
export function defaultSelectedRepoNames(
  repos: readonly Pick<AccessibleGithubRepo, 'fullName'>[],
  maxAutoSelect = DEFAULT_GITHUB_MAX_AUTO_SELECT,
): string[] {
  const cap = Math.max(0, Math.floor(maxAutoSelect))
  if (repos.length === 0 || repos.length > cap) return []
  return repos.map(repo => repo.fullName)
}

export async function listAccessibleGithubRepos(
  options: ListAccessibleGithubReposOptions = {},
): Promise<ListAccessibleGithubReposResult> {
  options.signal?.throwIfAborted()
  const effectivePath = options.patPath ?? resolveGithubPatPath(options.dataDir)
  const cred = await resolveFreshGithubCredential({
    dataDir: options.dataDir,
    patPath: options.patPath,
    githubBaseUrl: options.githubBaseUrl,
    fetchImpl: options.fetchImpl,
    signal: options.signal,
  })
  const pat = cred.accessToken
  const tokenKind = classifyGithubPatKind(pat)
  const isGithubAppToken = cred.authKind === 'github_app_device' || tokenKind === 'github_app'
  const secrets: NamedSecret[] = [
    { value: pat, placeholder: '[redacted]' },
    ...(cred.refreshToken ? [{ value: cred.refreshToken, placeholder: '[redacted]' }] : []),
  ]
  const apiBase = (options.apiBaseUrl ?? DEFAULT_GITHUB_API_BASE_URL).replace(/\/+$/, '')
  const fetchFn = options.fetchImpl ?? fetch
  const maxRepos = Math.max(1, Math.min(Math.floor(options.maxRepos ?? 200), 500))
  const perPage = Math.min(100, maxRepos)
  const maxPages = Math.ceil(maxRepos / perPage)

  const headers: Record<string, string> = {
    Authorization: `Bearer ${pat}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'Guardian/2 read-only repo connector',
  }

  const repos: AccessibleGithubRepo[] = []
  const repoIndexByKey = new Map<string, number>()
  const installations: GithubAppInstallationSummary[] = []
  let truncated = false
  let installationsChecked = false

  type RawRepoItem = {
    full_name?: unknown
    private?: unknown
    default_branch?: unknown
    updated_at?: unknown
    description?: unknown
  }

  const appendRepoBatch = (batch: RawRepoItem[]) => {
    for (const item of batch) {
      const fullName = typeof item.full_name === 'string' ? item.full_name.trim() : ''
      if (!fullName || !repoFullNamePattern.test(fullName)) continue
      const description = typeof item.description === 'string' && item.description.trim()
        ? redact(item.description.trim(), secrets).slice(0, 240)
        : null
      const candidate: AccessibleGithubRepo = {
        fullName,
        private: Boolean(item.private),
        defaultBranch: typeof item.default_branch === 'string' && item.default_branch.trim() ? item.default_branch.trim() : 'main',
        updatedAt: typeof item.updated_at === 'string' && item.updated_at.trim() ? item.updated_at.trim() : null,
        description,
      }
      const key = fullName.toLowerCase()
      const existingIdx = repoIndexByKey.get(key)
      if (existingIdx !== undefined) {
        const existing = repos[existingIdx]!
        if (candidate.private && !existing.private) {
          repos[existingIdx] = {
            fullName: candidate.fullName,
            private: true,
            defaultBranch: candidate.defaultBranch,
            updatedAt: candidate.updatedAt ?? existing.updatedAt,
            description: candidate.description ?? existing.description,
          }
        } else {
          repos[existingIdx] = {
            ...existing,
            description: existing.description ?? candidate.description,
            updatedAt: existing.updatedAt ?? candidate.updatedAt,
          }
        }
        continue
      }
      if (repos.length >= maxRepos) {
        truncated = true
        break
      }
      repoIndexByKey.set(key, repos.length)
      repos.push(candidate)
    }
  }

  const fetchInstallationRepos = async (throwOnAuthFailure: boolean): Promise<void> => {
    installationsChecked = true
    try {
      options.signal?.throwIfAborted()
      const instSignal = options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(20_000)]) : AbortSignal.timeout(20_000)
      const instRes = await fetchFn(`${apiBase}/user/installations?per_page=100`, {
        method: 'GET',
        headers,
        signal: instSignal,
      })
      if (!instRes.ok) {
        if (throwOnAuthFailure && instRes.status === 401) {
          const body = redact(await instRes.text().catch(() => ''), secrets).slice(0, 240)
          throw new Error(`GitHub rejected the token (HTTP 401): ${body || 'Bad credentials'}`)
        }
        return
      }
      const instPayload = await instRes.json() as {
        installations?: Array<{
          id?: unknown
          account?: { login?: unknown; type?: unknown }
          repository_selection?: unknown
          html_url?: unknown
        }>
      }
      const rawInstallations = Array.isArray(instPayload.installations) ? instPayload.installations : []
      for (const installation of rawInstallations.slice(0, 50)) {
        const instId = typeof installation.id === 'number' && Number.isSafeInteger(installation.id) && installation.id > 0
          ? installation.id
          : null
        if (!instId) continue
        const accountLogin = typeof installation.account?.login === 'string' && installation.account.login.trim()
          ? installation.account.login.trim().slice(0, 100)
          : `installation-${instId}`
        const accountType = typeof installation.account?.type === 'string' && installation.account.type.trim()
          ? installation.account.type.trim().slice(0, 40)
          : 'Unknown'
        const repositorySelection: GithubAppInstallationSummary['repositorySelection'] =
          installation.repository_selection === 'all'
            ? 'all'
            : installation.repository_selection === 'selected'
              ? 'selected'
              : 'unknown'
        const htmlUrl = typeof installation.html_url === 'string' && /^https?:\/\//i.test(installation.html_url.trim())
          ? installation.html_url.trim()
          : undefined
        installations.push({
          id: instId,
          accountLogin,
          accountType,
          repositorySelection,
          ...(htmlUrl ? { htmlUrl } : {}),
        })
      }

      for (const installation of installations.slice(0, 20)) {
        if (repos.length >= maxRepos) {
          truncated = true
          break
        }
        for (let page = 1; page <= maxPages && repos.length < maxRepos; page += 1) {
          options.signal?.throwIfAborted()
          const repoSignal = options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(20_000)]) : AbortSignal.timeout(20_000)
          const repoRes = await fetchFn(
            `${apiBase}/user/installations/${installation.id}/repositories?per_page=${perPage}${page > 1 ? `&page=${page}` : ''}`,
            { method: 'GET', headers, signal: repoSignal },
          )
          if (!repoRes.ok) break
          const repoPayload = await repoRes.json() as { repositories?: RawRepoItem[] }
          const batch = Array.isArray(repoPayload.repositories) ? repoPayload.repositories : []
          if (batch.length === 0) break
          appendRepoBatch(batch)
          if (batch.length < perPage) break
          if (repos.length >= maxRepos) {
            const linkHeader = repoRes.headers?.get?.('link') ?? ''
            if (linkHeader.includes('rel="next"') || page === maxPages) {
              truncated = true
            }
            break
          }
        }
      }
    } catch (err) {
      if (throwOnAuthFailure && err instanceof Error && err.message.includes('HTTP 401')) {
        throw err
      }
      // Best-effort fallback for GitHub App installations; keep any /user/repos results intact.
    }
  }

  // For GitHub App user-to-server tokens, query /user/installations FIRST so explicitly
  // installed private & org repos are always surfaced ahead of old public /user/repos entries.
  if (isGithubAppToken) {
    await fetchInstallationRepos(true)
  }

  if (repos.length < maxRepos) {
    for (let page = 1; page <= maxPages; page += 1) {
      options.signal?.throwIfAborted()
      const query = `per_page=${perPage}&sort=updated&affiliation=owner,collaborator,organization_member${page > 1 ? `&page=${page}` : ''}`
      const reqSignal = options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(20_000)]) : AbortSignal.timeout(20_000)
      const res = await fetchFn(`${apiBase}/user/repos?${query}`, { method: 'GET', headers, signal: reqSignal })
      if (!res.ok) {
        if (isGithubAppToken && repos.length > 0 && res.status !== 401) {
          break
        }
        const body = redact(await res.text().catch(() => ''), secrets).slice(0, 240)
        if (res.status === 401) {
          throw new Error(`GitHub rejected the token (HTTP 401): ${body || 'Bad credentials'}`)
        }
        if (res.status === 403) {
          throw new Error(`GitHub denied repository access (HTTP 403): ${body || 'Insufficient permissions'}`)
        }
        throw new Error(`GitHub API GET /user/repos failed (${res.status}): ${body}`)
      }
      const batch = await res.json() as RawRepoItem[]
      if (!Array.isArray(batch) || batch.length === 0) break

      appendRepoBatch(batch)

      if (batch.length < perPage) break
      if (repos.length >= maxRepos) {
        const linkHeader = res.headers?.get?.('link') ?? ''
        if (linkHeader.includes('rel="next"') || page === maxPages) {
          truncated = true
        }
        break
      }
    }
  }

  if (!installationsChecked && repos.length === 0 && repos.length < maxRepos) {
    await fetchInstallationRepos(false)
  }

  const installUrl = githubAppInstallUrl(resolveGithubAppSlug(options.dataDir), options.githubBaseUrl)
  const needsAppInstall = isGithubAppToken && installations.length === 0
  const privateRepoCount = repos.reduce((count, repo) => count + (repo.private ? 1 : 0), 0)

  observedGithubInstallations.set(resolve(effectivePath), {
    tokenFingerprint: fingerprintGithubToken(pat),
    installations: installations.map(item => ({ ...item })),
    needsAppInstall,
    privateRepoCount,
  })

  return {
    repos,
    tokenKind,
    truncated,
    installations,
    installUrl,
    needsAppInstall,
    privateRepoCount,
  }
}

function classifyRepoPath(filePath: string): { category: SyncedRepoFile['category']; priority: number } | null {
  const lower = filePath.toLowerCase()
  const base = lower.split('/').pop() ?? lower

  // Skip build output, vendored dependencies, minified assets, and tests
  if (/(?:^|\/)(?:node_modules|dist|build|\.next|\.nuxt|\.vercel|coverage|vendor|__tests__|__mocks__)\//.test(lower)) {
    return null
  }
  if (/\.(?:min\.js|map|png|jpg|jpeg|gif|webp|ico|woff2?|ttf|eot|pdf|zip|tar|gz|mp4|svg)$/i.test(lower)) {
    return null
  }
  if (/\.(?:test|spec)\.[a-z0-9]+$/i.test(lower)) {
    return null
  }

  // Manifests & lockfiles (highest priority for exact CVE correlation)
  if (base === 'package.json') return { category: 'manifest', priority: 100 }
  if (base === 'package-lock.json' || base === 'pnpm-lock.yaml' || base === 'bun.lock' || base === 'yarn.lock') {
    return { category: 'lockfile', priority: 95 }
  }
  if (base === 'go.sum' || base === 'requirements.txt' || base === 'pyproject.toml' || base === 'uv.lock' || base === 'cargo.lock') {
    return { category: 'lockfile', priority: 90 }
  }

  // OpenAPI & GraphQL specs
  if (/(?:openapi|swagger).*\.(?:json|ya?ml)$/i.test(base)) return { category: 'openapi', priority: 88 }
  if (/\.(?:graphql|gql)$/i.test(base)) return { category: 'graphql', priority: 85 }

  // Framework & security configs
  if (/^(?:next\.config|vercel\.json|netlify\.toml|wrangler\.toml|wrangler\.jsonc?|cors\.|security\.)/i.test(base)) {
    return { category: 'config', priority: 80 }
  }

  // High-signal server routes, middleware, auth, upload, webhook, billing, and API handlers
  if (/\.(?:ts|tsx|js|jsx|mts|mjs|cjs|py|go)$/i.test(base)) {
    if (/^middleware\./i.test(base) || /(?:^|\/)middleware\//i.test(lower)) return { category: 'route', priority: 84 }
    if (/(?:^|\/)(?:app\/api|pages\/api|src\/app\/api|src\/pages\/api|routes|api|handlers|controllers|endpoints)\//i.test(lower)) {
      return { category: 'route', priority: 78 }
    }
    if (/(?:auth|oauth|session|jwt|token|rbac|acl|permission|upload|presign|storage|webhook|billing|stripe|proxy|redirect|cors|graphql|trpc|admin|server)/i.test(base)) {
      return { category: 'route', priority: 72 }
    }
  }

  return null
}

function cleanSemver(raw: string): string | null {
  const trimmed = raw.trim().replace(/^[~^=<>!\s]+/, '').split(/[\s|,;]/, 1)[0]
  if (!trimmed || !/^\d+\.\d+/.test(trimmed)) return null
  return trimmed.slice(0, 64)
}

export function parseDependenciesFromFile(filePath: string, content: string): RepoDependency[] {
  const base = (filePath.split('/').pop() ?? filePath).toLowerCase()
  const out: RepoDependency[] = []
  const seen = new Set<string>()
  const add = (ecosystem: string, pkg: string, version: string | null) => {
    if (!pkg || !version) return
    const key = `${ecosystem}:${pkg}:${version}`
    if (seen.has(key)) return
    seen.add(key)
    out.push({ ecosystem, package: pkg, version, sourceFile: filePath })
  }

  if (base === 'package.json') {
    try {
      const parsed = JSON.parse(content) as {
        dependencies?: Record<string, string>
        devDependencies?: Record<string, string>
      }
      for (const [pkg, ver] of Object.entries({ ...parsed.dependencies, ...parsed.devDependencies })) {
        add('npm', pkg, cleanSemver(ver))
      }
    } catch { /* ignore malformed JSON */ }
    return out
  }

  if (base === 'package-lock.json') {
    try {
      const parsed = JSON.parse(content) as {
        packages?: Record<string, { version?: string }>
        dependencies?: Record<string, { version?: string }>
      }
      if (parsed.packages) {
        for (const [pkgPath, meta] of Object.entries(parsed.packages)) {
          if (!pkgPath || !meta?.version) continue
          const match = pkgPath.match(/(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)$/)
          if (match) add('npm', match[1], cleanSemver(meta.version))
        }
      }
      if (parsed.dependencies) {
        for (const [pkg, meta] of Object.entries(parsed.dependencies)) {
          if (meta?.version) add('npm', pkg, cleanSemver(meta.version))
        }
      }
    } catch { /* ignore */ }
    return out.slice(0, 500)
  }

  if (base === 'pnpm-lock.yaml') {
    // Matches both pnpm v9 (`'next@15.1.0':` / `@scope/pkg@1.2.3(...)`) and v6 (`/@scope/pkg@1.2.3:`)
    const lines = content.split('\n')
    let inPackages = false
    for (const line of lines) {
      if (/^packages:\s*$/.test(line)) {
        inPackages = true
        continue
      }
      if (inPackages && /^[a-zA-Z]/.test(line)) {
        inPackages = false
        continue
      }
      if (!inPackages) continue
      const match = line.match(/^\s{2}['"]?\/?((?:@[^/@'"\s]+\/)?[^/@'"\s(]+)[@/]([0-9]+\.[0-9]+\.[0-9A-Za-z.+-]*)/)
      if (match) add('npm', match[1], cleanSemver(match[2]))
    }
    return out.slice(0, 500)
  }

  if (base === 'bun.lock') {
    // bun.lock is JSONC (JSON with trailing commas). Parse package tuples like `"next": ["next@15.1.0", ...]`.
    for (const match of content.matchAll(/"((?:@[^/"\s]+\/)?[a-zA-Z0-9_.-]+)@([0-9]+\.[0-9]+\.[0-9A-Za-z.+-]*)"/g)) {
      add('npm', match[1], cleanSemver(match[2]))
    }
    return out.slice(0, 500)
  }

  if (base === 'yarn.lock') {
    let currentPkg: string | null = null
    for (const line of content.split('\n')) {
      if (!line.startsWith(' ') && !line.startsWith('\t') && line.trimEnd().endsWith(':')) {
        const header = line.trim().replace(/:$/, '').split(',')[0].trim().replace(/^["']|["']$/g, '')
        const atIdx = header.startsWith('@') ? header.indexOf('@', 1) : header.indexOf('@')
        currentPkg = atIdx > 0 ? header.slice(0, atIdx) : null
        continue
      }
      if (currentPkg) {
        const verMatch = line.match(/^\s+version(?::|\s+)\s*["']?([0-9]+\.[0-9]+\.[0-9A-Za-z.+-]*)["']?/)
        if (verMatch) {
          add('npm', currentPkg, cleanSemver(verMatch[1]))
          currentPkg = null
        }
      }
    }
    return out.slice(0, 500)
  }

  if (base === 'requirements.txt') {
    for (const line of content.split('\n')) {
      const m = line.trim().match(/^([a-zA-Z0-9_.-]+)(?:\[[^\]]+\])?\s*(?:==|>=|~=|<=)\s*([0-9][0-9a-zA-Z.*+-]*)/)
      if (m) add('PyPI', m[1], cleanSemver(m[2]))
    }
    return out.slice(0, 300)
  }

  if (base === 'pyproject.toml') {
    let section = ''
    let inDepsArray = false
    for (const rawLine of content.split('\n')) {
      const line = rawLine.replace(/#.*$/, '').trim()
      if (!line) continue
      const secMatch = line.match(/^\[([^\]]+)\]$/)
      if (secMatch) {
        section = secMatch[1].trim()
        inDepsArray = false
        continue
      }
      if (section === 'project' || section.startsWith('project.optional-dependencies')) {
        if (/^dependencies\s*=\s*\[/.test(line) || (section.startsWith('project.optional-dependencies') && /=\s*\[/.test(line))) {
          inDepsArray = !line.includes(']')
        }
        if (inDepsArray || /^dependencies\s*=/.test(line) || section.startsWith('project.optional-dependencies')) {
          for (const m of line.matchAll(/["']([a-zA-Z0-9_.-]+)(?:\[[^\]]+\])?\s*(?:==|>=|~=|<=|!=)\s*([0-9][0-9a-zA-Z.*+-]*)/g)) {
            add('PyPI', m[1], cleanSemver(m[2]))
          }
          if (line.includes(']')) inDepsArray = false
        }
      } else if (section === 'tool.poetry.dependencies' || section === 'tool.poetry.dev-dependencies' || section.endsWith('.dependencies')) {
        const kv = line.match(/^([a-zA-Z0-9_.-]+)\s*=\s*(?:"([^"]+)"|'([^']+)'|\{[^}]*version\s*=\s*["']([^"']+)["'])/)
        if (kv && kv[1].toLowerCase() !== 'python') {
          add('PyPI', kv[1], cleanSemver(kv[2] ?? kv[3] ?? kv[4] ?? ''))
        }
      }
    }
    return out.slice(0, 300)
  }

  if (base === 'go.sum') {
    for (const line of content.split('\n')) {
      const m = line.trim().match(/^([^\s]+)\s+v([0-9]+\.[0-9]+\.[0-9A-Za-z.+-]*)/)
      if (m) add('Go', m[1], m[2].replace(/\/go\.mod$/, ''))
    }
    return out.slice(0, 300)
  }

  if (base === 'cargo.lock') {
    let inPkg = false
    let pkgName: string | null = null
    let pkgVer: string | null = null
    const flush = () => {
      if (pkgName && pkgVer) add('crates.io', pkgName, cleanSemver(pkgVer))
      pkgName = null
      pkgVer = null
    }
    for (const rawLine of content.split('\n')) {
      const line = rawLine.trim()
      if (line === '[[package]]') {
        flush()
        inPkg = true
        continue
      }
      if (!inPkg) continue
      const nameMatch = line.match(/^name\s*=\s*"([^"]+)"/)
      if (nameMatch) { pkgName = nameMatch[1]; continue }
      const verMatch = line.match(/^version\s*=\s*"([^"]+)"/)
      if (verMatch) { pkgVer = verMatch[1]; continue }
    }
    flush()
    return out.slice(0, 500)
  }

  return out
}

function deduplicateDependencies(allDependencies: readonly RepoDependency[]): RepoDependency[] {
  const depMap = new Map<string, RepoDependency>()
  for (const dep of allDependencies) {
    const key = `${dep.ecosystem}:${dep.package}`
    const existing = depMap.get(key)
    const isManifest = dep.sourceFile.endsWith('package.json') || dep.sourceFile.endsWith('pyproject.toml')
    const existingIsManifest = existing
      ? (existing.sourceFile.endsWith('package.json') || existing.sourceFile.endsWith('pyproject.toml'))
      : false
    if (!existing || (!isManifest && existingIsManifest)) {
      depMap.set(key, dep)
    }
  }
  return [...depMap.values()]
}

function buildDependenciesSpec(fullName: string, dependencies: readonly RepoDependency[]): SyncedRepoSpec | null {
  if (dependencies.length === 0) return null
  const depLines = dependencies
    .slice(0, 600)
    .map(d => `${d.ecosystem}:${d.package}@${d.version} (${d.sourceFile})`)
  return {
    name: `${fullName}:dependencies`.slice(0, 160),
    kind: 'notes',
    content: `# Extracted Dependencies for ${fullName} (${dependencies.length} total)\n\n${depLines.join('\n')}`,
  }
}

function buildRepoSpecs(fullName: string, files: readonly SyncedRepoFile[], dependencies: readonly RepoDependency[]): SyncedRepoSpec[] {
  const specs: SyncedRepoSpec[] = []

  for (const file of files) {
    if (file.category === 'openapi') {
      specs.push({
        name: `${fullName}:${file.path}`.slice(0, 160),
        kind: 'openapi',
        content: file.content.slice(0, 512 * 1024),
      })
    } else if (file.category === 'graphql') {
      specs.push({
        name: `${fullName}:${file.path}`.slice(0, 160),
        kind: 'graphql',
        content: file.content.slice(0, 512 * 1024),
      })
    }
  }

  const routeFiles = files.filter(f => f.category === 'route' || f.category === 'config')
  if (routeFiles.length > 0) {
    const sections: string[] = [`# Read-Only Server Route & Security Handler Context: ${fullName}\n`]
    let total = 0
    for (const f of routeFiles) {
      const chunk = `\n## ${f.path}\n\`\`\`\n${f.content.slice(0, 24 * 1024)}\n\`\`\`\n`
      if (total + chunk.length > 512 * 1024) break
      sections.push(chunk)
      total += chunk.length
    }
    specs.push({
      name: `${fullName}:routes-and-handlers`.slice(0, 160),
      kind: 'routes',
      content: sections.join(''),
    })
  }

  const depSpec = buildDependenciesSpec(fullName, dependencies)
  if (depSpec) specs.push(depSpec)

  return specs
}

function buildClonedRepoSpecs(input: {
  fullName: string
  defaultBranch: string
  commitSha?: string
  mountPath: string
  treeCount: number
  topLevelDirs: readonly string[]
  topLevelFiles: readonly string[]
  manifestPaths: readonly string[]
  schemaFiles: readonly SyncedRepoFile[]
  dependencies: readonly RepoDependency[]
}): SyncedRepoSpec[] {
  const specs: SyncedRepoSpec[] = []

  const inventoryLines = [
    `# Cloned Repository Inventory: ${input.fullName}`,
    '',
    `- Repository: ${input.fullName}`,
    `- Branch: ${input.defaultBranch}${input.commitSha ? ` (${input.commitSha})` : ''}`,
    `- Container Mount Path (read-only): ${input.mountPath}`,
    `- Total Files: ${input.treeCount}`,
    `- Top-Level Directories: ${input.topLevelDirs.length ? input.topLevelDirs.join(', ') : '(none)'}`,
    `- Top-Level Files: ${input.topLevelFiles.length ? input.topLevelFiles.slice(0, 40).join(', ') : '(none)'}`,
    `- Manifests & Lockfiles Scanned (${input.manifestPaths.length}): ${input.manifestPaths.length ? input.manifestPaths.slice(0, 40).join(', ') : '(none)'}`,
    `- Dependencies Extracted: ${input.dependencies.length}`,
    '',
    'Explore this full codebase inside `derive_evidence` using standard bash commands:',
    `- \`find ${input.mountPath} -maxdepth 3\``,
    `- \`grep -rn "pattern" ${input.mountPath}\` or \`rg -n "pattern" ${input.mountPath}\``,
    `- \`sed -n '1,120p' ${input.mountPath}/path/to/file\``,
  ]
  specs.push({
    name: `${input.fullName}:inventory`.slice(0, 160),
    kind: 'notes',
    content: inventoryLines.join('\n'),
  })

  for (const file of input.schemaFiles) {
    if (file.category === 'openapi') {
      specs.push({
        name: `${input.fullName}:${file.path}`.slice(0, 160),
        kind: 'openapi',
        content: file.content.slice(0, 512 * 1024),
      })
    } else if (file.category === 'graphql') {
      specs.push({
        name: `${input.fullName}:${file.path}`.slice(0, 160),
        kind: 'graphql',
        content: file.content.slice(0, 512 * 1024),
      })
    }
  }

  const depSpec = buildDependenciesSpec(input.fullName, input.dependencies)
  if (depSpec) specs.push(depSpec)

  return specs
}

function runGit(
  args: string[],
  env: NodeJS.ProcessEnv,
  secrets: readonly NamedSecret[],
  signal?: AbortSignal,
  timeoutMs = defaultCloneTimeoutMs,
): Promise<{ stdout: string; stderr: string }> {
  signal?.throwIfAborted()
  const deadline = signal ? AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]) : AbortSignal.timeout(timeoutMs)
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn('git', args, {
      env,
      signal: deadline,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    const outChunks: Buffer[] = []
    const errChunks: Buffer[] = []
    let outLen = 0
    let errLen = 0
    const cap = 256 * 1024
    child.stdout.on('data', (chunk: Buffer) => {
      if (outLen < cap) {
        outChunks.push(chunk.subarray(0, cap - outLen))
        outLen += chunk.length
      }
    })
    child.stderr.on('data', (chunk: Buffer) => {
      if (errLen < cap) {
        errChunks.push(chunk.subarray(0, cap - errLen))
        errLen += chunk.length
      }
    })
    child.once('error', err => {
      if (deadline.aborted) {
        rejectPromise(new Error(`git ${args[0] ?? ''} aborted or timed out.`))
      } else {
        rejectPromise(new Error(redact(err.message, secrets)))
      }
    })
    child.once('close', code => {
      const stdout = redact(Buffer.concat(outChunks).toString('utf8'), secrets)
      const stderr = redact(Buffer.concat(errChunks).toString('utf8'), secrets)
      if (code === 0) {
        resolvePromise({ stdout, stderr })
      } else {
        const detail = (stderr || stdout).trim().slice(0, 300)
        rejectPromise(new Error(`git ${args[0] ?? ''} failed (exit ${code}): ${detail}`))
      }
    })
  })
}

function walkClonedRepo(
  rootDir: string,
  secrets: readonly NamedSecret[],
  maxFileBytes: number,
  warnings: string[],
): {
  treeCount: number
  topLevelDirs: string[]
  topLevelFiles: string[]
  manifestPaths: string[]
  files: SyncedRepoFile[]
  schemaFiles: SyncedRepoFile[]
  dependencies: RepoDependency[]
} {
  const resolvedRoot = realpathSync(rootDir)
  const topLevelDirs: string[] = []
  const topLevelFiles: string[] = []
  const manifestPaths: string[] = []
  const files: SyncedRepoFile[] = []
  const schemaFiles: SyncedRepoFile[] = []
  const allDependencies: RepoDependency[] = []
  let treeCount = 0

  const visit = (currentDir: string, depth: number) => {
    chmodSync(currentDir, 0o755)
    const entries = readdirSync(currentDir, { withFileTypes: true })
    entries.sort((a, b) => a.name.localeCompare(b.name))

    for (const entry of entries) {
      const fullPath = join(currentDir, entry.name)
      const lstat = lstatSync(fullPath)

      // Never allow symlinks escaping the clone root; strip all symlinks for safety.
      if (lstat.isSymbolicLink()) {
        let escaped = true
        try {
          const target = realpathSync(fullPath)
          escaped = !(target === resolvedRoot || target.startsWith(resolvedRoot + sep))
        } catch {
          escaped = true
        }
        if (escaped) {
          rmSync(fullPath, { force: true })
          warnings.push(`Removed out-of-tree symlink: ${relative(rootDir, fullPath).split(sep).join('/')}`)
        }
        continue
      }

      if (lstat.isDirectory()) {
        if (entry.name === '.git') {
          // Preserve bounded history for Stage-3 regression mining; sanitize + make readable.
          sanitizeGitMetadata(fullPath)
          chmodTreeReadable(fullPath)
          continue
        }
        if (depth === 0) topLevelDirs.push(entry.name)
        if (skippedDirNames.has(entry.name)) {
          // Still ensure readable permissions if somehow present in repo, without scanning dependencies inside it
          chmodTreeReadable(fullPath)
          continue
        }
        visit(fullPath, depth + 1)
        continue
      }

      if (!lstat.isFile()) continue
      chmodSync(fullPath, 0o644)
      treeCount += 1
      if (depth === 0) topLevelFiles.push(entry.name)

      const relPath = relative(rootDir, fullPath).split(sep).join('/')
      const lowerBase = entry.name.toLowerCase()
      const isManifest = lowerBase === 'package.json'
      const isLockfile = lockfileNames.has(lowerBase)
      const isOpenApi = /(?:openapi|swagger).*\.(?:json|ya?ml)$/i.test(lowerBase)
      const isGraphql = /\.(?:graphql|gql)$/i.test(lowerBase)

      if (isManifest || isLockfile) {
        manifestPaths.push(relPath)
        if (lstat.size <= defaultMaxLockfileBytes) {
          try {
            const raw = readFileSync(fullPath, 'utf8')
            allDependencies.push(...parseDependenciesFromFile(relPath, raw))
            const truncated = raw.length > maxFileBytes
            files.push({
              path: relPath,
              category: isManifest ? 'manifest' : 'lockfile',
              size: lstat.size,
              truncated,
              content: redact(truncated ? raw.slice(0, maxFileBytes) : raw, secrets),
            })
          } catch (err) {
            warnings.push(`Failed to read ${relPath}: ${redact(err instanceof Error ? err.message : String(err), secrets)}`)
          }
        } else {
          warnings.push(`Skipped oversized lockfile ${relPath} (${lstat.size} bytes).`)
        }
      } else if ((isOpenApi || isGraphql) && schemaFiles.length < 16 && lstat.size <= maxFileBytes * 2) {
        try {
          const raw = readFileSync(fullPath, 'utf8')
          const truncated = raw.length > maxFileBytes
          const item: SyncedRepoFile = {
            path: relPath,
            category: isOpenApi ? 'openapi' : 'graphql',
            size: lstat.size,
            truncated,
            content: redact(truncated ? raw.slice(0, maxFileBytes) : raw, secrets),
          }
          schemaFiles.push(item)
          files.push(item)
        } catch { /* ignore unreadable schema */ }
      }
    }
  }

  visit(rootDir, 0)
  return {
    treeCount,
    topLevelDirs,
    topLevelFiles,
    manifestPaths,
    files,
    schemaFiles,
    dependencies: deduplicateDependencies(allDependencies),
  }
}

function chmodTreeReadable(dirPath: string): void {
  try {
    chmodSync(dirPath, 0o755)
    for (const entry of readdirSync(dirPath, { withFileTypes: true })) {
      const fullPath = join(dirPath, entry.name)
      const st = lstatSync(fullPath)
      if (st.isSymbolicLink()) continue
      if (st.isDirectory()) chmodTreeReadable(fullPath)
      else if (st.isFile()) chmodSync(fullPath, 0o644)
    }
  } catch { /* best-effort */ }
}


function stripGitSymlinks(dirPath: string): void {
  let entries
  try {
    entries = readdirSync(dirPath, { withFileTypes: true })
  } catch {
    return
  }
  for (const entry of entries) {
    const fullPath = join(dirPath, entry.name)
    try {
      if (lstatSync(fullPath).isSymbolicLink()) {
        rmSync(fullPath, { force: true })
      } else if (entry.isDirectory()) {
        stripGitSymlinks(fullPath)
      }
    } catch { /* best-effort */ }
  }
}

/** Strip credentials/headers from `.git/config` and neutralize hooks before mounting. */
function sanitizeGitMetadata(gitDir: string): void {
  stripGitSymlinks(gitDir)
  const configPath = join(gitDir, 'config')
  try {
    if (!existsSync(configPath)) return
    const raw = readFileSync(configPath, 'utf8')
    const sections: string[] = []
    let skippingCredentialSection = false
    for (const line of raw.split('\n')) {
      const section = /^\s*\[([^\]]+)\]\s*$/.exec(line)
      if (section) {
        skippingCredentialSection = /^credential(?:\s|$)/i.test(section[1])
        if (!skippingCredentialSection) sections.push(line)
        continue
      }
      if (skippingCredentialSection) continue
      if (/extraheader/i.test(line) || /^\s*(?:username|password|token)\s*=/i.test(line)) continue
      sections.push(line.replace(/(https?:\/\/)[^/@\s]+@/gi, '$1'))
    }
    writeFileSync(configPath, sections.join('\n'), { mode: 0o644 })
    chmodSync(configPath, 0o644)
  } catch { /* best-effort: mount remains read-only */ }
  const hooksDir = join(gitDir, 'hooks')
  try {
    if (existsSync(hooksDir)) {
      for (const entry of readdirSync(hooksDir, { withFileTypes: true })) {
        if (entry.isFile()) chmodSync(join(hooksDir, entry.name), 0o644)
      }
    }
  } catch { /* best-effort */ }
}

export interface RepoCommitDiffMining {
  available: boolean
  reason?: string
  commitsScanned: number
  commitDiffs: CommitDiffSignal[]
}

/**
 * Mine a bounded, credential-free git history for security-relevant commit diffs.
 * Pure server-side operation; never emits raw diffs or repository contents.
 */
export function readRepoCommitDiffs(
  repoDir: string,
  options: { maxCommits?: number; diffBase?: string; maxDiffBytes?: number } = {},
): RepoCommitDiffMining {
  const gitDir = join(repoDir, '.git')
  if (!existsSync(gitDir)) return { available: false, reason: 'No .git directory in mounted repository.', commitsScanned: 0, commitDiffs: [] }
  const maxCommits = Math.max(1, Math.min(options.maxCommits ?? defaultMaxCommitDiffs, 200))
  const maxDiffBytes = Math.max(16_384, Math.min(options.maxDiffBytes ?? 262_144, 1024 * 1024))
  const baseArgs = ['-C', repoDir, '-c', 'safe.directory=*', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null']
  try {
    execFileSync('git', [...baseArgs, 'rev-parse', '--git-dir'], { encoding: 'utf8', timeout: 5_000, stdio: ['ignore', 'pipe', 'ignore'] })
  } catch {
    return { available: false, reason: 'Invalid git repository.', commitsScanned: 0, commitDiffs: [] }
  }
  const safeBase = options.diffBase && /^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,127}$/.test(options.diffBase) ? options.diffBase : undefined
  const range = safeBase ? `${safeBase}..HEAD` : undefined
  let logOut = ''
  try {
    const args = [...baseArgs, 'log', '-n', String(maxCommits), '--no-merges', '--pretty=format:===COMMIT===%H%x09%aI%x09%s', '--name-only']
    if (range) args.push(range)
    logOut = execFileSync('git', args, { encoding: 'utf8', timeout: 10_000, maxBuffer: 2 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] })
  } catch {
    return { available: false, reason: 'git log failed.', commitsScanned: 0, commitDiffs: [] }
  }
  const commits: Array<{ sha: string; subject: string; committedAt?: string; diff: string }> = []
  for (const block of logOut.split('===COMMIT===').slice(1)) {
    const lines = block.trim().split('\n')
    const [sha, committedAt, ...subjectParts] = (lines[0] ?? '').split('\t')
    if (!sha) continue
    commits.push({ sha, subject: subjectParts.join('\t'), ...(committedAt ? { committedAt } : {}), diff: '' })
  }
  for (const commit of commits) {
    try {
      commit.diff = execFileSync('git', [...baseArgs, 'show', '--unified=3', '--no-color', '--format=', commit.sha], {
        encoding: 'utf8', timeout: 8_000, maxBuffer: maxDiffBytes + 1024, stdio: ['ignore', 'pipe', 'ignore'],
      }).slice(0, maxDiffBytes)
    } catch { commit.diff = '' }
  }
  return {
    available: true,
    commitsScanned: commits.length,
    commitDiffs: mineSecurityRelevantCommitDiffs(commits, { maxSignals: 100, maxLinesPerFile: 12 }),
  }
}

export async function cloneGithubRepos(
  repoFullNames: readonly string[],
  targetRootDir: string,
  signal?: AbortSignal,
  options: GithubSyncOptions = {},
): Promise<SyncedGithubRepo[]> {
  signal?.throwIfAborted()
  if (!targetRootDir || /[\0,\r\n]/.test(targetRootDir)) {
    throw new Error('Invalid repository clone root directory.')
  }

  const cred = await resolveFreshGithubCredential({
    dataDir: options.dataDir,
    patPath: options.patPath,
    githubBaseUrl: options.githubBaseUrl,
    fetchImpl: options.fetchImpl,
    signal,
  })
  const pat = cred.accessToken
  const basicAuth = Buffer.from(`x-access-token:${pat}`, 'utf8').toString('base64')
  const secrets: NamedSecret[] = [
    { value: pat, placeholder: '[redacted]' },
    { value: basicAuth, placeholder: '[redacted]' },
    ...(cred.refreshToken ? [{ value: cred.refreshToken, placeholder: '[redacted]' }] : []),
  ]
  const gitBase = (options.gitBaseUrl ?? 'https://github.com').replace(/\/+$/, '')
  const gitBaseUrl = new URL(gitBase)
  if (!['https:', 'http:', 'file:'].includes(gitBaseUrl.protocol)) {
    throw new Error(`Unsupported Git base protocol: ${gitBaseUrl.protocol}`)
  }
  const maxFileBytes = Math.max(1024, Math.min(options.maxFileBytes ?? defaultMaxFileBytes, 2 * 1024 * 1024))
  const cloneTimeoutMs = Math.max(5_000, Math.min(options.cloneTimeoutMs ?? defaultCloneTimeoutMs, 600_000))
  const historyDepth = Math.max(1, Math.min(Math.floor(options.historyDepth ?? defaultHistoryDepth), 1000))
  const stripGitMetadata = options.stripGitMetadata === true
  const maxCommitDiffs = Math.max(0, Math.min(Math.floor(options.maxCommitDiffs ?? defaultMaxCommitDiffs), 200))

  mkdirSync(targetRootDir, { recursive: true, mode: 0o755 })
  chmodSync(targetRootDir, 0o755)
  const resolvedRoot = realpathSync(targetRootDir)

  const gitEnv: NodeJS.ProcessEnv = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    GIT_TERMINAL_PROMPT: '0',
    GIT_ASKPASS: 'echo',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
  }
  if (gitBaseUrl.protocol === 'https:' || gitBaseUrl.protocol === 'http:') {
    gitEnv.GIT_CONFIG_COUNT = '2'
    gitEnv.GIT_CONFIG_KEY_0 = `http.${gitBaseUrl.origin}/.extraHeader`
    gitEnv.GIT_CONFIG_VALUE_0 = `Authorization: Basic ${basicAuth}`
    gitEnv.GIT_CONFIG_KEY_1 = 'core.symlinks'
    gitEnv.GIT_CONFIG_VALUE_1 = 'false'
  } else {
    gitEnv.GIT_CONFIG_COUNT = '1'
    gitEnv.GIT_CONFIG_KEY_0 = 'core.symlinks'
    gitEnv.GIT_CONFIG_VALUE_0 = 'false'
  }

  const results: SyncedGithubRepo[] = []

  for (const rawName of repoFullNames) {
    signal?.throwIfAborted()
    const { fullName, owner, repo } = parseRepoFullName(rawName)
    const ownerDir = join(resolvedRoot, owner)
    const finalDir = join(ownerDir, repo)
    if (!resolve(finalDir).startsWith(resolvedRoot + sep)) {
      throw new Error(`Resolved clone path escapes root directory: ${fullName}`)
    }

    mkdirSync(ownerDir, { recursive: true, mode: 0o755 })
    chmodSync(ownerDir, 0o755)

    const stagingDir = join(ownerDir, `.tmp-${repo}-${randomUUID()}`)
    const backupDir = join(ownerDir, `.old-${repo}-${randomUUID()}`)
    const repoUrl = `${gitBase}/${owner}/${repo}.git`
    const warnings: string[] = []

    try {
      await runGit(
        ['clone', '--depth', String(historyDepth), '--single-branch', '--no-tags', '--', repoUrl, stagingDir],
        gitEnv,
        secrets,
        signal,
        cloneTimeoutMs,
      )

      let defaultBranch = 'main'
      let commitSha: string | undefined
      try {
        const br = await runGit(['-C', stagingDir, 'rev-parse', '--abbrev-ref', 'HEAD'], gitEnv, secrets, signal, 10_000)
        if (br.stdout.trim() && br.stdout.trim() !== 'HEAD') defaultBranch = br.stdout.trim()
      } catch { /* fallback to main */ }
      try {
        const sha = await runGit(['-C', stagingDir, 'rev-parse', '--short', 'HEAD'], gitEnv, secrets, signal, 10_000)
        if (sha.stdout.trim()) commitSha = sha.stdout.trim()
      } catch { /* optional */ }

      // Sanitize retained git metadata (strip credentials, symlinks, executable hooks).
      sanitizeGitMetadata(join(stagingDir, '.git'))

      // Walk full tree: strip escaping symlinks, set a+rX permissions for uid 10001:10001, extract all dependencies
      const walked = walkClonedRepo(stagingDir, secrets, maxFileBytes, warnings)

      // Mine security-relevant diffs from the bounded history before any optional cleanup.
      const mined = maxCommitDiffs > 0
        ? readRepoCommitDiffs(stagingDir, { maxCommits: maxCommitDiffs })
        : { available: false, commitsScanned: 0, commitDiffs: [] as CommitDiffSignal[] }
      if (stripGitMetadata) {
        rmSync(join(stagingDir, '.git'), { recursive: true, force: true })
      }

      // Atomically swap staged directory into final destination
      let movedOld = false
      try {
        if (existsSync(finalDir)) {
          renameSync(finalDir, backupDir)
          movedOld = true
        }
        renameSync(stagingDir, finalDir)
        if (movedOld) {
          rmSync(backupDir, { recursive: true, force: true })
        }
      } catch (swapErr) {
        if (movedOld && !existsSync(finalDir) && existsSync(backupDir)) {
          try { renameSync(backupDir, finalDir) } catch { /* ignore */ }
        }
        throw swapErr
      }

      const mountPath = `/repos/${owner}/${repo}`
      const specs = buildClonedRepoSpecs({
        fullName,
        defaultBranch,
        commitSha,
        mountPath,
        treeCount: walked.treeCount,
        topLevelDirs: walked.topLevelDirs,
        topLevelFiles: walked.topLevelFiles,
        manifestPaths: walked.manifestPaths,
        schemaFiles: walked.schemaFiles,
        dependencies: walked.dependencies,
      })

      results.push({
        fullName,
        defaultBranch,
        private: true,
        description: null,
        language: null,
        treeCount: walked.treeCount,
        files: walked.files,
        dependencies: walked.dependencies,
        specs,
        warnings,
        mountPath,
        localPath: finalDir,
        commitSha,
        topLevelDirs: walked.topLevelDirs,
        gitHistory: {
          depth: historyDepth,
          commitsScanned: mined.commitsScanned,
          commitDiffs: mined.commitDiffs,
          metadataPreserved: !stripGitMetadata,
        },
      })
    } finally {
      rmSync(stagingDir, { recursive: true, force: true })
      rmSync(backupDir, { recursive: true, force: true })
    }
  }

  return results
}

export async function syncGithubRepos(
  repoFullNames: readonly string[],
  signal?: AbortSignal,
  options: GithubSyncOptions = {},
): Promise<SyncedGithubRepo[]> {
  if (options.cloneDir) {
    return cloneGithubRepos(repoFullNames, options.cloneDir, signal, options)
  }

  signal?.throwIfAborted()
  const cred = await resolveFreshGithubCredential({
    dataDir: options.dataDir,
    patPath: options.patPath,
    githubBaseUrl: options.githubBaseUrl,
    fetchImpl: options.fetchImpl,
    signal,
  })
  const pat = cred.accessToken
  const secrets: NamedSecret[] = [
    { value: pat, placeholder: '[redacted]' },
    ...(cred.refreshToken ? [{ value: cred.refreshToken, placeholder: '[redacted]' }] : []),
  ]
  const apiBase = (options.apiBaseUrl ?? DEFAULT_GITHUB_API_BASE_URL).replace(/\/+$/, '')
  const fetchFn = options.fetchImpl ?? fetch
  const maxFilesPerRepo = Math.max(1, Math.min(options.maxFilesPerRepo ?? defaultMaxFilesPerRepo, 80))
  const maxFileBytes = Math.max(1024, Math.min(options.maxFileBytes ?? defaultMaxFileBytes, 2 * 1024 * 1024))
  const maxRepoBytes = Math.max(4096, Math.min(options.maxRepoBytes ?? defaultMaxRepoBytes, 8 * 1024 * 1024))

  const headers: Record<string, string> = {
    Authorization: `Bearer ${pat}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'Guardian/2 read-only repo connector',
  }

  const githubGetJson = async <T>(path: string): Promise<T> => {
    const reqSignal = signal ? AbortSignal.any([signal, AbortSignal.timeout(20_000)]) : AbortSignal.timeout(20_000)
    const res = await fetchFn(`${apiBase}${path}`, { method: 'GET', headers, signal: reqSignal })
    if (!res.ok) {
      const body = redact(await res.text().catch(() => ''), secrets).slice(0, 240)
      throw new Error(`GitHub API GET ${path} failed (${res.status}): ${body}`)
    }
    return await res.json() as T
  }

  const results: SyncedGithubRepo[] = []

  for (const rawName of repoFullNames) {
    signal?.throwIfAborted()
    const { fullName } = parseRepoFullName(rawName)

    const warnings: string[] = []
    const repoMeta = await githubGetJson<{
      default_branch?: string
      private?: boolean
      description?: string | null
      language?: string | null
    }>(`/repos/${fullName}`)

    const defaultBranch = repoMeta.default_branch || 'main'
    const treeResp = await githubGetJson<{
      truncated?: boolean
      tree?: Array<{ path?: string; type?: string; sha?: string; size?: number }>
    }>(`/repos/${fullName}/git/trees/${encodeURIComponent(defaultBranch)}?recursive=1`)

    if (treeResp.truncated) {
      warnings.push('GitHub git tree response was truncated due to repository size.')
    }

    const candidates: Array<{ path: string; sha: string; size: number; category: SyncedRepoFile['category']; priority: number }> = []
    for (const entry of treeResp.tree ?? []) {
      if (entry.type !== 'blob' || !entry.path || !entry.sha) continue
      const classified = classifyRepoPath(entry.path)
      if (!classified) continue
      candidates.push({
        path: entry.path,
        sha: entry.sha,
        size: entry.size ?? 0,
        category: classified.category,
        priority: classified.priority,
      })
    }

    // Prioritize manifests/lockfiles/schemas first, then shallower route/middleware files.
    candidates.sort((a, b) => {
      if (b.priority !== a.priority) return b.priority - a.priority
      const depthDiff = a.path.split('/').length - b.path.split('/').length
      if (depthDiff !== 0) return depthDiff
      return a.size - b.size
    })

    const files: SyncedRepoFile[] = []
    const allDependencies: RepoDependency[] = []
    let repoBytes = 0

    for (const candidate of candidates.slice(0, maxFilesPerRepo)) {
      signal?.throwIfAborted()
      if (repoBytes >= maxRepoBytes) {
        warnings.push(`Reached bounded repository byte cap (${maxRepoBytes} bytes).`)
        break
      }
      if (candidate.size > maxFileBytes * 4 && candidate.category !== 'lockfile') {
        warnings.push(`Skipped oversized file ${candidate.path} (${candidate.size} bytes).`)
        continue
      }

      try {
        const blob = await githubGetJson<{ content?: string; encoding?: string }>(`/repos/${fullName}/git/blobs/${encodeURIComponent(candidate.sha)}`)
        if (!blob.content) continue
        const decoded = blob.encoding === 'base64'
          ? Buffer.from(blob.content.replace(/\s+/g, ''), 'base64').toString('utf8')
          : blob.content

        // Extract dependencies before truncation/redaction of lockfile preview (lockfiles don't contain PATs, and we never return raw secrets).
        if (candidate.category === 'manifest' || candidate.category === 'lockfile') {
          allDependencies.push(...parseDependenciesFromFile(candidate.path, decoded))
        }

        const remaining = Math.max(0, maxRepoBytes - repoBytes)
        const limit = Math.min(maxFileBytes, remaining)
        const truncated = decoded.length > limit
        const safeContent = redact(truncated ? decoded.slice(0, limit) : decoded, secrets)
        repoBytes += Buffer.byteLength(safeContent)
        files.push({
          path: candidate.path,
          category: candidate.category,
          size: candidate.size,
          truncated,
          content: safeContent,
        })
      } catch (err) {
        warnings.push(`Failed to read ${candidate.path}: ${redact(err instanceof Error ? err.message : String(err), secrets)}`)
      }
    }

    const dependencies = deduplicateDependencies(allDependencies)

    results.push({
      fullName,
      defaultBranch,
      private: Boolean(repoMeta.private),
      description: repoMeta.description ? redact(repoMeta.description, secrets).slice(0, 300) : null,
      language: repoMeta.language ?? null,
      treeCount: treeResp.tree?.length ?? 0,
      files,
      dependencies,
      specs: buildRepoSpecs(fullName, files, dependencies),
      warnings,
    })
  }

  return results
}
