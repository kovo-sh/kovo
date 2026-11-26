import { createHash, randomUUID } from 'node:crypto'
import {
  accessSync,
  chmodSync,
  constants,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { redact } from './redact.ts'
import type { NamedSecret } from './redact.ts'

export const DEFAULT_GITHUB_PAT_PATH =
  typeof process !== 'undefined' && Boolean(process.versions?.node)
    ? join(homedir(), '.config', 'kovo-fixtures', 'github.pat')
    : ''
export const DEFAULT_GITHUB_MAX_AUTO_SELECT = 10
export const DEFAULT_GITHUB_BASE_URL = 'https://github.com'
export const DEFAULT_GITHUB_API_BASE_URL = 'https://api.github.com'
const GITHUB_REFRESH_LEEWAY_MS = 5 * 60 * 1000
const MAX_PENDING_DEVICE_FLOWS = 32
const repoFullNamePattern = /^[a-zA-Z0-9_.-]{1,100}\/[a-zA-Z0-9_.-]{1,100}$/
const githubAppSlugPattern = /^[a-z0-9-]+$/

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
  const envRaw = process.env.KOVO_GITHUB_APP_SLUG
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
  const envClientId = process.env.KOVO_GITHUB_CLIENT_ID?.trim()
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

export async function resolveFreshGithubCredential(options: {
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
        'User-Agent': 'KovoHunter/2 read-only repo connector',
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
    throw new Error('GitHub App Client ID is required. Set KOVO_GITHUB_CLIENT_ID or enter your GitHub App Client ID.')
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
      'User-Agent': 'KovoHunter/2 read-only repo connector',
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
      'User-Agent': 'KovoHunter/2 read-only repo connector',
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
        'User-Agent': 'KovoHunter/2 read-only repo connector',
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
    'User-Agent': 'KovoHunter/2 read-only repo connector',
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
