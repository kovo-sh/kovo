import { createFileRoute, Link, useNavigate, useRouter } from '@tanstack/react-router'
import { useEffect, useRef, useState } from 'react'
import {
  clearGithubToken,
  getGithubStatus,
  listGithubRepositories,
  listModels,
  removeModelProfile,
  saveGithubToken,
  testModel,
  toggleModelProfile,
} from '../actions.ts'
import { formatHumanTime, useAction } from '../components/common.tsx'
import { useGithubDeviceFlow } from '../components/github/useGithubDeviceFlow.ts'
import { GithubInstallBanner } from '../components/project/GithubInstallBanner.tsx'
import { Icon } from '../components/run/icons.tsx'
import { ModelProfileSheet } from '../components/settings/ModelProfileSheet.tsx'
import { Badge } from '../components/ui/badge.tsx'
import { Button, buttonVariants } from '../components/ui/button.tsx'
import { Card } from '../components/ui/card.tsx'
import { Dialog, DialogBody, DialogContent, DialogFooter, DialogTitle } from '../components/ui/dialog.tsx'
import { Disclosure, DisclosureContent, DisclosureTrigger } from '../components/ui/disclosure.tsx'
import { EmptyState } from '../components/ui/empty-state.tsx'
import { Input } from '../components/ui/input.tsx'
import { id } from '../domain.ts'
import type { PublicModelProfile } from '../domain.ts'
import { cn } from '../lib/cn.ts'

const CLOSE_ICON_CLASS =
  'block size-3.5 shrink-0 fill-none stroke-current [stroke-width:1.5] [stroke-linecap:round] [stroke-linejoin:round]'

const DANGER_OUTLINE_BTN =
  'border border-danger/35 bg-raise text-danger shadow-none hover:bg-danger-soft'

function ModelProfilesEmptyIllustration() {
  return (
    <svg
      width="180"
      height="88"
      viewBox="0 0 180 88"
      fill="none"
      aria-hidden="true"
      className="block text-fg"
    >
      <rect x="6" y="8" width="168" height="72" rx="10" fill="var(--sunk)" stroke="var(--line-2)" strokeWidth="1.2" />
      <rect x="20" y="29" width="34" height="30" rx="6" fill="var(--panel)" stroke="var(--line-strong)" strokeWidth="1.2" />
      <path d="M29 41h16M29 48h10" stroke="var(--fg-3)" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M54 44h22c8 0 10-16 20-16h18" stroke="var(--accent)" strokeWidth="1.6" strokeLinecap="round" />
      <path d="M54 44h22c8 0 10 16 20 16h18" stroke="var(--line-strong)" strokeWidth="1.4" strokeLinecap="round" strokeDasharray="3 3" />
      <circle cx="54" cy="44" r="3" fill="var(--panel)" stroke="currentColor" strokeWidth="1.4" />
      <rect x="114" y="17" width="46" height="22" rx="5" fill="var(--panel)" stroke="var(--accent)" strokeWidth="1.4" />
      <circle cx="124" cy="28" r="3" fill="var(--accent)" />
      <path d="M132 28h18" stroke="var(--fg-2)" strokeWidth="1.5" strokeLinecap="round" />
      <rect x="114" y="49" width="46" height="22" rx="5" fill="var(--panel)" stroke="var(--line-strong)" strokeWidth="1.2" />
      <circle cx="124" cy="60" r="3" fill="var(--panel)" stroke="var(--fg-3)" strokeWidth="1.4" />
      <path d="M132 60h18" stroke="var(--fg-3)" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  )
}

export const Route = createFileRoute('/settings')({
  validateSearch: (search): { runId?: string } => ({ runId: id.safeParse(search.runId).data }),
  loader: async () => {
    const [profiles, githubStatus] = await Promise.all([listModels(), getGithubStatus()])
    return { profiles, githubStatus }
  },
  component: SettingsWorkbenchPage,
})

type GithubStatusData = Awaited<ReturnType<typeof getGithubStatus>>

function githubConnectionSummary(status: GithubStatusData): { label: string; tone: 'ok' | 'neutral' } {
  if (!status.configured) return { label: 'Not connected', tone: 'neutral' }
  return {
    label: status.login ? `GitHub connected · @${status.login}` : 'GitHub connected',
    tone: 'ok',
  }
}

function GithubConnectionBand({ initialStatus }: { initialStatus: GithubStatusData }) {
  const router = useRouter()
  const [status, setStatus] = useState<GithubStatusData>(initialStatus)
  const [reconnecting, setReconnecting] = useState(false)
  const [patInput, setPatInput] = useState('')
  const [savingPat, setSavingPat] = useState(false)
  const [disconnecting, setDisconnecting] = useState(false)
  const [confirmDisconnect, setConfirmDisconnect] = useState(false)
  const [loadingInstallations, setLoadingInstallations] = useState(false)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const autoFetchedInstallationsRef = useRef(false)

  const device = useGithubDeviceFlow({
    configured: Boolean(status.githubDeviceFlowConfigured),
    disabled: savingPat || disconnecting,
    onStart: () => {
      setError('')
      setNotice('')
    },
    onAuthorized: async result => {
      setReconnecting(false)
      setError('')
      setStatus(result.accountStatus)
      const who = result.login ? ` · @${result.login}` : ''
      setNotice(`Connected to GitHub${who}. Found ${result.repoCount} accessible ${result.repoCount === 1 ? 'repository' : 'repositories'}.`)
      await router.invalidate()
    },
  })
  const {
    flow: deviceFlow,
    starting: startingFlow,
    error: deviceFlowError,
    clientId: clientIdInput,
    setClientId: setClientIdInput,
    codeCopied,
  } = device
  const displayError = error || deviceFlowError

  const isGithubAppSession = status.configured && (status.authKind === 'github_app_device' || status.tokenKind === 'github_app')

  useEffect(() => {
    setStatus(initialStatus)
  }, [initialStatus])

  useEffect(() => {
    if (!isGithubAppSession) {
      autoFetchedInstallationsRef.current = false
      return
    }
    if (status.installations !== undefined || autoFetchedInstallationsRef.current) return
    autoFetchedInstallationsRef.current = true
    let cancelled = false
    setLoadingInstallations(true)
    void listGithubRepositories()
      .then(res => {
        if (!cancelled) setStatus(res.status)
      })
      .catch(() => {
        // Best-effort background refresh; user can still click Refresh
      })
      .finally(() => {
        if (!cancelled) setLoadingInstallations(false)
      })
    return () => { cancelled = true }
  }, [isGithubAppSession, status.installations])

  async function refreshGithubInstallations() {
    if (loadingInstallations || disconnecting || startingFlow || savingPat) return
    setLoadingInstallations(true)
    setError('')
    try {
      const res = await listGithubRepositories()
      setStatus(res.status)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not refresh GitHub installations.')
    } finally {
      setLoadingInstallations(false)
    }
  }

  async function handleSavePat() {
    const trimmed = patInput.trim()
    if (trimmed.length < 10 || savingPat || disconnecting) return
    setSavingPat(true)
    setError('')
    setNotice('')
    try {
      const res = await saveGithubToken({ data: { token: trimmed } })
      setPatInput('')
      setReconnecting(false)
      setStatus(res.status)
      setNotice(`Read-only GitHub token saved privately on your machine. Found ${res.repos.length} accessible ${res.repos.length === 1 ? 'repository' : 'repositories'}.`)
      await router.invalidate()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not save GitHub token.')
    } finally {
      setSavingPat(false)
    }
  }

  async function handleDisconnect() {
    if (disconnecting) return
    setDisconnecting(true)
    setError('')
    setNotice('')
    try {
      const res = await clearGithubToken()
      setStatus(res.status)
      setReconnecting(false)
      setNotice(res.status.configured
        ? 'Removed your saved GitHub credential (a local fallback token is still active).'
        : 'Disconnected GitHub and removed the saved credential from this machine.')
      await router.invalidate()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not remove GitHub credential.')
    } finally {
      setDisconnecting(false)
    }
  }

  const badge = githubConnectionSummary(status)
  const showConnectPanel = !status.configured || reconnecting

  return (
    <section className="flex flex-col gap-3.5 border-t border-line pt-6" aria-labelledby="github-integration-heading">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="m-0 mb-0.5 text-[11.5px] font-medium text-fg-subtle">Source code &amp; dependency sync</p>
          <h2 id="github-integration-heading" className="m-0 text-[16px] font-semibold leading-[22px] tracking-[-0.015em] text-fg">
            GitHub integration
          </h2>
        </div>
        <Badge
          variant={badge.tone}
          className={cn('font-medium', badge.tone === 'neutral' && 'bg-sunk')}
        >
          <i
            className={cn(
              'inline-block size-1.5 flex-none rounded-full',
              badge.tone === 'ok' ? 'bg-ok' : 'bg-fg-faint',
            )}
            aria-hidden="true"
          />
          {badge.label}
        </Badge>
      </div>

      <Card className="overflow-hidden border-line">
        <div className="flex flex-col items-start justify-between gap-2.5 px-4 py-3.5 sm:flex-row sm:gap-5">
          <div className="flex min-w-0 flex-1 flex-col gap-[3px]">
            <span className="text-[13px] font-medium text-fg">
              {status.configured ? 'Read-only GitHub connection' : 'Sign in with GitHub'}
            </span>
            <p
              className="m-0 text-[12.5px] leading-[18px] text-fg-muted"
              title="Credentials are stored privately on this machine"
            >
              {status.configured && status.authKind === 'github_app_device'
                ? 'Authorized with read-only GitHub App access (code and metadata only). Tokens refresh automatically and stay stored privately on your machine.'
                : status.configured
                  ? 'Connected using a read-only GitHub access token stored privately on your machine.'
                  : 'Connect a read-only GitHub App with one-time code sign-in and automatic token refresh, stored privately on your machine.'}
            </p>
          </div>
          <div className="flex flex-none items-center gap-1.5 pt-0.5">
            {status.configured ? (
              <>
                <Button
                  type="button"
                  variant="outline"
                  disabled={disconnecting || startingFlow || savingPat}
                  onClick={() => {
                    setReconnecting(v => !v)
                    setError('')
                    setNotice('')
                  }}
                >
                  {reconnecting ? 'Cancel' : 'Change connection'}
                </Button>
                {status.source === 'vault' && (
                  <Button
                    type="button"
                    variant="outline"
                    className={DANGER_OUTLINE_BTN}
                    disabled={disconnecting || startingFlow || savingPat}
                    onClick={() => setConfirmDisconnect(true)}
                  >
                    {disconnecting ? 'Disconnecting…' : 'Disconnect'}
                  </Button>
                )}
              </>
            ) : !deviceFlow && status.githubDeviceFlowConfigured ? (
              <Button
                type="button"
                variant="default"
                disabled={startingFlow || savingPat}
                onClick={() => void device.start()}
              >
                {startingFlow ? 'Starting…' : 'Sign in with GitHub'}
              </Button>
            ) : null}
          </div>
        </div>

        {isGithubAppSession && !reconnecting && !deviceFlow && (
          <div className="border-t border-line bg-panel px-4 py-3">
            <GithubInstallBanner
              authKind={status.authKind}
              tokenKind={status.tokenKind}
              login={status.login}
              installUrl={status.installUrl}
              installations={status.installations}
              privateRepoCount={status.privateRepoCount}
              needsAppInstall={status.needsAppInstall}
              loading={loadingInstallations}
              onRefresh={() => void refreshGithubInstallations()}
            />
          </div>
        )}

        {showConnectPanel && !deviceFlow && (!status.githubDeviceFlowConfigured || reconnecting) && (
          <div className="flex flex-col gap-2 border-t border-line bg-sunk px-4 pt-3 pb-3.5">
            {!status.githubDeviceFlowConfigured ? (
              <>
                <div className="flex items-center justify-between gap-2.5 text-[12px]">
                  <strong className="text-fg">GitHub App Client ID</strong>
                  <span
                    className="text-fg-subtle"
                    title="Stored privately on this machine for one-click sign-in"
                  >
                    Needed once for one-click GitHub sign-in
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <Input
                    className="flex-1 font-mono text-[12px]!"
                    type="text"
                    value={clientIdInput}
                    onChange={e => setClientIdInput(e.target.value)}
                    placeholder="Iv23li…"
                    autoComplete="off"
                    disabled={startingFlow || savingPat}
                    aria-label="GitHub App Client ID"
                  />
                  <Button
                    type="button"
                    variant="default"
                    disabled={startingFlow || savingPat || clientIdInput.trim().length < 6}
                    onClick={() => void device.start()}
                  >
                    {startingFlow ? 'Starting…' : 'Sign in with GitHub'}
                  </Button>
                </div>
              </>
            ) : (
              <div className="flex items-center justify-between gap-2.5 text-[12px]">
                <span className="text-fg-subtle">Switch to a read-only GitHub App Device Flow session.</span>
                <Button
                  type="button"
                  variant="default"
                  disabled={startingFlow || savingPat}
                  onClick={() => void device.start()}
                >
                  {startingFlow ? 'Starting…' : 'Sign in with GitHub'}
                </Button>
              </div>
            )}
          </div>
        )}

        {deviceFlow && (
          <div
            className="flex flex-col gap-2 border-t border-line bg-sunk px-4 pt-3 pb-3.5"
            role="region"
            aria-label="GitHub device authorization"
          >
            <div className="flex items-center justify-between gap-2.5 text-[12px]">
              <strong className="text-fg">Enter this verification code on GitHub</strong>
              <Badge variant="accent" className="font-medium tabular-nums">
                Polling every {deviceFlow.intervalSec}s
              </Badge>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="select-all rounded-md border border-line-2 bg-panel px-3 py-[5px] font-mono text-[18px] font-semibold tracking-[0.14em] text-fg">
                {deviceFlow.userCode}
              </span>
              <Button
                type="button"
                variant="outline"
                onClick={() => void device.copyCode()}
              >
                {codeCopied ? 'Copied code' : 'Copy code'}
              </Button>
              <a
                className={cn(buttonVariants({ variant: 'default' }), 'no-underline')}
                href={deviceFlow.verificationUri}
                target="_blank"
                rel="noopener noreferrer"
              >
                Open GitHub verification ↗
              </a>
              <Button
                type="button"
                variant="ghost"
                onClick={() => void device.cancel()}
              >
                Cancel
              </Button>
            </div>
            <span className="text-[11.5px] text-fg-subtle">
              Waiting for GitHub approval… This view updates automatically once authorized.
            </span>
          </div>
        )}

        {showConnectPanel && (
          <div className="border-t border-line px-4 py-3">
            <Disclosure>
              <DisclosureTrigger className="w-full rounded-none bg-transparent px-0 py-0.5 text-[12.5px] font-medium text-fg-muted shadow-none hover:bg-transparent hover:text-fg">
                Or connect with a read-only GitHub token
              </DisclosureTrigger>
              <DisclosureContent className="flex flex-col gap-2 pt-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span
                    className="text-[12.5px] leading-[18px] text-fg-muted"
                    title="Stored privately on this machine"
                  >
                    Scope a read-only token to <strong className="text-fg">Contents: Read-only</strong> and paste it below (stored privately on your machine).
                  </span>
                  <a
                    className={cn(buttonVariants({ variant: 'outline' }), 'h-6 rounded-[5px] px-[7px] text-[12px] no-underline')}
                    href="https://github.com/settings/personal-access-tokens/new"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Create read-only token ↗
                  </a>
                </div>
                <div className="flex items-center gap-2">
                  <Input
                    className="flex-1 font-mono text-[12px]!"
                    type="password"
                    value={patInput}
                    onChange={e => setPatInput(e.target.value)}
                    placeholder="github_pat_…"
                    autoComplete="off"
                    disabled={savingPat || disconnecting}
                    aria-label="Read-only GitHub access token"
                  />
                  <Button
                    type="button"
                    variant="default"
                    disabled={savingPat || disconnecting || patInput.trim().length < 10}
                    onClick={() => void handleSavePat()}
                  >
                    {savingPat ? 'Saving…' : 'Save token'}
                  </Button>
                </div>
              </DisclosureContent>
            </Disclosure>
          </div>
        )}

        {displayError && (
          <div role="alert" className="border-t border-line bg-danger-soft px-4 py-[9px] text-[12px] text-danger">
            {displayError}
          </div>
        )}
        {notice && !error && (
          <div role="status" className="border-t border-line bg-ok-soft px-4 py-[9px] text-[12px] text-ok">
            {notice}
          </div>
        )}
      </Card>

      <Dialog
        open={confirmDisconnect}
        closeOnEscape={!disconnecting}
        onOpenChange={(nextOpen, details) => {
          if (!nextOpen) {
            if (disconnecting) {
              details.cancel()
              return
            }
            setConfirmDisconnect(false)
          }
        }}
      >
        <DialogContent
          role="alertdialog"
          className="max-w-[440px] overflow-hidden rounded-2xl border-line-2 bg-raise p-0"
        >
          <div className="flex items-center justify-between gap-3 border-b border-line px-4 py-3">
            <DialogTitle id="sw-disconnect-title">Disconnect GitHub?</DialogTitle>
            <Button
              type="button"
              variant="ghost"
              className="size-6 min-w-6 rounded-[5px] p-0 text-fg-subtle"
              disabled={disconnecting}
              onClick={() => setConfirmDisconnect(false)}
              aria-label="Close"
            >
              <Icon name="close" size={14} className={CLOSE_ICON_CLASS} />
            </Button>
          </div>
          <DialogBody className="p-4 text-[12.5px] leading-5 text-fg-muted">
            <p className="m-0">
              This removes the saved GitHub credential from this machine. Source sync and repository discovery stop until you connect again.
            </p>
          </DialogBody>
          <DialogFooter className="gap-1.5 px-4 py-2.5">
            <Button
              type="button"
              variant="ghost"
              disabled={disconnecting}
              onClick={() => setConfirmDisconnect(false)}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="outline"
              className={DANGER_OUTLINE_BTN}
              disabled={disconnecting}
              onClick={() => {
                setConfirmDisconnect(false)
                void handleDisconnect()
              }}
            >
              {disconnecting ? 'Disconnecting…' : 'Disconnect'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </section>
  )
}

function healthLabel(profile: PublicModelProfile): { text: string; tone: 'ok' | 'warn' | 'bad' | 'off' } {
  if (!profile.enabled) return { text: 'Disabled', tone: 'off' }
  if (profile.healthState === 'open') {
    if (profile.cooldownUntil && profile.cooldownUntil > Date.now()) {
      const secs = Math.max(1, Math.ceil((profile.cooldownUntil - Date.now()) / 1000))
      return { text: `Temporarily unavailable (${secs}s)`, tone: 'bad' }
    }
    return { text: 'Temporarily unavailable', tone: 'bad' }
  }
  if (profile.healthState === 'half_open') return { text: 'Recovering', tone: 'warn' }
  return { text: 'Healthy', tone: 'ok' }
}

function poolSummary(profiles: PublicModelProfile[]): { label: string; tone: 'ok' | 'warn' | 'danger' | 'neutral' } {
  const enabled = profiles.filter(p => p.enabled)
  if (enabled.length === 0) return { label: 'No model enabled', tone: 'warn' }
  const openCount = enabled.filter(p => p.healthState === 'open').length
  const halfCount = enabled.filter(p => p.healthState === 'half_open').length
  if (openCount === enabled.length) return { label: `All models unavailable · ${enabled.length} of ${profiles.length}`, tone: 'danger' }
  if (openCount > 0 || halfCount > 0) return { label: `Some models unavailable · ${enabled.length} of ${profiles.length} enabled`, tone: 'warn' }
  return { label: `Ready · ${enabled.length} of ${profiles.length} enabled`, tone: 'ok' }
}

function formatK(value: number) {
  if (value >= 1_000_000) {
    const m = value / 1_048_576
    return Number.isInteger(m) ? `${m}M` : `${(value / 1_000_000).toFixed(2).replace(/\.?0+$/, '')}M`
  }
  return value >= 1000 ? `${Math.round(value / 1000)}k` : String(value)
}

function formatRate(value: number) {
  if (value === 0) return '$0'
  if (value < 0.01) return `$${Number(value.toFixed(4))}`
  if (value < 0.1) return `$${Number(value.toFixed(3))}`
  return `$${value.toFixed(2)}`
}

function shortEndpointHost(endpoint: string): string {
  try {
    const url = new URL(endpoint)
    return url.host + (url.pathname && url.pathname !== '/' ? url.pathname : '')
  } catch {
    return endpoint
  }
}

function toneDotClass(tone: 'ok' | 'warn' | 'bad' | 'danger' | 'off' | 'neutral'): string {
  switch (tone) {
    case 'ok':
      return 'bg-ok'
    case 'warn':
      return 'bg-warn'
    case 'bad':
    case 'danger':
      return 'bg-danger'
    case 'off':
    case 'neutral':
      return 'bg-fg-faint'
  }
}

function statusTextClass(tone: 'ok' | 'warn' | 'bad' | 'off'): string {
  switch (tone) {
    case 'ok':
      return 'text-ok'
    case 'warn':
      return 'text-warn'
    case 'bad':
      return 'text-danger'
    case 'off':
      return 'text-fg-muted'
  }
}

function SettingsWorkbenchPage() {
  const { profiles, githubStatus } = Route.useLoaderData()
  const { runId } = Route.useSearch()
  const navigate = useNavigate()
  const poolAction = useAction()

  const [sheetOpen, setSheetOpen] = useState(false)
  const [editing, setEditing] = useState<PublicModelProfile>()
  const [testingId, setTestingId] = useState<string | null>(null)
  const [pageStatus, setPageStatus] = useState('')
  const [confirmDelete, setConfirmDelete] = useState<PublicModelProfile | null>(null)

  const pool = poolSummary(profiles)
  const enabledCount = profiles.filter(p => p.enabled).length

  function openCreate() {
    setEditing(undefined)
    setPageStatus('')
    setSheetOpen(true)
  }

  function openEdit(profile: PublicModelProfile) {
    setEditing(profile)
    setPageStatus('')
    setSheetOpen(true)
  }

  function handleRowTest(profile: PublicModelProfile) {
    setPageStatus('')
    setTestingId(profile.id)
    void poolAction.submit(
      () => testModel({
        data: {
          id: profile.id,
          name: profile.name,
          endpoint: profile.endpoint,
          model: profile.model,
          protocol: profile.protocol,
          key: '',
          priority: profile.priority,
          enabled: profile.enabled,
          contextWindow: profile.contextWindow,
          maxTokens: profile.maxTokens,
          thinkingLevel: profile.thinkingLevel,
          roleAffinity: profile.roleAffinity,
          inputCostPerMtok: profile.inputCostPerMtok,
          cachedInputCostPerMtok: profile.cachedInputCostPerMtok,
          outputCostPerMtok: profile.outputCostPerMtok,
        },
      }),
      () => {
        setTestingId(null)
        setPageStatus(
          profile.healthState === 'closed'
            ? `${profile.name}: connection verified. The model streamed a valid tool call.`
            : `${profile.name}: connection verified. Cooldown cleared and profile marked healthy.`,
        )
      },
    ).finally(() => setTestingId(null))
  }

  return (
    <main className="flex min-h-full flex-col bg-panel font-sans text-[13px] leading-5 tracking-[-0.003em] text-fg">
      <header className="sticky top-0 z-10 flex-none border-b border-line bg-panel px-4 sm:px-6">
        <div className="flex h-11 min-w-0 items-center gap-2.5">
          {runId ? (
            <>
              <Link
                to="/runs/$runId"
                params={{ runId }}
                className="whitespace-nowrap text-[12.5px] text-fg-subtle no-underline transition-colors hover:text-fg"
              >
                ← Back to run
              </Link>
              <span className="text-[12px] text-fg-faint" aria-hidden="true">/</span>
            </>
          ) : (
            <>
              <Link
                to="/"
                className="whitespace-nowrap text-[12.5px] text-fg-subtle no-underline transition-colors hover:text-fg"
              >
                Projects
              </Link>
              <span className="text-[12px] text-fg-faint" aria-hidden="true">/</span>
            </>
          )}
          <h1 className="m-0 truncate text-[13.5px] font-semibold leading-5 tracking-[-0.012em] text-fg">
            Settings
          </h1>
          <Badge
            variant={pool.tone}
            className={cn('font-medium tabular-nums', pool.tone === 'neutral' && 'bg-sunk')}
          >
            <i className={cn('inline-block size-1.5 flex-none rounded-full', toneDotClass(pool.tone))} aria-hidden="true" />
            {pool.label}
          </Badge>
          <span className="min-w-2 flex-1" />
          {profiles.length > 0 && (
            <div className="flex flex-none items-center gap-2">
              <Button type="button" variant="default" onClick={openCreate}>
                <span aria-hidden="true">+</span>
                Add model profile
              </Button>
            </div>
          )}
        </div>
      </header>

      {poolAction.error && (
        <div
          role="alert"
          className="flex items-center gap-2.5 border-b border-line bg-danger-soft px-4 py-2 text-[12.5px] text-danger sm:px-6"
        >
          <span className="min-w-0 flex-1">{poolAction.error}</span>
        </div>
      )}
      {pageStatus && !poolAction.error && (
        <div
          role="status"
          className="flex items-center gap-2.5 border-b border-line bg-ok-soft px-4 py-2 text-[12.5px] text-ok sm:px-6"
        >
          <span className="min-w-0 flex-1">{pageStatus}</span>
          <Button
            type="button"
            variant="ghost"
            className="h-6 rounded-[5px] px-[7px] text-[12px]"
            onClick={() => setPageStatus('')}
          >
            Dismiss
          </Button>
        </div>
      )}

      <div className="mx-auto flex w-full max-w-[1040px] flex-1 flex-col gap-8 px-4 pt-6 pb-[72px] sm:px-6">
        <section className="flex flex-col gap-3" aria-labelledby="model-pool-heading">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <p className="m-0 mb-0.5 text-[11.5px] font-medium text-fg-subtle">Automatic failover pool</p>
              <h2 id="model-pool-heading" className="m-0 text-[16px] font-semibold leading-[22px] tracking-[-0.015em] text-fg">
                Model profiles
              </h2>
            </div>
            <span
              className="text-[12px] tabular-nums text-fg-subtle"
              title="Keys are stored privately on this machine"
            >
              {profiles.length > 0
                ? `${enabledCount} of ${profiles.length} enabled · highest priority tried first`
                : '0 profiles configured · keys stored privately on your machine'}
            </span>
          </div>

          {profiles.length === 0 ? (
            <Card className="border-line">
              <EmptyState
                className="max-w-[560px] gap-3.5 px-6 py-10 [&>[data-slot=empty-state-icon]]:h-auto [&>[data-slot=empty-state-icon]]:w-auto [&>[data-slot=empty-state-icon]>svg]:h-auto [&>[data-slot=empty-state-icon]>svg]:w-auto"
                icon={<ModelProfilesEmptyIllustration />}
                title="No model profiles configured"
                description="Connect OpenRouter or any OpenAI / Anthropic compatible provider so Kovo Hunter can map attack surfaces, investigate security issues, and verify findings."
                action={(
                  <Button type="button" variant="default" onClick={openCreate}>
                    Add model profile
                  </Button>
                )}
              />
            </Card>
          ) : (
            <Card className="overflow-x-auto border-line">
              <table className="w-full border-collapse text-left" aria-label="Configured model profiles">
                <thead>
                  <tr>
                    <th className="h-8 whitespace-nowrap border-b border-line bg-sunk px-3.5 text-[11.5px] font-medium text-fg-subtle">
                      Profile &amp; model
                    </th>
                    <th className="h-8 whitespace-nowrap border-b border-line bg-sunk px-3.5 text-[11.5px] font-medium text-fg-subtle">
                      Status
                    </th>
                    <th className="h-8 whitespace-nowrap border-b border-line bg-sunk px-3.5 text-[11.5px] font-medium text-fg-subtle">
                      Priority &amp; limits
                    </th>
                    <th className="h-8 whitespace-nowrap border-b border-line bg-sunk px-3.5 text-[11.5px] font-medium text-fg-subtle">
                      Pricing (per 1M)
                    </th>
                    <th className="h-8 whitespace-nowrap border-b border-line bg-sunk px-3.5 text-right text-[11.5px] font-medium text-fg-subtle">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {profiles.map(profile => {
                    const status = healthLabel(profile)
                    const isRowTesting = testingId === profile.id && poolAction.pending
                    const updated = formatHumanTime(profile.updatedAt)
                    return (
                      <tr
                        key={profile.id}
                        data-enabled={profile.enabled}
                        className="border-b border-line transition-colors last:border-b-0 hover:bg-hover data-[enabled=false]:opacity-65"
                      >
                        <td className="px-3.5 py-[11px] align-middle">
                          <div className="flex min-w-[200px] flex-col gap-[3px]">
                            <div className="flex flex-wrap items-center gap-[7px]">
                              <span className="font-medium text-fg">{profile.name}</span>
                              <span
                                className="max-w-full truncate font-mono text-[11.5px] text-fg-muted"
                                title={profile.model}
                              >
                                {profile.model}
                              </span>
                            </div>
                            <div className="flex flex-wrap items-center gap-2 text-[12px] text-fg-subtle">
                              <span>{profile.protocol === 'messages' ? 'Anthropic Messages' : 'OpenAI Responses'}</span>
                              <span aria-hidden="true">·</span>
                              <span className="font-mono text-[11.5px]" title={profile.endpoint}>
                                {shortEndpointHost(profile.endpoint)}
                              </span>
                              <span aria-hidden="true">·</span>
                              <span>Role: {profile.roleAffinity ?? 'any'}</span>
                              {updated.label && (
                                <>
                                  <span aria-hidden="true">·</span>
                                  <span className="tabular-nums" title={updated.full}>
                                    Updated {updated.label}
                                  </span>
                                </>
                              )}
                            </div>
                            {profile.lastError && (
                              <span
                                className="mt-0.5 max-w-[440px] truncate text-[11.5px] text-danger"
                                title={profile.lastError}
                              >
                                Last error: {profile.lastError}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-3.5 py-[11px] align-middle">
                          <span
                            className={cn(
                              'inline-flex items-center gap-[7px] whitespace-nowrap text-[12.5px]',
                              statusTextClass(status.tone),
                            )}
                            title={profile.healthState === 'closed' ? 'Healthy' : status.text}
                          >
                            <i
                              className={cn('inline-block size-1.5 flex-none rounded-full', toneDotClass(status.tone))}
                              aria-hidden="true"
                            />
                            {status.text}
                          </span>
                        </td>
                        <td className="px-3.5 py-[11px] align-middle">
                          <div className="flex flex-col gap-0.5 whitespace-nowrap text-[12px] tabular-nums text-fg-muted">
                            <span>Priority {profile.priority}</span>
                            <small className="text-[11.5px] text-fg-subtle">
                              {formatK(profile.contextWindow)} ctx · {formatK(profile.maxTokens)} out · {profile.thinkingLevel}
                            </small>
                          </div>
                        </td>
                        <td className="px-3.5 py-[11px] align-middle">
                          <div className="flex flex-col gap-0.5 whitespace-nowrap text-[12px] tabular-nums text-fg-muted">
                            <span>
                              {formatRate(profile.inputCostPerMtok)} in · {formatRate(profile.outputCostPerMtok)} out
                            </span>
                            <small className="text-[11.5px] text-fg-subtle">
                              {formatRate(profile.cachedInputCostPerMtok)} cached
                            </small>
                          </div>
                        </td>
                        <td className="px-3.5 py-[11px] text-right align-middle">
                          <div className="inline-flex items-center justify-end gap-1 whitespace-nowrap">
                            <Button
                              type="button"
                              variant="outline"
                              className="h-6 rounded-[5px] px-[7px] text-[12px]"
                              disabled={poolAction.pending}
                              onClick={() => handleRowTest(profile)}
                            >
                              {isRowTesting ? 'Testing…' : 'Test'}
                            </Button>
                            <Button
                              type="button"
                              variant="ghost"
                              className="h-6 rounded-[5px] px-[7px] text-[12px]"
                              disabled={poolAction.pending}
                              onClick={() => openEdit(profile)}
                            >
                              Edit
                            </Button>
                            <Button
                              type="button"
                              variant="ghost"
                              className="h-6 rounded-[5px] px-[7px] text-[12px]"
                              disabled={poolAction.pending}
                              onClick={() => {
                                setPageStatus('')
                                void poolAction.submit(
                                  () => toggleModelProfile({ data: { profileId: profile.id, enabled: !profile.enabled } }),
                                  () => setPageStatus(`${profile.name} ${profile.enabled ? 'disabled' : 'enabled'}.`),
                                )
                              }}
                            >
                              {profile.enabled ? 'Disable' : 'Enable'}
                            </Button>
                            <Button
                              type="button"
                              variant="outline"
                              className="h-6 rounded-[5px] border-0 bg-transparent px-[7px] text-[12px] text-fg-subtle shadow-none hover:bg-danger-soft hover:text-danger"
                              disabled={poolAction.pending}
                              onClick={() => {
                                setPageStatus('')
                                setConfirmDelete(profile)
                              }}
                            >
                              Delete
                            </Button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </Card>
          )}
        </section>

        <GithubConnectionBand initialStatus={githubStatus} />
      </div>

      <ModelProfileSheet
        open={sheetOpen}
        editing={editing}
        profiles={profiles}
        onClose={() => {
          setSheetOpen(false)
          setEditing(undefined)
        }}
        onSaved={async message => {
          setSheetOpen(false)
          setEditing(undefined)
          setPageStatus(message)
          if (runId) await navigate({ to: '/runs/$runId', params: { runId } })
        }}
      />

      <Dialog
        open={Boolean(confirmDelete)}
        closeOnEscape={!poolAction.pending}
        onOpenChange={(nextOpen, details) => {
          if (!nextOpen) {
            if (poolAction.pending) {
              details.cancel()
              return
            }
            setConfirmDelete(null)
          }
        }}
      >
        <DialogContent
          role="alertdialog"
          className="max-w-[440px] overflow-hidden rounded-2xl border-line-2 bg-raise p-0"
        >
          <div className="flex items-center justify-between gap-3 border-b border-line px-4 py-3">
            <DialogTitle id="sw-delete-profile-title">Delete model profile?</DialogTitle>
            <Button
              type="button"
              variant="ghost"
              className="size-6 min-w-6 rounded-[5px] p-0 text-fg-subtle"
              disabled={poolAction.pending}
              onClick={() => setConfirmDelete(null)}
              aria-label="Close"
            >
              <Icon name="close" size={14} className={CLOSE_ICON_CLASS} />
            </Button>
          </div>
          <DialogBody className="p-4 text-[12.5px] leading-5 text-fg-muted">
            {confirmDelete && (
              <p className="m-0">
                Remove <strong className="text-fg">{confirmDelete.name}</strong> from the failover pool. Its saved API key is deleted from this machine and cannot be recovered.
              </p>
            )}
          </DialogBody>
          <DialogFooter className="gap-1.5 px-4 py-2.5">
            <Button
              type="button"
              variant="ghost"
              disabled={poolAction.pending}
              onClick={() => setConfirmDelete(null)}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="outline"
              className={DANGER_OUTLINE_BTN}
              disabled={poolAction.pending}
              onClick={() => {
                if (!confirmDelete) return
                const profile = confirmDelete
                void poolAction.submit(
                  () => removeModelProfile({ data: { profileId: profile.id } }),
                  () => {
                    if (editing?.id === profile.id) {
                      setEditing(undefined)
                      setSheetOpen(false)
                    }
                    setConfirmDelete(null)
                    setPageStatus(`${profile.name} deleted.`)
                  },
                )
              }}
            >
              {poolAction.pending ? 'Deleting…' : 'Delete profile'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </main>
  )
}
