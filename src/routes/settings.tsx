import { createFileRoute, Link, useNavigate, useRouter } from '@tanstack/react-router'
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import {
  clearGithubToken,
  getGithubStatus,
  listGithubRepositories,
  listModels,
  removeModelProfile,
  saveGithubToken,
  setModelProfilePriorities,
  testModel,
  toggleModelProfile,
  updateWorkspaceAction,
  workspaceData,
} from '../actions.ts'
import { formatHumanTime, useAction } from '../components/common.tsx'
import { useGithubDeviceFlow } from '../components/github/useGithubDeviceFlow.ts'
import { GithubInstallBanner } from '../components/project/GithubInstallBanner.tsx'
import { Icon } from '../components/run/icons.tsx'
import { ModelProfileSheet } from '../components/settings/ModelProfileSheet.tsx'
import { useServerDraft } from '../components/settings/useServerDraft.ts'
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
import { failoverPriorities, failoverRoleLabel } from '../model-pool-presets.ts'

const CLOSE_ICON_CLASS =
  'block size-3.5 shrink-0 fill-none stroke-current [stroke-width:1.5] [stroke-linecap:round] [stroke-linejoin:round]'

const DANGER_OUTLINE_BTN =
  'border border-danger/35 bg-raise text-danger shadow-none hover:bg-danger-soft'

function ModelProfilesEmptyIllustration() {
  return (
    <svg
      viewBox="0 0 180 88"
      fill="none"
      aria-hidden="true"
      className="block h-auto w-full max-w-[180px] text-fg"
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
    const [profiles, githubStatus, workspaceSummary] = await Promise.all([
      listModels(),
      getGithubStatus(),
      workspaceData(),
    ])
    return { profiles, githubStatus, workspace: workspaceSummary.workspace }
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

/** Identity of the saved GitHub connection (no secrets): changes when it is connected, switched or removed. */
function githubConnectionKey(status: GithubStatusData): string {
  return [status.configured ? 'on' : 'off', status.authKind, status.tokenKind, status.login, status.source, status.clientIdSource]
    .map(part => part ?? '')
    .join('|')
}

/** Compact "Updated elsewhere · Reload" affordance for draft-protected fields. */
function UpdatedElsewhereHint({ onReload, className }: { onReload: () => void; className?: string }) {
  return (
    <span role="status" data-testid="updated-elsewhere" className={cn('inline-flex items-center gap-1 text-[11.5px] font-medium text-warn-text', className)}>
      <i className="inline-block size-1.5 flex-none rounded-full bg-warn" aria-hidden="true" />
      Updated elsewhere
      <span aria-hidden="true" className="text-fg-faint">·</span>
      <button
        type="button"
        className="h-auto cursor-pointer whitespace-normal rounded-[4px] border-0 bg-transparent p-0 text-[11.5px] font-medium text-accent-text underline-offset-2 shadow-none hover:underline"
        onClick={onReload}
      >
        Reload
      </button>
    </span>
  )
}

const SUBTLE_DISCLOSURE_TRIGGER =
  'h-auto w-full rounded-none bg-transparent px-0 py-0.5 text-[12.5px] font-medium whitespace-normal text-fg-muted shadow-none hover:bg-transparent hover:text-fg'

interface OtherWaysToConnectProps {
  status: GithubStatusData
  showCustomApp: boolean
  patInput: string
  onPatInput: (value: string) => void
  savingPat: boolean
  disconnecting: boolean
  onSavePat: () => void
  clientIdInput: string
  onClientIdInput: (value: string) => void
  startingFlow: boolean
  onStartCustomApp: () => void
  changedElsewhere: boolean
  onReloadConnection: () => void
}

/**
 * Secondary connection paths (read-only PAT, custom GitHub App / Enterprise) behind one
 * collapsed disclosure, so the GitHub App sign-in stays the single prominent action.
 * Opens by default only when no App sign-in is available.
 */
function OtherWaysToConnect(props: OtherWaysToConnectProps) {
  const { status, changedElsewhere } = props
  return (
    <div className="border-t border-line px-4 py-3">
      <Disclosure defaultOpen={!status.githubDeviceFlowConfigured || changedElsewhere}>
        <DisclosureTrigger className={SUBTLE_DISCLOSURE_TRIGGER}>
          Other ways to connect
          <span className="font-normal text-fg-subtle">Read-only token · Enterprise</span>
        </DisclosureTrigger>
        <DisclosureContent className="flex flex-col gap-3.5 pt-2.5" aria-label="Other ways to connect GitHub">
          {changedElsewhere && <UpdatedElsewhereHint onReload={props.onReloadConnection} />}
          <PatConnectSection {...props} />
          {props.showCustomApp && <CustomAppConnectSection {...props} />}
        </DisclosureContent>
      </Disclosure>
    </div>
  )
}

function PatConnectSection({ patInput, onPatInput, savingPat, disconnecting, onSavePat }: OtherWaysToConnectProps) {
  return (
    <div className="flex flex-col gap-2" data-slot="github-pat">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-[12.5px] leading-[18px] text-fg-muted" title="Stored privately on this machine">
          <strong className="font-medium text-fg">Read-only access token.</strong> Scope it to <strong className="text-fg">Contents: Read-only</strong> and paste it below (stored privately on your machine).
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
          onChange={e => onPatInput(e.target.value)}
          placeholder="github_pat_…"
          autoComplete="off"
          disabled={savingPat || disconnecting}
          aria-label="Read-only GitHub access token"
        />
        <Button
          type="button"
          variant="default"
          disabled={savingPat || disconnecting || patInput.trim().length < 10}
          onClick={onSavePat}
        >
          {savingPat ? 'Saving…' : 'Save token'}
        </Button>
      </div>
    </div>
  )
}

function CustomAppConnectSection({ status, clientIdInput, onClientIdInput, startingFlow, savingPat, onStartCustomApp }: OtherWaysToConnectProps) {
  return (
    <div className="flex flex-col gap-2 border-t border-line pt-3" data-slot="github-custom-app">
      <span className="text-[12.5px] leading-[18px] text-fg-muted">
        <strong className="font-medium text-fg">Custom GitHub App / Enterprise.</strong>{' '}
        {status.clientIdSource === 'env'
          ? 'A custom GitHub App Client ID is active via KOVO_GITHUB_CLIENT_ID. Enter a Client ID below to override it for this sign-in.'
          : status.clientIdSource === 'vault'
            ? 'A custom GitHub App Client ID is saved on this machine. Enter another Client ID below to switch apps.'
            : 'By default, Kovo uses the official Kovo Security GitHub App. Enter a custom Client ID only for GitHub Enterprise Server or custom organization apps.'}
      </span>
      <div className="flex items-center gap-2">
        <Input
          className="flex-1 font-mono text-[12px]!"
          type="text"
          value={clientIdInput}
          onChange={e => onClientIdInput(e.target.value)}
          placeholder="Iv23li…"
          autoComplete="off"
          disabled={startingFlow || savingPat}
          aria-label="Custom GitHub App Client ID"
        />
        <Button
          type="button"
          variant="outline"
          disabled={startingFlow || savingPat || clientIdInput.trim().length < 6}
          onClick={onStartCustomApp}
        >
          {startingFlow ? 'Starting…' : 'Sign in with custom App'}
        </Button>
      </div>
    </div>
  )
}

function GithubConnectionBand({ initialStatus }: { initialStatus: GithubStatusData }) {
  const router = useRouter()
  const [status, setStatus] = useState<GithubStatusData>(initialStatus)
  const [reconnecting, setReconnecting] = useState(false)
  // Secrets are never echoed back, so the PAT's server value is always empty: revalidation
  // and polls can never clear a token that is being typed.
  const [patInput, setPatInput] = useServerDraft('')
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
  // The connection itself can change elsewhere (another tab, a paired device). While a token
  // or client ID is being typed the connect panel stays put and offers a reload instead.
  const typingCredential = patInput.length > 0 || clientIdInput.length > 0
  const [, , connection] = useServerDraft(githubConnectionKey(status), { hold: typingCredential })
  const connectionChangedElsewhere = typingCredential && connection.serverChanged

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
  const showConnectPanel = !status.configured || reconnecting || connectionChangedElsewhere

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
                  : 'Connect the read-only Kovo Security GitHub App with one-time code sign-in and automatic token refresh, stored privately on your machine.'}
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

        {showConnectPanel && !deviceFlow && reconnecting && status.githubDeviceFlowConfigured && (
          <div className="flex flex-col gap-2 border-t border-line bg-sunk px-4 pt-3 pb-3.5">
            <div className="flex flex-wrap items-center justify-between gap-2.5 text-[12px]">
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
          <OtherWaysToConnect
            status={status}
            showCustomApp={!deviceFlow}
            patInput={patInput}
            onPatInput={setPatInput}
            savingPat={savingPat}
            disconnecting={disconnecting}
            onSavePat={() => void handleSavePat()}
            clientIdInput={clientIdInput}
            onClientIdInput={setClientIdInput}
            startingFlow={startingFlow}
            onStartCustomApp={() => void device.start()}
            changedElsewhere={connectionChangedElsewhere}
            onReloadConnection={() => {
              setPatInput('')
              setClientIdInput('')
              connection.acceptServer()
            }}
          />
        )}

        {displayError && (
          <div role="alert" className="min-w-0 border-t border-line bg-danger-soft px-4 py-[9px] text-[12px] text-danger [overflow-wrap:anywhere]">
            {displayError}
          </div>
        )}
        {notice && !error && (
          <div role="status" className="min-w-0 border-t border-line bg-ok-soft px-4 py-[9px] text-[12px] text-ok-text [overflow-wrap:anywhere]">
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
              size="icon"
              className="size-6 flex-none rounded-[5px] p-0 text-fg-subtle"
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

/** Whole seconds left on an open circuit's cooldown (0 when none is running). */
function cooldownSeconds(profile: PublicModelProfile, now: number): number {
  if (!profile.enabled || profile.healthState !== 'open' || !profile.cooldownUntil) return 0
  return Math.max(0, Math.ceil((profile.cooldownUntil - now) / 1000))
}

/** "42s" / "2m 05s" for the live cooldown countdown. */
function formatCooldown(secs: number): string {
  if (secs < 60) return `${secs}s`
  return `${Math.floor(secs / 60)}m ${String(secs % 60).padStart(2, '0')}s`
}

function healthLabel(profile: PublicModelProfile, now: number): { text: string; tone: 'ok' | 'warn' | 'bad' | 'off'; cooldown: number } {
  if (!profile.enabled) return { text: 'Disabled', tone: 'off', cooldown: 0 }
  if (profile.healthState === 'open') {
    const cooldown = cooldownSeconds(profile, now)
    return { text: cooldown > 0 ? 'Cooling down' : 'Unavailable', tone: 'bad', cooldown }
  }
  if (profile.healthState === 'half_open') return { text: 'Recovering', tone: 'warn', cooldown: 0 }
  return { text: 'Healthy', tone: 'ok', cooldown: 0 }
}

/** A circuit that is open or half-open needs live polling until it closes again. */
function needsHealthWatch(profile: PublicModelProfile): boolean {
  return profile.enabled && profile.healthState !== 'closed'
}

export const HEALTH_POLL_MS = 10_000
const COOLDOWN_TICK_MS = 1_000

/** Shared 1s clock, running only while a cooldown is counting down. */
function useCooldownClock(active: boolean): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!active) return
    setNow(Date.now())
    const timer = window.setInterval(() => setNow(Date.now()), COOLDOWN_TICK_MS)
    return () => window.clearInterval(timer)
  }, [active])
  return now
}

/** Move one profile `delta` places in the ranked list (null when it would leave the list). */
function moveProfile(list: readonly PublicModelProfile[], index: number, delta: -1 | 1): PublicModelProfile[] | null {
  const target = index + delta
  if (index < 0 || target < 0 || target >= list.length) return null
  const next = [...list]
  const [moved] = next.splice(index, 1)
  next.splice(target, 0, moved!)
  const priorities = failoverPriorities(next.length)
  return next.map((profile, rank) => ({ ...profile, priority: priorities[rank]! }))
}

interface LiveProfiles {
  profiles: PublicModelProfile[]
  now: number
  reordering: boolean
  reorderError: string
  reorder: (profileId: string, delta: -1 | 1) => Promise<boolean>
}

/**
 * The model pool as shown on screen: loader data, refreshed every 10s (paused while the tab is
 * hidden) whenever a circuit is open / half-open, with optimistic reorders rolled back on error.
 * Polls read only `listModels`, so workspace / GitHub drafts are never revalidated underneath.
 */
function useLiveProfiles(loaderProfiles: PublicModelProfile[]): LiveProfiles {
  const router = useRouter()
  const [override, setOverride] = useState<{ source: PublicModelProfile[]; profiles: PublicModelProfile[] }>()
  const [reordering, setReordering] = useState(false)
  const [reorderError, setReorderError] = useState('')
  const reorderingRef = useRef(false)
  const sourceRef = useRef(loaderProfiles)
  sourceRef.current = loaderProfiles
  const profiles = override && override.source === loaderProfiles ? override.profiles : loaderProfiles
  const watching = profiles.some(needsHealthWatch)
  const counting = profiles.some(p => p.enabled && p.healthState === 'open' && Boolean(p.cooldownUntil))
  const now = useCooldownClock(counting)
  const expired = profiles.filter(p => p.enabled && p.healthState === 'open' && p.cooldownUntil !== null && p.cooldownUntil <= now).length

  const poll = useCallback(async () => {
    if (typeof document !== 'undefined' && document.hidden) return
    try {
      const next = await listModels()
      if (!reorderingRef.current) setOverride({ source: sourceRef.current, profiles: next })
    } catch {
      // Keep the last known pool; the next tick retries.
    }
  }, [])

  useEffect(() => {
    if (!watching) return
    const timer = window.setInterval(() => void poll(), HEALTH_POLL_MS)
    const onVisible = () => { if (!document.hidden) void poll() }
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      window.clearInterval(timer)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [watching, poll])

  // A countdown that reaches zero flips the circuit to half-open server-side: fetch it now.
  useEffect(() => { if (expired > 0) void poll() }, [expired, poll])

  const reorder = useCallback(async (profileId: string, delta: -1 | 1) => {
    const previous = profiles
    const next = moveProfile(previous, previous.findIndex(p => p.id === profileId), delta)
    if (!next || reorderingRef.current) return false
    reorderingRef.current = true
    setReordering(true)
    setReorderError('')
    setOverride({ source: sourceRef.current, profiles: next })
    try {
      await setModelProfilePriorities({ data: { order: next.map(p => p.id) } })
      await router.invalidate()
      return true
    } catch (failure) {
      setOverride({ source: sourceRef.current, profiles: previous })
      setReorderError(failure instanceof Error ? failure.message : 'Kovo could not save the failover order.')
      return false
    } finally {
      reorderingRef.current = false
      setReordering(false)
    }
  }, [profiles, router])

  return { profiles, now, reordering, reorderError, reorder }
}

function poolSummary(profiles: PublicModelProfile[]): { label: string; tone: 'ok' | 'warn' | 'danger' | 'neutral' } {
  const enabled = profiles.filter(p => p.enabled)
  if (enabled.length === 0) return { label: 'No model enabled', tone: 'warn' }
  const openCount = enabled.filter(p => p.healthState === 'open').length
  const halfCount = enabled.filter(p => p.healthState === 'half_open').length
  if (openCount === enabled.length) return { label: `All models unavailable · ${enabled.length} of ${profiles.length}`, tone: 'danger' }
  if (openCount > 0) return { label: `${openCount} unavailable · ${enabled.length} of ${profiles.length} enabled`, tone: 'warn' }
  if (halfCount > 0) return { label: `${halfCount} recovering · ${enabled.length} of ${profiles.length} enabled`, tone: 'warn' }
  return { label: `Ready · ${enabled.length} of ${profiles.length} enabled`, tone: 'ok' }
}

/** Decimal token units: 999_999 -> "1M" (never "1000k"), 1_048_576 -> "1.05M". */
function formatK(value: number) {
  if (value >= 999_500) return `${Number((value / 1_000_000).toFixed(2))}M`
  return value >= 1000 ? `${Math.round(value / 1000)}k` : String(value)
}

/** USD per 1M tokens with grouping ("$1,234.56"); sub-dime rates keep 2 significant digits. */
function formatRate(value: number) {
  if (value === 0) return '$0'
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: value >= 0.1 ? 2 : 0,
    maximumSignificantDigits: value < 0.1 ? 2 : undefined,
  }).format(value)
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
      return 'text-ok-text'
    case 'warn':
      return 'text-warn-text'
    case 'bad':
      return 'text-danger'
    case 'off':
      return 'text-fg-muted'
  }
}

function WorkspaceSettingsBand({ workspace }: { workspace: { id: string; name: string } }) {
  const [focused, setFocused] = useState(false)
  // Revalidation only replaces the input while it is pristine and unfocused; a dirty or
  // focused draft is never clobbered and gets an "Updated elsewhere · Reload" hint instead.
  const [name, setName, draft] = useServerDraft(workspace.name, { hold: focused })
  const [notice, setNotice] = useState('')
  const action = useAction()

  const trimmed = name.trim()
  const unchanged = trimmed === workspace.name

  return (
    <section className="flex flex-col gap-3.5 border-t border-line pt-6" aria-labelledby="workspace-settings-heading">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="m-0 mb-0.5 text-[11.5px] font-medium text-fg-subtle">General</p>
          <h2 id="workspace-settings-heading" className="m-0 text-[16px] font-semibold leading-[22px] tracking-[-0.015em] text-fg">
            Workspace
          </h2>
        </div>
      </div>

      <Card className="overflow-hidden border-line">
        <form
          onSubmit={event => {
            event.preventDefault()
            if (!trimmed || unchanged) return
            setNotice('')
            void action.submit(() => updateWorkspaceAction({
              data: {
                requestId: crypto.randomUUID(),
                workspaceId: workspace.id,
                name: trimmed,
              },
            }), () => setNotice('Workspace name updated.'))
          }}
        >
          <div className="flex flex-col gap-2.5 px-4 py-3.5 sm:flex-row sm:items-end sm:gap-3">
            <div className="grid flex-1 gap-1.5">
              <div className="flex min-h-4 flex-wrap items-center justify-between gap-x-3 gap-y-1">
                <label htmlFor="workspace-name-input" className="text-[12px] font-medium text-fg-muted">Workspace name</label>
                {draft.serverChanged && name !== workspace.name && (
                  <UpdatedElsewhereHint onReload={() => {
                    draft.acceptServer()
                    setNotice('')
                  }} />
                )}
              </div>
              <Input
                id="workspace-name-input"
                className="w-full"
                name="workspaceName"
                value={name}
                onFocus={() => setFocused(true)}
                onBlur={() => setFocused(false)}
                onChange={e => {
                  setName(e.target.value)
                  if (notice) setNotice('')
                }}
                placeholder="Personal workspace"
                maxLength={160}
                required
                disabled={action.pending}
              />
            </div>
            <Button
              type="submit"
              variant="default"
              disabled={action.pending || !trimmed || unchanged}
            >
              {action.pending ? 'Saving…' : 'Save'}
            </Button>
          </div>
          {action.error && (
            <div role="alert" className="min-w-0 border-t border-line bg-danger-soft px-4 py-[9px] text-[12px] text-danger [overflow-wrap:anywhere]">
              {action.error}
            </div>
          )}
          {notice && !action.error && (
            <div role="status" className="min-w-0 border-t border-line bg-ok-soft px-4 py-[9px] text-[12px] text-ok-text [overflow-wrap:anywhere]">
              {notice}
            </div>
          )}
        </form>
      </Card>
    </section>
  )
}

function protocolLabel(protocol: PublicModelProfile['protocol']): string {
  if (protocol === 'messages') return 'Anthropic Messages'
  if (protocol === 'chat-completions') return 'OpenAI Chat Completions'
  return 'OpenAI Responses'
}

// Each item carries its own leading "·" in a fixed 15px box; the row is
// shifted left by that box inside an overflow-hidden wrapper, so the dot of
// whichever item starts a line is clipped and no line starts or ends with an
// orphan separator when the meta line wraps.
const META_LINE_CLASS = [
  '-ml-[15px] flex flex-wrap items-center gap-y-0.5 text-[12px] text-fg-subtle',
  "[&>*]:whitespace-nowrap [&>*]:before:inline-block [&>*]:before:w-[15px] [&>*]:before:text-center [&>*]:before:text-fg-faint [&>*]:before:content-['·']",
].join(' ')

/** Protocol · endpoint · role · updated, with separators that travel with their items. */
function ProfileMetaLine({ profile, updated }: {
  profile: PublicModelProfile
  updated: { label: string; full: string }
}) {
  return (
    <div className="min-w-0 overflow-hidden" data-slot="profile-meta">
      <div className={META_LINE_CLASS}>
        <span>{protocolLabel(profile.protocol)}</span>
        <span className="min-w-0 max-w-[260px] truncate font-mono text-[11.5px]" title={profile.endpoint}>
          {shortEndpointHost(profile.endpoint)}
        </span>
        <span>Role: {profile.roleAffinity ?? 'any'}</span>
        {updated.label && (
          <span className="tabular-nums" title={updated.full}>Updated {updated.label}</span>
        )}
      </div>
    </div>
  )
}

const TH_CLASS = 'h-8 whitespace-nowrap border-b border-line bg-sunk px-3.5 text-[11.5px] font-medium text-fg-subtle'
const ROW_BUTTON = 'h-6 rounded-[5px] px-[7px] text-[12px]'

interface ModelPoolTableProps {
  profiles: PublicModelProfile[]
  now: number
  busy: boolean
  /** A reorder is in flight: move buttons stay focusable (re-entry is guarded) so focus never drops. */
  reordering: boolean
  testingId: string | null
  onTest: (profile: PublicModelProfile) => void
  onEdit: (profile: PublicModelProfile) => void
  onToggle: (profile: PublicModelProfile) => void
  onDelete: (profile: PublicModelProfile) => void
  onMove: (profile: PublicModelProfile, delta: -1 | 1) => Promise<boolean>
}

/** Failover roles: enabled profiles take Primary, Fallback 1, … in list order; disabled ones are skipped. */
function failoverRoles(profiles: readonly PublicModelProfile[]): string[] {
  let enabledRank = 0
  return profiles.map(p => (p.enabled ? failoverRoleLabel(++enabledRank) : 'Skipped · disabled'))
}

function ModelPoolTable({ profiles, now, busy, reordering, testingId, onTest, onEdit, onToggle, onDelete, onMove }: ModelPoolTableProps) {
  const tableRef = useRef<HTMLTableElement>(null)
  const focusAfterMove = useRef<{ id: string; dir: 'up' | 'down' } | null>(null)
  const roles = failoverRoles(profiles)
  // Reordering moves the row (and may disable the pressed button at a boundary): keep
  // keyboard focus on the moved profile's move control after every re-render of the order.
  useLayoutEffect(() => {
    const target = focusAfterMove.current
    if (!target) return
    const row = tableRef.current?.querySelector<HTMLElement>(`tr[data-profile-id="${target.id}"]`)
    const button = row?.querySelector<HTMLButtonElement>(`[data-move="${target.dir}"]:not(:disabled)`)
      ?? row?.querySelector<HTMLButtonElement>('[data-move]:not(:disabled)')
    if (button && document.activeElement !== button) button.focus()
    if (!reordering) focusAfterMove.current = null
  }, [profiles, reordering])
  const move = (profile: PublicModelProfile, delta: -1 | 1) => {
    focusAfterMove.current = { id: profile.id, dir: delta < 0 ? 'up' : 'down' }
    void onMove(profile, delta)
  }
  return (
    <Card className="overflow-x-auto border-line">
      <table ref={tableRef} className="w-full border-collapse text-left" aria-label="Configured model profiles">
        <thead>
          <tr>
            <th className={cn(TH_CLASS, 'w-[1%] pr-1 pl-2.5 text-center')}><span className="sr-only">Failover order</span><span aria-hidden="true">#</span></th>
            {/* Preferred share for the contained profile column (its content no longer sizes it). */}
            <th className={cn(TH_CLASS, 'w-[34%] pl-2')}>Profile &amp; model</th>
            <th className={TH_CLASS}>Status</th>
            <th className={TH_CLASS}>Failover &amp; limits</th>
            <th className={TH_CLASS}>Pricing (per 1M)</th>
            <th className={cn(TH_CLASS, 'text-right')}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {profiles.map((profile, index) => (
            <ModelPoolRow
              key={profile.id}
              profile={profile}
              rank={index + 1}
              role={roles[index]!}
              last={index === profiles.length - 1}
              now={now}
              busy={busy}
              testing={testingId === profile.id}
              onTest={onTest}
              onEdit={onEdit}
              onToggle={onToggle}
              onDelete={onDelete}
              onMove={move}
            />
          ))}
        </tbody>
      </table>
    </Card>
  )
}

interface ModelPoolRowProps {
  profile: PublicModelProfile
  rank: number
  role: string
  last: boolean
  now: number
  busy: boolean
  testing: boolean
  onTest: (profile: PublicModelProfile) => void
  onEdit: (profile: PublicModelProfile) => void
  onToggle: (profile: PublicModelProfile) => void
  onDelete: (profile: PublicModelProfile) => void
  onMove: (profile: PublicModelProfile, delta: -1 | 1) => void
}

function RankCell({ profile, rank, last, busy, onMove }: Pick<ModelPoolRowProps, 'profile' | 'rank' | 'last' | 'busy' | 'onMove'>) {
  return (
    <td className="w-[1%] py-[9px] pr-1 pl-2.5 align-middle">
      <div className="flex items-center gap-1.5">
        <span
          className="grid size-5 flex-none place-items-center rounded-full border border-line-2 bg-panel text-[11px] font-semibold tabular-nums text-fg"
          data-testid="failover-rank"
          aria-label={`Failover rank ${rank}`}
        >
          {rank}
        </span>
        <div className="flex flex-col gap-0.5">
          <Button
            type="button"
            variant="ghost"
            size="icon"
            data-move="up"
            className="size-[18px] rounded-[4px] p-0 text-fg-subtle"
            disabled={busy || rank === 1}
            aria-label={`Move up: ${profile.name}`}
            title="Move up"
            onClick={() => onMove(profile, -1)}
          >
            <Icon name="chev" size={12} className="rotate-180" />
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            data-move="down"
            className="size-[18px] rounded-[4px] p-0 text-fg-subtle"
            disabled={busy || last}
            aria-label={`Move down: ${profile.name}`}
            title="Move down"
            onClick={() => onMove(profile, 1)}
          >
            <Icon name="chev" size={12} />
          </Button>
        </div>
      </div>
    </td>
  )
}

function StatusCell({ profile, now }: { profile: PublicModelProfile; now: number }) {
  const status = healthLabel(profile, now)
  const title = status.cooldown > 0
    ? `Temporarily unavailable · retrying in ${formatCooldown(status.cooldown)}`
    : profile.healthState === 'open' ? 'Temporarily unavailable' : status.text
  return (
    <td className="px-3.5 py-[11px] align-middle">
      {/* Status swaps colour instantly (no transition) so a flip is never mistaken for motion. */}
      <div className="flex flex-col gap-0.5 whitespace-nowrap transition-none" data-testid="profile-status" title={title}>
        <span className={cn('inline-flex items-center gap-[7px] text-[12.5px] transition-none', statusTextClass(status.tone))}>
          <i className={cn('inline-block size-1.5 flex-none rounded-full transition-none', toneDotClass(status.tone))} aria-hidden="true" />
          {status.text}
        </span>
        {status.cooldown > 0 && (
          <small className="pl-[13px] text-[11.5px] text-fg-subtle">
            Retry in{' '}
            <span className="tabular-nums" data-testid="cooldown-remaining" suppressHydrationWarning>{formatCooldown(status.cooldown)}</span>
          </small>
        )}
      </div>
    </td>
  )
}

function ModelPoolRow({ profile, rank, role, last, now, busy, testing, onTest, onEdit, onToggle, onDelete, onMove }: ModelPoolRowProps) {
  const updated = formatHumanTime(profile.updatedAt)
  return (
    <tr
      data-enabled={profile.enabled}
      data-profile-id={profile.id}
      className="border-b border-line transition-colors last:border-b-0 hover:bg-hover data-[enabled=false]:opacity-65"
    >
      <RankCell profile={profile} rank={rank} last={last} busy={busy} onMove={onMove} />
      <td className="max-w-[460px] py-[11px] pr-3.5 pl-2 align-middle">
        {/* contain-inline-size: unbroken names, model IDs and URLs never raise the
            column's min-content width, so Status and Actions stay on screen. */}
        <div className="flex min-w-[200px] max-w-[460px] flex-col gap-[3px] contain-inline-size">
          <div className="flex min-w-0 flex-wrap items-center gap-[7px]">
            <span className="line-clamp-2 min-w-0 font-medium text-fg [overflow-wrap:anywhere]" title={profile.name}>
              {profile.name}
            </span>
            <span className="min-w-0 max-w-full truncate font-mono text-[11.5px] text-fg-muted" title={profile.model}>
              {profile.model}
            </span>
          </div>
          <ProfileMetaLine profile={profile} updated={updated} />
          {profile.lastError && (
            <span className="mt-0.5 max-w-[440px] truncate text-[11.5px] text-danger" title={profile.lastError}>
              Last error: {profile.lastError}
            </span>
          )}
        </div>
      </td>
      <StatusCell profile={profile} now={now} />
      <td className="px-3.5 py-[11px] align-middle">
        <div className="flex flex-col gap-0.5 whitespace-nowrap text-[12px] tabular-nums text-fg-muted">
          <span>
            <span className="font-medium text-fg" data-testid="failover-role">{role}</span>
            <span className="text-fg-subtle"> · priority {profile.priority}</span>
          </span>
          <small className="text-[11.5px] text-fg-subtle">
            {formatK(profile.contextWindow)} ctx · {formatK(profile.maxTokens)} out · {profile.thinkingLevel}
          </small>
        </div>
      </td>
      <td className="px-3.5 py-[11px] align-middle">
        <div className="flex flex-col gap-0.5 whitespace-nowrap text-[12px] tabular-nums text-fg-muted">
          <span>{formatRate(profile.inputCostPerMtok)} in · {formatRate(profile.outputCostPerMtok)} out</span>
          <small className="text-[11.5px] text-fg-subtle">{formatRate(profile.cachedInputCostPerMtok)} cached</small>
        </div>
      </td>
      <td className="px-3.5 py-[11px] text-right align-middle">
        <div className="inline-flex items-center justify-end gap-1 whitespace-nowrap">
          <Button type="button" variant="outline" className={ROW_BUTTON} disabled={busy} onClick={() => onTest(profile)}>
            {testing ? 'Testing…' : 'Test'}
          </Button>
          <Button type="button" variant="ghost" className={ROW_BUTTON} disabled={busy} onClick={() => onEdit(profile)}>
            Edit
          </Button>
          <Button type="button" variant="ghost" className={ROW_BUTTON} disabled={busy} onClick={() => onToggle(profile)}>
            {profile.enabled ? 'Disable' : 'Enable'}
          </Button>
          <Button
            type="button"
            variant="outline"
            className={cn(ROW_BUTTON, 'border-0 bg-transparent text-fg-subtle shadow-none hover:bg-danger-soft hover:text-danger')}
            disabled={busy}
            onClick={() => onDelete(profile)}
          >
            Delete
          </Button>
        </div>
      </td>
    </tr>
  )
}

function SettingsWorkbenchPage() {
  const { profiles: loaderProfiles, githubStatus, workspace } = Route.useLoaderData()
  const live = useLiveProfiles(loaderProfiles)
  const profiles = live.profiles
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
    <main className="flex min-h-0 flex-1 flex-col bg-panel font-sans text-[13px] leading-5 tracking-[-0.003em] text-fg">
      <header className="sticky top-0 z-10 flex-none border-b border-line bg-panel px-4 sm:px-6">
        <div className="flex min-h-11 min-w-0 flex-wrap items-center gap-x-2.5 gap-y-1.5 py-2">
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
            className={cn('min-w-0 max-w-full shrink font-medium tabular-nums', pool.tone === 'neutral' && 'bg-sunk')}
          >
            <i className={cn('inline-block size-1.5 flex-none rounded-full', toneDotClass(pool.tone))} aria-hidden="true" />
            {pool.label}
          </Badge>
          <span className="min-w-2 flex-1" />
          {profiles.length > 0 && (
            <div className="flex flex-none items-center gap-2">
              <Button type="button" variant="default" onClick={openCreate}>
                <span aria-hidden="true">+</span>
                <span className="max-[560px]:sr-only">Add model profile</span>
              </Button>
            </div>
          )}
        </div>
      </header>

      {(poolAction.error || live.reorderError) && (
        <div
          role="alert"
          className="flex min-w-0 flex-none items-center gap-2.5 border-b border-line bg-danger-soft px-4 py-2 text-[12.5px] text-danger [overflow-wrap:anywhere] sm:px-6"
        >
          <span className="min-w-0 flex-1">{poolAction.error || live.reorderError}</span>
        </div>
      )}
      {pageStatus && !poolAction.error && !live.reorderError && (
        <div
          role="status"
          className="flex min-w-0 flex-none items-center gap-2.5 border-b border-line bg-ok-soft px-4 py-2 text-[12.5px] text-ok-text [overflow-wrap:anywhere] sm:px-6"
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

      <div className="min-h-0 flex-1 overflow-auto">
        <div className="mx-auto flex w-full max-w-[1040px] flex-col gap-8 px-4 pt-6 pb-[72px] sm:px-6">
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
                ? `${enabledCount} of ${profiles.length} enabled · tried in failover order, top first`
                : '0 profiles configured · keys stored privately on your machine'}
            </span>
          </div>

          {profiles.length === 0 ? (
            <Card className="border-line">
              <EmptyState
                className="max-w-[560px] gap-3.5 px-6 py-10 [&>[data-slot=empty-state-icon]]:h-auto [&>[data-slot=empty-state-icon]]:w-full [&>[data-slot=empty-state-icon]>svg]:h-auto [&>[data-slot=empty-state-icon]>svg]:w-full [&>[data-slot=empty-state-icon]>svg]:max-w-[180px]"
                icon={<ModelProfilesEmptyIllustration />}
                title="No model profiles configured"
                description="Connect OpenRouter or any OpenAI / Anthropic compatible provider so Kovo can map attack surfaces, investigate security issues, and verify findings."
                action={(
                  <Button type="button" variant="default" onClick={openCreate}>
                    Add model profile
                  </Button>
                )}
              />
            </Card>
          ) : (
            <ModelPoolTable
              profiles={profiles}
              now={live.now}
              busy={poolAction.pending}
              reordering={live.reordering}
              testingId={poolAction.pending ? testingId : null}
              onTest={handleRowTest}
              onEdit={openEdit}
              onToggle={profile => {
                setPageStatus('')
                void poolAction.submit(
                  () => toggleModelProfile({ data: { profileId: profile.id, enabled: !profile.enabled } }),
                  () => setPageStatus(`${profile.name} ${profile.enabled ? 'disabled' : 'enabled'}.`),
                )
              }}
              onDelete={profile => {
                setPageStatus('')
                setConfirmDelete(profile)
              }}
              onMove={(profile, delta) => {
                setPageStatus('')
                return live.reorder(profile.id, delta).then(ok => {
                  if (ok) setPageStatus(`${profile.name} moved ${delta < 0 ? 'up' : 'down'} in the failover order.`)
                  return ok
                })
              }}
            />
          )}
        </section>

        <GithubConnectionBand initialStatus={githubStatus} />
        <WorkspaceSettingsBand workspace={workspace} />
        </div>
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
              size="icon"
              className="size-6 flex-none rounded-[5px] p-0 text-fg-subtle"
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
