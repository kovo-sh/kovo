import { Link } from '@tanstack/react-router'
import { useEffect, useRef, useState } from 'react'
import {
  importSpec,
  listGithubRepositories,
  removeProjectSpec,
  syncGithubRepositories,
} from '../../actions.ts'
import { maxSpecBytes } from '../../domain.ts'
import { cn } from '../../lib/cn.ts'
import { formatHumanTime, FormError, useAction } from '../common.tsx'
import { Badge } from '../ui/badge.tsx'
import { Button, buttonVariants } from '../ui/button.tsx'
import { Card, CardBody, CardFooter, CardHeader } from '../ui/card.tsx'
import { Disclosure, DisclosureContent, DisclosureTrigger } from '../ui/disclosure.tsx'
import { EmptyState } from '../ui/empty-state.tsx'
import { Input, NativeSelect, Textarea } from '../ui/input.tsx'
import { GithubInstallBanner } from './GithubInstallBanner.tsx'
import { GroupedRepoPicker } from './GroupedRepoPicker.tsx'
import type { DiscoveredGithubRepo, ProjectLoaderData } from './types.ts'
import { safeHost } from './types.ts'

interface Props {
  data: ProjectLoaderData
}

function SourcesEmptyIllustration() {
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
      <rect x="22" y="22" width="46" height="44" rx="6" fill="var(--panel)" stroke="var(--line-strong)" strokeWidth="1.2" />
      <circle cx="34" cy="34" r="3" fill="var(--accent)" />
      <circle cx="34" cy="54" r="3" fill="var(--panel)" stroke="var(--accent)" strokeWidth="1.4" />
      <circle cx="52" cy="44" r="3" fill="var(--panel)" stroke="currentColor" strokeWidth="1.4" />
      <path d="M34 37v14M37 35.5c5 0 6 8.5 12 8.5" stroke="var(--accent)" strokeWidth="1.4" strokeLinecap="round" />
      <path d="M74 44h30" stroke="var(--line-strong)" strokeWidth="1.4" strokeLinecap="round" strokeDasharray="3 3" />
      <path d="M99 39.5 104.5 44 99 48.5" stroke="var(--accent)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
      <rect x="112" y="22" width="46" height="44" rx="6" fill="var(--panel)" stroke="var(--accent)" strokeWidth="1.4" />
      <path d="M122 34h26M122 43h18M122 52h22" stroke="var(--fg-3)" strokeWidth="1.5" strokeLinecap="round" />
      <circle cx="147" cy="43" r="2.2" fill="var(--accent)" />
    </svg>
  )
}

function formatGithubConnectionBadge(status: ProjectLoaderData['githubPatStatus']): string {
  if (!status.configured) return 'Not connected'
  return status.login ? `GitHub connected · @${status.login}` : 'GitHub connected'
}

export function ProjectSourcesTab({ data }: Props) {
  const { project, specs, githubPatStatus } = data
  const [liveGithubStatus, setLiveGithubStatus] = useState(githubPatStatus)
  const [repoPickerOpen, setRepoPickerOpen] = useState(false)
  const [discoveredRepos, setDiscoveredRepos] = useState<DiscoveredGithubRepo[]>([])
  const [reposLoaded, setReposLoaded] = useState(false)
  const [reposTruncated, setReposTruncated] = useState(false)
  const [repoSearch, setRepoSearch] = useState('')
  const [selectedRepos, setSelectedRepos] = useState<string[]>([])
  const [githubNotice, setGithubNotice] = useState('')
  const [specNotice, setSpecNotice] = useState('')
  const [specName, setSpecName] = useState('')
  const [specContent, setSpecContent] = useState('')
  const [manualUploadOpen, setManualUploadOpen] = useState(false)
  const manualUploadRef = useRef<HTMLDivElement | null>(null)

  const githubAction = useAction()
  const specAction = useAction()

  useEffect(() => {
    setLiveGithubStatus(githubPatStatus)
  }, [githubPatStatus])

  function openManualUpload() {
    setManualUploadOpen(true)
    manualUploadRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }

  function loadGithubRepos() {
    setGithubNotice('')
    void githubAction.submit(() => listGithubRepositories(), result => {
      setLiveGithubStatus(result.status)
      setDiscoveredRepos(result.repos)
      setSelectedRepos(result.defaultSelected)
      setReposTruncated(result.truncated)
      setReposLoaded(true)
      setRepoPickerOpen(true)
    })
  }

  function openRepoPicker() {
    setGithubNotice('')
    if (repoPickerOpen && reposLoaded) {
      setRepoPickerOpen(false)
      return
    }
    setRepoPickerOpen(true)
    if (!reposLoaded) loadGithubRepos()
  }

  async function onSpecFileSelected(file: File | undefined) {
    if (!file) return
    if (file.size > maxSpecBytes) {
      setSpecNotice(`File exceeds the ${Math.round(maxSpecBytes / (1024 * 1024))} MiB spec limit.`)
      return
    }
    const text = await file.text()
    setSpecName(current => current || file.name.slice(0, 160))
    setSpecContent(text)
  }

  const maxSyncBatch = 20
  const showBroadNote = discoveredRepos.length > 10 || liveGithubStatus.tokenKind === 'classic'
  const showRepoSheet = liveGithubStatus.configured && repoPickerOpen
  // Keep strictly ONE primary CTA visible at a time across header, active sheet, and empty state.
  const emptyOwnsPrimary = specs.length === 0 && liveGithubStatus.configured && !showRepoSheet
  const headerShowDiscoverBtn = specs.length > 0 || showRepoSheet

  return (
    <section aria-label="Source repositories">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="m-0 text-[13px] font-semibold text-fg">Source repositories (read-only)</h2>
            <Badge
              variant={liveGithubStatus.configured ? 'ok' : 'neutral'}
              className={!liveGithubStatus.configured ? 'bg-sunk' : undefined}
            >
              {formatGithubConnectionBadge(liveGithubStatus)}
            </Badge>
          </div>
          <p
            className="mt-0.5 text-[12px] text-fg-subtle"
            title="Credentials are stored privately on this machine and never shown again"
          >
            Optional read-only GitHub sync for source code, API schemas, and dependency checks. GitHub credentials are managed centrally in Settings.
          </p>
        </div>
        {liveGithubStatus.configured && (
          <div className="flex flex-wrap items-center gap-1.5">
            {headerShowDiscoverBtn && (
              <Button
                type="button"
                variant={showRepoSheet ? 'outline' : 'default'}
                disabled={githubAction.pending}
                onClick={openRepoPicker}
                aria-expanded={repoPickerOpen}
              >
                {repoPickerOpen ? 'Hide repos' : 'Discover & sync repos'}
              </Button>
            )}
            <Link
              to="/settings"
              search={{}}
              className={cn(buttonVariants({ variant: 'ghost' }), 'no-underline')}
            >
              Manage in Settings
            </Link>
          </div>
        )}
      </div>

      {githubNotice && (
        <p
          role="status"
          className="mb-3.5 flex items-center gap-2 rounded-[7px] border border-line bg-sunk px-3 py-[7px] text-[12.5px] text-fg-muted"
        >
          {githubNotice}
        </p>
      )}
      {specNotice && (
        <p
          role="status"
          className="mb-3.5 flex items-center gap-2 rounded-[7px] border border-line bg-sunk px-3 py-[7px] text-[12.5px] text-fg-muted"
        >
          {specNotice}
        </p>
      )}

      {!liveGithubStatus.configured && (
        <Card id="pw-github-connect" className="mb-4 overflow-hidden border-line">
          <CardBody className="flex flex-wrap items-center justify-between gap-3 py-3.5">
            <div className="flex min-w-0 flex-1 flex-col gap-0.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[13px] font-semibold text-fg">Connect GitHub in Settings</span>
                <Badge variant="neutral" className="bg-sunk">Read-only · Auto-refresh</Badge>
              </div>
              <p className="m-0 text-[12px] text-fg-subtle">
                Sign in with the read-only GitHub App or save a scoped access token in Settings to discover and sync repositories for this project.
              </p>
            </div>
            <Link
              to="/settings"
              search={{}}
              className={cn(buttonVariants({ variant: 'default' }), 'flex-none no-underline')}
            >
              Connect GitHub in Settings
            </Link>
          </CardBody>
        </Card>
      )}

      {showRepoSheet && (
        <Card className="pw-repo-sheet mb-4 overflow-hidden border-line">
          <CardHeader className="items-center py-2.5">
            <span className="text-[13px] font-semibold text-fg">Select repositories to sync</span>
            <div className="flex flex-wrap items-center gap-1.5">
              <Button type="button" variant="ghost" disabled={githubAction.pending} onClick={loadGithubRepos}>
                {githubAction.pending && !reposLoaded ? 'Loading…' : 'Refresh'}
              </Button>
              <Link
                to="/settings"
                search={{}}
                className={cn(buttonVariants({ variant: 'ghost' }), 'no-underline')}
              >
                GitHub settings
              </Link>
            </div>
          </CardHeader>

          <GithubInstallBanner
            authKind={liveGithubStatus.authKind}
            tokenKind={liveGithubStatus.tokenKind}
            login={liveGithubStatus.login}
            installUrl={liveGithubStatus.installUrl}
            installations={liveGithubStatus.installations}
            privateRepoCount={liveGithubStatus.privateRepoCount}
            needsAppInstall={liveGithubStatus.needsAppInstall}
            loading={githubAction.pending}
            onRefresh={loadGithubRepos}
            flush
          />

          <div className="grid gap-2 border-b border-line bg-panel px-4 py-2.5">
            <p className="m-0 text-[12px] text-fg-subtle">
              Read-only shallow clone + automatic OpenAPI, GraphQL, route, and lockfile extraction.
              {reposTruncated && ' Showing the 200 most recently updated repositories.'}
            </p>

            {liveGithubStatus.source === 'fixture' && (
              <p className="m-0 text-[11.5px] text-fg-subtle">
                Using a local fallback GitHub token. Open{' '}
                <Link to="/settings" search={{}} className="font-medium text-accent hover:underline">
                  Settings
                </Link>{' '}
                to sign in with GitHub or save your own read-only token instead.
              </p>
            )}

            {showBroadNote && discoveredRepos.length > 0 && (
              <div className="flex flex-wrap items-center justify-between gap-2.5 rounded-[7px] border border-warn-line bg-warn-soft px-2.5 py-2 text-[12px] text-fg-muted">
                <span>
                  {liveGithubStatus.tokenKind === 'classic'
                    ? `Classic GitHub token detected (${discoveredRepos.length} accessible repos).`
                    : `Found ${discoveredRepos.length} accessible repos.`}{' '}
                  {discoveredRepos.length > 10
                    ? 'Nothing was pre-selected so you do not accidentally clone everything.'
                    : 'Consider scoping a read-only token or GitHub App installation to only the target repositories.'}
                </span>
              </div>
            )}
          </div>

          {githubAction.pending && !reposLoaded ? (
            <div className="px-4 py-3.5 text-[12.5px]">
              <span className="text-fg-subtle">Discovering accessible repositories…</span>
            </div>
          ) : (
            <GroupedRepoPicker
              repos={discoveredRepos}
              selectedRepos={selectedRepos}
              onChangeSelectedRepos={setSelectedRepos}
              search={repoSearch}
              onSearchChange={setRepoSearch}
              maxSelectable={maxSyncBatch}
              disabled={githubAction.pending}
              variant="detailed"
              searchPlaceholder="Filter repositories by name, branch, or description…"
              emptyMessage="No repositories were returned for this account. Verify the GitHub App installation or token grants Contents: Read-only on at least one repository."
            />
          )}

          {(selectedRepos.length > maxSyncBatch || githubAction.error) && (
            <div className="grid gap-1.5 border-t border-line px-4 py-2.5">
              {selectedRepos.length > maxSyncBatch && (
                <p role="alert" className="m-0 text-[12px] text-danger">
                  Select at most {maxSyncBatch} repositories per sync batch.
                </p>
              )}
              <FormError error={githubAction.error} />
            </div>
          )}

          <CardFooter className="flex-wrap py-2.5">
            <span className="mr-auto text-[12px] tabular-nums text-fg-subtle">
              {selectedRepos.length} of {discoveredRepos.length} selected
            </span>
            <Button type="button" variant="ghost" onClick={() => setRepoPickerOpen(false)}>
              Close
            </Button>
            <Button
              type="button"
              variant="default"
              disabled={githubAction.pending || selectedRepos.length === 0 || selectedRepos.length > maxSyncBatch}
              onClick={() => {
                setGithubNotice('')
                void githubAction.submit(
                  () => syncGithubRepositories({ data: { projectId: project.id, repos: selectedRepos } }),
                  result => {
                    setRepoPickerOpen(false)
                    const warnText = result.warnings.length ? ` Warnings: ${result.warnings.join('; ')}` : ''
                    setGithubNotice(`Synced ${result.repos.length} ${result.repos.length === 1 ? 'repo' : 'repos'}: ${result.specsImported} specs imported, ${result.dependenciesExtracted} dependencies extracted.${warnText}`)
                  },
                )
              }}
            >
              {githubAction.pending ? 'Syncing…' : `Sync selected (${selectedRepos.length})`}
            </Button>
          </CardFooter>
        </Card>
      )}

      <div className="mb-2 mt-[18px] flex flex-wrap items-center justify-between gap-3">
        <h2 className="m-0 text-[13px] font-semibold text-fg">
          Synced snapshots &amp; specs <span className="font-normal tabular-nums text-fg-subtle">({specs.length})</span>
        </h2>
      </div>

      {specs.length > 0 ? (
        <div className="border-t border-line">
          {specs.map(spec => {
            const imported = formatHumanTime(spec.createdAt)
            return (
              <div
                key={spec.id}
                className="flex min-h-[44px] items-center justify-between gap-3 border-b border-line px-1 py-2 transition-colors hover:bg-hover"
              >
                <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                  <div className="flex min-w-0 flex-wrap items-center gap-1.5 font-medium text-fg">
                    <strong className="font-mono text-[12px] font-semibold">{spec.name}</strong>
                    <Badge variant="neutral" className="bg-sunk">{spec.kind}</Badge>
                    {spec.origin && <Badge variant="accent">{safeHost(spec.origin)}</Badge>}
                  </div>
                  <div className="text-[12px] tabular-nums text-fg-subtle">
                    {Math.max(1, Math.round(spec.bytes / 1024))} KiB
                    {imported.label && (
                      <>
                        {' · '}
                        <span title={imported.full}>Imported {imported.label}</span>
                      </>
                    )}
                  </div>
                </div>
                <div className="flex flex-none items-center gap-2">
                  <Button
                    type="button"
                    variant="ghost"
                    className="data-[slot=button]:text-danger data-[slot=button]:hover:bg-danger-soft data-[slot=button]:hover:text-danger"
                    disabled={specAction.pending}
                    onClick={() => {
                      void specAction.submit(() => removeProjectSpec({ data: {
                        requestId: crypto.randomUUID(),
                        projectId: project.id,
                        specId: spec.id,
                      } }), () => setSpecNotice(`Removed spec "${spec.name}".`))
                    }}
                  >
                    Delete
                  </Button>
                </div>
              </div>
            )
          })}
        </div>
      ) : (
        <div className="mt-3.5 rounded-card border border-line bg-sunk">
          <EmptyState
            icon={<SourcesEmptyIllustration />}
            title="No repositories or specs synced yet"
            description="Connect GitHub to pull read-only code and dependency context, or upload an OpenAPI or GraphQL schema manually."
            className="max-w-[440px] py-9 [&_[data-slot=empty-state-icon]]:size-auto [&_[data-slot=empty-state-icon]>svg]:h-[88px] [&_[data-slot=empty-state-icon]>svg]:w-[180px]"
            action={
              emptyOwnsPrimary ? (
                <>
                  <Button
                    type="button"
                    variant="default"
                    disabled={githubAction.pending}
                    onClick={openRepoPicker}
                  >
                    Discover repositories
                  </Button>
                  <Button type="button" variant="ghost" onClick={openManualUpload}>
                    Upload schema manually
                  </Button>
                </>
              ) : (
                <Button type="button" variant="outline" onClick={openManualUpload}>
                  Upload schema manually
                </Button>
              )
            }
          />
        </div>
      )}

      <div ref={manualUploadRef}>
        <Disclosure
          open={manualUploadOpen}
          onOpenChange={setManualUploadOpen}
          className="mt-3.5 border-t border-line pt-2.5"
        >
          <DisclosureTrigger className="h-auto bg-transparent px-0 py-1 text-fg-muted shadow-none hover:bg-transparent hover:text-fg">
            Advanced configuration
          </DisclosureTrigger>
          <DisclosureContent className="grid gap-2.5 pt-2.5">
            <p className="m-0 text-[12px] text-fg-subtle">
              Kovo Hunter automatically discovers runtime schemas and extracts OpenAPI, GraphQL, and lockfile specs from synced repositories. Use manual upload only when you need to supply an extra schema or lockfile directly.
            </p>
            <Card className="overflow-hidden border-line">
              <form
                onSubmit={event => {
                  event.preventDefault()
                  const form = new FormData(event.currentTarget)
                  const originVal = String(form.get('origin') ?? '').trim()
                  const kindRaw = String(form.get('kind') ?? 'openapi')
                  const kind = (['openapi', 'graphql', 'routes', 'notes'] as const).includes(kindRaw as 'openapi')
                    ? kindRaw as 'openapi' | 'graphql' | 'routes' | 'notes' : 'notes'
                  void specAction.submit(() => importSpec({ data: {
                    requestId: crypto.randomUUID(),
                    projectId: project.id,
                    name: specName.trim() || String(form.get('name') ?? '').trim(),
                    kind,
                    ...(originVal ? { origin: originVal } : {}),
                    content: specContent,
                  } }), saved => {
                    setSpecName('')
                    setSpecContent('')
                    setSpecNotice(`Imported spec "${saved.name}" (${saved.kind}).`)
                  })
                }}
              >
                <CardHeader className="items-center py-2.5">
                  <span className="text-[13px] font-semibold text-fg">Upload OpenAPI, GraphQL, or lockfile</span>
                </CardHeader>
                <CardBody className="grid gap-3 py-3.5">
                  <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-2">
                    <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                      Name
                      <Input
                        className="w-full"
                        name="name"
                        required
                        maxLength={160}
                        value={specName}
                        onChange={e => setSpecName(e.target.value)}
                        placeholder="openapi.yaml or package-lock.json"
                      />
                    </label>
                    <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                      Kind
                      <NativeSelect className="w-full" name="kind" defaultValue="openapi">
                        <option value="openapi">OpenAPI / Swagger</option>
                        <option value="graphql">GraphQL schema</option>
                        <option value="routes">Route map / Server handlers</option>
                        <option value="notes">Lockfile / Dependencies / Notes</option>
                      </NativeSelect>
                    </label>
                  </div>
                  <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-2">
                    <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                      Target origin (optional)
                      <Input
                        className="w-full"
                        name="origin"
                        placeholder={project.seeds[0] ?? 'https://api.example.com'}
                      />
                    </label>
                    <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                      Load from file (optional, up to 2 MiB)
                      <Input
                        className="w-full pt-[3px]!"
                        type="file"
                        accept=".json,.yaml,.yml,.graphql,.gql,.txt,.md,.lock"
                        onChange={e => {
                          void onSpecFileSelected(e.target.files?.[0])
                        }}
                      />
                    </label>
                  </div>
                  <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                    Content
                    <Textarea
                      className="w-full font-mono text-[12px]"
                      name="content"
                      rows={6}
                      required
                      value={specContent}
                      onChange={e => setSpecContent(e.target.value)}
                      placeholder="Paste OpenAPI, GraphQL SDL, lockfile JSON, or route notes…"
                    />
                  </label>
                  <FormError error={specAction.error} />
                </CardBody>
                <CardFooter className="py-2.5">
                  <Button type="submit" variant="outline" disabled={specAction.pending || !specContent.trim()}>
                    Import spec
                  </Button>
                </CardFooter>
              </form>
            </Card>
          </DisclosureContent>
        </Disclosure>
      </div>
    </section>
  )
}
