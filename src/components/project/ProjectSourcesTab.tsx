import { useState } from 'react'
import {
  clearGithubToken,
  importSpec,
  listGithubRepositories,
  removeProjectSpec,
  saveGithubToken,
  syncGithubRepositories,
} from '../../actions.ts'
import { maxSpecBytes } from '../../domain.ts'
import { FormError, timeText, useAction } from '../common.tsx'
import { Checkbox } from '../ui/checkbox.tsx'
import type { DiscoveredGithubRepo, ProjectLoaderData } from './types.ts'
import { formatGithubPatBadge, formatIsoDay, safeHost } from './types.ts'

interface Props {
  data: ProjectLoaderData
}

export function ProjectSourcesTab({ data }: Props) {
  const { project, specs, githubPatStatus } = data
  const [githubTokenInput, setGithubTokenInput] = useState('')
  const [editingGithubToken, setEditingGithubToken] = useState(false)
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

  const githubAction = useAction()
  const specAction = useAction()

  function loadGithubRepos() {
    setGithubNotice('')
    void githubAction.submit(() => listGithubRepositories(), result => {
      setDiscoveredRepos(result.repos)
      setSelectedRepos(result.defaultSelected)
      setReposTruncated(result.truncated)
      setReposLoaded(true)
      setRepoPickerOpen(true)
      setEditingGithubToken(false)
    })
  }

  function openRepoPicker() {
    setEditingGithubToken(false)
    setGithubNotice('')
    if (repoPickerOpen && reposLoaded) {
      setRepoPickerOpen(false)
      return
    }
    setRepoPickerOpen(true)
    if (!reposLoaded) loadGithubRepos()
  }

  function toggleSelectedRepo(fullName: string, checked: boolean) {
    setSelectedRepos(prev =>
      checked
        ? (prev.includes(fullName) ? prev : [...prev, fullName])
        : prev.filter(name => name !== fullName),
    )
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

  const needle = repoSearch.trim().toLowerCase()
  const filteredRepos = needle
    ? discoveredRepos.filter(r =>
      r.fullName.toLowerCase().includes(needle) ||
      (r.description?.toLowerCase().includes(needle) ?? false) ||
      r.defaultBranch.toLowerCase().includes(needle),
    )
    : discoveredRepos
  const maxSyncBatch = 20
  const showBroadNote = discoveredRepos.length > 10 || githubPatStatus.tokenKind === 'classic'

  return <section aria-label="Source repositories">
    <div className="pw-sec-head">
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <h2>Source repositories (read-only)</h2>
          <span className={githubPatStatus.configured ? 'pw-tag ok' : 'pw-tag solid'}>
            {formatGithubPatBadge(githubPatStatus)}
          </span>
        </div>
        <p>Optional read-only GitHub sync for grey-box code, schema, and CVE context. Tokens stay in your local 0600 vault and are never echoed back.</p>
      </div>
      {githubPatStatus.configured && <div className="pw-sec-actions">
        <button
          type="button"
          className="pw-btn primary"
          disabled={githubAction.pending}
          onClick={openRepoPicker}
          aria-expanded={repoPickerOpen}
        >
          {repoPickerOpen ? 'Hide repos' : 'Discover & sync repos'}
        </button>
        <button
          type="button"
          className="pw-btn ghost"
          disabled={githubAction.pending}
          onClick={() => { setEditingGithubToken(v => !v); setGithubNotice('') }}
          aria-expanded={editingGithubToken}
        >
          {editingGithubToken ? 'Cancel' : 'Update token'}
        </button>
      </div>}
    </div>

    {githubNotice && <p role="status" className="notice">{githubNotice}</p>}
    {specNotice && <p role="status" className="notice">{specNotice}</p>}

    {(!githubPatStatus.configured || editingGithubToken) && <form
      className="pw-sheet"
      style={{ marginBottom: 16 }}
      onSubmit={event => {
        event.preventDefault()
        const token = githubTokenInput.trim()
        if (!token) return
        setGithubNotice('')
        void githubAction.submit(() => saveGithubToken({ data: { token } }), result => {
          setGithubTokenInput('')
          setEditingGithubToken(false)
          setDiscoveredRepos(result.repos)
          setSelectedRepos(result.defaultSelected)
          setReposTruncated(result.truncated)
          setReposLoaded(true)
          setRepoPickerOpen(true)
          setRepoSearch('')
          setGithubNotice(`Token saved to local 0600 vault. Found ${result.repos.length} accessible ${result.repos.length === 1 ? 'repository' : 'repositories'}.`)
        })
      }}
    >
      <div className="pw-sheet-h">
        <span>{githubPatStatus.configured ? 'Update GitHub personal access token' : 'Connect GitHub with a Fine-Grained PAT'}</span>
        <a
          className="pw-btn"
          href="https://github.com/settings/personal-access-tokens/new"
          target="_blank"
          rel="noopener noreferrer"
        >
          Create Fine-Grained PAT on GitHub ↗
        </a>
      </div>
      <div className="pw-sheet-b">
        <ol className="pw-steps">
          <li>Under <strong>Repository access</strong>, choose <strong>Only select repositories</strong> and pick the repos you want Guardian to inspect.</li>
          <li>Under <strong>Repository permissions</strong>, set <strong>Contents: Read-only</strong>.</li>
          <li>Click <strong>Generate token</strong> and paste it below — Guardian stores it in your local <code>0600</code> vault and auto-discovers accessible repos.</li>
        </ol>
        <label className="pw-fld">GitHub Personal Access Token
          <input
            className="pw-in mono"
            name="githubPat"
            type="password"
            required
            minLength={10}
            maxLength={512}
            autoComplete="off"
            value={githubTokenInput}
            onChange={e => setGithubTokenInput(e.target.value)}
            placeholder="github_pat_…"
          />
        </label>
        <FormError error={githubAction.error} />
      </div>
      <div className="pw-sheet-f">
        <span className="hint">Read-only access; token never leaves the local vault.</span>
        {githubPatStatus.configured && (
          <button type="button" className="pw-btn ghost" onClick={() => { setEditingGithubToken(false); setGithubTokenInput('') }}>
            Cancel
          </button>
        )}
        <button type="submit" className="pw-btn primary" disabled={githubAction.pending || githubTokenInput.trim().length < 10}>
          {githubAction.pending ? 'Saving & discovering…' : 'Save token & discover repos'}
        </button>
      </div>
    </form>}

    {githubPatStatus.configured && !editingGithubToken && repoPickerOpen && <div className="pw-sheet" style={{ marginBottom: 16 }}>
      <div className="pw-sheet-h">
        <span>Select repositories to sync</span>
        <div className="pw-sec-actions">
          <button type="button" className="pw-btn ghost" disabled={githubAction.pending} onClick={loadGithubRepos}>
            {githubAction.pending && !reposLoaded ? 'Loading…' : 'Refresh'}
          </button>
          {githubPatStatus.source === 'vault' && (
            <button
              type="button"
              className="pw-btn ghost danger"
              disabled={githubAction.pending}
              onClick={() => {
                setGithubNotice('')
                void githubAction.submit(() => clearGithubToken(), result => {
                  setDiscoveredRepos([])
                  setSelectedRepos([])
                  setReposLoaded(false)
                  setRepoPickerOpen(false)
                  setRepoSearch('')
                  setGithubNotice(result.status.configured
                    ? 'Removed saved vault token (fallback fixture PAT is still present).'
                    : 'Removed saved GitHub token from local vault.')
                })
              }}
            >
              Remove saved token
            </button>
          )}
        </div>
      </div>
      <div className="pw-sheet-b">
        <p className="muted" style={{ margin: 0, fontSize: 12 }}>
          Read-only shallow clone + automatic OpenAPI, GraphQL, route, and lockfile extraction.
          {reposTruncated && ' Showing the 200 most recently updated repositories.'}
        </p>

        {githubPatStatus.source === 'fixture' && (
          <p className="muted" style={{ margin: 0, fontSize: 11.5 }}>
            Using fallback fixture PAT from <code>~/.config/guardian-fixtures/github.pat</code>. Click <strong>Update token</strong> to store a vault token instead.
          </p>
        )}

        {showBroadNote && discoveredRepos.length > 0 && <div className="pw-broad-note">
          <span>
            {githubPatStatus.tokenKind === 'classic'
              ? `Classic PAT detected (${discoveredRepos.length} accessible repos).`
              : `Found ${discoveredRepos.length} accessible repos.`}{' '}
            {discoveredRepos.length > 10
              ? 'Nothing was pre-selected so you do not accidentally clone everything.'
              : 'Consider scoping a Fine-Grained PAT to only the target repositories.'}
          </span>
          <button
            type="button"
            className="pw-btn"
            disabled={githubAction.pending || filteredRepos.length === 0}
            onClick={() => setSelectedRepos(filteredRepos.slice(0, maxSyncBatch).map(r => r.fullName))}
          >
            Select all{filteredRepos.length > maxSyncBatch ? ` (first ${maxSyncBatch})` : ` (${filteredRepos.length})`}
          </button>
        </div>}

        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
          <input
            className="pw-in"
            style={{ flex: 1, minWidth: 200 }}
            type="search"
            value={repoSearch}
            onChange={e => setRepoSearch(e.target.value)}
            placeholder="Filter repositories by name, branch, or description…"
            aria-label="Filter GitHub repositories"
          />
          <button
            type="button"
            className="pw-btn ghost"
            disabled={githubAction.pending || filteredRepos.length === 0}
            onClick={() => setSelectedRepos(filteredRepos.slice(0, maxSyncBatch).map(r => r.fullName))}
          >
            Select all
          </button>
          <button
            type="button"
            className="pw-btn ghost"
            disabled={githubAction.pending || selectedRepos.length === 0}
            onClick={() => setSelectedRepos([])}
          >
            Clear
          </button>
        </div>

        {githubAction.pending && !reposLoaded ? (
          <p className="muted" style={{ margin: 0 }}>Discovering accessible repositories…</p>
        ) : filteredRepos.length > 0 ? (
          <ul className="pw-repo-list" aria-label="Accessible GitHub repositories">
            {filteredRepos.map(repo => {
              const checked = selectedRepos.includes(repo.fullName)
              const updatedLabel = formatIsoDay(repo.updatedAt)
              return <li key={repo.fullName} className="pw-repo-row">
                <label className="pw-repo-label">
                  <Checkbox
                    checked={checked}
                    aria-label={`Select repository ${repo.fullName}`}
                    onCheckedChange={next => toggleSelectedRepo(repo.fullName, Boolean(next))}
                  />
                  <span className="pw-repo-meta">
                    <span className="pw-row-title">
                      <strong className="mono">{repo.fullName}</strong>
                      <span className="pw-tag solid">{repo.private ? 'private' : 'public'}</span>
                      <span className="pw-tag accent">{repo.defaultBranch}</span>
                      {updatedLabel && <span className="muted" style={{ fontSize: 11.5 }}>Updated {updatedLabel}</span>}
                    </span>
                    {repo.description && <small className="muted" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{repo.description}</small>}
                  </span>
                </label>
              </li>
            })}
          </ul>
        ) : (
          <p className="muted" style={{ margin: 0 }}>
            {discoveredRepos.length === 0
              ? 'No repositories were returned for this token. Verify the token grants Repository permissions → Contents: Read-only on at least one repository.'
              : `No repositories match "${repoSearch.trim()}".`}
          </p>
        )}

        {selectedRepos.length > maxSyncBatch && (
          <p role="alert" className="err" style={{ margin: 0 }}>Select at most {maxSyncBatch} repositories per sync batch.</p>
        )}
        <FormError error={githubAction.error} />
      </div>
      <div className="pw-sheet-f">
        <span className="hint num">{selectedRepos.length} of {discoveredRepos.length} selected</span>
        <button type="button" className="pw-btn ghost" onClick={() => setRepoPickerOpen(false)}>Close</button>
        <button
          type="button"
          className="pw-btn primary"
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
        </button>
      </div>
    </div>}

    <div className="pw-sec-head" style={{ marginTop: 18 }}>
      <h2>Synced snapshots &amp; specs <span className="muted num">({specs.length})</span></h2>
    </div>
    {specs.length > 0 ? (
      <div className="pw-table-wrap">
        {specs.map(spec => <div key={spec.id} className="pw-row">
          <div className="pw-row-main">
            <div className="pw-row-title">
              <strong className="mono">{spec.name}</strong>
              <span className="pw-tag solid">{spec.kind}</span>
              {spec.origin && <span className="pw-tag accent">{safeHost(spec.origin)}</span>}
            </div>
            <div className="pw-row-sub num">
              {Math.max(1, Math.round(spec.bytes / 1024))} KiB · Imported {timeText(spec.createdAt)}
            </div>
          </div>
          <div className="pw-row-right">
            <button
              type="button"
              className="pw-btn ghost danger"
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
            </button>
          </div>
        </div>)}
      </div>
    ) : (
      <div className="pw-empty">
        <p>No repositories or specs synced yet.</p>
      </div>
    )}

    <details className="pw-disclosure">
      <summary>Advanced: upload schemas or lockfiles manually</summary>
      <div className="pw-disclosure-body">
        <p className="muted" style={{ margin: 0, fontSize: 12 }}>
          Guardian automatically discovers runtime schemas and extracts OpenAPI, GraphQL, and lockfile specs from synced repositories. Use manual upload only when you need to supply an extra schema or lockfile directly.
        </p>
        <form
          className="pw-sheet"
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
          <div className="pw-sheet-h"><span>Upload OpenAPI, GraphQL, or lockfile</span></div>
          <div className="pw-sheet-b">
            <div className="pw-grid-2">
              <label className="pw-fld">Name
                <input className="pw-in" name="name" required maxLength={160} value={specName} onChange={e => setSpecName(e.target.value)}
                  placeholder="openapi.yaml or package-lock.json" />
              </label>
              <label className="pw-fld">Kind
                <select className="pw-select" name="kind" defaultValue="openapi">
                  <option value="openapi">OpenAPI / Swagger</option>
                  <option value="graphql">GraphQL schema</option>
                  <option value="routes">Route map / Server handlers</option>
                  <option value="notes">Lockfile / Dependencies / Notes</option>
                </select>
              </label>
            </div>
            <div className="pw-grid-2">
              <label className="pw-fld">Target origin (optional)
                <input className="pw-in" name="origin" placeholder={project.seeds[0] ?? 'https://api.example.com'} />
              </label>
              <label className="pw-fld">Load from file (optional, up to 2 MiB)
                <input className="pw-in" style={{ paddingTop: 3 }} type="file" accept=".json,.yaml,.yml,.graphql,.gql,.txt,.md,.lock" onChange={e => {
                  void onSpecFileSelected(e.target.files?.[0])
                }} />
              </label>
            </div>
            <label className="pw-fld">Content
              <textarea className="pw-textarea mono" name="content" rows={6} required value={specContent} onChange={e => setSpecContent(e.target.value)}
                placeholder="Paste OpenAPI, GraphQL SDL, lockfile JSON, or route notes…" />
            </label>
            <FormError error={specAction.error} />
          </div>
          <div className="pw-sheet-f">
            <button type="submit" className="pw-btn primary" disabled={specAction.pending || !specContent.trim()}>Import spec</button>
          </div>
        </form>
      </div>
    </details>
  </section>
}
