import { useEffect, useMemo, useState } from 'react'
import { listGithubRepositories, saveGithubToken } from '../../actions.ts'
import { Checkbox } from '../ui/checkbox.tsx'
import { Input } from '../ui/input.tsx'
import type { DiscoveredGithubRepo } from './types.ts'

export interface GithubPatStatusSummary {
  configured: boolean
  source: 'vault' | 'fixture' | null
  tokenKind: 'fine_grained' | 'classic' | 'unknown' | null
}

interface Props {
  initialPatStatus: GithubPatStatusSummary
  selectedRepos: string[]
  onChangeSelectedRepos: (repos: string[]) => void
  disabled?: boolean
}

const MAX_SYNC_REPOS = 20

function patKindTag(status: GithubPatStatusSummary): string {
  if (status.tokenKind === 'fine_grained') return 'Fine-grained PAT'
  if (status.tokenKind === 'classic') return 'Classic PAT'
  return 'GitHub PAT'
}

export function CreateProjectGithubBlock({
  initialPatStatus,
  selectedRepos,
  onChangeSelectedRepos,
  disabled = false,
}: Props) {
  const [patStatus, setPatStatus] = useState<GithubPatStatusSummary>(initialPatStatus)
  const [expandedConnect, setExpandedConnect] = useState(false)
  const [tokenInput, setTokenInput] = useState('')
  const [savingToken, setSavingToken] = useState(false)
  const [loadingRepos, setLoadingRepos] = useState(false)
  const [repos, setRepos] = useState<DiscoveredGithubRepo[]>([])
  const [reposLoaded, setReposLoaded] = useState(false)
  const [search, setSearch] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    if (!patStatus.configured || reposLoaded) return
    let cancelled = false
    setLoadingRepos(true)
    setError('')
    void listGithubRepositories()
      .then(result => {
        if (cancelled) return
        setPatStatus(result.status)
        setRepos(result.repos)
        setReposLoaded(true)
        if (result.repos.length === 1) {
          onChangeSelectedRepos([result.repos[0]!.fullName])
        }
      })
      .catch(err => {
        if (cancelled) return
        setError(err instanceof Error ? err.message : 'Could not load GitHub repositories.')
      })
      .finally(() => {
        if (!cancelled) setLoadingRepos(false)
      })
    return () => { cancelled = true }
  }, [patStatus.configured, reposLoaded, onChangeSelectedRepos])

  const filteredRepos = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return repos
    return repos.filter(r =>
      r.fullName.toLowerCase().includes(q) ||
      r.defaultBranch.toLowerCase().includes(q) ||
      (r.description?.toLowerCase().includes(q) ?? false),
    )
  }, [repos, search])

  async function handleRefresh() {
    if (loadingRepos || disabled) return
    setLoadingRepos(true)
    setError('')
    try {
      const result = await listGithubRepositories()
      setPatStatus(result.status)
      setRepos(result.repos)
      setReposLoaded(true)
      if (result.repos.length === 1 && selectedRepos.length === 0) {
        onChangeSelectedRepos([result.repos[0]!.fullName])
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not refresh repositories.')
    } finally {
      setLoadingRepos(false)
    }
  }

  async function handleSaveToken() {
    const trimmed = tokenInput.trim()
    if (trimmed.length < 10 || savingToken || disabled) return
    setSavingToken(true)
    setError('')
    try {
      const result = await saveGithubToken({ data: { token: trimmed } })
      setTokenInput('')
      setPatStatus(result.status)
      setRepos(result.repos)
      setReposLoaded(true)
      setExpandedConnect(false)
      setSearch('')
      onChangeSelectedRepos(result.repos.length === 1 ? [result.repos[0]!.fullName] : [])
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not save GitHub token.')
    } finally {
      setSavingToken(false)
    }
  }

  function toggleRepo(fullName: string, checked: boolean) {
    if (checked) {
      if (selectedRepos.includes(fullName)) return
      if (selectedRepos.length >= MAX_SYNC_REPOS) return
      onChangeSelectedRepos([...selectedRepos, fullName])
    } else {
      onChangeSelectedRepos(selectedRepos.filter(n => n !== fullName))
    }
  }

  if (!patStatus.configured) {
    return <div
      style={{
        borderTop: '1px solid var(--line)',
        paddingTop: 11,
        display: 'grid',
        gap: 8,
      }}
    >
      <button
        type="button"
        onClick={() => { setExpandedConnect(v => !v); setError('') }}
        aria-expanded={expandedConnect}
        disabled={disabled}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          width: '100%',
          padding: '2px 0',
          border: 0,
          background: 'transparent',
          color: 'var(--fg-2)',
          fontSize: 12.5,
          fontWeight: 500,
          textAlign: 'left',
          cursor: 'pointer',
        }}
      >
        <span style={{ color: 'var(--fg-3)', display: 'inline-block', transform: expandedConnect ? 'rotate(90deg)' : 'none', transition: 'transform 140ms' }}>▸</span>
        <span>Connect GitHub for grey-box source &amp; CVE context</span>
        <span className="tag solid" style={{ marginLeft: 'auto' }}>Optional</span>
      </button>

      {expandedConnect && <div
        style={{
          border: '1px solid var(--line)',
          borderRadius: 8,
          background: 'var(--sunk)',
          padding: '10px 12px',
          display: 'grid',
          gap: 8,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 12, color: 'var(--fg-2)' }}>
            Choose <b>Only select repositories</b> → <b>Contents: Read-only</b> → Generate &amp; paste.
          </span>
          <a
            className="btn"
            href="https://github.com/settings/personal-access-tokens/new"
            target="_blank"
            rel="noopener noreferrer"
          >
            Create Fine-Grained PAT ↗
          </a>
        </div>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <Input
            type="password"
            value={tokenInput}
            onChange={e => setTokenInput(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter') {
                e.preventDefault()
                void handleSaveToken()
              }
            }}
            placeholder="github_pat_…"
            autoComplete="off"
            disabled={savingToken || disabled}
            aria-label="GitHub Personal Access Token"
            style={{ flex: 1 }}
          />
          <button
            type="button"
            className="btn primary"
            disabled={savingToken || disabled || tokenInput.trim().length < 10}
            onClick={() => void handleSaveToken()}
          >
            {savingToken ? 'Connecting…' : 'Save & discover'}
          </button>
        </div>
        {error && <p role="alert" style={{ margin: 0, color: 'var(--bad)', fontSize: 12 }}>{error}</p>}
        <span className="sh-hint">Stored locally in your 0600 vault and never echoed back.</span>
      </div>}
    </div>
  }

  return <div
    style={{
      borderTop: '1px solid var(--line)',
      paddingTop: 11,
      display: 'grid',
      gap: 8,
    }}
  >
    <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
      <span style={{ fontSize: 12.5, fontWeight: 500, color: 'var(--fg)' }}>
        Source repositories (GitHub, read-only)
      </span>
      <span className="tag ok">{patKindTag(patStatus)}</span>
      <span className="tag solid">Optional</span>
      <button
        type="button"
        className="btn ghost"
        style={{ marginLeft: 'auto' }}
        disabled={loadingRepos || disabled}
        onClick={() => void handleRefresh()}
      >
        {loadingRepos ? 'Loading…' : 'Refresh'}
      </button>
    </div>

    {loadingRepos && !reposLoaded ? (
      <span className="sh-hint">Discovering accessible GitHub repositories…</span>
    ) : error ? (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
        <span role="alert" style={{ color: 'var(--bad)', fontSize: 12 }}>{error}</span>
        <button type="button" className="btn ghost" onClick={() => void handleRefresh()}>Retry</button>
      </div>
    ) : repos.length === 0 ? (
      <span className="sh-hint">No repositories returned for this token. You can still create the project and sync repos later.</span>
    ) : <>
      {repos.length > 1 && <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
        <Input
          type="search"
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Filter repositories…"
          aria-label="Filter GitHub repositories"
          disabled={disabled}
          style={{ flex: 1, minWidth: 160 }}
        />
        <button
          type="button"
          className="btn ghost"
          disabled={disabled || filteredRepos.length === 0}
          onClick={() => onChangeSelectedRepos(filteredRepos.slice(0, MAX_SYNC_REPOS).map(r => r.fullName))}
        >
          Select all
        </button>
        <button
          type="button"
          className="btn ghost"
          disabled={disabled || selectedRepos.length === 0}
          onClick={() => onChangeSelectedRepos([])}
        >
          Clear
        </button>
      </div>}

      <div
        role="group"
        aria-label="Accessible GitHub repositories"
        style={{
          maxHeight: 168,
          overflowY: 'auto',
          border: '1px solid var(--line)',
          borderRadius: 8,
          background: 'var(--sunk)',
        }}
      >
        {filteredRepos.length === 0 ? (
          <div style={{ padding: '10px 12px', color: 'var(--fg-3)', fontSize: 12 }}>
            No repositories match “{search.trim()}”.
          </div>
        ) : filteredRepos.map((repo, idx) => {
          const checked = selectedRepos.includes(repo.fullName)
          const atCap = !checked && selectedRepos.length >= MAX_SYNC_REPOS
          return <label
            key={repo.fullName}
            className="checkbox"
            style={{
              padding: '7px 10px',
              margin: 0,
              borderTop: idx === 0 ? 'none' : '1px solid var(--line)',
              cursor: atCap || disabled ? 'default' : 'pointer',
              opacity: atCap ? 0.55 : 1,
              background: checked ? 'var(--accent-soft)' : 'transparent',
            }}
          >
            <Checkbox
              checked={checked}
              disabled={disabled || atCap}
              aria-label={`Select repository ${repo.fullName}`}
              onCheckedChange={next => toggleRepo(repo.fullName, Boolean(next))}
            />
            <span className="mono" style={{ fontSize: 12, color: 'var(--fg)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
              {repo.fullName}
            </span>
            <span className="tag solid">{repo.private ? 'private' : 'public'}</span>
            <span className="tag accent">{repo.defaultBranch}</span>
          </label>
        })}
      </div>

      <span className="sh-hint num">
        {selectedRepos.length > 0
          ? `${selectedRepos.length} ${selectedRepos.length === 1 ? 'repository' : 'repositories'} selected — will sync read-only right after project creation.`
          : `Pick the ${repos.length === 1 ? 'repo' : '1–2 repos'} belonging to this project (optional, max ${MAX_SYNC_REPOS}).`}
      </span>
    </>}
  </div>
}
