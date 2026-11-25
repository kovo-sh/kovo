import { useMemo, useState } from 'react'
import { formatHumanTime } from '../common.tsx'
import { Icon } from '../run/icons.tsx'
import { Checkbox } from '../ui/checkbox.tsx'
import type { DiscoveredGithubRepo } from './types.ts'

export interface GroupedRepoItem {
  repo: DiscoveredGithubRepo
  owner: string
  name: string
}

export interface RepoOwnerGroup {
  owner: string
  items: GroupedRepoItem[]
  totalCount: number
}

export interface GroupedRepoPickerProps {
  repos: DiscoveredGithubRepo[]
  selectedRepos: string[]
  onChangeSelectedRepos: (repos: string[]) => void
  search: string
  onSearchChange: (value: string) => void
  maxSelectable?: number
  disabled?: boolean
  variant?: 'compact' | 'detailed'
  searchPlaceholder?: string
  emptyMessage?: string
}

export function splitRepoFullName(fullName: string): { owner: string; name: string } {
  const slashIdx = fullName.indexOf('/')
  if (slashIdx <= 0 || slashIdx === fullName.length - 1) {
    return { owner: 'Other', name: fullName }
  }
  return {
    owner: fullName.slice(0, slashIdx),
    name: fullName.slice(slashIdx + 1),
  }
}

export function groupReposByOwner(
  repos: DiscoveredGithubRepo[],
  search: string,
): { allGroups: RepoOwnerGroup[]; visibleGroups: RepoOwnerGroup[]; filteredRepos: DiscoveredGithubRepo[] } {
  const totalByOwner = new Map<string, RepoOwnerGroup>()
  for (const repo of repos) {
    const { owner, name } = splitRepoFullName(repo.fullName)
    let group = totalByOwner.get(owner)
    if (!group) {
      group = { owner, items: [], totalCount: 0 }
      totalByOwner.set(owner, group)
    }
    group.items.push({ repo, owner, name })
    group.totalCount += 1
  }
  const allGroups = Array.from(totalByOwner.values())

  const needle = search.trim().toLowerCase()
  if (!needle) {
    return { allGroups, visibleGroups: allGroups, filteredRepos: repos }
  }

  const visibleGroups: RepoOwnerGroup[] = []
  const filteredRepos: DiscoveredGithubRepo[] = []
  for (const group of allGroups) {
    const matched = group.items.filter(({ repo }) =>
      repo.fullName.toLowerCase().includes(needle) ||
      repo.defaultBranch.toLowerCase().includes(needle) ||
      (repo.description?.toLowerCase().includes(needle) ?? false),
    )
    if (matched.length > 0) {
      visibleGroups.push({
        owner: group.owner,
        items: matched,
        totalCount: group.totalCount,
      })
      for (const item of matched) filteredRepos.push(item.repo)
    }
  }

  return { allGroups, visibleGroups, filteredRepos }
}

export function GroupedRepoPicker({
  repos,
  selectedRepos,
  onChangeSelectedRepos,
  search,
  onSearchChange,
  maxSelectable = 20,
  disabled = false,
  variant = 'compact',
  searchPlaceholder,
  emptyMessage = 'No repositories found.',
}: GroupedRepoPickerProps) {
  const [manualExpanded, setManualExpanded] = useState<Record<string, boolean>>({})
  const [searchToggled, setSearchToggled] = useState<{ needle: string; collapsed: Record<string, boolean> }>({
    needle: '',
    collapsed: {},
  })

  const needle = search.trim().toLowerCase()
  const isSearching = needle.length > 0

  const selectedSet = useMemo(() => new Set(selectedRepos), [selectedRepos])
  const { allGroups, visibleGroups, filteredRepos } = useMemo(
    () => groupReposByOwner(repos, search),
    [repos, search],
  )

  const showToolbar = variant === 'detailed' ? repos.length > 0 : repos.length > 1
  const remainingCap = Math.max(0, maxSelectable - selectedRepos.length)

  function isGroupExpanded(group: RepoOwnerGroup, index: number, selectedInGroup: number): boolean {
    if (isSearching) {
      if (searchToggled.needle === needle && searchToggled.collapsed[group.owner]) {
        return false
      }
      return true
    }
    if (group.owner in manualExpanded) {
      return Boolean(manualExpanded[group.owner])
    }
    if (allGroups.length <= 2) return true
    return index === 0 || selectedInGroup > 0
  }

  function toggleGroup(owner: string, currentlyExpanded: boolean) {
    if (isSearching) {
      setSearchToggled(prev => ({
        needle,
        collapsed: {
          ...(prev.needle === needle ? prev.collapsed : {}),
          [owner]: currentlyExpanded,
        },
      }))
      return
    }
    setManualExpanded(prev => ({ ...prev, [owner]: !currentlyExpanded }))
  }

  function toggleRepo(fullName: string, checked: boolean) {
    if (checked) {
      if (selectedSet.has(fullName)) return
      if (selectedRepos.length >= maxSelectable) return
      onChangeSelectedRepos([...selectedRepos, fullName])
    } else {
      onChangeSelectedRepos(selectedRepos.filter(n => n !== fullName))
    }
  }

  function selectOrg(group: RepoOwnerGroup) {
    if (disabled) return
    const next = [...selectedRepos]
    for (const { repo } of group.items) {
      if (next.length >= maxSelectable) break
      if (!selectedSet.has(repo.fullName)) {
        next.push(repo.fullName)
      }
    }
    if (next.length !== selectedRepos.length) {
      onChangeSelectedRepos(next)
    }
  }

  function clearOrg(group: RepoOwnerGroup) {
    if (disabled) return
    const groupFullNames = new Set(group.items.map(i => i.repo.fullName))
    const next = selectedRepos.filter(name => !groupFullNames.has(name))
    if (next.length !== selectedRepos.length) {
      onChangeSelectedRepos(next)
    }
  }

  function handleSelectAllVisible() {
    if (disabled || filteredRepos.length === 0) return
    onChangeSelectedRepos(filteredRepos.slice(0, maxSelectable).map(r => r.fullName))
  }

  if (repos.length === 0) {
    return <div className={`grp-empty grp-${variant}`}>{emptyMessage}</div>
  }

  return (
    <div className={`grp-root grp-${variant}`}>
      {showToolbar && (
        <div className="grp-toolbar">
          <div className="grp-search-wrap">
            <Icon name="search" size={13} className="grp-search-ico" />
            <input
              type="search"
              className="grp-search-input"
              value={search}
              onChange={e => onSearchChange(e.target.value)}
              placeholder={
                searchPlaceholder ??
                (variant === 'detailed'
                  ? 'Filter repositories by name, branch, or description…'
                  : 'Filter repositories…')
              }
              aria-label="Filter GitHub repositories"
              disabled={disabled}
            />
          </div>
          <div className="grp-toolbar-actions">
            <button
              type="button"
              className="grp-tb-btn"
              disabled={disabled || filteredRepos.length === 0}
              onClick={handleSelectAllVisible}
            >
              {variant === 'detailed'
                ? `Select all${filteredRepos.length > maxSelectable ? ` (first ${maxSelectable})` : filteredRepos.length > 0 ? ` (${filteredRepos.length})` : ''}`
                : 'Select all'}
            </button>
            {selectedRepos.length > 0 && (
              <button
                type="button"
                className="grp-tb-btn"
                disabled={disabled}
                onClick={() => onChangeSelectedRepos([])}
              >
                Clear
              </button>
            )}
          </div>
        </div>
      )}

      <div className="grp-list" role="group" aria-label="Accessible GitHub repositories">
        {visibleGroups.length === 0 ? (
          <div className="grp-empty">No repositories match “{search.trim()}”.</div>
        ) : (
          visibleGroups.map((group, groupIdx) => {
            const selectedInGroup = group.items.reduce(
              (count, item) => count + (selectedSet.has(item.repo.fullName) ? 1 : 0),
              0,
            )
            const expanded = isGroupExpanded(group, groupIdx, selectedInGroup)
            const hasUnselected = selectedInGroup < group.items.length
            const canSelectOrg = hasUnselected && remainingCap > 0

            return (
              <div
                key={group.owner}
                className={`grp-org${expanded ? ' expanded' : ''}${selectedInGroup > 0 ? ' has-sel' : ''}`}
              >
                <div className="grp-org-head">
                  <button
                    type="button"
                    className="grp-org-toggle"
                    aria-expanded={expanded}
                    onClick={() => toggleGroup(group.owner, expanded)}
                  >
                    <span className={`grp-org-chev${expanded ? ' open' : ''}`} aria-hidden="true">
                      <Icon name="chevR" size={12} />
                    </span>
                    <span className="grp-org-name" title={group.owner}>
                      <span className="grp-org-at">@</span>
                      {group.owner}
                    </span>
                    <span className="grp-org-count num">
                      {isSearching ? `${group.items.length} / ${group.totalCount}` : group.items.length}
                    </span>
                    {selectedInGroup > 0 && (
                      <span className="grp-org-sel num">{selectedInGroup} selected</span>
                    )}
                  </button>

                  <div className="grp-org-actions">
                    {canSelectOrg && (
                      <button
                        type="button"
                        className="grp-org-act grp-org-act-select"
                        disabled={disabled}
                        onClick={() => selectOrg(group)}
                      >
                        Select org
                      </button>
                    )}
                    {selectedInGroup > 0 && (
                      <button
                        type="button"
                        className="grp-org-act grp-org-act-clear"
                        disabled={disabled}
                        onClick={() => clearOrg(group)}
                      >
                        Clear
                      </button>
                    )}
                  </div>
                </div>

                {expanded && (
                  <div className="grp-org-repos">
                    {group.items.map(({ repo, name }) => {
                      const checked = selectedSet.has(repo.fullName)
                      const atCap = !checked && selectedRepos.length >= maxSelectable
                      const updated = variant === 'detailed' ? formatHumanTime(repo.updatedAt) : null

                      return (
                        <label
                          key={repo.fullName}
                          className={`grp-repo-row${checked ? ' on' : ''}${atCap || disabled ? ' disabled' : ''}`}
                        >
                          <Checkbox
                            checked={checked}
                            disabled={disabled || atCap}
                            aria-label={`Select repository ${repo.fullName}`}
                            onCheckedChange={next => toggleRepo(repo.fullName, Boolean(next))}
                          />
                          {variant === 'detailed' ? (
                            <span className="grp-repo-detail">
                              <span className="grp-repo-line">
                                <span className="mono grp-repo-name" title={repo.fullName}>{name}</span>
                                <span className={`grp-vis ${repo.private ? 'private' : 'public'}`}>
                                  {repo.private ? 'private' : 'public'}
                                </span>
                                <span className="grp-branch mono">{repo.defaultBranch}</span>
                                {updated?.label && (
                                  <span className="grp-updated num" title={updated.full}>
                                    Updated {updated.label}
                                  </span>
                                )}
                              </span>
                              {repo.description && (
                                <span className="grp-repo-desc">{repo.description}</span>
                              )}
                            </span>
                          ) : (
                            <>
                              <span className="mono grp-repo-name" title={repo.fullName}>{name}</span>
                              <span className={`grp-vis ${repo.private ? 'private' : 'public'}`}>
                                {repo.private ? 'private' : 'public'}
                              </span>
                            </>
                          )}
                        </label>
                      )
                    })}
                  </div>
                )}
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}
