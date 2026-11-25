import { cva } from 'class-variance-authority'
import { useMemo, useState } from 'react'
import { cn } from '../../lib/cn.ts'
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

const repoRowVariants = cva(
  'm-0 flex min-h-[34px] flex-row justify-start gap-2.5 border-t border-line text-[12.5px] font-normal leading-[18px] transition-colors duration-[var(--d1)] first:border-t-0',
  {
    variants: {
      variant: {
        compact: 'items-center py-1.5 pl-[26px] pr-3',
        detailed: 'items-start py-[9px] pl-[30px] pr-4',
      },
      selected: {
        true: 'bg-sel',
        false: '',
      },
      disabled: {
        true: 'cursor-default opacity-52',
        false: 'cursor-pointer',
      },
    },
    compoundVariants: [
      { selected: false, disabled: false, className: 'hover:bg-hover' },
      { selected: true, disabled: false, className: 'hover:bg-accent-soft' },
    ],
    defaultVariants: {
      variant: 'compact',
      selected: false,
      disabled: false,
    },
  },
)

const visibilityBadgeVariants = cva(
  'inline-flex h-[18px] flex-none items-center whitespace-nowrap text-[10.5px]',
  {
    variants: {
      visibility: {
        private: 'rounded-full border border-line-2 bg-sunk px-1.5 font-medium text-fg-muted',
        public: 'bg-transparent px-0.5 font-normal text-fg-subtle',
      },
    },
  },
)

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
  const isDetailed = variant === 'detailed'

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
    return (
      <div className={cn('text-[12px] text-fg-subtle', isDetailed ? 'p-4' : 'px-3 py-3.5')}>
        {emptyMessage}
      </div>
    )
  }

  return (
    <div className="flex flex-col bg-panel">
      {showToolbar && (
        <div
          className={cn(
            'flex items-center gap-1.5 border-b border-line bg-panel transition-colors duration-[var(--d1)] focus-within:border-b-accent-line',
            isDetailed ? 'min-h-10 py-[5px] pl-4 pr-3' : 'min-h-9 py-1 pl-3 pr-2',
          )}
        >
          <div className="flex min-w-[120px] flex-1 items-center gap-[7px]">
            <Icon name="search" size={13} className="flex-none text-fg-subtle" />
            <input
              type="search"
              className="h-[26px] w-full min-w-0 flex-1 rounded-none border-0 bg-transparent p-0 text-[12.5px] leading-5 text-fg shadow-none outline-none placeholder:text-fg-subtle focus:shadow-none focus:outline-none"
              value={search}
              onChange={e => onSearchChange(e.target.value)}
              placeholder={
                searchPlaceholder ??
                (isDetailed
                  ? 'Filter repositories by name, branch, or description…'
                  : 'Filter repositories…')
              }
              aria-label="Filter GitHub repositories"
              disabled={disabled}
            />
          </div>
          <div className="flex flex-none items-center gap-0.5">
            <button
              type="button"
              className="h-6 cursor-pointer rounded-[5px] border-0 bg-transparent px-[7px] text-[11.5px] font-medium text-fg-muted shadow-none transition-colors duration-[var(--d1)] hover:bg-hover hover:text-fg disabled:cursor-default disabled:opacity-45 disabled:hover:bg-transparent"
              disabled={disabled || filteredRepos.length === 0}
              onClick={handleSelectAllVisible}
            >
              {isDetailed
                ? `Select all${filteredRepos.length > maxSelectable ? ` (first ${maxSelectable})` : filteredRepos.length > 0 ? ` (${filteredRepos.length})` : ''}`
                : 'Select all'}
            </button>
            {selectedRepos.length > 0 && (
              <button
                type="button"
                className="h-6 cursor-pointer rounded-[5px] border-0 bg-transparent px-[7px] text-[11.5px] font-medium text-fg-muted shadow-none transition-colors duration-[var(--d1)] hover:bg-hover hover:text-fg disabled:cursor-default disabled:opacity-45 disabled:hover:bg-transparent"
                disabled={disabled}
                onClick={() => onChangeSelectedRepos([])}
              >
                Clear
              </button>
            )}
          </div>
        </div>
      )}

      <div
        className={cn('overflow-y-auto bg-panel', isDetailed ? 'max-h-96' : 'max-h-[216px]')}
        role="group"
        aria-label="Accessible GitHub repositories"
      >
        {visibleGroups.length === 0 ? (
          <div className={cn('text-[12px] text-fg-subtle', isDetailed ? 'p-4' : 'px-3 py-3.5')}>
            No repositories match “{search.trim()}”.
          </div>
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
              <div key={group.owner} className="border-t border-line first:border-t-0">
                <div
                  className={cn(
                    'group/org flex items-center justify-between gap-1.5 bg-sunk transition-colors duration-[var(--d1)] hover:bg-[color-mix(in_srgb,var(--hover)_70%,var(--sunk))]',
                    isDetailed ? 'min-h-[34px] pl-2.5 pr-3' : 'min-h-8 pl-1.5 pr-2',
                  )}
                >
                  <button
                    type="button"
                    className={cn(
                      'flex min-w-0 flex-1 cursor-pointer items-center gap-1.5 rounded-none border-0 bg-transparent px-1.5 text-left text-fg shadow-none hover:bg-transparent',
                      isDetailed ? 'h-[34px]' : 'h-8',
                    )}
                    aria-expanded={expanded}
                    onClick={() => toggleGroup(group.owner, expanded)}
                  >
                    <span
                      className={cn(
                        'inline-flex size-3.5 flex-none items-center justify-center text-fg-subtle transition-[transform,color] duration-[var(--d1)] ease-guardian',
                        expanded && 'rotate-90 text-fg-muted',
                      )}
                      aria-hidden="true"
                    >
                      <Icon name="chevR" size={12} />
                    </span>
                    <span className="min-w-0 truncate text-[12px] font-semibold text-fg" title={group.owner}>
                      <span className="mr-px font-normal text-fg-subtle">@</span>
                      {group.owner}
                    </span>
                    <span className="inline-flex h-[17px] min-w-[18px] flex-none items-center justify-center rounded-full border border-line-2 bg-panel px-[5px] text-[11px] font-medium tabular-nums text-fg-subtle">
                      {isSearching ? `${group.items.length} / ${group.totalCount}` : group.items.length}
                    </span>
                    {selectedInGroup > 0 && (
                      <span className="inline-flex h-[17px] flex-none items-center whitespace-nowrap rounded-full border border-accent/28 bg-accent-soft px-1.5 text-[10.5px] font-medium tabular-nums text-accent">
                        {selectedInGroup} selected
                      </span>
                    )}
                  </button>

                  <div className="flex flex-none items-center gap-0.5">
                    {canSelectOrg && (
                      <button
                        type="button"
                        className="h-[22px] cursor-pointer rounded-sm border-0 bg-transparent px-1.5 text-[11px] font-medium text-fg-subtle opacity-0 shadow-none transition-[opacity,background-color,color] duration-[var(--d1)] hover:bg-hover hover:text-fg group-hover/org:opacity-100 group-focus-within/org:opacity-100 disabled:cursor-default disabled:opacity-45 [@media(hover:none)]:opacity-100"
                        disabled={disabled}
                        onClick={() => selectOrg(group)}
                      >
                        Select org
                      </button>
                    )}
                    {selectedInGroup > 0 && (
                      <button
                        type="button"
                        className="h-[22px] cursor-pointer rounded-sm border-0 bg-transparent px-1.5 text-[11px] font-medium text-fg-muted shadow-none transition-[opacity,background-color,color] duration-[var(--d1)] hover:bg-hover hover:text-fg disabled:cursor-default disabled:opacity-45"
                        disabled={disabled}
                        onClick={() => clearOrg(group)}
                      >
                        Clear
                      </button>
                    )}
                  </div>
                </div>

                {expanded && (
                  <div className="border-t border-line bg-panel">
                    {group.items.map(({ repo, name }) => {
                      const checked = selectedSet.has(repo.fullName)
                      const atCap = !checked && selectedRepos.length >= maxSelectable
                      const isRowDisabled = atCap || disabled
                      const updated = isDetailed ? formatHumanTime(repo.updatedAt) : null

                      return (
                        <label
                          key={repo.fullName}
                          className={repoRowVariants({
                            variant,
                            selected: checked,
                            disabled: isRowDisabled,
                          })}
                        >
                          <Checkbox
                            checked={checked}
                            disabled={isRowDisabled}
                            className={isDetailed ? 'mt-0.5 flex-none' : 'flex-none'}
                            aria-label={`Select repository ${repo.fullName}`}
                            onCheckedChange={next => toggleRepo(repo.fullName, Boolean(next))}
                          />
                          {isDetailed ? (
                            <span className="flex min-w-0 flex-1 flex-col gap-0.5">
                              <span className="flex min-w-0 flex-wrap items-center gap-1.5">
                                <span
                                  className="flex-[0_1_auto] truncate font-mono text-[12px] font-semibold text-fg"
                                  title={repo.fullName}
                                >
                                  {name}
                                </span>
                                <span
                                  className={visibilityBadgeVariants({
                                    visibility: repo.private ? 'private' : 'public',
                                  })}
                                >
                                  {repo.private ? 'private' : 'public'}
                                </span>
                                <span className="inline-flex h-[18px] flex-none items-center whitespace-nowrap rounded-full border border-line bg-sunk px-1.5 font-mono text-[10.5px] text-fg-muted">
                                  {repo.defaultBranch}
                                </span>
                                {updated?.label && (
                                  <span
                                    className="whitespace-nowrap text-[11.5px] tabular-nums text-fg-subtle"
                                    title={updated.full}
                                  >
                                    Updated {updated.label}
                                  </span>
                                )}
                              </span>
                              {repo.description && (
                                <span className="truncate text-[11.5px] leading-4 text-fg-subtle">
                                  {repo.description}
                                </span>
                              )}
                            </span>
                          ) : (
                            <>
                              <span
                                className="min-w-0 flex-1 truncate font-mono text-[12px] font-medium text-fg"
                                title={repo.fullName}
                              >
                                {name}
                              </span>
                              <span
                                className={visibilityBadgeVariants({
                                  visibility: repo.private ? 'private' : 'public',
                                })}
                              >
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
