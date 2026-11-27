import { useState } from 'react'
import {
  addProjectAsset,
  bulkRemoveProjectAssetsAction,
  bulkUpdateProjectAssetScopeAction,
  clearProjectAssetAccessPolicyAction,
  updateProjectAssetAction,
  updateProjectAssetScope,
} from '../../actions.ts'
import { cn } from '../../lib/cn.ts'
import { AccessPolicyImport } from '../access-policy-import.tsx'
import { formatHumanTime, FormError, useAction } from '../common.tsx'
import { DnsInventoryImport } from '../dns-inventory-import.tsx'
import { Icon } from '../run/icons.tsx'
import { Badge } from '../ui/badge.tsx'
import { Button } from '../ui/button.tsx'
import { Checkbox } from '../ui/checkbox.tsx'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/dialog.tsx'
import { EmptyState } from '../ui/empty-state.tsx'
import { Input } from '../ui/input.tsx'
import type { ProjectLoaderData } from './types.ts'
import { safeHost } from './types.ts'

interface Props {
  data: ProjectLoaderData
  onDeleteAsset: (assetId: string) => Promise<unknown>
}

function safeHostname(raw: string | undefined): string {
  if (!raw) return ''
  try {
    return new URL(raw).hostname
  } catch {
    return raw.replace(/^https?:\/\//i, '').split(/[/:?#]/)[0] ?? ''
  }
}

type InventoryFilter = 'all' | 'needs_approval' | 'approved' | 'first_party' | 'third_party'

export function ProjectInventoryTab({ data, onDeleteAsset }: Props) {
  const { project, assets } = data
  const [panel, setPanel] = useState<'dns' | 'access'>()
  const [addHostOpen, setAddHostOpen] = useState(false)
  const [assetToEdit, setAssetToEdit] = useState<ProjectLoaderData['assets'][number] | null>(null)
  const [editOrigin, setEditOrigin] = useState('')
  const [editSource, setEditSource] = useState('')
  const [editThirdParty, setEditThirdParty] = useState(false)
  const [assetToDelete, setAssetToDelete] = useState<ProjectLoaderData['assets'][number] | null>(null)
  const [bulkDeleteOpen, setBulkDeleteOpen] = useState(false)
  const [candidateOrigin, setCandidateOrigin] = useState('')
  const [candidateSource, setCandidateSource] = useState('')
  const [candidateThirdParty, setCandidateThirdParty] = useState(false)
  const [candidateIncludeSubdomains, setCandidateIncludeSubdomains] = useState(false)
  const [notice, setNotice] = useState('')
  const [hostSearch, setHostSearch] = useState('')
  const [filter, setFilter] = useState<InventoryFilter>('all')
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set())
  const inventoryAction = useAction()

  function togglePanel(next: 'dns' | 'access') {
    setPanel(cur => cur === next ? undefined : next)
    setNotice('')
  }

  function resetAddHostForm() {
    setCandidateOrigin('')
    setCandidateSource('')
    setCandidateThirdParty(false)
    setCandidateIncludeSubdomains(false)
  }

  function openEditAsset(asset: ProjectLoaderData['assets'][number]) {
    setEditOrigin(asset.origin)
    setEditSource(asset.source)
    setEditThirdParty(Boolean(asset.thirdParty))
    setAssetToEdit(asset)
    setNotice('')
  }

  const approvedOriginSet = new Set(project.defaultScope)
  const assetIdSet = new Set(assets.map(a => a.id))
  const effectiveSelectedIds = new Set([...selectedIds].filter(assetId => assetIdSet.has(assetId)))
  const selectedCount = effectiveSelectedIds.size
  const selectedAssets = assets.filter(asset => effectiveSelectedIds.has(asset.id))

  const counts = {
    all: assets.length,
    needs_approval: assets.filter(asset => !approvedOriginSet.has(asset.origin)).length,
    approved: assets.filter(asset => approvedOriginSet.has(asset.origin)).length,
    first_party: assets.filter(asset => !asset.thirdParty).length,
    third_party: assets.filter(asset => asset.thirdParty).length,
  }

  const filterPills: readonly { id: InventoryFilter; label: string; count: number }[] = [
    { id: 'all', label: 'All', count: counts.all },
    { id: 'needs_approval', label: 'Needs approval', count: counts.needs_approval },
    { id: 'approved', label: 'Approved', count: counts.approved },
    { id: 'first_party', label: 'First-party', count: counts.first_party },
    { id: 'third_party', label: 'Third-party', count: counts.third_party },
  ]

  const searchTerm = hostSearch.trim().toLowerCase()
  const filteredAssets = assets.filter(asset => {
    if (filter === 'needs_approval') return !approvedOriginSet.has(asset.origin)
    if (filter === 'approved') return approvedOriginSet.has(asset.origin)
    if (filter === 'first_party') return !asset.thirdParty
    if (filter === 'third_party') return asset.thirdParty
    return true
  })
  const visibleAssets = searchTerm
    ? filteredAssets.filter(asset => {
      const haystack = `${safeHost(asset.origin)} ${asset.source ?? ''} ${asset.dnsSource?.zone ?? ''}`.toLowerCase()
      return haystack.includes(searchTerm)
    })
    : filteredAssets
  const approvedAssets = visibleAssets.filter(asset => approvedOriginSet.has(asset.origin))
  const needsApprovalAssets = visibleAssets.filter(asset => !approvedOriginSet.has(asset.origin))
  const unapprovedFirstPartyAssets = needsApprovalAssets.filter(asset => !asset.thirdParty)

  const selectedVisibleCount = visibleAssets.filter(asset => effectiveSelectedIds.has(asset.id)).length
  const allVisibleSelected = visibleAssets.length > 0 && selectedVisibleCount === visibleAssets.length
  const someVisibleSelected = selectedVisibleCount > 0 && !allVisibleSelected

  function toggleSelectAsset(assetId: string, checked: boolean) {
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (checked) next.add(assetId)
      else next.delete(assetId)
      return next
    })
  }

  function toggleSelectAllVisible(checked: boolean) {
    setSelectedIds(prev => {
      const next = new Set(prev)
      for (const asset of visibleAssets) {
        if (checked) next.add(asset.id)
        else next.delete(asset.id)
      }
      return next
    })
  }

  function handleApproveAllFirstParty() {
    const ids = unapprovedFirstPartyAssets.map(asset => asset.id)
    if (ids.length === 0) return
    setNotice('')
    void inventoryAction.submit(
      () => bulkUpdateProjectAssetScopeAction({
        data: {
          requestId: crypto.randomUUID(),
          projectId: project.id,
          assetIds: ids,
          approveInDefaultScope: true,
        },
      }),
      res => {
        const updatedSet = new Set(res.updatedIds)
        setSelectedIds(prev => new Set([...prev].filter(id => !updatedSet.has(id))))
        setNotice(`Approved ${res.updatedCount} first-party ${res.updatedCount === 1 ? 'host' : 'hosts'} in project scope.`)
      },
    )
  }

  function handleBulkApprove(approveInDefaultScope: boolean) {
    const ids = [...effectiveSelectedIds]
    if (ids.length === 0) return
    setNotice('')
    void inventoryAction.submit(
      () => bulkUpdateProjectAssetScopeAction({
        data: {
          requestId: crypto.randomUUID(),
          projectId: project.id,
          assetIds: ids,
          approveInDefaultScope,
        },
      }),
      res => {
        setSelectedIds(new Set())
        setNotice(
          `${approveInDefaultScope ? 'Approved' : 'Unapproved'} ${res.updatedCount} ${res.updatedCount === 1 ? 'host' : 'hosts'} ${approveInDefaultScope ? 'in' : 'from'} project scope.`,
        )
      },
    )
  }

  function handleBulkRemove() {
    const ids = [...effectiveSelectedIds]
    if (ids.length === 0) return
    setNotice('')
    void inventoryAction.submit(
      () => bulkRemoveProjectAssetsAction({
        data: {
          requestId: crypto.randomUUID(),
          projectId: project.id,
          assetIds: ids,
        },
      }),
      res => {
        setSelectedIds(new Set())
        setBulkDeleteOpen(false)
        setNotice(`Removed ${res.removedCount} ${res.removedCount === 1 ? 'host' : 'hosts'} from project inventory.`)
      },
    )
  }

  function renderAsset(asset: ProjectLoaderData['assets'][number]) {
    const externalCname = asset.dnsSource?.externalAliases?.[0]
    const isDefaultApproved = approvedOriginSet.has(asset.origin)
    const isSelected = effectiveSelectedIds.has(asset.id)
    const hostLabel = safeHost(asset.origin)
    const policyRecorded = asset.accessPolicy?.recordedAt
      ? formatHumanTime(asset.accessPolicy.recordedAt)
      : null
    return (
      <div
        key={asset.id}
        data-testid={`inventory-row-${asset.id}`}
        className={cn(
          'flex min-h-[44px] items-center justify-between gap-3 border-b border-line px-1.5 py-2 transition-colors hover:bg-hover',
          isSelected && 'bg-accent-soft/35 hover:bg-accent-soft/50',
        )}
      >
        <div className="flex min-w-0 flex-1 items-center gap-2.5">
          <Checkbox
            data-testid={`select-asset-${asset.id}`}
            checked={isSelected}
            disabled={inventoryAction.pending}
            aria-label={`Select host ${hostLabel}`}
            onCheckedChange={checked => toggleSelectAsset(asset.id, Boolean(checked))}
          />
          <div className="flex min-w-0 flex-1 flex-col gap-0.5">
            <div className="flex min-w-0 flex-wrap items-center gap-1.5 font-medium text-fg">
              <strong className="truncate font-mono text-[12px] font-semibold">{hostLabel}</strong>
              {asset.includeSubdomains && !asset.thirdParty && (
                <Badge variant="accent">*.{asset.dnsSource?.zone ?? hostLabel}</Badge>
              )}
              {asset.thirdParty && externalCname ? (
                <Badge variant="warn">Third-party CNAME ({externalCname})</Badge>
              ) : asset.thirdParty ? (
                <Badge variant="warn">Third party</Badge>
              ) : null}
              {asset.accessPolicy && <Badge variant="neutral" className="bg-sunk">Access policy</Badge>}
            </div>
            <div className="truncate text-[12px] text-fg-subtle">
              {[
                asset.source,
                asset.dnsSource?.zone,
              ].filter(Boolean).join(' · ')}
              {policyRecorded?.label && (
                <>
                  {' · '}
                  <span className="tabular-nums" title={policyRecorded.full}>
                    Policy recorded {policyRecorded.label}
                  </span>
                </>
              )}
            </div>
          </div>
        </div>
        <div className="flex flex-none items-center gap-2.5">
          {project.environment === 'public' && !asset.thirdParty && (
            <label
              className="inline-flex cursor-pointer select-none items-center gap-[7px] text-[12px] font-normal text-fg-muted"
              title="Automatically include live first-party subdomains discovered passively (excludes third-party hosted services)"
            >
              <Checkbox
                checked={Boolean(asset.includeSubdomains)}
                disabled={inventoryAction.pending}
                aria-label={`Include subdomains for ${hostLabel}`}
                onCheckedChange={checked => {
                  const next = Boolean(checked)
                  void inventoryAction.submit(() => updateProjectAssetScope({ data: {
                    requestId: crypto.randomUUID(),
                    projectId: project.id,
                    assetId: asset.id,
                    includeSubdomains: next,
                  } }), () => setNotice(`${next ? 'Enabled' : 'Disabled'} subdomain discovery for ${hostLabel}.`))
                }}
              />
              <code className="font-mono text-[12px]">*.domain</code>
            </label>
          )}
          <label
            className="inline-flex cursor-pointer select-none items-center gap-[7px] text-[12px] font-normal text-fg-muted"
            title={asset.thirdParty
              ? 'Third-party CNAMEs stay unchecked by default; check only if you have authorization to test this custom domain'
              : 'Include or exclude this host from the project’s approved scan scope'}
          >
            <Checkbox
              checked={isDefaultApproved}
              disabled={inventoryAction.pending}
              aria-label={`${isDefaultApproved ? 'Remove' : 'Approve'} ${asset.thirdParty ? 'third-party host ' : 'host '}${hostLabel} ${isDefaultApproved ? 'from' : 'in'} project scope`}
              onCheckedChange={checked => {
                const next = Boolean(checked)
                void inventoryAction.submit(() => updateProjectAssetScope({ data: {
                  requestId: crypto.randomUUID(),
                  projectId: project.id,
                  assetId: asset.id,
                  approveInDefaultScope: next,
                } }), () => setNotice(`${next ? 'Approved' : 'Removed'} ${hostLabel} ${next ? 'in' : 'from'} project scope.`))
              }}
            />
            <span>{isDefaultApproved ? 'Approved in scope' : 'Approve in scope'}</span>
          </label>
          {asset.accessPolicy && (
            <Button
              type="button"
              variant="ghost"
              disabled={inventoryAction.pending}
              aria-label={`Clear access policy for ${hostLabel}`}
              onClick={() => {
                setNotice('')
                void inventoryAction.submit(() => clearProjectAssetAccessPolicyAction({
                  data: {
                    requestId: crypto.randomUUID(),
                    projectId: project.id,
                    assetId: asset.id,
                  },
                }), () => setNotice(`Cleared access policy for ${hostLabel}.`))
              }}
            >
              Clear policy
            </Button>
          )}
          <Button
            type="button"
            variant="ghost"
            disabled={inventoryAction.pending}
            aria-label={`Edit host ${hostLabel}`}
            onClick={() => openEditAsset(asset)}
          >
            Edit
          </Button>
          <Button
            type="button"
            variant="ghost"
            className="data-[slot=button]:text-danger data-[slot=button]:hover:bg-danger-soft data-[slot=button]:hover:text-danger"
            disabled={inventoryAction.pending}
            aria-label={`Delete host ${hostLabel}`}
            onClick={() => setAssetToDelete(asset)}
          >
            Delete
          </Button>
        </div>
      </div>
    )
  }

  return (
    <section aria-label="Project inventory">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="m-0 text-[13px] font-semibold text-fg">
            Hosts &amp; Assets <span className="font-normal tabular-nums text-fg-subtle">({assets.length})</span>
          </h2>
          <p className="mt-0.5 text-[12px] text-fg-subtle">
            Starting hosts, DNS exports, and passively discovered subdomains. Third-party hosted services stay unchecked unless explicitly approved.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {assets.length > 0 && (
            <Button
              type="button"
              variant="default"
              onClick={() => {
                setAddHostOpen(true)
                setNotice('')
              }}
            >
              Add host
            </Button>
          )}
          <Button
            type="button"
            variant="outline"
            onClick={() => togglePanel('dns')}
            aria-expanded={panel === 'dns'}
          >
            Import DNS export
          </Button>
          <Button
            type="button"
            variant="outline"
            onClick={() => togglePanel('access')}
            aria-expanded={panel === 'access'}
          >
            Import access records
          </Button>
        </div>
      </div>

      {notice && (
        <p
          role="status"
          className="mb-3.5 flex items-center gap-2 rounded-[7px] border border-line bg-sunk px-3 py-[7px] text-[12.5px] text-fg-muted"
        >
          {notice}
        </p>
      )}
      {!addHostOpen && !assetToDelete && !assetToEdit && !bulkDeleteOpen && <FormError error={inventoryAction.error} />}

      {panel === 'dns' && (
        <div className="mb-3.5">
          <DnsInventoryImport
            projectId={project.id}
            defaultZone={safeHostname(project.seeds[0])}
            cancel={() => setPanel(undefined)}
            imported={({ added, existing }) => {
              setPanel(undefined)
              setNotice(`Added ${added} ${added === 1 ? 'host' : 'hosts'}. Skipped ${existing} existing.`)
            }}
          />
        </div>
      )}

      {panel === 'access' && (
        <div className="mb-3.5">
          <AccessPolicyImport
            projectId={project.id}
            assets={assets}
            cancel={() => setPanel(undefined)}
            imported={({ origin, cases }) => {
              setPanel(undefined)
              setNotice(`Imported ${cases} access ${cases === 1 ? 'case' : 'cases'} for ${safeHostname(origin) || origin}.`)
            }}
          />
        </div>
      )}

      {assets.length > 0 && (
        <div
          data-testid="inventory-filter-bar"
          className="mb-3 flex flex-wrap items-center justify-between gap-2 rounded-[7px] border border-line bg-sunk/50 px-2.5 py-2"
        >
          <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filter hosts">
            <label
              className="mr-1 inline-flex cursor-pointer select-none items-center gap-1.5 border-r border-line pr-2.5 text-[12px] font-medium text-fg-muted"
              title="Select or deselect all currently visible hosts for batch actions"
            >
              <Checkbox
                data-testid="inventory-select-all"
                checked={allVisibleSelected}
                indeterminate={someVisibleSelected}
                disabled={visibleAssets.length === 0 || inventoryAction.pending}
                aria-label="Select all visible hosts"
                onCheckedChange={checked => toggleSelectAllVisible(Boolean(checked))}
              />
              <span>Select all visible</span>
            </label>
            {filterPills.map(pill => {
              const active = filter === pill.id
              return (
                <button
                  key={pill.id}
                  type="button"
                  data-testid={`inventory-filter-${pill.id}`}
                  aria-pressed={active}
                  onClick={() => setFilter(pill.id)}
                  className={cn(
                    'inline-flex h-auto cursor-pointer items-center gap-1.5 whitespace-normal rounded-full border px-2.5 py-1 text-[12px] font-medium leading-tight shadow-none transition-colors',
                    active
                      ? 'border-accent-line bg-accent-soft text-accent hover:bg-accent-soft'
                      : 'border-line-2 bg-panel text-fg-muted hover:bg-hover hover:text-fg',
                  )}
                >
                  <span>{pill.label}</span>
                  <span className={cn('text-[11px] font-normal tabular-nums', active ? 'text-accent' : 'text-fg-subtle')}>
                    {pill.count}
                  </span>
                </button>
              )
            })}
          </div>
          <Input
            className="h-[26px]! w-[190px] max-w-full"
            type="search"
            value={hostSearch}
            onChange={e => setHostSearch(e.target.value)}
            placeholder="Search hosts"
            aria-label="Search hosts"
          />
        </div>
      )}

      {assets.length === 0 ? (
        <div className="mt-3.5 rounded-card border border-line bg-sunk">
          <EmptyState
            title="No hosts in scope yet"
            description="Add a starting host or import a DNS export so Kovo knows what belongs to this project."
            action={
              <Button
                type="button"
                variant="default"
                onClick={() => {
                  setAddHostOpen(true)
                  setNotice('')
                }}
              >
                Add host
              </Button>
            }
          />
        </div>
      ) : visibleAssets.length === 0 ? (
        <div className="mt-3.5 flex flex-wrap items-center justify-between gap-2 border-t border-line px-3 py-2.5 text-[12px] leading-[18px] text-fg-subtle">
          <span>
            {hostSearch.trim()
              ? `No hosts match “${hostSearch.trim()}”.`
              : 'No hosts match the selected filter.'}
          </span>
          {(filter !== 'all' || hostSearch.trim().length > 0) && (
            <Button
              type="button"
              variant="ghost"
              onClick={() => {
                setFilter('all')
                setHostSearch('')
              }}
            >
              Show all hosts
            </Button>
          )}
        </div>
      ) : (
        <>
          {approvedAssets.length > 0 && (
            <div className="border-t border-line">
              <div className="flex flex-wrap items-center justify-between gap-2.5 px-1.5 pb-[7px] pt-2.5">
                <h3 className="m-0 text-[12px] font-semibold text-fg">
                  Approved in scope <span className="font-normal tabular-nums text-fg-subtle">({approvedAssets.length})</span>
                </h3>
                <span className="text-[11.5px] text-fg-subtle">Included in scan scope</span>
              </div>
              {approvedAssets.map(renderAsset)}
            </div>
          )}
          {needsApprovalAssets.length > 0 && (
            <div className={cn('border-t border-line', approvedAssets.length > 0 && 'mt-[18px]')}>
              <div className="flex flex-wrap items-center justify-between gap-2.5 px-1.5 pb-[7px] pt-2.5">
                <div className="flex flex-wrap items-baseline gap-2">
                  <h3 className="m-0 text-[12px] font-semibold text-fg">
                    Needs approval <span className="font-normal tabular-nums text-fg-subtle">({needsApprovalAssets.length})</span>
                  </h3>
                  <span className="text-[11.5px] text-fg-subtle">Approve hosts before they enter scan scope</span>
                </div>
                {unapprovedFirstPartyAssets.length > 0 && (
                  <Button
                    type="button"
                    variant="outline"
                    data-testid="approve-all-first-party"
                    disabled={inventoryAction.pending}
                    onClick={handleApproveAllFirstParty}
                  >
                    Approve all first-party ({unapprovedFirstPartyAssets.length})
                  </Button>
                )}
              </div>
              {needsApprovalAssets.map(renderAsset)}
            </div>
          )}
        </>
      )}

      {selectedCount > 0 && (
        <div
          data-testid="inventory-batch-bar"
          className="sticky bottom-0 z-20 mt-4 flex flex-wrap items-center justify-between gap-2.5 border-t border-line bg-surface/95 px-3.5 py-2.5 shadow-card backdrop-blur-sm"
        >
          <div className="flex items-center gap-2">
            <span className="text-[12.5px] font-medium tabular-nums text-fg" data-testid="inventory-batch-count">
              {selectedCount} selected
            </span>
            <Button
              type="button"
              variant="ghost"
              disabled={inventoryAction.pending}
              onClick={() => setSelectedIds(new Set())}
            >
              Clear
            </Button>
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            <Button
              type="button"
              variant="default"
              data-testid="batch-approve-selected"
              disabled={inventoryAction.pending}
              onClick={() => handleBulkApprove(true)}
            >
              {inventoryAction.pending ? 'Updating…' : `Approve selected (${selectedCount})`}
            </Button>
            <Button
              type="button"
              variant="outline"
              data-testid="batch-unapprove-selected"
              disabled={inventoryAction.pending}
              onClick={() => handleBulkApprove(false)}
            >
              Unapprove selected
            </Button>
            <Button
              type="button"
              variant="ghost"
              data-testid="batch-remove-selected"
              className="data-[slot=button]:text-danger data-[slot=button]:hover:bg-danger-soft data-[slot=button]:hover:text-danger"
              disabled={inventoryAction.pending}
              onClick={() => setBulkDeleteOpen(true)}
            >
              Remove selected
            </Button>
          </div>
        </div>
      )}

      <Dialog
        open={addHostOpen}
        closeOnEscape={!inventoryAction.pending}
        onOpenChange={nextOpen => {
          if (!nextOpen && !inventoryAction.pending) {
            setAddHostOpen(false)
          }
        }}
      >
        <DialogContent className="flex max-h-[calc(100vh-56px)] max-w-[560px] flex-col overflow-hidden p-0">
          <form
            className="flex min-h-0 flex-1 flex-col"
            onSubmit={event => {
              event.preventDefault()
              void inventoryAction.submit(() => addProjectAsset({ data: {
                requestId: crypto.randomUUID(),
                projectId: project.id,
                origin: candidateOrigin,
                source: candidateSource.trim() || 'Manual entry',
                thirdParty: candidateThirdParty,
                includeSubdomains: project.environment === 'public' && !candidateThirdParty && candidateIncludeSubdomains,
              } }), () => {
                resetAddHostForm()
                setAddHostOpen(false)
                setNotice('Added host to project inventory.')
              })
            }}
          >
            <DialogHeader className="flex-row items-center justify-between gap-2.5 border-b border-line bg-raise px-4 py-2.5">
              <DialogTitle className="text-[13px] font-semibold text-fg">Add host</DialogTitle>
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="size-[26px]"
                disabled={inventoryAction.pending}
                onClick={() => setAddHostOpen(false)}
                aria-label="Close"
              >
                <Icon name="close" size={14} />
              </Button>
            </DialogHeader>
            <DialogBody className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto p-4">
              <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-2">
                <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                  Host
                  <Input
                    className="w-full"
                    name="origin"
                    value={candidateOrigin}
                    onChange={e => setCandidateOrigin(e.target.value)}
                    placeholder="docs.example.com"
                    required
                  />
                </label>
                <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                  Source (optional)
                  <Input
                    className="w-full"
                    name="source"
                    value={candidateSource}
                    onChange={e => setCandidateSource(e.target.value)}
                    placeholder="Manual entry"
                    maxLength={160}
                  />
                </label>
              </div>
              <label className="inline-flex cursor-pointer select-none items-center gap-[7px] text-[12.5px] font-normal text-fg-muted">
                <Checkbox
                  name="thirdParty"
                  checked={candidateThirdParty}
                  aria-label="Third-party service"
                  onCheckedChange={checked => {
                    const next = Boolean(checked)
                    setCandidateThirdParty(next)
                    if (next) setCandidateIncludeSubdomains(false)
                  }}
                />
                <span>Third-party service</span>
              </label>
              {project.environment === 'public' && !candidateThirdParty && (
                <div className="grid gap-1">
                  <label className="inline-flex cursor-pointer select-none items-center gap-[7px] text-[12.5px] font-normal text-fg-muted">
                    <Checkbox
                      name="includeSubdomains"
                      checked={candidateIncludeSubdomains}
                      aria-label="Include subdomains (*.domain)"
                      onCheckedChange={checked => setCandidateIncludeSubdomains(Boolean(checked))}
                    />
                    <span>
                      Include subdomains (<code className="font-mono text-[12px]">*.domain</code>)
                    </span>
                  </label>
                  <span
                    className="text-[11.5px] text-fg-subtle"
                    title="Uses passive Certificate Transparency logs and live DNS during initial discovery"
                  >
                    Automatically discovers first-party subdomains before scanning. Third-party hosted services stay unchecked until you explicitly approve them.
                  </span>
                </div>
              )}
              <FormError error={inventoryAction.error} />
            </DialogBody>
            <DialogFooter>
              <Button
                type="button"
                variant="ghost"
                disabled={inventoryAction.pending}
                onClick={() => setAddHostOpen(false)}
              >
                Cancel
              </Button>
              <Button type="submit" variant="default" disabled={inventoryAction.pending}>
                {inventoryAction.pending ? 'Adding…' : 'Add to project'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog
        open={Boolean(assetToEdit)}
        closeOnEscape={!inventoryAction.pending}
        onOpenChange={nextOpen => {
          if (!nextOpen && !inventoryAction.pending) setAssetToEdit(null)
        }}
      >
        <DialogContent className="flex max-h-[calc(100vh-56px)] max-w-[480px] flex-col overflow-hidden p-0">
          {assetToEdit && (
            <form
              className="flex min-h-0 flex-1 flex-col"
              onSubmit={event => {
                event.preventDefault()
                const target = assetToEdit
                void inventoryAction.submit(() => updateProjectAssetAction({
                  data: {
                    requestId: crypto.randomUUID(),
                    projectId: project.id,
                    assetId: target.id,
                    origin: editOrigin.trim(),
                    source: editSource.trim() || 'Manual entry',
                    thirdParty: editThirdParty,
                  },
                }), updated => {
                  setAssetToEdit(null)
                  setNotice(`Updated host ${safeHost(updated.origin) || updated.origin}.`)
                })
              }}
            >
              <DialogHeader className="flex-row items-center justify-between gap-2.5 border-b border-line bg-raise px-4 py-2.5">
                <DialogTitle className="text-[13px] font-semibold text-fg">Edit host</DialogTitle>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="size-[26px]"
                  disabled={inventoryAction.pending}
                  onClick={() => setAssetToEdit(null)}
                  aria-label="Close"
                >
                  <Icon name="close" size={14} />
                </Button>
              </DialogHeader>
              <DialogBody className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto p-4">
                <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                  Host
                  <Input
                    className="w-full font-mono text-[12px]"
                    name="editAssetOrigin"
                    value={editOrigin}
                    onChange={e => setEditOrigin(e.target.value)}
                    required
                    disabled={inventoryAction.pending}
                  />
                </label>
                <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                  Source
                  <Input
                    className="w-full"
                    name="editAssetSource"
                    value={editSource}
                    onChange={e => setEditSource(e.target.value)}
                    maxLength={160}
                    required
                    disabled={inventoryAction.pending}
                  />
                </label>
                <label className="inline-flex cursor-pointer select-none items-center gap-[7px] text-[12.5px] font-normal text-fg-muted">
                  <Checkbox
                    name="editAssetThirdParty"
                    checked={editThirdParty}
                    disabled={inventoryAction.pending}
                    aria-label="Third-party service"
                    onCheckedChange={checked => setEditThirdParty(Boolean(checked))}
                  />
                  <span>Third-party service</span>
                </label>
                <FormError error={inventoryAction.error} />
              </DialogBody>
              <DialogFooter>
                <Button
                  type="button"
                  variant="ghost"
                  disabled={inventoryAction.pending}
                  onClick={() => setAssetToEdit(null)}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  variant="default"
                  disabled={inventoryAction.pending || !editOrigin.trim() || !editSource.trim()}
                >
                  {inventoryAction.pending ? 'Saving…' : 'Save changes'}
                </Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>

      <Dialog
        open={Boolean(assetToDelete)}
        closeOnEscape={!inventoryAction.pending}
        onOpenChange={nextOpen => {
          if (!nextOpen && !inventoryAction.pending) setAssetToDelete(null)
        }}
      >
        <DialogContent
          role="alertdialog"
          className="flex max-h-[calc(100vh-56px)] max-w-[440px] flex-col overflow-hidden p-0"
        >
          {assetToDelete && (
            <>
              <DialogHeader className="flex-row items-center justify-between gap-2.5 border-b border-line bg-raise px-4 py-2.5">
                <DialogTitle className="inline-flex items-center gap-2 text-[13px] font-semibold text-fg">
                  <Icon name="trash" size={15} className="text-danger" />
                  <span>Delete host</span>
                </DialogTitle>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="size-[26px]"
                  disabled={inventoryAction.pending}
                  onClick={() => setAssetToDelete(null)}
                  aria-label="Close"
                >
                  <Icon name="close" size={14} />
                </Button>
              </DialogHeader>
              <DialogBody className="flex min-h-0 flex-1 flex-col gap-3.5 overflow-y-auto p-4">
                <DialogDescription className="text-[12.5px] leading-5 text-fg-muted">
                  Remove <strong className="font-mono font-semibold text-fg">{safeHost(assetToDelete.origin)}</strong> from this project&apos;s inventory and default scan scope? Existing runs keep their historical records.
                </DialogDescription>
                <FormError error={inventoryAction.error} />
              </DialogBody>
              <DialogFooter>
                <Button
                  type="button"
                  variant="ghost"
                  disabled={inventoryAction.pending}
                  onClick={() => setAssetToDelete(null)}
                >
                  Cancel
                </Button>
                <Button
                  type="button"
                  variant="default"
                  className="data-[slot=button]:bg-danger data-[slot=button]:text-white data-[slot=button]:hover:bg-danger hover:brightness-[1.08]"
                  disabled={inventoryAction.pending}
                  onClick={() => {
                    const target = assetToDelete
                    void inventoryAction.submit(() => onDeleteAsset(target.id), () => {
                      setAssetToDelete(null)
                      setNotice(`Removed ${safeHost(target.origin)} from project inventory.`)
                    })
                  }}
                >
                  <Icon name="trash" size={13} />
                  {inventoryAction.pending ? 'Deleting…' : 'Delete host'}
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>
      <Dialog
        open={bulkDeleteOpen && selectedCount > 0}
        closeOnEscape={!inventoryAction.pending}
        onOpenChange={nextOpen => {
          if (!nextOpen && !inventoryAction.pending) setBulkDeleteOpen(false)
        }}
      >
        <DialogContent
          role="alertdialog"
          className="flex max-h-[calc(100vh-56px)] max-w-[460px] flex-col overflow-hidden p-0"
        >
          <DialogHeader className="flex-row items-center justify-between gap-2.5 border-b border-line bg-raise px-4 py-2.5">
            <DialogTitle className="inline-flex items-center gap-2 text-[13px] font-semibold text-fg">
              <Icon name="trash" size={15} className="text-danger" />
              <span>Remove {selectedCount} {selectedCount === 1 ? 'host' : 'hosts'}</span>
            </DialogTitle>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="size-[26px]"
              disabled={inventoryAction.pending}
              onClick={() => setBulkDeleteOpen(false)}
              aria-label="Close"
            >
              <Icon name="close" size={14} />
            </Button>
          </DialogHeader>
          <DialogBody className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto p-4">
            <DialogDescription className="text-[12.5px] leading-5 text-fg-muted">
              Remove <strong className="font-semibold text-fg">{selectedCount} {selectedCount === 1 ? 'host' : 'hosts'}</strong> from this project&apos;s inventory and default scan scope? Existing runs keep their historical records.
            </DialogDescription>
            <ul className="m-0 list-disc space-y-0.5 pl-4 font-mono text-[12px] text-fg-muted">
              {selectedAssets.slice(0, 5).map(asset => (
                <li key={asset.id} className="truncate">{safeHost(asset.origin)}</li>
              ))}
              {selectedAssets.length > 5 && (
                <li className="list-none font-sans text-fg-subtle">+{selectedAssets.length - 5} more</li>
              )}
            </ul>
            <FormError error={inventoryAction.error} />
          </DialogBody>
          <DialogFooter>
            <Button
              type="button"
              variant="ghost"
              disabled={inventoryAction.pending}
              onClick={() => setBulkDeleteOpen(false)}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="default"
              data-testid="confirm-bulk-remove"
              className="data-[slot=button]:bg-danger data-[slot=button]:text-white data-[slot=button]:hover:bg-danger hover:brightness-[1.08]"
              disabled={inventoryAction.pending}
              onClick={handleBulkRemove}
            >
              <Icon name="trash" size={13} />
              {inventoryAction.pending ? 'Removing…' : `Remove ${selectedCount} ${selectedCount === 1 ? 'host' : 'hosts'}`}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </section>
  )
}
