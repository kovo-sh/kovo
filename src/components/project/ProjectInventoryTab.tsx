import { useState } from 'react'
import {
  addProjectAsset,
  clearProjectAssetAccessPolicyAction,
  updateProjectAssetAction,
  updateProjectAssetScope,
} from '../../actions.ts'
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

export function ProjectInventoryTab({ data, onDeleteAsset }: Props) {
  const { project, assets } = data
  const [panel, setPanel] = useState<'dns' | 'access'>()
  const [addHostOpen, setAddHostOpen] = useState(false)
  const [assetToEdit, setAssetToEdit] = useState<ProjectLoaderData['assets'][number] | null>(null)
  const [editOrigin, setEditOrigin] = useState('')
  const [editSource, setEditSource] = useState('')
  const [editThirdParty, setEditThirdParty] = useState(false)
  const [assetToDelete, setAssetToDelete] = useState<ProjectLoaderData['assets'][number] | null>(null)
  const [candidateOrigin, setCandidateOrigin] = useState('')
  const [candidateSource, setCandidateSource] = useState('')
  const [candidateThirdParty, setCandidateThirdParty] = useState(false)
  const [candidateIncludeSubdomains, setCandidateIncludeSubdomains] = useState(false)
  const [notice, setNotice] = useState('')
  const [hostSearch, setHostSearch] = useState('')
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

  const searchTerm = hostSearch.trim().toLowerCase()
  const visibleAssets = searchTerm
    ? assets.filter(asset => {
      const haystack = `${safeHost(asset.origin)} ${asset.source ?? ''} ${asset.dnsSource?.zone ?? ''}`.toLowerCase()
      return haystack.includes(searchTerm)
    })
    : assets
  const approvedAssets = visibleAssets.filter(asset => project.defaultScope.includes(asset.origin))
  const needsApprovalAssets = visibleAssets.filter(asset => !project.defaultScope.includes(asset.origin))

  function renderAsset(asset: ProjectLoaderData['assets'][number]) {
    const externalCname = asset.dnsSource?.externalAliases?.[0]
    const isDefaultApproved = project.defaultScope.includes(asset.origin)
    const hostLabel = safeHost(asset.origin)
    const policyRecorded = asset.accessPolicy?.recordedAt
      ? formatHumanTime(asset.accessPolicy.recordedAt)
      : null
    return (
      <div
        key={asset.id}
        className="flex min-h-[44px] items-center justify-between gap-3 border-b border-line px-1 py-2 transition-colors hover:bg-hover"
      >
        <div className="flex min-w-0 flex-1 flex-col gap-0.5">
          <div className="flex min-w-0 flex-wrap items-center gap-1.5 font-medium text-fg">
            <strong className="font-mono text-[12px] font-semibold">{hostLabel}</strong>
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
          <div className="text-[12px] text-fg-subtle">
            {asset.source}
            {asset.dnsSource ? ` · ${asset.dnsSource.zone}` : ''}
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
          {assets.length > 6 && (
            <Input
              className="h-[26px]! w-[180px]"
              type="search"
              value={hostSearch}
              onChange={e => setHostSearch(e.target.value)}
              placeholder="Search hosts"
              aria-label="Search hosts"
            />
          )}
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
      {!addHostOpen && !assetToDelete && !assetToEdit && <FormError error={inventoryAction.error} />}

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

      {assets.length === 0 ? (
        <div className="mt-3.5 rounded-card border border-line bg-sunk">
          <EmptyState
            title="No hosts in scope yet"
            description="Add a starting host or import a DNS export so Kovo Hunter knows what belongs to this project."
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
        <p className="mt-3.5 border-t border-line px-3 py-2.5 text-[12px] leading-[18px] text-fg-subtle">
          No hosts match “{hostSearch.trim()}”.
        </p>
      ) : (
        <>
          {approvedAssets.length > 0 && (
            <div className="border-t border-line">
              <div className="flex items-baseline justify-between gap-2.5 px-1 pb-[7px] pt-2.5">
                <h3 className="m-0 text-[12px] font-semibold text-fg">
                  Approved in scope <span className="font-normal tabular-nums text-fg-subtle">({approvedAssets.length})</span>
                </h3>
                <span className="text-[11.5px] text-fg-subtle">Included in scan scope</span>
              </div>
              {approvedAssets.map(renderAsset)}
            </div>
          )}
          {needsApprovalAssets.length > 0 && (
            <div className="mt-[18px] border-t border-line">
              <div className="flex items-baseline justify-between gap-2.5 px-1 pb-[7px] pt-2.5">
                <h3 className="m-0 text-[12px] font-semibold text-fg">
                  Needs approval <span className="font-normal tabular-nums text-fg-subtle">({needsApprovalAssets.length})</span>
                </h3>
                <span className="text-[11.5px] text-fg-subtle">Approve hosts before they enter scan scope</span>
              </div>
              {needsApprovalAssets.map(renderAsset)}
            </div>
          )}
        </>
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
    </section>
  )
}
