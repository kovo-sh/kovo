import { useState } from 'react'
import { addProjectAsset, updateProjectAssetScope } from '../../actions.ts'
import { AccessPolicyImport } from '../access-policy-import.tsx'
import { formatHumanTime, FormError, useAction } from '../common.tsx'
import { DnsInventoryImport } from '../dns-inventory-import.tsx'
import { Checkbox } from '../ui/checkbox.tsx'
import type { ProjectLoaderData } from './types.ts'
import { safeHost } from './types.ts'

interface Props {
  data: ProjectLoaderData
}

function safeHostname(raw: string | undefined): string {
  if (!raw) return ''
  try {
    return new URL(raw).hostname
  } catch {
    return raw.replace(/^https?:\/\//i, '').split(/[/:?#]/)[0] ?? ''
  }
}

export function ProjectInventoryTab({ data }: Props) {
  const { project, assets } = data
  const [panel, setPanel] = useState<'candidate' | 'dns' | 'access'>()
  const [candidateThirdParty, setCandidateThirdParty] = useState(false)
  const [candidateIncludeSubdomains, setCandidateIncludeSubdomains] = useState(false)
  const [notice, setNotice] = useState('')
  const [hostSearch, setHostSearch] = useState('')
  const inventoryAction = useAction()

  function togglePanel(next: typeof panel) {
    setPanel(cur => cur === next ? undefined : next)
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
    return <div key={asset.id} className="pw-row">
      <div className="pw-row-main">
        <div className="pw-row-title">
          <strong className="mono">{hostLabel}</strong>
          {asset.includeSubdomains && !asset.thirdParty && (
            <span className="pw-tag accent">*.{asset.dnsSource?.zone ?? hostLabel}</span>
          )}
          {asset.thirdParty && externalCname ? (
            <span className="pw-tag warn">Third-party CNAME ({externalCname})</span>
          ) : asset.thirdParty ? (
            <span className="pw-tag warn">Third party</span>
          ) : null}
          {asset.accessPolicy && <span className="pw-tag solid">Access policy</span>}
        </div>
        <div className="pw-row-sub">
          {asset.source}
          {asset.dnsSource ? ` · ${asset.dnsSource.zone}` : ''}
          {policyRecorded?.label && (
            <>
              {' · '}
              <span className="num" title={policyRecorded.full}>Policy recorded {policyRecorded.label}</span>
            </>
          )}
        </div>
      </div>
      <div className="pw-row-right">
        {project.environment === 'public' && !asset.thirdParty && (
          <label
            className="pw-chk"
            style={{ fontSize: 12 }}
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
            <code>*.domain</code>
          </label>
        )}
        {asset.thirdParty ? (
          <label
            className="pw-chk"
            style={{ fontSize: 12 }}
            title="Third-party CNAMEs stay unchecked by default; check only if you have authorization to test this custom domain"
          >
            <Checkbox
              checked={isDefaultApproved}
              disabled={inventoryAction.pending}
              aria-label={`Approve third-party host ${hostLabel} in project scope`}
              onCheckedChange={checked => {
                const next = Boolean(checked)
                void inventoryAction.submit(() => updateProjectAssetScope({ data: {
                  requestId: crypto.randomUUID(),
                  projectId: project.id,
                  assetId: asset.id,
                  approveInDefaultScope: next,
                } }), () => setNotice(`${next ? 'Explicitly approved' : 'Removed'} third-party host ${hostLabel} ${next ? 'in' : 'from'} project scope.`))
              }}
            />
            <span>{isDefaultApproved ? 'Approved in scope' : 'Approve in scope'}</span>
          </label>
        ) : isDefaultApproved ? (
          <span className="pw-tag solid">Approved in scope</span>
        ) : (
          <label
            className="pw-chk"
            style={{ fontSize: 12 }}
            title="Add this host to the project's approved scan scope"
          >
            <Checkbox
              checked={false}
              disabled={inventoryAction.pending}
              aria-label={`Approve host ${hostLabel} in project scope`}
              onCheckedChange={() => {
                void inventoryAction.submit(() => updateProjectAssetScope({ data: {
                  requestId: crypto.randomUUID(),
                  projectId: project.id,
                  assetId: asset.id,
                  approveInDefaultScope: true,
                } }), () => setNotice(`Approved ${hostLabel} in project scope.`))
              }}
            />
            <span>Approve in scope</span>
          </label>
        )}
      </div>
    </div>
  }

  return <section aria-label="Project inventory">
    <div className="pw-sec-head">
      <div>
        <h2>Hosts &amp; Assets <span className="muted num">({assets.length})</span></h2>
        <p>Starting hosts, DNS exports, and passively discovered subdomains. Third-party hosted services stay unchecked unless explicitly approved.</p>
      </div>
      <div className="pw-sec-actions">
        {assets.length > 6 && (
          <input
            className="pw-in pw-host-search"
            type="search"
            value={hostSearch}
            onChange={e => setHostSearch(e.target.value)}
            placeholder="Search hosts"
            aria-label="Search hosts"
          />
        )}
        <button type="button" className="pw-btn primary" onClick={() => togglePanel('candidate')} aria-expanded={panel === 'candidate'}>
          {panel === 'candidate' ? 'Close' : 'Add host'}
        </button>
        <button type="button" className="pw-btn" onClick={() => togglePanel('dns')} aria-expanded={panel === 'dns'}>Import DNS export</button>
        <button type="button" className="pw-btn" onClick={() => togglePanel('access')} aria-expanded={panel === 'access'}>Import access records</button>
      </div>
    </div>

    {notice && <p role="status" className="notice">{notice}</p>}

    {panel === 'dns' && <div style={{ marginBottom: 14 }}>
      <DnsInventoryImport
        projectId={project.id}
        defaultZone={safeHostname(project.seeds[0])}
        cancel={() => setPanel(undefined)}
        imported={({ added, existing }) => {
          setPanel(undefined)
          setNotice(`Added ${added} ${added === 1 ? 'host' : 'hosts'}. Skipped ${existing} existing.`)
        }}
      />
    </div>}

    {panel === 'access' && <div style={{ marginBottom: 14 }}>
      <AccessPolicyImport
        projectId={project.id}
        assets={assets}
        cancel={() => setPanel(undefined)}
        imported={({ origin, cases }) => {
          setPanel(undefined)
          setNotice(`Imported ${cases} access ${cases === 1 ? 'case' : 'cases'} for ${safeHostname(origin) || origin}.`)
        }}
      />
    </div>}

    {panel === 'candidate' && <form
      className="pw-sheet"
      style={{ marginBottom: 14 }}
      onSubmit={event => {
        event.preventDefault()
        const form = new FormData(event.currentTarget)
        let prepared: unknown
        const supplied = String(form.get('prepared') ?? '').trim()
        if (supplied) {
          try {
            prepared = JSON.parse(supplied)
          } catch {
            void inventoryAction.submit(async () => { throw new Error('Prepared evidence must be valid JSON.') })
            return
          }
        }
        void inventoryAction.submit(() => addProjectAsset({ data: {
          requestId: crypto.randomUUID(),
          projectId: project.id,
          origin: String(form.get('origin')),
          source: String(form.get('source') ?? '').trim() || 'Manual entry',
          thirdParty: candidateThirdParty,
          includeSubdomains: project.environment === 'public' && !candidateThirdParty && candidateIncludeSubdomains,
          prepared: prepared as Parameters<typeof addProjectAsset>[0]['data']['prepared'],
        } }), () => {
          setCandidateThirdParty(false)
          setCandidateIncludeSubdomains(false)
          setPanel(undefined)
          setNotice('Added host to project inventory.')
        })
      }}
    >
      <div className="pw-sheet-h">
        <span>Add host</span>
        <button type="button" className="pw-btn ghost" onClick={() => setPanel(undefined)}>Close</button>
      </div>
      <div className="pw-sheet-b">
        <div className="pw-grid-2">
          <label className="pw-fld">Host
            <input className="pw-in" name="origin" placeholder="docs.example.com" required />
          </label>
          <label className="pw-fld">Source (optional)
            <input className="pw-in" name="source" placeholder="Manual entry" maxLength={160} />
          </label>
        </div>
        <label className="pw-chk">
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
        {project.environment === 'public' && !candidateThirdParty && <div style={{ display: 'grid', gap: 4 }}>
          <label className="pw-chk">
            <Checkbox
              name="includeSubdomains"
              checked={candidateIncludeSubdomains}
              aria-label="Include subdomains (*.domain)"
              onCheckedChange={checked => setCandidateIncludeSubdomains(Boolean(checked))}
            />
            <span>Include subdomains (<code>*.domain</code>)</span>
          </label>
          <span
            className="muted"
            style={{ fontSize: 11.5 }}
            title="Uses passive Certificate Transparency logs and live DNS during initial discovery"
          >
            Automatically discovers first-party subdomains before scanning. Third-party hosted services stay unchecked until you explicitly approve them.
          </span>
        </div>}
        <details className="pw-disclosure" style={{ marginTop: 4 }}>
          <summary>Advanced configuration</summary>
          <div className="pw-disclosure-body">
            <label className="pw-fld">Prepared response metadata (JSON)
              <textarea
                className="pw-textarea mono"
                name="prepared"
                rows={4}
                placeholder={'{"status":200,"mediaType":"text/html","transportMaxAge":31536000,"includeSubDomains":false,"contentTypeOptions":"nosniff","referrerPolicy":"strict-origin-when-cross-origin"}'}
              />
            </label>
          </div>
        </details>
        <FormError error={inventoryAction.error} />
      </div>
      <div className="pw-sheet-f">
        <button type="button" className="pw-btn ghost" onClick={() => setPanel(undefined)}>Cancel</button>
        <button type="submit" className="pw-btn primary" disabled={inventoryAction.pending}>Add to project</button>
      </div>
    </form>}

    {assets.length === 0 ? (
      <div className="pw-empty-card">
        <h3>No hosts in scope yet</h3>
        <p>Add a starting host or import a DNS export so Kovo Hunter knows what belongs to this project.</p>
        <button type="button" className="pw-btn primary" onClick={() => togglePanel('candidate')}>
          Add host
        </button>
      </div>
    ) : visibleAssets.length === 0 ? (
      <p className="pw-footnote">No hosts match “{hostSearch.trim()}”.</p>
    ) : <>
      {approvedAssets.length > 0 && (
        <div className="pw-table-wrap">
          <div className="pw-group-head">
            <h3>Approved in scope <span className="num muted">({approvedAssets.length})</span></h3>
            <span className="muted">Included in scan scope</span>
          </div>
          {approvedAssets.map(renderAsset)}
        </div>
      )}
      {needsApprovalAssets.length > 0 && (
        <div className="pw-table-wrap pw-table-wrap-spaced">
          <div className="pw-group-head">
            <h3>Needs approval <span className="num muted">({needsApprovalAssets.length})</span></h3>
            <span className="muted">Approve hosts before they enter scan scope</span>
          </div>
          {needsApprovalAssets.map(renderAsset)}
        </div>
      )}
    </>}
  </section>
}
