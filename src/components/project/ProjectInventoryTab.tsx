import { useState } from 'react'
import { addProjectAsset, updateProjectAssetScope } from '../../actions.ts'
import { AccessPolicyImport } from '../access-policy-import.tsx'
import { FormError, useAction } from '../common.tsx'
import { DnsInventoryImport } from '../dns-inventory-import.tsx'
import { Checkbox } from '../ui/checkbox.tsx'
import type { ProjectLoaderData } from './types.ts'
import { safeHost } from './types.ts'

interface Props {
  data: ProjectLoaderData
}

export function ProjectInventoryTab({ data }: Props) {
  const { project, assets } = data
  const [panel, setPanel] = useState<'candidate' | 'dns' | 'access'>()
  const [candidateThirdParty, setCandidateThirdParty] = useState(false)
  const [candidateIncludeSubdomains, setCandidateIncludeSubdomains] = useState(false)
  const [notice, setNotice] = useState('')
  const inventoryAction = useAction()

  function togglePanel(next: typeof panel) {
    setPanel(cur => cur === next ? undefined : next)
    setNotice('')
  }

  return <section aria-label="Project inventory">
    <div className="pw-sec-head">
      <div>
        <h2>Hosts &amp; Assets <span className="muted num">({assets.length})</span></h2>
        <p>Seed hosts, DNS exports, and passive CT-discovered subdomains. Managed third-party SaaS CNAMEs stay unchecked unless explicitly approved.</p>
      </div>
      <div className="pw-sec-actions">
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
        defaultZone={new URL(project.seeds[0]).hostname}
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
          setNotice(`Imported ${cases} access ${cases === 1 ? 'case' : 'cases'} for ${new URL(origin).hostname}.`)
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
          source: String(form.get('source')),
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
          <label className="pw-fld">Source
            <input className="pw-in" name="source" placeholder="Service ownership inventory" required maxLength={160} />
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
          <span className="muted" style={{ fontSize: 11.5 }}>
            Enables passive CT-log + live DNS discovery in Phase 0 for first-party subdomains. Managed third-party SaaS CNAMEs stay unchecked and require explicit approval.
          </span>
        </div>}
        <details className="pw-disclosure" style={{ marginTop: 4 }}>
          <summary>Supply prepared evidence (optional)</summary>
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

    <div className="pw-table-wrap">
      {assets.map(asset => {
        const externalCname = asset.dnsSource?.externalAliases?.[0]
        const isDefaultApproved = project.defaultScope.includes(asset.origin)
        const hostLabel = safeHost(asset.origin)
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
            </div>
          </div>
          <div className="pw-row-right">
            {project.environment === 'public' && !asset.thirdParty && (
              <label
                className="pw-chk"
                style={{ fontSize: 12 }}
                title="Auto-admit live first-party subdomains discovered via passive CT logs (excludes third-party SaaS CNAMEs)"
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
                    } }), () => setNotice(`${next ? 'Enabled' : 'Disabled'} *.domain passive discovery for ${hostLabel}.`))
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
            ) : (
              <span className="pw-tag solid">{isDefaultApproved ? 'Project default' : 'Candidate'}</span>
            )}
          </div>
        </div>
      })}
    </div>
  </section>
}
