import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import {
  addProjectAsset,
  createRun,
  importSpec,
  projectData,
  registerPersona,
  removePersona,
  removeProjectSpec,
  syncGithubRepositories,
} from '../actions.ts'
import { AccessPolicyImport } from '../components/access-policy-import.tsx'
import { FormError, Status, timeText, useAction } from '../components/common.tsx'
import { DnsInventoryImport } from '../components/dns-inventory-import.tsx'
import { capabilityTierMeta, formatUsd, phaseNames } from '../components/run-state.ts'
import { Button } from '../components/ui/button.tsx'
import { Checkbox } from '../components/ui/checkbox.tsx'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '../components/ui/collapsible.tsx'
import { Input, NativeSelect, Textarea } from '../components/ui/input.tsx'
import {
  defaultBudgetRequests,
  defaultBudgetUsd,
  defaultMaxRpsPerOrigin,
  defaultWorkerConcurrency,
  defaultWorkerMaxTurns,
  maxBudgetRequests,
  maxRpsPerOriginCeiling,
  maxSpecBytes,
  maxWorkerConcurrency,
  maxWorkerMaxTurns,
} from '../domain.ts'
import type { CapabilityTier } from '../domain.ts'

export const Route = createFileRoute('/projects/$projectId')({
  loader: ({ params }) => projectData({ data: { projectId: params.projectId } }),
  component: ProjectPage,
})

function ProjectPage() {
  const { project, assets, personas, specs, runs, hasGithubPat } = Route.useLoaderData()
  const navigate = useNavigate()
  const [panel, setPanel] = useState<'candidate' | 'dns' | 'access'>()
  const [specPanel, setSpecPanel] = useState<'upload' | 'github'>()
  const [addingPersona, setAddingPersona] = useState(false)
  const [authKind, setAuthKind] = useState<'cookie' | 'bearer' | 'header'>('bearer')
  const [tier, setTier] = useState<CapabilityTier>(1)
  const [notice, setNotice] = useState('')
  const [personaNotice, setPersonaNotice] = useState('')
  const [specNotice, setSpecNotice] = useState('')
  const [specName, setSpecName] = useState('')
  const [specContent, setSpecContent] = useState('')
  const [starting, setStarting] = useState(runs.length === 0)
  const action = useAction()
  const inventoryAction = useAction()
  const personaAction = useAction()
  const specAction = useAction()

  function toggleInventory(next: typeof panel) {
    setPanel(current => current === next ? undefined : next)
    setNotice('')
  }

  function toggleSpecPanel(next: typeof specPanel) {
    setSpecPanel(current => current === next ? undefined : next)
    setSpecNotice('')
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

  return <main className="workspace-page">
    <Link className="back-link" to="/">← Projects</Link>
    <div className="page-title">
      <div>
        <div className="inline-badges">
          <h1>{project.name}</h1>
          {project.environment === 'local-lab'
            ? <span className="badge badge-attention">Local lab</span>
            : <span className="badge">Public HTTPS</span>}
        </div>
        <p className="muted">{project.seeds.map(seed => new URL(seed).hostname).join(', ')}</p>
      </div>
      {!starting && <Button variant="default" onClick={() => setStarting(true)}>New run</Button>}
    </div>

    {starting && <form className="form-card" onSubmit={event => {
      event.preventDefault()
      const form = new FormData(event.currentTarget)
      const capabilityTier = Number(form.get('capabilityTier') ?? tier) as CapabilityTier
      const sourceMode = capabilityTier === 0 ? 'prepared' as const : 'public' as const
      void action.submit(() => createRun({ data: {
        requestId: crypto.randomUUID(),
        projectId: project.id,
        goal: String(form.get('goal')),
        sourceMode,
        capabilityTier,
        budgetUsd: Number(form.get('budgetUsd') ?? defaultBudgetUsd),
        budgetRequests: Number(form.get('budgetRequests') ?? defaultBudgetRequests),
        maxRpsPerOrigin: Number(form.get('maxRpsPerOrigin') ?? defaultMaxRpsPerOrigin),
        workerConcurrency: Number(form.get('workerConcurrency') ?? defaultWorkerConcurrency),
        workerMaxTurns: Number(form.get('workerMaxTurns') ?? defaultWorkerMaxTurns),
      } }), async result => { await navigate({ to: '/runs/$runId', params: { runId: result.id } }) })
    }}>
      <div className="section-heading">
        <h2>Start a run</h2>
        {runs.length > 0 && <Button variant="ghost" onClick={() => setStarting(false)}>Cancel</Button>}
      </div>
      <label>Run goal
        <Textarea name="goal" rows={3} maxLength={8000} required
          placeholder="Assess authentication, API authorization, client-side exposure, and reachable CVEs across approved hosts." />
      </label>
      <label>Capability tier
        <NativeSelect name="capabilityTier" value={tier} onChange={event => setTier(Number(event.target.value) as CapabilityTier)}>
          <option value={0}>{capabilityTierMeta[0].name}</option>
          <option value={1}>{capabilityTierMeta[1].name}</option>
          <option value={2}>{capabilityTierMeta[2].name}</option>
          <option value={3}>{capabilityTierMeta[3].name}</option>
        </NativeSelect>
        <span className="muted">{capabilityTierMeta[tier].summary}</span>
      </label>
      <div className="field-grid-3">
        <label>Budget (USD)
          <Input name="budgetUsd" type="number" min={0.1} max={500} step="any" required defaultValue={defaultBudgetUsd} />
        </label>
        <label>Max brokered requests
          <Input name="budgetRequests" type="number" min={0} max={maxBudgetRequests} step={1} required defaultValue={tier === 0 ? 0 : defaultBudgetRequests} />
        </label>
        <label>Max RPS / origin
          <Input name="maxRpsPerOrigin" type="number" min={1} max={maxRpsPerOriginCeiling} step={1} required defaultValue={defaultMaxRpsPerOrigin} />
        </label>
      </div>
      <div className="field-grid-2">
        <label>Worker concurrency
          <Input name="workerConcurrency" type="number" min={1} max={maxWorkerConcurrency} step={1} required defaultValue={defaultWorkerConcurrency} />
        </label>
        <label>Worker max turns
          <Input name="workerMaxTurns" type="number" min={1} max={maxWorkerMaxTurns} step={1} required defaultValue={defaultWorkerMaxTurns} />
        </label>
      </div>
      <FormError error={action.error} />
      <div className="form-actions"><Button type="submit" variant="default" disabled={action.pending}>Create run</Button></div>
    </form>}

    {runs.length > 0 && <section aria-label="Run history" className="stacked-section">
      <h2>Run history</h2>
      <ul className="project-list">{runs.map(run => <li key={run.id}>
        <Link to="/runs/$runId" params={{ runId: run.id }}>
          <span>
            <strong>{run.goal}</strong>
            <small>
              {timeText(run.createdAt)} · {capabilityTierMeta[run.capabilityTier].short} · {phaseNames[run.phase]} · {run.turnsUsed} turns · {run.spentRequests} reqs · {formatUsd(run.spentUsd)}
            </small>
          </span>
          <Status status={run.status} />
        </Link>
      </li>)}</ul>
    </section>}

    <section className="stacked-section" aria-label="Project inventory">
      <div className="section-heading"><h2>Project inventory</h2>
        <div className="toolbar inventory-toolbar">
          <Button onClick={() => toggleInventory('candidate')} aria-expanded={panel === 'candidate'}>Add candidate</Button>
          <Button onClick={() => toggleInventory('dns')} aria-expanded={panel === 'dns'}>Import DNS export</Button>
          <Button onClick={() => toggleInventory('access')} aria-expanded={panel === 'access'}>Import access records</Button>
        </div>
      </div>
      {notice && <p role="status" className="muted">{notice}</p>}
      {panel === 'dns' && <DnsInventoryImport projectId={project.id} defaultZone={new URL(project.seeds[0]).hostname}
        cancel={() => setPanel(undefined)} imported={({ added, existing }) => {
          setPanel(undefined)
          setNotice(`Added ${added} ${added === 1 ? 'host' : 'hosts'}. Skipped ${existing} existing.`)
        }} />}
      {panel === 'access' && <AccessPolicyImport projectId={project.id} assets={assets}
        cancel={() => setPanel(undefined)} imported={({ origin, cases }) => {
          setPanel(undefined)
          setNotice(`Imported ${cases} access ${cases === 1 ? 'case' : 'cases'} for ${new URL(origin).hostname}.`)
        }} />}
      {panel === 'candidate' && <form className="form-card" onSubmit={event => {
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
          requestId: crypto.randomUUID(), projectId: project.id,
          origin: String(form.get('origin')), source: String(form.get('source')), thirdParty: form.has('thirdParty'),
          prepared: prepared as Parameters<typeof addProjectAsset>[0]['data']['prepared'],
        } }), () => setPanel(undefined))
      }}>
        <label>Host<Input name="origin" placeholder="docs.example.com" required /></label>
        <label>Source<Input name="source" placeholder="Service ownership inventory" required maxLength={160} /></label>
        <label className="checkbox"><Checkbox name="thirdParty" aria-label="Third-party service" /> Third-party service</label>
        <Collapsible className="provider-advanced">
          <CollapsibleTrigger render={<Button variant="ghost" />}>Supply prepared evidence</CollapsibleTrigger>
          <CollapsibleContent keepMounted>
            <label>Prepared response metadata
              <Textarea name="prepared" rows={4} placeholder={'{"status":200,"mediaType":"text/html","transportMaxAge":31536000,"includeSubDomains":false,"contentTypeOptions":"nosniff","referrerPolicy":"strict-origin-when-cross-origin"}'} />
            </label>
          </CollapsibleContent>
        </Collapsible>
        <FormError error={inventoryAction.error} />
        <div className="form-actions"><Button type="submit" variant="default" disabled={inventoryAction.pending}>Add to project</Button></div>
      </form>}
      <ul className="project-list">{assets.map(asset => <li key={asset.id}>
        <div className="list-row"><span><strong>{new URL(asset.origin).hostname}</strong>
          <small>{asset.source}{asset.dnsSource ? ` · ${asset.dnsSource.zone}` : ''}{asset.accessPolicy ? ' · Access policy records' : ''}</small></span>
          <span className="muted">{asset.thirdParty ? 'Third party' : project.defaultScope.includes(asset.origin) ? 'Project default' : 'Candidate'}</span>
        </div>
      </li>)}</ul>
    </section>

    <section className="stacked-section" aria-label="Persona vault">
      <div className="section-heading">
        <div>
          <h2>Persona vault</h2>
          <p className="muted">Opaque test accounts for Tier 2/3 validation. Secrets are stored locally at 0600 and injected only on allowlisted origins.</p>
        </div>
        <Button onClick={() => { setAddingPersona(v => !v); setPersonaNotice('') }} aria-expanded={addingPersona}>
          {addingPersona ? 'Close' : 'Add persona'}
        </Button>
      </div>
      {personaNotice && <p role="status" className="muted">{personaNotice}</p>}
      {addingPersona && <form className="form-card" onSubmit={event => {
        event.preventDefault()
        const form = new FormData(event.currentTarget)
        const element = event.currentTarget
        const selectedKind = form.get('authKind') === 'cookie' ? 'cookie' as const
          : form.get('authKind') === 'header' ? 'header' as const : 'bearer' as const
        const allowlist = String(form.get('originAllowlist') ?? '').split(/[\s,]+/).filter(Boolean)
        const canaryMarkers = String(form.get('canaryMarkers') ?? '').split(',').map(s => s.trim()).filter(Boolean)
        const headerNameRaw = String(form.get('headerName') ?? '').trim()
        void personaAction.submit(() => registerPersona({ data: {
          requestId: crypto.randomUUID(),
          projectId: project.id,
          handle: String(form.get('handle') ?? '').trim(),
          roleLabel: String(form.get('roleLabel') ?? '').trim(),
          originAllowlist: allowlist,
          authKind: selectedKind,
          ...(selectedKind === 'header' && headerNameRaw ? { headerName: headerNameRaw } : {}),
          secret: String(form.get('secret') ?? ''),
          canaryMarkers,
        } }), created => {
          const secretInput = element.elements.namedItem('secret') as HTMLInputElement | null
          if (secretInput) secretInput.value = ''
          setAddingPersona(false)
          setPersonaNotice(`Saved persona "${created.handle}". Secret stored in local 0600 vault.`)
        })
      }}>
        <h3>Add test persona</h3>
        <div className="field-grid-2">
          <label>Handle (lowercase, opaque to workers)
            <Input name="handle" required pattern="[a-z0-9][a-z0-9_-]{0,47}" placeholder="tenant_a" />
          </label>
          <label>Role label
            <Input name="roleLabel" required maxLength={160} placeholder="Standard tenant member" />
          </label>
        </div>
        <label>Origin allowlist (one per line or comma-separated)
          <Textarea name="originAllowlist" rows={2} required defaultValue={project.seeds.join('\n')} />
        </label>
        <div className="field-grid-2">
          <label>Authentication kind
            <NativeSelect name="authKind" value={authKind} onChange={event => setAuthKind(event.target.value as 'cookie' | 'bearer' | 'header')}>
              <option value="bearer">Bearer token (Authorization: Bearer …)</option>
              <option value="cookie">Session cookie (Cookie: …)</option>
              <option value="header">Custom request header</option>
            </NativeSelect>
          </label>
          {authKind === 'header' && <label>Header name
            <Input name="headerName" required pattern="[A-Za-z0-9-]{1,64}" placeholder="X-Api-Key" />
          </label>}
        </div>
        <label>Credential secret
          <Input name="secret" type="password" required maxLength={4096} autoComplete="off" placeholder="Never displayed back after saving" />
        </label>
        <label>Canary markers (optional, comma-separated)
          <Input name="canaryMarkers" placeholder="tenant-a-canary@example.test, org_alpha_001" />
          <span className="muted">Strings that indicate cross-tenant data leakage if seen by another persona.</span>
        </label>
        <FormError error={personaAction.error} />
        <div className="form-actions">
          <Button onClick={() => setAddingPersona(false)}>Cancel</Button>
          <Button type="submit" variant="default" disabled={personaAction.pending}>Save persona</Button>
        </div>
      </form>}
      {personas.length > 0 ? <ul className="project-list">{personas.map(persona => <li key={persona.id}>
        <div className="list-row">
          <span>
            <span className="inline-badges">
              <strong>{persona.handle}</strong>
              <span className="badge badge-trace">{persona.roleLabel}</span>
              <span className="badge">{persona.authKind}{persona.headerName ? ` · ${persona.headerName}` : ''}</span>
            </span>
            <small>Allowlist: {persona.originAllowlist.map(o => new URL(o).hostname).join(', ')}
              {persona.canaryMarkers.length > 0 && ` · ${persona.canaryMarkers.length} canary ${persona.canaryMarkers.length === 1 ? 'marker' : 'markers'}`}</small>
          </span>
          <Button variant="ghost" className="btn-danger" disabled={personaAction.pending} onClick={() => {
            void personaAction.submit(() => removePersona({ data: {
              requestId: crypto.randomUUID(), projectId: project.id, personaId: persona.id,
            } }), () => setPersonaNotice(`Removed persona "${persona.handle}".`))
          }}>Delete</Button>
        </div>
      </li>)}</ul> : <p className="muted" style={{ marginTop: 8 }}>No personas configured yet.</p>}
    </section>

    <section className="stacked-section" aria-label="Specs and GitHub repo sync">
      <div className="section-heading">
        <div>
          <h2>Specs &amp; GitHub repo sync</h2>
          <p className="muted">Supply OpenAPI/GraphQL schemas, lockfiles, or sync authorized repositories read-only for grey-box CVE &amp; route context.</p>
        </div>
        <div className="toolbar inventory-toolbar">
          <Button onClick={() => toggleSpecPanel('upload')} aria-expanded={specPanel === 'upload'}>Import spec / lockfile</Button>
          <Button onClick={() => toggleSpecPanel('github')} aria-expanded={specPanel === 'github'}>Sync GitHub repos</Button>
        </div>
      </div>
      {specNotice && <p role="status" className="muted">{specNotice}</p>}
      {specPanel === 'upload' && <form className="form-card" onSubmit={event => {
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
          setSpecPanel(undefined)
          setSpecName('')
          setSpecContent('')
          setSpecNotice(`Imported spec "${saved.name}" (${saved.kind}).`)
        })
      }}>
        <h3>Import spec, routes, or lockfile</h3>
        <div className="field-grid-2">
          <label>Name
            <Input name="name" required maxLength={160} value={specName} onChange={e => setSpecName(e.target.value)}
              placeholder="openapi.yaml or package-lock.json" />
          </label>
          <label>Kind
            <NativeSelect name="kind" defaultValue="openapi">
              <option value="openapi">OpenAPI / Swagger</option>
              <option value="graphql">GraphQL schema</option>
              <option value="routes">Route map / Server handlers</option>
              <option value="notes">Lockfile / Dependencies / Notes</option>
            </NativeSelect>
          </label>
        </div>
        <label>Target origin (optional)
          <Input name="origin" placeholder={project.seeds[0] ?? 'https://api.example.com'} />
        </label>
        <label>Load from file (optional, up to 2 MiB)
          <Input type="file" accept=".json,.yaml,.yml,.graphql,.gql,.txt,.md,.lock" onChange={e => {
            void onSpecFileSelected(e.target.files?.[0])
          }} />
        </label>
        <label>Content
          <Textarea name="content" rows={6} required value={specContent} onChange={e => setSpecContent(e.target.value)}
            placeholder="Paste OpenAPI, GraphQL SDL, lockfile JSON, or route notes…" />
        </label>
        <FormError error={specAction.error} />
        <div className="form-actions">
          <Button onClick={() => setSpecPanel(undefined)}>Cancel</Button>
          <Button type="submit" variant="default" disabled={specAction.pending || !specContent.trim()}>Import spec</Button>
        </div>
      </form>}
      {specPanel === 'github' && <form className="form-card" onSubmit={event => {
        event.preventDefault()
        const form = new FormData(event.currentTarget)
        const repos = String(form.get('repos') ?? '').split(/[\s,]+/).map(s => s.trim()).filter(Boolean)
        void specAction.submit(() => syncGithubRepositories({ data: { projectId: project.id, repos } }), result => {
          setSpecPanel(undefined)
          const warnText = result.warnings.length ? ` Warnings: ${result.warnings.join('; ')}` : ''
          setSpecNotice(`Synced ${result.repos.length} ${result.repos.length === 1 ? 'repo' : 'repos'}: ${result.specsImported} specs imported, ${result.dependenciesExtracted} dependencies extracted.${warnText}`)
        })
      }}>
        <div className="section-heading">
          <h3>Sync authorized GitHub repositories (read-only)</h3>
          <span className={hasGithubPat ? 'badge badge-complete' : 'badge badge-attention'}>
            {hasGithubPat ? 'GitHub PAT ready' : 'PAT not detected'}
          </span>
        </div>
        <p className="muted">Reads the read-only token strictly from <code>~/.config/guardian-fixtures/github.pat</code> (0600). Imports lockfiles, OpenAPI/GraphQL schemas, and server route context with secrets redacted.</p>
        <label>Repositories (<code>owner/repo</code>, one per line or comma-separated)
          <Textarea name="repos" rows={3} required placeholder={'org/web-app\norg/api-service'} />
        </label>
        <FormError error={specAction.error} />
        <div className="form-actions">
          <Button onClick={() => setSpecPanel(undefined)}>Cancel</Button>
          <Button type="submit" variant="default" disabled={specAction.pending || !hasGithubPat}>Sync read-only</Button>
        </div>
      </form>}
      {specs.length > 0 ? <ul className="project-list">{specs.map(spec => <li key={spec.id}>
        <div className="list-row">
          <span>
            <span className="inline-badges">
              <strong>{spec.name}</strong>
              <span className="badge">{spec.kind}</span>
              {spec.origin && <span className="badge badge-trace">{new URL(spec.origin).hostname}</span>}
            </span>
            <small>{Math.max(1, Math.round(spec.bytes / 1024))} KiB · Imported {timeText(spec.createdAt)}</small>
          </span>
          <Button variant="ghost" className="btn-danger" disabled={specAction.pending} onClick={() => {
            void specAction.submit(() => removeProjectSpec({ data: {
              requestId: crypto.randomUUID(), projectId: project.id, specId: spec.id,
            } }), () => setSpecNotice(`Removed spec "${spec.name}".`))
          }}>Delete</Button>
        </div>
      </li>)}</ul> : <p className="muted" style={{ marginTop: 8 }}>No specs or repository snapshots imported yet.</p>}
    </section>
  </main>
}
