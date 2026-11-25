// Consent sheet for waiting runs (rendered by Overview), and the scope
// editor it shares with the header's "Edit scope" overlay.
//
// Real commands:
//   phase `consent` → { action: 'discover', consent: true }      (start discovery on the project seeds)
//   phase `review`  → { action: 'scope', assetIds, expectedScopeRevision, consent: true, tier, policy, budget… }
//   later phases    → the same `scope` command saves a scope revision; `candidate` adds a host for review.
// Approving goes through the shared decision store: it stamps immediately and
// sends when the 6 s undo window closes.
import { Link } from '@tanstack/react-router'
import { useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { approvalPolicies, canReviewScope, maxBudgetRequests, maxRpsPerOriginCeiling, maxScopeHosts } from '../../../domain.ts'
import type { ApprovalPolicy, CapabilityTier } from '../../../domain.ts'
import { approvalPolicyMeta, capabilityTierMeta } from '../../run-state.ts'
import { useRun } from '../data.tsx'
import type { Command } from '../data.tsx'
import { useDecisions } from '../decisions.tsx'
import { consentKey } from '../model.ts'
import { Kbd } from '../display.tsx'
import { cap, fmtN, fmtUsd, host, plural, words } from '../format.ts'
import { StatusGlyph } from '../glyphs.tsx'
import { Icon } from '../icons.tsx'
import { useShortcuts } from '../keyboard.tsx'
import { TIER_SHORT } from '../meta.ts'
import { useOverlays } from '../overlays.tsx'
import { LabPanel } from './lab.tsx'
import { useToast } from '../toast.tsx'

interface Draft {
  assetIds: string[]
  capabilityTier: CapabilityTier
  approvalPolicy: ApprovalPolicy
  approvedPersonaIds: string[]
  budgetUsd: number
  budgetRequests: number
  maxRpsPerOrigin: number
}

/** Hosts and default selection for the scope sheet, per phase. */
function useScopeModel() {
  const { detail } = useRun()
  const r = detail.run
  const p = detail.project
  return useMemo(() => {
    const discovery = r.phase === 'consent'
    const hosts = discovery
      ? p.seeds.map(s => ({ id: s, origin: s, thirdParty: false, source: 'Project seed', externalCname: null as string | null }))
      : r.candidates.map(c => ({
        id: c.id,
        origin: c.origin,
        thirdParty: c.thirdParty,
        source: c.source,
        externalCname: c.dnsSource?.externalAliases?.[0] ?? null,
      }))
    const defaults = r.scopeRevision > 0 ? [...r.approved]
      : r.candidates.filter(a => !a.thirdParty && (p.defaultScope.length ? p.defaultScope.includes(a.origin) : !a.dnsSource)).map(a => a.id)
    return { discovery, hosts, defaults }
  }, [r, p])
}

function initialDraft(r: ReturnType<typeof useRun>['detail']['run'], defaults: string[]): Draft {
  return {
    assetIds: defaults, capabilityTier: r.capabilityTier, approvalPolicy: r.approvalPolicy ?? 'auto_review',
    approvedPersonaIds: [...r.approvedPersonaIds], budgetUsd: r.budgetUsd, budgetRequests: r.budgetRequests, maxRpsPerOrigin: r.maxRpsPerOrigin,
  }
}

function scopeCommand(r: ReturnType<typeof useRun>['detail']['run'], d: Draft, saveProject = false): Command {
  return {
    action: 'scope', assetIds: d.assetIds, expectedScopeRevision: r.scopeRevision, consent: true, saveProject,
    capabilityTier: d.capabilityTier, approvalPolicy: d.approvalPolicy,
    approvedPersonaIds: d.capabilityTier >= 2 ? d.approvedPersonaIds : [],
    budgetUsd: d.budgetUsd, budgetRequests: d.budgetRequests, maxRpsPerOrigin: d.maxRpsPerOrigin,
  }
}

/**
 * The scope card: capability / budget / approvals / rate / workers / personas,
 * the host grid, and a footer with the primary action. Editable when `editing`.
 */
function ScopeCard({ editing, draft, setDraft, footer }: {
  editing: boolean
  draft: Draft
  setDraft: (fn: (d: Draft) => Draft) => void
  footer: ReactNode
}) {
  const { detail } = useRun()
  const r = detail.run
  const { discovery, hosts } = useScopeModel()
  const selected = new Set(draft.assetIds)
  const shownHosts = editing || discovery ? hosts : hosts.filter(h => selected.has(h.id))
  const kv = (k: string, v: ReactNode) => <div><div className="k">{k}</div><div className="v">{v}</div></div>
  const canEditConfig = editing && !discovery
  return <div className="sheet">
    <div className="sheet-h">
      <Icon name="globe" /><span>Proposed scope</span>
      <span className="muted num">{discovery ? plural(hosts.length, 'host') + ' from project seeds' : `${selected.size} of ${plural(hosts.length, 'discovered host')}`}</span>
      {editing && !discovery && <span style={{ marginLeft: 'auto', display: 'flex', gap: 4 }}>
        <button type="button" className="btn ghost" style={{ height: 22 }} onClick={() => setDraft(d => ({ ...d, assetIds: hosts.filter(h => !h.thirdParty).slice(0, maxScopeHosts).map(h => h.id) }))}>First-party</button>
        <button type="button" className="btn ghost" style={{ height: 22 }} onClick={() => setDraft(d => ({ ...d, assetIds: [] }))}>Clear</button>
      </span>}
    </div>
    <div className="kv num">
      {kv('Capability', canEditConfig
        ? <select value={draft.capabilityTier} onChange={e => setDraft(d => ({ ...d, capabilityTier: Number(e.target.value) as CapabilityTier }))} aria-label="Capability tier">
          {([0, 1, 2, 3] as const).map(t => <option key={t} value={t}>{capabilityTierMeta[t].short}</option>)}
        </select>
        : <>Tier {draft.capabilityTier} · {TIER_SHORT[draft.capabilityTier]}</>)}
      {kv('Budget', canEditConfig
        ? <span style={{ display: 'flex', gap: 4 }}>
          <input className="field-in num" type="number" min={0.1} max={500} step="any" value={draft.budgetUsd} aria-label="Budget USD" style={{ width: 74, height: 26 }} onChange={e => setDraft(d => ({ ...d, budgetUsd: Number(e.target.value) }))} />
          <input className="field-in num" type="number" min={0} max={maxBudgetRequests} step={1} value={draft.budgetRequests} aria-label="Request cap (0 = uncapped)" title="Request cap (0 = uncapped)" style={{ width: 74, height: 26 }} onChange={e => setDraft(d => ({ ...d, budgetRequests: Number(e.target.value) }))} />
        </span>
        : <>{fmtUsd(draft.budgetUsd)} · {draft.budgetRequests ? fmtN(draft.budgetRequests) + ' requests' : 'uncapped requests'}</>)}
      {kv('Approvals', canEditConfig && draft.capabilityTier === 3
        ? <select value={draft.approvalPolicy} onChange={e => setDraft(d => ({ ...d, approvalPolicy: e.target.value as ApprovalPolicy }))} aria-label="Approval policy">
          {approvalPolicies.map(p => <option key={p} value={p}>{approvalPolicyMeta[p].label}</option>)}
        </select>
        : <>{draft.capabilityTier === 3 ? approvalPolicyMeta[draft.approvalPolicy].label : cap(draft.approvalPolicy)}</>)}
      {kv('Rate limit', canEditConfig
        ? <input className="field-in num" type="number" min={1} max={maxRpsPerOriginCeiling} step={1} value={draft.maxRpsPerOrigin} aria-label="Requests per second per origin" style={{ width: 74, height: 26 }} onChange={e => setDraft(d => ({ ...d, maxRpsPerOrigin: Number(e.target.value) }))} />
        : <>{draft.maxRpsPerOrigin} req/s per origin</>)}
      {kv('Workers', <>{r.workerConcurrency} concurrent · {r.workerMaxTurns} turns</>)}
      {kv('Test accounts', draft.approvedPersonaIds.length && draft.capabilityTier >= 2 ? plural(draft.approvedPersonaIds.length, 'test account') : 'None (anonymous)')}
    </div>
    {canEditConfig && detail.personas.length > 0 && <div className="sheet-x">
      <span className="muted">Bind test accounts{draft.capabilityTier < 2 ? ' (Tier 2 or 3)' : ''}</span>
      {detail.personas.map(p => <label key={p.id} className="chk">
        <input type="checkbox" disabled={draft.capabilityTier < 2} checked={draft.approvedPersonaIds.includes(p.id)}
          onChange={e => setDraft(d => ({ ...d, approvedPersonaIds: e.target.checked ? [...d.approvedPersonaIds, p.id] : d.approvedPersonaIds.filter(x => x !== p.id) }))} />
        <b style={{ fontWeight: 500, color: 'var(--fg)' }}>{p.handle}</b> · {p.roleLabel}
      </label>)}
    </div>}
    {editing && !discovery
      ? <div className="hosts mono edit">
        {hosts.map(h => <label key={h.id} className={selected.has(h.id) ? '' : 'off'} title={`${h.origin} · ${h.source}`}>
          <input type="checkbox" aria-label={'Include ' + host(h.origin)} checked={selected.has(h.id)} onChange={e => setDraft(d => ({ ...d, assetIds: e.target.checked ? [...d.assetIds, h.id] : d.assetIds.filter(x => x !== h.id) }))} />
          <span>{host(h.origin)}</span>
          {h.thirdParty && <span className="third" title={h.externalCname ? `Third-party CNAME (${h.externalCname}) — unchecked by default` : 'Third-party host — unchecked by default'}>
            {h.externalCname ? `Third-party CNAME (${h.externalCname})` : '3P'}
          </span>}
        </label>)}
      </div>
      : <div className="hosts mono">
        {shownHosts.map(h => <span key={h.id} title={`${h.origin} · ${h.source}`}>{host(h.origin)}</span>)}
        {!shownHosts.length && <span style={{ color: 'var(--fg-3)' }}>No hosts selected.</span>}
      </div>}
    {editing && discovery && <div className="sheet-x"><span className="muted">Discovery runs on the project seeds. Hosts it finds come back here for scope review; edit the seeds on the <Link to="/projects/$projectId" params={{ projectId: detail.project.id }} style={{ textDecoration: 'underline' }}>project page</Link>.</span></div>}
    {footer}
  </div>
}

const STEPS: [string, string][] = [['Consent', 'Approve hosts, tier and budget.'], ['Threat model', 'Rank hosts by attack surface.'], ['Investigation', 'Workers probe through the broker.'], ['Verification', 'Zero-LLM replay of every finding.'], ['Report', 'Findings, coverage and gaps.']]

/** Overview for a waiting run: "Nothing has been sent yet." */
export function ConsentView() {
  const { detail } = useRun()
  const q = useDecisions()
  const r = detail.run
  const { discovery, hosts, defaults } = useScopeModel()
  const [editing, setEditing] = useState(false)
  const [draft, setDraftState] = useState<Draft>(() => initialDraft(r, defaults))
  const setDraft = (fn: (d: Draft) => Draft) => setDraftState(fn)
  const ck = consentKey(r)
  const decision = q.get(ck)
  const scoped = Boolean(decision)
  const nw = (r.goal || '').split(/\s+/).filter(Boolean).length
  const count = discovery ? hosts.length : draft.assetIds.length
  const overLimit = draft.assetIds.length > maxScopeHosts
  const canApprove = q.canAct(ck, 'scope') && (discovery || (count > 0 && !overLimit))

  const approve = () => {
    if (!canApprove) return
    const command: Command = discovery ? { action: 'discover', consent: true } : scopeCommand(r, draft)
    q.decide(ck, 'scope', {
      command,
      message: discovery ? `Discovery approved for ${plural(hosts.length, 'host')}` : `Scope approved for ${plural(count, 'host')} at Tier ${draft.capabilityTier}`,
    })
    setEditing(false)
  }
  useShortcuts([{ key: 'a', run: () => { if (!canApprove) return false; approve() } }])

  const eyebrow = scoped
    ? decision!.state === 'sent' ? 'Approved · the coordinator is starting' : 'Approved · sends when the undo window closes'
    : r.phase === 'review' ? 'Waiting on your scope approval' : 'Waiting on your consent'
  return <div className="consent"><div className="consent-in">
    <span className="eyebrow"><StatusGlyph status={scoped ? 'complete' : 'waiting'} />{eyebrow}</span>
    <div className="display">Nothing has been sent <em>yet.</em></div>
    <p className="lede">The coordinator received the goal “{r.goal}” and is holding until you approve the {discovery ? 'discovery' : 'scope'} below. No request leaves the broker before that.</p>
    {nw < 6 && <div className="callout"><Icon name="alert" /><div>This goal is {words(nw)} word{nw === 1 ? '' : 's'} long. The coordinator will plan broadly across all {plural(count, 'host')}. Sharpen it in the coordinator chat to focus the {fmtUsd(draft.budgetUsd)} budget.</div></div>}
    <ScopeCard editing={editing} draft={draft} setDraft={setDraft} footer={
      <div className="sheet-f">
        <span className="muted">{overLimit ? `Choose up to ${maxScopeHosts} hosts.` : draft.capabilityTier === 3 ? 'Tier 3 requests will still ask before sending.' : `Approving authorizes a scoped defensive assessment at Tier ${draft.capabilityTier}.`}</span>
        {scoped
          ? decision!.state !== 'sent' && <button type="button" className="btn" onClick={() => q.reopen(ck)}><Icon name="undo" />Undo</button>
          : <>
            <button type="button" className="btn ghost" onClick={() => { if (editing) setDraftState(initialDraft(r, defaults)); setEditing(!editing) }}>{editing ? 'Reset' : 'Edit scope'}</button>
            <button type="button" className="btn primary" disabled={!canApprove} onClick={approve}>
              Approve &amp; start<Kbd style={{ background: 'transparent', color: 'inherit', boxShadow: 'inset 0 0 0 1px currentColor', opacity: 0.7 }}>A</Kbd>
            </button>
          </>}
      </div>} />
    <div className="next">{STEPS.map((s, i) => <div key={s[0]} className={(scoped ? 1 : 0) === i ? 'cur' : ''}><b>{s[0]}</b>{s[1]}</div>)}</div>
    <LabPanel />
  </div></div>
}

/** Header "Edit scope" overlay for runs past consent: save a scope revision or add a candidate host. */
export function ScopeOverlay() {
  const { detail, send, pending } = useRun()
  const overlays = useOverlays()
  const toast = useToast()
  const r = detail.run
  const { discovery, defaults } = useScopeModel()
  const [draft, setDraftState] = useState<Draft>(() => initialDraft(r, defaults))
  const [saveProject, setSaveProject] = useState(false)
  const [adding, setAdding] = useState(false)
  const [origin, setOrigin] = useState('')
  const [source, setSource] = useState('')
  const [thirdParty, setThirdParty] = useState(false)
  const [err, setErr] = useState('')
  const editable = canReviewScope(r.phase, r.status) && !discovery
  useShortcuts([{ key: 'Escape', allowInInput: true, run: () => overlays.closeScope() }], { priority: 100, exclusive: true })
  const save = () => {
    const command = scopeCommand(r, draft, saveProject)
    overlays.closeScope()
    toast.undoable({ message: `Saving scope revision ${r.scopeRevision + 1} (${plural(draft.assetIds.length, 'host')})`, icon: 'globe', sub: 'Sends when this closes', commit: () => send(command) })
  }
  return <div className="overlay open" onMouseDown={e => { if (e.target === e.currentTarget) overlays.closeScope() }}>
    <div className="pal" role="dialog" aria-modal="true" aria-label="Edit scope" style={{ width: 720, maxHeight: '80vh', overflow: 'auto', padding: 0 }}>
      <ScopeCard editing={editable} draft={draft} setDraft={fn => setDraftState(fn)} footer={<>
        {adding && <form className="sheet-x" onSubmit={e => {
          e.preventDefault()
          setErr('')
          send({ action: 'candidate', candidate: { origin, source, thirdParty } }).then(() => { setAdding(false); setOrigin(''); setSource('') }, (x: unknown) => setErr(x instanceof Error ? x.message : 'Could not add the host'))
        }}>
          <span className="muted">Add a candidate host for scope review</span>
          <div style={{ display: 'flex', gap: 6 }}>
            <input className="field-in" required placeholder="docs.example.com" value={origin} onChange={e => setOrigin(e.target.value)} aria-label="Host" style={{ flex: 1 }} />
            <input className="field-in" required maxLength={160} placeholder="Source (e.g. service inventory)" value={source} onChange={e => setSource(e.target.value)} aria-label="Source" style={{ flex: 1 }} />
          </div>
          <label className="chk"><input type="checkbox" checked={thirdParty} onChange={e => setThirdParty(e.target.checked)} />Third-party service</label>
          {err && <span className="err-line">{err}</span>}
          <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}><button type="button" className="btn ghost" onClick={() => setAdding(false)}>Cancel</button><button type="submit" className="btn" disabled={pending > 0}>Add for review</button></div>
        </form>}
        <div className="sheet-f">
          {editable ? <label className="chk muted" style={{ marginRight: 'auto' }}><input type="checkbox" checked={saveProject} onChange={e => setSaveProject(e.target.checked)} />Save as the project default</label>
            : <span className="muted">{discovery ? 'Scope is reviewed after discovery.' : `Scope can’t change while the run is ${r.status}.`}</span>}
          {r.phase !== 'complete' && !discovery && !adding && <button type="button" className="btn ghost" onClick={() => setAdding(true)}><Icon name="plus" />Add host</button>}
          <button type="button" className="btn ghost" onClick={() => overlays.closeScope()}>Close</button>
          {editable && <button type="button" className="btn primary" disabled={!draft.assetIds.length || draft.assetIds.length > maxScopeHosts} onClick={save}>{r.phase === 'review' ? 'Approve scope' : 'Save scope revision'}</button>}
        </div>
      </>} />
    </div>
  </div>
}
