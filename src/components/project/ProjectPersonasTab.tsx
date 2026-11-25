import { useEffect, useState } from 'react'
import { registerPersona, removePersona } from '../../actions.ts'
import type { PersonaAuthKind, PersonaLoginAdapter, PublicPersona } from '../../domain.ts'
import { FormError, useAction } from '../common.tsx'
import { parseCurlOrHeader } from '../curl-parser.ts'
import type { PersonaTestState, ProjectLoaderData } from './types.ts'
import { formatPersonaAuthBadge, LOGIN_URL_PLACEHOLDERS, safeHost } from './types.ts'

interface Props {
  data: ProjectLoaderData
  personaTests: Record<string, PersonaTestState>
  onTestPersona: (persona: PublicPersona) => void
  onPersonaCreated: (created: { id: string; handle: string }) => void
}

export function ProjectPersonasTab({ data, personaTests, onTestPersona, onPersonaCreated }: Props) {
  const { project, personas } = data
  const [modalOpen, setModalOpen] = useState(false)
  const [authKind, setAuthKind] = useState<PersonaAuthKind>('login')
  const [loginAdapter, setLoginAdapter] = useState<PersonaLoginAdapter>('auto')
  const [loginEmail, setLoginEmail] = useState('')
  const [loginUrl, setLoginUrl] = useState('')
  const [handle, setHandle] = useState('')
  const [roleLabel, setRoleLabel] = useState('')
  const [headerName, setHeaderName] = useState('')
  const [origins, setOrigins] = useState(() => project.seeds.join('\n'))
  const [secret, setSecret] = useState('')
  const [canaries, setCanaries] = useState('')
  const [curlPaste, setCurlPaste] = useState('')
  const [curlNote, setCurlNote] = useState('')
  const [notice, setNotice] = useState('')
  const personaAction = useAction()

  useEffect(() => {
    if (!modalOpen) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setModalOpen(false) }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [modalOpen])

  function resetForm() {
    setHandle('')
    setRoleLabel('')
    setHeaderName('')
    setLoginAdapter('auto')
    setLoginEmail('')
    setLoginUrl('')
    setOrigins(project.seeds.join('\n'))
    setSecret('')
    setCanaries('')
    setCurlPaste('')
    setCurlNote('')
  }

  function prefillPair(which: 'user_a' | 'user_b') {
    setHandle(which)
    setRoleLabel(which === 'user_a' ? 'User A (Control / Owner)' : 'User B (Cross-User Probe)')
    setAuthKind('login')
    setLoginAdapter('auto')
    setOrigins(project.seeds.join('\n'))
    setSecret('')
    setCurlNote('')
  }

  function applyCurlParse(rawText: string) {
    const parsed = parseCurlOrHeader(rawText)
    if (!parsed) {
      setCurlNote('Could not detect a Cookie:, Authorization: Bearer, or custom auth header.')
      return
    }
    setAuthKind(parsed.authKind)
    if (parsed.headerName) setHeaderName(parsed.headerName)
    if (parsed.origin && !origins.includes(parsed.origin)) {
      setOrigins(prev => prev.trim() ? `${prev.trim()}\n${parsed.origin}` : parsed.origin!)
    }
    setSecret(parsed.secret)
    setCurlPaste('')
    setCurlNote(parsed.summary)
  }

  return <section aria-label="Persona vault">
    <div className="pw-sec-head">
      <div>
        <h2>Persona vault <span className="muted num">({personas.length})</span></h2>
        <p>Opaque test accounts for Tier 2/3 validation. Secrets are stored locally at 0600 and injected only on allowlisted origins.</p>
      </div>
      <div className="pw-sec-actions">
        <button type="button" className="pw-btn primary" onClick={() => { setModalOpen(true); setNotice('') }}>
          Add persona
        </button>
      </div>
    </div>

    {notice && <p role="status" className="notice">{notice}</p>}

    {personas.length > 0 ? (
      <div className="pw-table-wrap">
        {personas.map(persona => {
          const test = personaTests[persona.id]
          return <div key={persona.id} className="pw-row">
            <div className="pw-row-main">
              <div className="pw-row-title">
                <strong className="mono">{persona.handle}</strong>
                <span className="pw-tag accent">{persona.roleLabel}</span>
                <span className="pw-tag solid">{formatPersonaAuthBadge(persona)}</span>
                {test && (
                  <span className={`pw-tag ${test.status === 'ok' ? 'ok' : test.status === 'warn' ? 'warn' : test.status === 'error' ? 'bad' : 'solid'}`}>
                    {test.message}
                  </span>
                )}
              </div>
              <div className="pw-row-sub">
                Allowlist: {persona.originAllowlist.map(safeHost).join(', ')}
                {persona.canaryMarkers.length > 0 && ` · ${persona.canaryMarkers.length} canary ${persona.canaryMarkers.length === 1 ? 'marker' : 'markers'}`}
              </div>
            </div>
            <div className="pw-row-right">
              <button
                type="button"
                className="pw-btn ghost"
                disabled={test?.status === 'testing'}
                onClick={() => onTestPersona(persona)}
              >
                {test?.status === 'testing' ? 'Testing…' : test?.status === 'ok' ? 'Test Auth ✓' : 'Test Auth'}
              </button>
              <button
                type="button"
                className="pw-btn ghost danger"
                disabled={personaAction.pending}
                onClick={() => {
                  void personaAction.submit(() => removePersona({ data: {
                    requestId: crypto.randomUUID(),
                    projectId: project.id,
                    personaId: persona.id,
                  } }), () => setNotice(`Removed persona "${persona.handle}".`))
                }}
              >
                Delete
              </button>
            </div>
          </div>
        })}
      </div>
    ) : (
      <div className="pw-empty">
        <p>No personas configured yet. Add User A &amp; User B for authenticated BOLA/IDOR checks.</p>
        <button type="button" className="pw-btn primary" onClick={() => setModalOpen(true)}>Add first persona</button>
      </div>
    )}

    {modalOpen && <div
      className="pw-overlay"
      role="dialog"
      aria-modal="true"
      aria-label="Add test persona"
      onMouseDown={e => { if (e.target === e.currentTarget) setModalOpen(false) }}
    >
      <form
        className="pw-modal"
        onSubmit={event => {
          event.preventDefault()
          const allowlist = origins.split(/[\s,]+/).filter(Boolean)
          const canaryMarkers = canaries.split(',').map(s => s.trim()).filter(Boolean)
          const headerNameRaw = headerName.trim()
          const loginUrlRaw = loginUrl.trim()
          void personaAction.submit(() => registerPersona({ data: {
            requestId: crypto.randomUUID(),
            projectId: project.id,
            handle: handle.trim(),
            roleLabel: roleLabel.trim(),
            originAllowlist: allowlist,
            authKind,
            ...(authKind === 'header' && headerNameRaw ? { headerName: headerNameRaw } : {}),
            ...(authKind === 'login' ? {
              loginConfig: {
                adapter: loginAdapter,
                email: loginEmail.trim(),
                ...(loginUrlRaw ? { loginUrl: loginUrlRaw } : {}),
              },
            } : {}),
            secret,
            canaryMarkers,
          } }), created => {
            resetForm()
            setModalOpen(false)
            setNotice(`Saved persona "${created.handle}". Secret stored in local 0600 vault.`)
            onPersonaCreated(created)
          })
        }}
      >
        <div className="pw-sheet-h">
          <span>Add test persona</span>
          <div className="pw-sec-actions">
            <button type="button" className="pw-btn ghost" onClick={() => prefillPair('user_a')}>Prefill User A</button>
            <button type="button" className="pw-btn ghost" onClick={() => prefillPair('user_b')}>Prefill User B</button>
            <button type="button" className="pw-btn ghost" onClick={() => setModalOpen(false)}>Close</button>
          </div>
        </div>
        <div className="pw-sheet-b">
          {authKind !== 'login' && <div style={{ display: 'grid', gap: 6 }}>
            <div style={{ display: 'flex', gap: 6 }}>
              <input
                className="pw-in mono"
                value={curlPaste}
                onChange={e => setCurlPaste(e.target.value)}
                onPaste={e => {
                  const pasted = e.clipboardData.getData('text')
                  if (pasted) {
                    e.preventDefault()
                    applyCurlParse(pasted)
                  }
                }}
                placeholder="Paste cURL or Cookie / Authorization header to auto-extract credentials…"
              />
              <button type="button" className="pw-btn" onClick={() => applyCurlParse(curlPaste)} disabled={!curlPaste.trim()}>
                Parse cURL
              </button>
            </div>
            {curlNote && <span className="muted" style={{ fontSize: 11.5 }}>{curlNote}</span>}
          </div>}

          <div className="pw-grid-2">
            <label className="pw-fld">Handle (lowercase, opaque to workers)
              <input className="pw-in mono" name="handle" required pattern="[a-z0-9][a-z0-9_-]{0,47}" placeholder="tenant_a"
                value={handle} onChange={e => setHandle(e.target.value)} />
            </label>
            <label className="pw-fld">Role label
              <input className="pw-in" name="roleLabel" required maxLength={160} placeholder="Standard tenant member"
                value={roleLabel} onChange={e => setRoleLabel(e.target.value)} />
            </label>
          </div>

          <label className="pw-fld">Origin allowlist (one per line or comma-separated)
            <textarea className="pw-textarea mono" name="originAllowlist" rows={2} required
              value={origins} onChange={e => setOrigins(e.target.value)} />
          </label>

          <div className="pw-grid-2">
            <label className="pw-fld">Authentication kind
              <select className="pw-select" name="authKind" value={authKind} onChange={e => setAuthKind(e.target.value as PersonaAuthKind)}>
                <option value="login">Email + Password (auto-login &amp; refresh)</option>
                <option value="cookie">Session cookie (Cookie: …)</option>
                <option value="bearer">Bearer token (Authorization: Bearer …)</option>
                <option value="header">Custom request header</option>
              </select>
            </label>
            {authKind === 'header' && <label className="pw-fld">Header name
              <input className="pw-in mono" name="headerName" required pattern="[A-Za-z0-9-]{1,64}" placeholder="X-Api-Key"
                value={headerName} onChange={e => setHeaderName(e.target.value)} />
            </label>}
          </div>

          {authKind === 'login' ? <>
            <div className="pw-grid-2">
              <label className="pw-fld">Email
                <input className="pw-in" name="loginEmail" type="email" required maxLength={320} autoComplete="off"
                  value={loginEmail} onChange={e => setLoginEmail(e.target.value)} placeholder="guardian-a@example.com" />
              </label>
              <label className="pw-fld">Password
                <input className="pw-in" name="secret" type="password" required maxLength={4096} autoComplete="off"
                  value={secret} onChange={e => setSecret(e.target.value)} placeholder="Stored in local 0600 vault" />
              </label>
            </div>
            <div className="pw-grid-2">
              <label className="pw-fld">Auth method
                <select className="pw-select" name="loginAdapter" value={loginAdapter} onChange={e => setLoginAdapter(e.target.value as PersonaLoginAdapter)}>
                  <option value="auto">Auto-detect</option>
                  <option value="clerk">Clerk (auto-refresh 60s JWT)</option>
                  <option value="json">JSON API / Better Auth</option>
                  <option value="supabase">Supabase Auth</option>
                  <option value="form">Login Form (Browser)</option>
                </select>
              </label>
              <label className="pw-fld">Login URL (optional)
                <input className="pw-in" name="loginUrl" type="url" maxLength={500} autoComplete="off"
                  value={loginUrl} onChange={e => setLoginUrl(e.target.value)} placeholder={LOGIN_URL_PLACEHOLDERS[loginAdapter]} />
              </label>
            </div>
          </> : (
            <label className="pw-fld">Credential secret
              <input className="pw-in" name="secret" type="password" required maxLength={4096} autoComplete="off"
                value={secret} onChange={e => setSecret(e.target.value)} placeholder="Never displayed back after saving" />
            </label>
          )}

          <label className="pw-fld">Canary markers (optional, comma-separated)
            <input className="pw-in mono" name="canaryMarkers" value={canaries} onChange={e => setCanaries(e.target.value)}
              placeholder="tenant-a-canary@example.test, org_alpha_001" />
            <small>Strings that indicate cross-tenant data leakage if seen by another persona.</small>
          </label>
          <FormError error={personaAction.error} />
        </div>
        <div className="pw-sheet-f">
          <span className="hint">Stored in local 0600 vault; never enters LLM prompts.</span>
          <button type="button" className="pw-btn ghost" onClick={() => setModalOpen(false)}>Cancel</button>
          <button type="submit" className="pw-btn primary" disabled={personaAction.pending}>Save persona</button>
        </div>
      </form>
    </div>}
  </section>
}
