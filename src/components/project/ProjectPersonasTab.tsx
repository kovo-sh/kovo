import { useEffect, useState } from 'react'
import { registerPersona, removePersona } from '../../actions.ts'
import type { PersonaAuthKind, PersonaLoginAdapter, PublicPersona } from '../../domain.ts'
import { FormError, useAction } from '../common.tsx'
import { parseCurlOrHeader } from '../curl-parser.ts'
import { Icon } from '../run/icons.tsx'
import type { PersonaTestState, ProjectLoaderData } from './types.ts'
import { formatPersonaAuthBadge, LOGIN_URL_PLACEHOLDERS, safeHost } from './types.ts'

interface Props {
  data: ProjectLoaderData
  personaTests: Record<string, PersonaTestState>
  onTestPersona: (persona: PublicPersona) => void
  onPersonaCreated: (created: { id: string; handle: string }) => void
}

function CrossAccountEmptySvg() {
  return (
    <svg
      className="pw-empty-art"
      width="180"
      height="88"
      viewBox="0 0 180 88"
      fill="none"
      aria-hidden="true"
    >
      {/* Left card: User A */}
      <rect
        x="4"
        y="14"
        width="68"
        height="60"
        rx="8"
        fill="var(--pw-panel)"
        stroke="var(--pw-line-2)"
        strokeWidth="1.2"
      />
      <circle
        cx="19"
        cy="31"
        r="7.5"
        fill="var(--pw-accent-soft)"
        stroke="var(--pw-accent-line)"
        strokeWidth="1.1"
      />
      <circle cx="19" cy="29.3" r="2.1" stroke="var(--pw-accent)" strokeWidth="1.2" />
      <path
        d="M15.4 35.1c.65-1.75 1.9-2.55 3.6-2.55s2.95.8 3.6 2.55"
        stroke="var(--pw-accent)"
        strokeWidth="1.2"
        strokeLinecap="round"
      />
      <text
        x="31"
        y="34"
        fill="var(--pw-fg)"
        fontSize="9.5"
        fontWeight="600"
        fontFamily="inherit"
      >
        User A
      </text>
      <rect x="13" y="47" width="46" height="4.5" rx="2.25" fill="var(--pw-line-2)" />
      <rect x="13" y="56" width="31" height="4.5" rx="2.25" fill="var(--pw-line)" />

      {/* Right card: User B */}
      <rect
        x="108"
        y="14"
        width="68"
        height="60"
        rx="8"
        fill="var(--pw-panel)"
        stroke="var(--pw-line-2)"
        strokeWidth="1.2"
      />
      <circle
        cx="123"
        cy="31"
        r="7.5"
        fill="var(--pw-sunk)"
        stroke="var(--pw-line-strong)"
        strokeWidth="1.1"
      />
      <circle cx="123" cy="29.3" r="2.1" stroke="var(--pw-fg-2)" strokeWidth="1.2" />
      <path
        d="M119.4 35.1c.65-1.75 1.9-2.55 3.6-2.55s2.95.8 3.6 2.55"
        stroke="var(--pw-fg-2)"
        strokeWidth="1.2"
        strokeLinecap="round"
      />
      <text
        x="135"
        y="34"
        fill="var(--pw-fg)"
        fontSize="9.5"
        fontWeight="600"
        fontFamily="inherit"
      >
        User B
      </text>
      <rect x="117" y="47" width="46" height="4.5" rx="2.25" fill="var(--pw-line-2)" />
      <rect x="117" y="56" width="34" height="4.5" rx="2.25" fill="var(--pw-line)" />

      {/* Center vertical isolation boundary */}
      <line
        x1="90"
        y1="6"
        x2="90"
        y2="24"
        stroke="var(--pw-line-strong)"
        strokeWidth="1.25"
        strokeDasharray="3 3"
        strokeLinecap="round"
      />
      <line
        x1="90"
        y1="64"
        x2="90"
        y2="82"
        stroke="var(--pw-line-strong)"
        strokeWidth="1.25"
        strokeDasharray="3 3"
        strokeLinecap="round"
      />

      {/* Shield + lock emblem on the boundary */}
      <path
        d="M90 26L102 30.8V42.4C102 50.6 96.9 56.8 90 60.5C83.1 56.8 78 50.6 78 42.4V30.8L90 26Z"
        fill="var(--pw-panel)"
        stroke="var(--pw-accent)"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
      <path
        d="M90 28.6L99.5 32.4V42.2C99.5 48.9 95.4 54.1 90 57.3C84.6 54.1 80.5 48.9 80.5 42.2V32.4L90 28.6Z"
        fill="var(--pw-accent-soft)"
      />
      <rect
        x="85.8"
        y="41.8"
        width="8.4"
        height="6.8"
        rx="1.6"
        fill="var(--pw-accent)"
      />
      <path
        d="M87.4 41.8V39.6A2.6 2.6 0 0 1 92.6 39.6V41.8"
        stroke="var(--pw-accent)"
        strokeWidth="1.4"
        strokeLinecap="round"
      />
      <circle cx="90" cy="45.1" r="1" fill="var(--pw-panel)" />
    </svg>
  )
}

export function ProjectPersonasTab({ data, personaTests, onTestPersona, onPersonaCreated }: Props) {
  const { project, personas } = data
  const [modalOpen, setModalOpen] = useState(false)
  const [personaToDelete, setPersonaToDelete] = useState<PublicPersona | null>(null)
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
    if (!modalOpen && !personaToDelete) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape' || personaAction.pending) return
      e.preventDefault()
      if (personaToDelete) setPersonaToDelete(null)
      else setModalOpen(false)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [modalOpen, personaToDelete, personaAction.pending])

  function deriveHandle(label: string): string {
    return label
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9_-]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 48)
  }

  function handleAccountLabel(value: string) {
    setRoleLabel(value)
    setHandle(deriveHandle(value))
  }

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

  return <section aria-label="Test accounts">
    <div className="pw-sec-head">
      <div>
        <h2>Test accounts <span className="muted num">({personas.length})</span></h2>
        <p>Add test logins so Kovo Hunter can scan behind sign-in and check whether one user can reach another user&apos;s data. Credentials stay encrypted on your machine.</p>
      </div>
      {personas.length > 0 && (
        <div className="pw-sec-actions">
          <button type="button" className="pw-btn primary" onClick={() => { setModalOpen(true); setNotice('') }}>
            Add test account
          </button>
        </div>
      )}
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
                {test?.status === 'testing' ? 'Verifying…' : test?.status === 'ok' ? 'Verify sign-in ✓' : 'Verify sign-in'}
              </button>
              <button
                type="button"
                className="pw-btn ghost danger"
                disabled={personaAction.pending}
                onClick={() => setPersonaToDelete(persona)}
              >
                Delete
              </button>
            </div>
          </div>
        })}
      </div>
    ) : (
      <div className="pw-empty-card">
        <CrossAccountEmptySvg />
        <h3>No test accounts yet</h3>
        <p>Add one login to scan signed-in views, or two logins (User A &amp; User B) to test cross-account isolation.</p>
        <button type="button" className="pw-btn primary" onClick={() => { setModalOpen(true); setNotice('') }}>
          Add test account
        </button>
      </div>
    )}

    {modalOpen && <div
      className="pw-overlay"
      role="dialog"
      aria-modal="true"
      aria-label="Add test account"
      onMouseDown={e => {
        if (e.target === e.currentTarget && !personaAction.pending) setModalOpen(false)
      }}
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
            setNotice(`Saved test account "${created.handle}". Credentials stay encrypted on your machine.`)
            onPersonaCreated(created)
          })
        }}
      >
        <div className="pw-sheet-h">
          <span>Add test account</span>
          <button
            type="button"
            className="pw-btn ghost"
            style={{ padding: '0 6px' }}
            onClick={() => setModalOpen(false)}
            disabled={personaAction.pending}
            aria-label="Close"
          >
            <Icon name="close" size={14} />
          </button>
        </div>
        <div className="pw-sheet-b">
          <div className="pw-persona-quickfill">
            <span className="muted">Quick fill</span>
            <button type="button" className="pw-chip" onClick={() => prefillPair('user_a')}>User A</button>
            <button type="button" className="pw-chip" onClick={() => prefillPair('user_b')}>User B</button>
          </div>

          <div className="pw-grid-2">
            <label className="pw-fld">Account label
              <input
                className="pw-in"
                name="roleLabel"
                required
                maxLength={160}
                placeholder="User A (Owner)"
                value={roleLabel}
                onChange={e => handleAccountLabel(e.target.value)}
              />
              <small>Used as the readable name; the handle is derived automatically.</small>
            </label>
            <label className="pw-fld">Sign-in method
              <select className="pw-select" name="authKind" value={authKind} onChange={e => setAuthKind(e.target.value as PersonaAuthKind)}>
                <option value="login">Email + Password (auto-login &amp; refresh)</option>
                <option value="cookie">Session cookie (Cookie: …)</option>
                <option value="bearer">Bearer token (Authorization: Bearer …)</option>
                <option value="header">Custom request header</option>
              </select>
            </label>
          </div>

          {authKind !== 'login' && <div className="pw-curl-helper">
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
                Parse
              </button>
            </div>
            {curlNote && <span className="muted" style={{ fontSize: 11.5 }}>{curlNote}</span>}
          </div>}

          {authKind === 'login' ? (
            <div className="pw-grid-2">
              <label className="pw-fld">Email
                <input className="pw-in" name="loginEmail" type="email" required maxLength={320} autoComplete="off"
                  value={loginEmail} onChange={e => setLoginEmail(e.target.value)} placeholder="test-a@example.com" />
              </label>
              <label className="pw-fld">Password
                <input className="pw-in" name="secret" type="password" required maxLength={4096} autoComplete="off"
                  value={secret} onChange={e => setSecret(e.target.value)} placeholder="Encrypted on your machine" />
              </label>
            </div>
          ) : (
            <label className="pw-fld">Credential secret
              <input className="pw-in" name="secret" type="password" required maxLength={4096} autoComplete="off"
                value={secret} onChange={e => setSecret(e.target.value)} placeholder="Never displayed back after saving" />
            </label>
          )}

          <details className="pw-disclosure pw-persona-advanced">
            <summary>Advanced configuration</summary>
            <div className="pw-disclosure-body">
              <div className="pw-grid-2">
                <label className="pw-fld">Handle (lowercase identifier)
                  <input className="pw-in mono" name="handle" required pattern="[a-z0-9][a-z0-9_-]{0,47}" placeholder="user-a"
                    value={handle} onChange={e => setHandle(e.target.value)} />
                </label>
                {authKind === 'login' ? (
                  <label className="pw-fld">Auth provider
                    <select className="pw-select" name="loginAdapter" value={loginAdapter} onChange={e => setLoginAdapter(e.target.value as PersonaLoginAdapter)}>
                      <option value="auto">Auto-detect</option>
                      <option value="clerk">Clerk (auto-refresh 60s JWT)</option>
                      <option value="json">JSON API / Better Auth</option>
                      <option value="supabase">Supabase Auth</option>
                      <option value="form">Login Form (Browser)</option>
                    </select>
                  </label>
                ) : authKind === 'header' ? (
                  <label className="pw-fld">Header name
                    <input className="pw-in mono" name="headerName" required pattern="[A-Za-z0-9-]{1,64}" placeholder="X-Api-Key"
                      value={headerName} onChange={e => setHeaderName(e.target.value)} />
                  </label>
                ) : null}
              </div>

              {authKind === 'login' && (
                <label className="pw-fld">Login URL (optional)
                  <input className="pw-in" name="loginUrl" type="url" maxLength={500} autoComplete="off"
                    value={loginUrl} onChange={e => setLoginUrl(e.target.value)} placeholder={LOGIN_URL_PLACEHOLDERS[loginAdapter]} />
                </label>
              )}

              <label className="pw-fld">Allowed sites (one per line or comma-separated)
                <textarea className="pw-textarea mono" name="originAllowlist" rows={2} required
                  value={origins} onChange={e => setOrigins(e.target.value)} />
              </label>

              <label className="pw-fld">Leak detection markers (optional, comma-separated)
                <input className="pw-in mono" name="canaryMarkers" value={canaries} onChange={e => setCanaries(e.target.value)}
                  placeholder="tenant-a-canary@example.test, org_alpha_001" />
                <small>Strings that indicate cross-tenant data leakage if seen by another test account.</small>
              </label>
            </div>
          </details>

          <FormError error={personaAction.error} />
        </div>
        <div className="pw-sheet-f">
          <span className="hint">Credentials stay encrypted on your machine and are never sent to AI models.</span>
          <button type="button" className="pw-btn ghost" disabled={personaAction.pending} onClick={() => setModalOpen(false)}>Cancel</button>
          <button type="submit" className="pw-btn primary" disabled={personaAction.pending}>Save test account</button>
        </div>
      </form>
    </div>}

    {personaToDelete && (
      <div
        className="pw-overlay"
        onMouseDown={e => {
          if (e.target === e.currentTarget && !personaAction.pending) setPersonaToDelete(null)
        }}
      >
        <div className="pw-modal" style={{ width: 440 }} role="alertdialog" aria-modal="true" aria-labelledby="pw-del-persona-title">
          <div className="pw-modal-hdr">
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
              <Icon name="trash" size={15} style={{ color: 'var(--pw-bad)' }} />
              <span id="pw-del-persona-title">Delete test account</span>
            </span>
            <button
              type="button"
              className="pw-btn ghost"
              style={{ padding: '0 6px' }}
              disabled={personaAction.pending}
              onClick={() => setPersonaToDelete(null)}
              aria-label="Close"
            >
              <Icon name="close" size={14} />
            </button>
          </div>
          <div className="pw-modal-body">
            <p className="dim" style={{ margin: 0, fontSize: 12.5 }}>
              Remove <strong style={{ color: 'var(--pw-fg)' }}>{personaToDelete.handle}</strong> and its saved credential from this project. This cannot be undone.
            </p>
            <div className="pw-confirm-summary">
              <div className="pw-confirm-goal">{personaToDelete.roleLabel}</div>
              <div className="pw-confirm-meta num">
                <span className="pw-tag solid">{formatPersonaAuthBadge(personaToDelete)}</span>
                <span className="pw-tag solid">{personaToDelete.originAllowlist.map(safeHost).join(', ') || 'No sites listed'}</span>
              </div>
            </div>
            {personaAction.error && <p className="err" role="alert" style={{ margin: 0 }}>{personaAction.error}</p>}
          </div>
          <div className="pw-modal-ftr">
            <button type="button" className="pw-btn ghost" disabled={personaAction.pending} onClick={() => setPersonaToDelete(null)}>
              Cancel
            </button>
            <button
              type="button"
              className="pw-btn danger-solid"
              disabled={personaAction.pending}
              onClick={() => {
                const target = personaToDelete
                void personaAction.submit(() => removePersona({ data: {
                  requestId: crypto.randomUUID(),
                  projectId: project.id,
                  personaId: target.id,
                } }), () => {
                  setPersonaToDelete(null)
                  setNotice(`Removed test account "${target.handle}".`)
                })
              }}
            >
              <Icon name="trash" size={13} />
              {personaAction.pending ? 'Deleting…' : 'Delete account'}
            </button>
          </div>
        </div>
      </div>
    )}
  </section>
}
