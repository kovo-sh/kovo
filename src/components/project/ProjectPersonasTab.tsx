import { useState } from 'react'
import { registerPersona, removePersona } from '../../actions.ts'
import type { PersonaAuthKind, PersonaLoginAdapter, PublicPersona } from '../../domain.ts'
import { FormError, useAction } from '../common.tsx'
import { parseCurlOrHeader } from '../curl-parser.ts'
import { Icon } from '../run/icons.tsx'
import { Badge } from '../ui/badge.tsx'
import { Button } from '../ui/button.tsx'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/dialog.tsx'
import { Disclosure, DisclosureContent, DisclosureTrigger } from '../ui/disclosure.tsx'
import { EmptyState } from '../ui/empty-state.tsx'
import { Input, NativeSelect, Textarea } from '../ui/input.tsx'
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
      className="block"
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
        fill="var(--panel)"
        stroke="var(--line-2)"
        strokeWidth="1.2"
      />
      <circle
        cx="19"
        cy="31"
        r="7.5"
        fill="var(--accent-soft)"
        stroke="var(--accent-line)"
        strokeWidth="1.1"
      />
      <circle cx="19" cy="29.3" r="2.1" stroke="var(--accent)" strokeWidth="1.2" />
      <path
        d="M15.4 35.1c.65-1.75 1.9-2.55 3.6-2.55s2.95.8 3.6 2.55"
        stroke="var(--accent)"
        strokeWidth="1.2"
        strokeLinecap="round"
      />
      <text
        x="31"
        y="34"
        fill="var(--fg)"
        fontSize="9.5"
        fontWeight="600"
        fontFamily="inherit"
      >
        User A
      </text>
      <rect x="13" y="47" width="46" height="4.5" rx="2.25" fill="var(--line-2)" />
      <rect x="13" y="56" width="31" height="4.5" rx="2.25" fill="var(--line)" />

      {/* Right card: User B */}
      <rect
        x="108"
        y="14"
        width="68"
        height="60"
        rx="8"
        fill="var(--panel)"
        stroke="var(--line-2)"
        strokeWidth="1.2"
      />
      <circle
        cx="123"
        cy="31"
        r="7.5"
        fill="var(--sunk)"
        stroke="var(--line-strong)"
        strokeWidth="1.1"
      />
      <circle cx="123" cy="29.3" r="2.1" stroke="var(--fg-2)" strokeWidth="1.2" />
      <path
        d="M119.4 35.1c.65-1.75 1.9-2.55 3.6-2.55s2.95.8 3.6 2.55"
        stroke="var(--fg-2)"
        strokeWidth="1.2"
        strokeLinecap="round"
      />
      <text
        x="135"
        y="34"
        fill="var(--fg)"
        fontSize="9.5"
        fontWeight="600"
        fontFamily="inherit"
      >
        User B
      </text>
      <rect x="117" y="47" width="46" height="4.5" rx="2.25" fill="var(--line-2)" />
      <rect x="117" y="56" width="34" height="4.5" rx="2.25" fill="var(--line)" />

      {/* Center vertical isolation boundary */}
      <line
        x1="90"
        y1="6"
        x2="90"
        y2="24"
        stroke="var(--line-strong)"
        strokeWidth="1.25"
        strokeDasharray="3 3"
        strokeLinecap="round"
      />
      <line
        x1="90"
        y1="64"
        x2="90"
        y2="82"
        stroke="var(--line-strong)"
        strokeWidth="1.25"
        strokeDasharray="3 3"
        strokeLinecap="round"
      />

      {/* Shield + lock emblem on the boundary */}
      <path
        d="M90 26L102 30.8V42.4C102 50.6 96.9 56.8 90 60.5C83.1 56.8 78 50.6 78 42.4V30.8L90 26Z"
        fill="var(--panel)"
        stroke="var(--accent)"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
      <path
        d="M90 28.6L99.5 32.4V42.2C99.5 48.9 95.4 54.1 90 57.3C84.6 54.1 80.5 48.9 80.5 42.2V32.4L90 28.6Z"
        fill="var(--accent-soft)"
      />
      <rect
        x="85.8"
        y="41.8"
        width="8.4"
        height="6.8"
        rx="1.6"
        fill="var(--accent)"
      />
      <path
        d="M87.4 41.8V39.6A2.6 2.6 0 0 1 92.6 39.6V41.8"
        stroke="var(--accent)"
        strokeWidth="1.4"
        strokeLinecap="round"
      />
      <circle cx="90" cy="45.1" r="1" fill="var(--panel)" />
    </svg>
  )
}

type PersonaSignInMethod = PersonaAuthKind | 'clerk_client'

export function ProjectPersonasTab({ data, personaTests, onTestPersona, onPersonaCreated }: Props) {
  const { project, personas } = data
  const [modalOpen, setModalOpen] = useState(false)
  const [personaToDelete, setPersonaToDelete] = useState<PublicPersona | null>(null)
  const [signInMethod, setSignInMethod] = useState<PersonaSignInMethod>('login')
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
  const isClerkClient = signInMethod === 'clerk_client'
  const effectiveAuthKind: PersonaAuthKind = isClerkClient ? 'login' : signInMethod

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
    setSignInMethod('login')
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
    setRoleLabel(which === 'user_a' ? 'User A (Control / Owner)' : 'User B (Cross-User)')
    if (!isClerkClient) {
      setSignInMethod('login')
      setLoginAdapter('auto')
    }
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
    setSignInMethod(parsed.authKind)
    if (parsed.headerName) setHeaderName(parsed.headerName)
    if (parsed.origin && !origins.includes(parsed.origin)) {
      setOrigins(prev => prev.trim() ? `${prev.trim()}\n${parsed.origin}` : parsed.origin!)
    }
    setSecret(parsed.secret)
    setCurlPaste('')
    setCurlNote(parsed.summary)
  }

  return (
    <section aria-label="Test accounts">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="m-0 text-[13px] font-semibold text-fg">
            Test accounts <span className="font-normal tabular-nums text-fg-subtle">({personas.length})</span>
          </h2>
          <p className="mt-0.5 text-[12px] text-fg-subtle">
            Add test logins so Kovo Hunter can scan behind sign-in and check whether one user can reach another user&apos;s data. Credentials stay encrypted on your machine.
          </p>
        </div>
        {personas.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5">
            <Button
              type="button"
              variant="default"
              onClick={() => {
                setModalOpen(true)
                setNotice('')
              }}
            >
              Add test account
            </Button>
          </div>
        )}
      </div>

      {notice && (
        <p
          role="status"
          className="mb-3.5 flex items-center gap-2 rounded-[7px] border border-line bg-sunk px-3 py-[7px] text-[12.5px] text-fg-muted"
        >
          {notice}
        </p>
      )}

      {personas.length > 0 ? (
        <div className="border-t border-line">
          {personas.map(persona => {
            const test = personaTests[persona.id]
            const testVariant = test?.status === 'ok'
              ? 'ok'
              : test?.status === 'warn'
                ? 'warn'
                : test?.status === 'error'
                  ? 'danger'
                  : 'neutral'
            return (
              <div
                key={persona.id}
                className="flex min-h-[44px] items-center justify-between gap-3 border-b border-line px-1 py-2 transition-colors hover:bg-hover"
              >
                <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                  <div className="flex min-w-0 flex-wrap items-center gap-1.5 font-medium text-fg">
                    <strong className="font-mono text-[12px] font-semibold">{persona.handle}</strong>
                    <Badge variant="accent">{persona.roleLabel}</Badge>
                    <Badge variant="neutral" className="bg-sunk">{formatPersonaAuthBadge(persona)}</Badge>
                    {test && (
                      <Badge variant={testVariant} className={testVariant === 'neutral' ? 'bg-sunk' : undefined}>
                        {test.message}
                      </Badge>
                    )}
                  </div>
                  <div className="text-[12px] text-fg-subtle">
                    Allowlist: {persona.originAllowlist.map(safeHost).join(', ')}
                    {persona.canaryMarkers.length > 0 && ` · ${persona.canaryMarkers.length} leak detection ${persona.canaryMarkers.length === 1 ? 'marker' : 'markers'}`}
                  </div>
                </div>
                <div className="flex flex-none items-center gap-2">
                  <Button
                    type="button"
                    variant="ghost"
                    disabled={test?.status === 'testing'}
                    onClick={() => onTestPersona(persona)}
                  >
                    {test?.status === 'testing' ? 'Verifying…' : test?.status === 'ok' ? 'Verify sign-in ✓' : 'Verify sign-in'}
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    className="data-[slot=button]:text-danger data-[slot=button]:hover:bg-danger-soft data-[slot=button]:hover:text-danger"
                    disabled={personaAction.pending}
                    onClick={() => setPersonaToDelete(persona)}
                  >
                    Delete
                  </Button>
                </div>
              </div>
            )
          })}
        </div>
      ) : (
        <div className="mt-3.5 rounded-card border border-line bg-sunk">
          <EmptyState
            icon={<CrossAccountEmptySvg />}
            title="No test accounts yet"
            description="Add one login to scan signed-in views, or two logins (User A & User B) to test cross-account isolation."
            className="max-w-[440px] py-9 [&_[data-slot=empty-state-icon]]:size-auto [&_[data-slot=empty-state-icon]>svg]:h-[88px] [&_[data-slot=empty-state-icon]>svg]:w-[180px]"
            action={
              <Button
                type="button"
                variant="default"
                onClick={() => {
                  setModalOpen(true)
                  setNotice('')
                }}
              >
                Add test account
              </Button>
            }
          />
        </div>
      )}

      <Dialog
        open={modalOpen}
        closeOnEscape={!personaAction.pending}
        onOpenChange={nextOpen => {
          if (!nextOpen && !personaAction.pending) setModalOpen(false)
        }}
      >
        <DialogContent className="flex max-h-[calc(100vh-56px)] max-w-[680px] flex-col overflow-hidden p-0">
          <form
            className="flex min-h-0 flex-1 flex-col"
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
                authKind: effectiveAuthKind,
                ...(effectiveAuthKind === 'header' && headerNameRaw ? { headerName: headerNameRaw } : {}),
                ...(effectiveAuthKind === 'login' ? {
                  loginConfig: {
                    adapter: isClerkClient ? 'clerk_client' : loginAdapter,
                    ...(!isClerkClient ? { email: loginEmail.trim() } : {}),
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
            <DialogHeader className="flex-row items-center justify-between gap-2.5 border-b border-line bg-raise px-4 py-2.5">
              <DialogTitle className="text-[13px] font-semibold text-fg">Add test account</DialogTitle>
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="size-[26px]"
                onClick={() => setModalOpen(false)}
                disabled={personaAction.pending}
                aria-label="Close"
              >
                <Icon name="close" size={14} />
              </Button>
            </DialogHeader>
            <DialogBody className="flex min-h-0 flex-1 flex-col gap-3.5 overflow-y-auto p-4">
              <div className="flex flex-wrap items-center gap-1.5 text-[12px]">
                <span className="mr-0.5 text-fg-subtle">Quick fill</span>
                <button
                  type="button"
                  className="h-6 cursor-pointer rounded-[5px] border border-line-2 bg-panel px-2 text-[11.5px] font-medium text-fg-muted shadow-none transition-colors hover:bg-hover hover:text-fg"
                  onClick={() => prefillPair('user_a')}
                >
                  User A
                </button>
                <button
                  type="button"
                  className="h-6 cursor-pointer rounded-[5px] border border-line-2 bg-panel px-2 text-[11.5px] font-medium text-fg-muted shadow-none transition-colors hover:bg-hover hover:text-fg"
                  onClick={() => prefillPair('user_b')}
                >
                  User B
                </button>
              </div>

              <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-2">
                <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                  Account label
                  <Input
                    className="w-full"
                    name="roleLabel"
                    required
                    maxLength={160}
                    placeholder="User A (Owner)"
                    value={roleLabel}
                    onChange={e => handleAccountLabel(e.target.value)}
                  />
                  <small className="text-[11.5px] font-normal text-fg-subtle">
                    Used as the readable name; the handle is derived automatically.
                  </small>
                </label>
                <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                  Sign-in method
                  <NativeSelect
                    className="w-full"
                    name="authKind"
                    value={signInMethod}
                    onChange={e => setSignInMethod(e.target.value as PersonaSignInMethod)}
                  >
                    <option value="login">Email + Password (auto-login &amp; refresh)</option>
                    <option value="clerk_client">Clerk __client cookie (auto-refresh)</option>
                    <option value="cookie">Session cookie (Cookie: …)</option>
                    <option value="bearer">Bearer token (Authorization: Bearer …)</option>
                    <option value="header">Custom request header</option>
                  </NativeSelect>
                </label>
              </div>

              {effectiveAuthKind !== 'login' && (
                <div className="grid gap-1.5">
                  <div className="flex items-center gap-1.5">
                    <Input
                      className="flex-1 font-mono text-[12px]"
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
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => applyCurlParse(curlPaste)}
                      disabled={!curlPaste.trim()}
                    >
                      Parse
                    </Button>
                  </div>
                  {curlNote && <span className="text-[11.5px] text-fg-subtle">{curlNote}</span>}
                </div>
              )}

              {isClerkClient ? (
                <div className="grid gap-2.5">
                  <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                    Clerk __client cookie
                    <Input
                      className="w-full font-mono text-[12px]"
                      name="secret"
                      type="password"
                      required
                      maxLength={4096}
                      autoComplete="off"
                      value={secret}
                      onChange={e => setSecret(e.target.value)}
                      placeholder="Paste __client cookie value from DevTools (clerk.yourdomain.com)"
                    />
                    <small className="text-[11.5px] font-normal text-fg-subtle">
                      In your signed-in browser, open DevTools → Application → Cookies on <code className="font-mono">clerk.&lt;domain&gt;</code> or <code className="font-mono">*.clerk.accounts.dev</code> and copy <code className="font-mono">__client</code>. Accepts raw value, <code className="font-mono">__client=…</code>, or a full <code className="font-mono">Cookie:</code> header.
                    </small>
                  </label>
                  <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                    Clerk Frontend API URL (optional)
                    <Input
                      className="w-full"
                      name="loginUrl"
                      type="url"
                      maxLength={500}
                      autoComplete="off"
                      value={loginUrl}
                      onChange={e => setLoginUrl(e.target.value)}
                      placeholder={LOGIN_URL_PLACEHOLDERS.clerk_client}
                    />
                  </label>
                </div>
              ) : effectiveAuthKind === 'login' ? (
                <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-2">
                  <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                    Email
                    <Input
                      className="w-full"
                      name="loginEmail"
                      type="email"
                      required
                      maxLength={320}
                      autoComplete="off"
                      value={loginEmail}
                      onChange={e => setLoginEmail(e.target.value)}
                      placeholder="test-a@example.com"
                    />
                  </label>
                  <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                    Password
                    <Input
                      className="w-full"
                      name="secret"
                      type="password"
                      required
                      maxLength={4096}
                      autoComplete="off"
                      value={secret}
                      onChange={e => setSecret(e.target.value)}
                      placeholder="Encrypted on your machine"
                    />
                  </label>
                </div>
              ) : (
                <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                  Credential secret
                  <Input
                    className="w-full"
                    name="secret"
                    type="password"
                    required
                    maxLength={4096}
                    autoComplete="off"
                    value={secret}
                    onChange={e => setSecret(e.target.value)}
                    placeholder="Never displayed back after saving"
                  />
                </label>
              )}

              <Disclosure className="border-t border-line pt-2.5">
                <DisclosureTrigger className="h-auto bg-transparent px-0 py-1 text-fg-muted shadow-none hover:bg-transparent hover:text-fg">
                  Advanced configuration
                </DisclosureTrigger>
                <DisclosureContent className="grid gap-2.5 pt-2.5">
                  <div className="grid grid-cols-1 items-start gap-2.5 sm:grid-cols-2">
                    <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                      Handle (lowercase identifier)
                      <Input
                        className="w-full font-mono text-[12px]"
                        name="handle"
                        required
                        pattern="[a-z0-9][a-z0-9_-]{0,47}"
                        placeholder="user-a"
                        value={handle}
                        onChange={e => setHandle(e.target.value)}
                      />
                    </label>
                    {effectiveAuthKind === 'login' && !isClerkClient ? (
                      <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                        Auth provider
                        <NativeSelect
                          className="w-full"
                          name="loginAdapter"
                          value={loginAdapter}
                          onChange={e => {
                            const next = e.target.value as PersonaLoginAdapter
                            if (next === 'clerk_client') {
                              setSignInMethod('clerk_client')
                              setLoginAdapter('auto')
                            } else {
                              setLoginAdapter(next)
                            }
                          }}
                        >
                          <option value="auto">Auto-detect</option>
                          <option value="clerk">Clerk (auto-refresh 60s JWT)</option>
                          <option value="clerk_client">Clerk __client cookie (auto-refresh)</option>
                          <option value="json">JSON API / Better Auth</option>
                          <option value="supabase">Supabase Auth</option>
                          <option value="form">Login Form (Browser)</option>
                        </NativeSelect>
                      </label>
                    ) : effectiveAuthKind === 'header' ? (
                      <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                        Header name
                        <Input
                          className="w-full font-mono text-[12px]"
                          name="headerName"
                          required
                          pattern="[A-Za-z0-9-]{1,64}"
                          placeholder="X-Api-Key"
                          value={headerName}
                          onChange={e => setHeaderName(e.target.value)}
                        />
                      </label>
                    ) : null}
                  </div>

                  {effectiveAuthKind === 'login' && !isClerkClient && (
                    <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                      Login URL (optional)
                      <Input
                        className="w-full"
                        name="loginUrl"
                        type="url"
                        maxLength={500}
                        autoComplete="off"
                        value={loginUrl}
                        onChange={e => setLoginUrl(e.target.value)}
                        placeholder={LOGIN_URL_PLACEHOLDERS[loginAdapter]}
                      />
                    </label>
                  )}

                  <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                    Allowed sites (one per line or comma-separated)
                    <Textarea
                      className="w-full font-mono text-[12px]"
                      name="originAllowlist"
                      rows={2}
                      required
                      value={origins}
                      onChange={e => setOrigins(e.target.value)}
                    />
                  </label>

                  <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                    Leak detection markers (optional, comma-separated)
                    <Input
                      className="w-full font-mono text-[12px]"
                      name="canaryMarkers"
                      value={canaries}
                      onChange={e => setCanaries(e.target.value)}
                      placeholder="test-marker@example.com, org_alpha_001"
                    />
                    <small className="text-[11.5px] font-normal text-fg-subtle">
                      Strings that indicate cross-tenant data leakage if seen by another test account.
                    </small>
                  </label>
                </DisclosureContent>
              </Disclosure>

              <FormError error={personaAction.error} />
            </DialogBody>
            <DialogFooter className="flex-wrap">
              <span className="mr-auto text-[12px] text-fg-subtle">
                Credentials stay encrypted on your machine and are never sent to AI models.
              </span>
              <Button
                type="button"
                variant="ghost"
                disabled={personaAction.pending}
                onClick={() => setModalOpen(false)}
              >
                Cancel
              </Button>
              <Button type="submit" variant="default" disabled={personaAction.pending}>
                Save test account
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog
        open={Boolean(personaToDelete)}
        closeOnEscape={!personaAction.pending}
        onOpenChange={nextOpen => {
          if (!nextOpen && !personaAction.pending) setPersonaToDelete(null)
        }}
      >
        <DialogContent
          role="alertdialog"
          className="flex max-h-[calc(100vh-56px)] max-w-[440px] flex-col overflow-hidden p-0"
        >
          {personaToDelete && (
            <>
              <DialogHeader className="flex-row items-center justify-between gap-2.5 border-b border-line bg-raise px-4 py-2.5">
                <DialogTitle className="inline-flex items-center gap-2 text-[13px] font-semibold text-fg">
                  <Icon name="trash" size={15} className="text-danger" />
                  <span>Delete test account</span>
                </DialogTitle>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="size-[26px]"
                  disabled={personaAction.pending}
                  onClick={() => setPersonaToDelete(null)}
                  aria-label="Close"
                >
                  <Icon name="close" size={14} />
                </Button>
              </DialogHeader>
              <DialogBody className="flex min-h-0 flex-1 flex-col gap-3.5 overflow-y-auto p-4">
                <DialogDescription className="text-[12.5px] leading-5 text-fg-muted">
                  Remove <strong className="font-semibold text-fg">{personaToDelete.handle}</strong> and its saved credential from this project. This cannot be undone.
                </DialogDescription>
                <div className="flex flex-col gap-2 rounded-lg border border-line bg-sunk px-3 py-2.5">
                  <div className="line-clamp-2 text-[13px] font-medium text-fg">
                    {personaToDelete.roleLabel}
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5 tabular-nums">
                    <Badge variant="neutral" className="bg-panel">
                      {formatPersonaAuthBadge(personaToDelete)}
                    </Badge>
                    <Badge variant="neutral" className="bg-panel">
                      {personaToDelete.originAllowlist.map(safeHost).join(', ') || 'No sites listed'}
                    </Badge>
                  </div>
                </div>
                {personaAction.error && (
                  <p className="m-0 text-[12px] text-danger" role="alert">
                    {personaAction.error}
                  </p>
                )}
              </DialogBody>
              <DialogFooter>
                <Button
                  type="button"
                  variant="ghost"
                  disabled={personaAction.pending}
                  onClick={() => setPersonaToDelete(null)}
                >
                  Cancel
                </Button>
                <Button
                  type="button"
                  variant="default"
                  className="data-[slot=button]:bg-danger data-[slot=button]:text-white data-[slot=button]:hover:bg-danger hover:brightness-[1.08]"
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
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>
    </section>
  )
}
