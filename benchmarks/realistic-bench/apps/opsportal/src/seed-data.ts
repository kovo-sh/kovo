// Deterministic seed data keyed by the per-seed canary salt. Teams A and B are the persona tenants;
// team C is background. Customer records carry rbc_ data canaries and integrations carry rbs_ secret
// canaries so the impact side-channel can detect cross-tenant disclosure. Log files are written into
// the jailed virtual log root.
import type { Db } from '../../../lib/db.ts'
import type { Vfs } from '../../../lib/vfs.ts'
import type { IdCodec } from '../../../lib/ids.ts'
import type { CanaryRegistry } from '../../../lib/canary.ts'
import type { PersonaCredential, PersonaId } from '../../../lib/types.ts'
import { LOG_ROOT } from './context.ts'
import { prun } from './common/sql.ts'

export interface SeedDeps {
  db: Db
  vfs: Vfs
  ids: IdCodec
  canaries: CanaryRegistry
  personas: Record<PersonaId, PersonaCredential>
  /** Base origin of the loopback internal metrics/metadata mock, when started by the server. */
  internalOrigin?: string
}

export function seedData(deps: SeedDeps): void {
  const { db, vfs, ids, canaries, personas, internalOrigin } = deps
  const slugA = personas.persona_a.tenant
  const slugB = personas.persona_b.tenant
  const slugC = `bg${slugA.slice(0, 3)}`
  const ext = (kind: string, n: number): string => ids.encode(kind, n)

  const teams: Array<[number, string, string]> = [
    [1, slugA, 'Team Aurora'], [2, slugB, 'Team Borealis'], [3, slugC, 'Team Cedar'],
  ]
  for (const [id, slug, name] of teams) {
    prun(db, 'INSERT INTO teams(id, ext_id, slug, name, plan) VALUES (?,?,?,?,?)',
      [id, ext('team', id), slug, name, 'enterprise'])
  }

  const users: Array<[PersonaId, string]> = [
    ['persona_a', slugA], ['admin', slugA], ['viewer', slugA], ['persona_b', slugB],
  ]
  users.forEach(([pid, slug], idx) => {
    const c = personas[pid]
    prun(db, 'INSERT INTO users(id, ext_id, team_id, email, password, role, name, persona) VALUES (?,?,?,?,?,?,?,?)',
      [idx + 1, ext('user', idx + 1), slug, c.email, c.password, c.role, pid, pid])
  })
  prun(db, 'INSERT INTO users(id, ext_id, team_id, email, password, role, name, persona) VALUES (?,?,?,?,?,?,?,?)',
    [5, ext('user', 5), slugC, `ops@cedar-${slugC}.test`, 'rb_fake_cedar_pw', 'owner', 'Cedar Ops', 'none'])

  // accounts: two per persona team, one background
  const acct: Array<[number, string, string]> = [
    [1, slugA, 'Globex'], [2, slugA, 'Initech'], [3, slugB, 'Umbrella'], [4, slugB, 'Soylent'], [5, slugC, 'Hooli'],
  ]
  for (const [id, slug, name] of acct) {
    const canary = canaries.tenantToken(slug, `acct${id}`)
    prun(db, 'INSERT INTO accounts(id, ext_id, team_id, name, tier, owner_email, notes) VALUES (?,?,?,?,?,?,?)',
      [id, ext('account', id), slug, name, 'gold', `ops@${name.toLowerCase()}.test`, `internal-ref ${canary}`])
  }

  // tickets: tie each account to a ticket whose body holds that team's data canary
  acct.forEach(([aid, slug, name], i) => {
    const tid = i + 1
    const canary = canaries.tenantToken(slug, `ticket${tid}`)
    prun(db, 'INSERT INTO tickets(id, ext_id, team_id, account_id, subject, body, status, priority, assignee_id) VALUES (?,?,?,?,?,?,?,?,?)',
      [tid, ext('ticket', tid), slug, ext('account', aid), `Onboarding ${name}`,
        `Escalation context ${canary}`, 'open', 'high', ext('user', slug === slugB ? 4 : 1)])
  })

  prun(db, 'INSERT INTO ticket_notes(id, ext_id, ticket_id, team_id, author, body, created_at) VALUES (?,?,?,?,?,?,?)',
    [1, ext('note', 1), ext('ticket', 1), slugA, 'persona_a', 'Reviewed account posture; looks healthy.', 1700000000])

  const integ: Array<[number, string, string]> = [[1, slugA, 'PagerDuty'], [2, slugB, 'Slack']]
  for (const [id, slug, name] of integ) {
    const secret = canaries.secretToken(slug, `integ${id}`)
    prun(db, 'INSERT INTO integrations(id, ext_id, team_id, name, kind, secret, config_url) VALUES (?,?,?,?,?,?,?)',
      [id, ext('integration', id), slug, name, 'alerting', secret, 'http://127.0.0.1:1/config'])
  }

  prun(db, 'INSERT INTO webhook_targets(id, ext_id, team_id, name, url) VALUES (?,?,?,?,?)',
    [1, ext('webhook', 1), slugA, 'Deploy notifier', 'http://127.0.0.1:1/notify'])
  // The internal metrics relay points at the loopback mock the server registers at boot; its origin is
  // only known at runtime, so it is wired in here when provided.
  if (internalOrigin) {
    prun(db, 'INSERT INTO webhook_targets(id, ext_id, team_id, name, url) VALUES (?,?,?,?,?)',
      [20, ext('webhook', 20), slugA, 'Internal metrics relay', `${internalOrigin}/latest/meta-data/`])
  }
  prun(db, 'INSERT INTO saved_searches(id, ext_id, team_id, name, query) VALUES (?,?,?,?,?)',
    [1, ext('search', 1), slugA, 'Open high priority', 'status=open'])
  prun(db, 'INSERT INTO jobs(id, ext_id, team_id, name, kind, status) VALUES (?,?,?,?,?,?)',
    [1, ext('job', 1), slugA, 'Nightly backup', 'backup', 'pending'])
  prun(db, 'INSERT INTO feature_flags(id, ext_id, team_id, flag_key, value, scope) VALUES (?,?,?,?,?,?)',
    [1, ext('flag', 1), slugB, 'beta_dashboard', 'on', 'team'])
  prun(db, 'INSERT INTO feature_flags(id, ext_id, team_id, flag_key, value, scope) VALUES (?,?,?,?,?,?)',
    [2, ext('flag', 2), slugB, 'rollout_ref', canaries.tenantToken(slugB, 'flag2'), 'team'])
  prun(db, 'INSERT INTO reports(id, ext_id, team_id, name, template) VALUES (?,?,?,?,?)',
    [1, ext('report', 1), slugA, 'Weekly summary', 'Report for {{ account }}: {{ total }} open tickets'])
  prun(db, 'INSERT INTO audit_events(id, ext_id, team_id, actor, action, detail) VALUES (?,?,?,?,?,?)',
    [1, ext('audit', 1), slugA, 'persona_a', 'login', 'ok'])
  prun(db, 'INSERT INTO api_tokens(id, ext_id, team_id, user_id, scopes) VALUES (?,?,?,?,?)',
    [1, ext('token', 1), slugA, ext('user', 1), 'read'])

  // virtual log files inside the jailed log root, plus a synthetic secret outside it
  vfs.write(`${LOG_ROOT}/app.log`, 'INFO service started\nINFO request handled\n')
  vfs.write(`${LOG_ROOT}/access.log`, 'GET /dashboard 200\nPOST /login 200\n')
  vfs.write('/var/log/system/audit.log', 'AUTH session opened for ops\nAUTH session closed\n')
  vfs.write('/etc/opsportal/secrets.env', 'SESSION_SECRET=rb_fake_session_secret\n')
}
