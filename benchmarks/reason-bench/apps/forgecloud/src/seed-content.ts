// Deterministic workspace content: projects, pipelines, runs, secrets, artifacts, exports,
// deployments, webhooks and automations. Everything is synthetic and per-seed; workspace secrets and
// runner credentials are clearly fake `rbs_` canaries.
import type { Db } from '../../../lib/db.ts'
import type { IdCodec } from '../../../lib/ids.ts'
import type { CanaryRegistry } from '../../../lib/canary.ts'
import type { Prng } from '../../../lib/prng.ts'

export interface SeedOrg {
  code: 'org_a' | 'org_b'
  slug: string
  name: string
  externalId: string
  ssoTenant: string
}

interface ContentDeps {
  ids: IdCodec
  canaries: CanaryRegistry
  rng: Prng
  startTs: number
  signingSalt: string
}

interface SeedOrgPair { a: SeedOrg; b: SeedOrg }

const PROJECT_NAMES = ['control-plane', 'atlas-secrets', 'edge-runtime', 'data-pipeline', 'billing-svc']
const SECRET_NAMES = ['registry-pull', 'prod-deploy-key', 'npm-token', 'cloud-credentials']

export function seedContent(db: Db, deps: ContentDeps, orgs: SeedOrgPair): { files: Record<string, string> } {
  const { ids, canaries, startTs, signingSalt } = deps
  const files: Record<string, string> = {}
  let n = 1000
  const next = (kind: string): string => ids.encode(kind, ++n)

  for (const org of [orgs.a, orgs.b]) {
    const wsDefaults = [
      { name: 'main', isDefault: 1 },
      { name: 'platform', isDefault: 0 },
      { name: 'release', isDefault: 0 },
    ]
    const workspaceExts: string[] = []
    for (const ws of wsDefaults) {
      const ext = next('workspace')
      workspaceExts.push(ext)
      db.run('INSERT INTO workspaces (external_id,org_slug,name,is_default,visibility) VALUES (?,?,?,?,?)',
        [ext, org.slug, `${org.slug}-${ws.name}`, ws.isDefault, 'private'])
    }

    const projectExts: string[] = []
    PROJECT_NAMES.forEach((base, i) => {
      const ext = next('project')
      projectExts.push(ext)
      const visibility = i === 1 ? 'private' : i % 3 === 0 ? 'internal' : 'private'
      const desc = `${org.name} ${base} workstream. Ref ${canaries.tenantToken(org.slug, `project${i}`)}.`
      db.run(
        'INSERT INTO projects (external_id,org_slug,workspace_ext,name,description,visibility,state,owner_ext) VALUES (?,?,?,?,?,?,?,?)',
        [ext, org.slug, workspaceExts[i % workspaceExts.length], `${org.slug}-${base}`, desc, visibility,
          i === 4 ? 'archived' : 'active', ''],
      )
    })

    projectExts.forEach((projectExt, pi) => {
      for (let k = 1; k <= 2; k++) {
        const pipelineExt = next('pipeline')
        const archived = (pi + k) % 4 === 0
        const shared = org.code === 'org_b' && pi === 1
        db.run(
          'INSERT INTO pipelines (external_id,org_slug,project_ext,name,state,visibility,runner,definition) VALUES (?,?,?,?,?,?,?,?)',
          [pipelineExt, org.slug, projectExt, `${pi === 1 ? 'secure' : 'build'}-${k}${archived ? '-legacy' : ''}`,
            archived ? 'archived' : 'active', shared ? 'shared' : k === 2 ? 'internal' : 'private',
            k === 2 ? 'linux-arm' : 'linux', `steps:\n  - checkout\n  - test\n  - package-${k}\n`],
        )
        for (let r = 1; r <= 2; r++) {
          const runExt = next('run')
          const logPath = `/builds/${org.slug}/${runExt}.log`
          const runToken = canaries.secretToken(`${org.slug}-runner`, `run${pi}${k}${r}`)
          const state = r === 1 ? 'success' : r === 2 ? (archived ? 'failed' : 'running') : 'queued'
          db.run(
            'INSERT INTO pipeline_runs (external_id,org_slug,project_ext,pipeline_ext,number,state,commit_ref,actor_ext,log_path,env_preview_token,started_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
            [runExt, org.slug, projectExt, pipelineExt, 100 + pi * 10 + k * 2 + r, state,
              `refs/heads/main@${deps.rng.hex(4)}`, '', logPath, runToken, startTs - (pi + k) * 3600_000],
          )
          files[logPath] = [
            `[info] ${org.slug} pipeline ${pipelineExt} run ${runExt}`,
            `[info] checkout complete (${deps.rng.hex(4)})`,
            `[info] tests passed: ${18 + pi} suites`,
            `[info] artifact packaged for ${org.name}`,
            `[info] environment: ${k === 2 ? 'staging' : 'dev'}`,
            `[done] state=${state}`,
            '',
          ].join('\n')
        }
      }
    })

    SECRET_NAMES.forEach((name, i) => {
      const ext = next('secret')
      const value = canaries.secretToken(org.slug, `secret:${name}`)
      db.run(
        'INSERT INTO secrets (external_id,org_slug,workspace_ext,project_ext,name,value,kind,version) VALUES (?,?,?,?,?,?,?,?)',
        [ext, org.slug, workspaceExts[0], projectExts[i % projectExts.length], `${org.slug}/${name}`, value,
          i === 1 ? 'deploy-key' : 'opaque', 1 + (i % 2)],
      )
    })

    const artifactNames = ['audit.json', 'release.tar', 'coverage.json']
    artifactNames.forEach((name, i) => {
      const ext = next('artifact')
      const vfsPath = `/exports/${org.slug}/${name}`
      files[vfsPath] = name.endsWith('.json')
        ? JSON.stringify({ org: org.slug, kind: name.replace('.json', ''), ref: canaries.tenantToken(org.slug, `artifact${i}`) })
        : `release archive for ${org.name}\n${canaries.tenantToken(org.slug, `artifact${i}`)}\n`
      db.run(
        'INSERT INTO artifacts (external_id,org_slug,project_ext,name,vfs_path,size,checksum) VALUES (?,?,?,?,?,?,?)',
        [ext, org.slug, projectExts[i % projectExts.length], name, vfsPath, 1024 + i * 256, deps.rng.hex(8)],
      )
    })

    for (let i = 0; i < 2; i++) {
      const ext = next('export')
      const vfsPath = `/exports/${org.slug}/export-${ext}.json`
      const state = i === 0 ? 'ready' : 'queued'
      files[vfsPath] = JSON.stringify({
        org: org.slug, kind: 'audit', generatedAt: startTs - i * 86_400_000,
        marker: canaries.tenantToken(org.slug, `export${i}`),
      })
      db.run(
        'INSERT INTO exports (external_id,org_slug,requested_by,kind,state,vfs_path,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?)',
        [ext, org.slug, '', 'audit', state, vfsPath, startTs - i * 3600_000, startTs + 7 * 86_400_000],
      )
    }

    const deploymentStates = [
      { state: 'pending', approval: 'pending', auto: 0, env: 'staging' },
      { state: 'disputed', approval: 'rejected', auto: 0, env: 'production' },
      { state: 'scheduled', approval: 'approved', auto: 1, env: 'production' },
      { state: 'released', approval: 'approved', auto: 1, env: 'staging' },
    ]
    deploymentStates.forEach((d, i) => {
      db.run(
        'INSERT INTO deployments (external_id,org_slug,project_ext,env,version,state,approval_status,auto_release_scheduled,scheduled_at,requested_by,approved_by,disputed_at,released_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
        [next('deployment'), org.slug, projectExts[i % projectExts.length], d.env, `v1.${i}.${deps.rng.hex(2)}`,
          d.state, d.approval, d.auto, d.auto ? startTs + 3600_000 : 0, '', d.approval === 'approved' ? 'seed' : '',
          d.state === 'disputed' ? startTs - 3600_000 : 0, d.state === 'released' ? startTs - 7200_000 : 0],
      )
    })

    const hookExt = next('webhook')
    db.run(
      'INSERT INTO webhooks (external_id,org_slug,url,secret,signing_salt,events,active) VALUES (?,?,?,?,?,?,?)',
      [hookExt, org.slug, `http://127.0.0.1:9/hooks/${org.slug}`, `rb_fake_whk_${deps.rng.hex(6)}`,
        signingSalt, 'build.completed,deploy.approved', 1],
    )
    for (let i = 0; i < 3; i++) {
      db.run(
        'INSERT INTO webhook_deliveries (external_id,org_slug,webhook_ext,event,status,detail,created_at) VALUES (?,?,?,?,?,?,?)',
        [next('delivery'), org.slug, hookExt, i === 0 ? 'build.completed' : 'deploy.approved',
          i === 0 ? 'delivered' : 'failed',
          i === 0 ? 'receiver returned 200' : 'connect ECONNREFUSED 127.0.0.1:9 after 2000ms',
          startTs - i * 1800_000],
      )
    }

    db.run(
      'INSERT INTO automations (external_id,org_slug,workspace_ext,name,role_template,created_by) VALUES (?,?,?,?,?,?)',
      [next('automation'), org.slug, workspaceExts[0], `${org.slug}-release-bot`, 'viewer', ''],
    )
  }

  return { files }
}
