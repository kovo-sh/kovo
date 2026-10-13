import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { runInNewContext } from 'node:vm';
import { parse } from 'yaml';

// Execute the actual workflow gates, never a copy of their validation logic.
const workflow = parse(readFileSync('.github/workflows/publish.yml', 'utf8'));
const { build, publish } = workflow.jobs;
assert.deepEqual(build.permissions, { contents: 'read' });
assert.equal(build.environment, undefined);
assert.ok(!JSON.stringify(build).includes('secrets.'));
assert.equal(build.steps[0].with['persist-credentials'], false);
assert.equal(publish.needs, 'build');
assert.equal(publish.environment, 'npm-publish');
assert.deepEqual(publish.permissions, { contents: 'read', 'id-token': 'write' });
assert.ok(!publish.steps.some(step => step.uses?.startsWith('actions/checkout@')));
assert.ok(!publish.steps.some(step => /npm (ci|run)|npm install(?! --global npm@11\.5\.1 --ignore-scripts)/.test(step.run ?? '')));
for (const job of [build, publish]) {
  assert.equal(job.env.NPM_CONFIG_IGNORE_SCRIPTS, 'true');
  assert.equal(job.env.NPM_CONFIG_USERCONFIG, '/dev/null');
  for (const step of job.steps) {
    if (step.uses) assert.match(step.uses, /^actions\/(checkout|setup-node|upload-artifact|download-artifact)@[a-f0-9]{40}$/);
  }
}
const step = (job, name) => job.steps.find(item => item.name === name).run;
const metadata = step(build, 'Validate release metadata');
const pack = step(build, 'Pack the verified release');
const verify = step(publish, 'Verify tarball and release metadata');
const registry = step(publish, 'Require an absent package for bootstrap or a newer OIDC version');
const firstPublish = publish.steps.findIndex(item => item.name === 'Publish first version with provenance');
assert.ok(publish.steps.findIndex(item => item.id === 'verified') < firstPublish);
assert.ok(publish.steps.findIndex(item => item.run === registry) < firstPublish);
for (const item of publish.steps.slice(firstPublish)) {
  assert.match(item.run, /npm publish "\$TARBALL_PATH" --provenance --access public/);
}
assert.equal(publish.steps[firstPublish].env.NODE_AUTH_TOKEN, '${{ secrets.NPM_CLI_BOOTSTRAP_TOKEN }}');
assert.equal(publish.steps.filter(item => JSON.stringify(item).includes('secrets.')).length, 1);

const root = mkdtempSync(join(tmpdir(), 'cli-release-test-'));
const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
const env = { ...process.env, NPM_CONFIG_IGNORE_SCRIPTS: 'true', NPM_CONFIG_USERCONFIG: '/dev/null',
  RELEASE_EVENT: 'workflow_dispatch', RELEASE_REF: 'refs/heads/main', GITHUB_OUTPUT: join(root, 'outputs'),
  EXPECTED_NAME: pkg.name, EXPECTED_VERSION: pkg.version, TARBALL_PATH: join(root, 'release/package.tgz') };
const shell = (script, overrides = {}) => spawnSync('bash', ['-e', '-o', 'pipefail', '-c', script], {
  cwd: root, env: { ...env, ...overrides }, encoding: 'utf8', timeout: 30000,
});
const passes = (script, overrides) => {
  const result = shell(script, overrides);
  assert.equal(result.status, 0, result.stderr);
};
const refuses = (script, overrides, reason) => {
  const result = shell(script, overrides);
  assert.notEqual(result.status, 0);
  assert.ok(result.stderr.includes(reason), result.stderr);
};
const writePackage = value => writeFileSync(join(root, 'package.json'), JSON.stringify(value));
function tarball(value) {
  mkdirSync(join(root, 'package'), { recursive: true });
  writeFileSync(join(root, 'package/package.json'), JSON.stringify(value));
  mkdirSync(join(root, 'release'), { recursive: true });
  passes('tar -czf "$TARBALL_PATH" package/package.json');
  env.EXPECTED_SHA256 = createHash('sha256').update(readFileSync(env.TARBALL_PATH)).digest('hex');
}
try {
  writePackage({ ...pkg, scripts: { prepack: 'exit 99', prepare: 'exit 99' } });
  passes(metadata);
  passes(pack); // Real npm pack, with lifecycle scripts that would fail if run.
  env.EXPECTED_SHA256 = readFileSync(env.GITHUB_OUTPUT, 'utf8').match(/sha256=([a-f0-9]{64})/)[1];
  passes(verify);
  const provenance = spawnSync('node', [resolve('scripts/test-provenance.cjs'), env.TARBALL_PATH], {
    env, encoding: 'utf8', timeout: 30000,
  });
  assert.equal(provenance.status, 0, provenance.stderr);
  console.log(provenance.stdout.trim());
  for (const invalid of [
    { name: 'wrong' }, { license: 'MIT' }, { version: '01.2.3' }, { version: '1.2.3-beta.1' },
    { version: '1.2.3+build' }, { version: 123 }, { dependencies: { zod: '1' } },
    { optionalDependencies: { zod: '1' } }, { peerDependencies: { zod: '1' } },
    { dependencies: null }, { dependencies: [] }, { dependencies: false },
  ]) {
    writePackage({ ...pkg, ...invalid });
    refuses(metadata, {}, 'Invalid release package metadata');
    tarball({ ...pkg, ...invalid });
    refuses(verify, {}, 'Invalid release package metadata');
  }
  writePackage(pkg);
  tarball(pkg);
  const original = readFileSync(env.TARBALL_PATH);
  const altered = Buffer.from(original);
  altered[altered.length - 1] ^= 1;
  writeFileSync(env.TARBALL_PATH, altered);
  refuses(verify, {}, 'Tarball digest mismatch');
  writeFileSync(env.TARBALL_PATH, original);
  for (const overrides of [{ RELEASE_EVENT: 'push' }, { RELEASE_REF: 'refs/heads/feature' }, { RELEASE_REF: 'refs/tags/v0.1.0' }]) {
    refuses(metadata, overrides, 'Release must be dispatched on main');
    refuses(verify, overrides, 'Release must be dispatched on main');
  }
  for (const digest of ['', 'bad', '0'.repeat(64)]) refuses(verify, { EXPECTED_SHA256: digest }, 'Tarball digest mismatch');
  refuses(verify, { EXPECTED_NAME: '' }, 'Invalid release package metadata');
  refuses(verify, { EXPECTED_VERSION: '9.9.9' }, 'Invalid release package metadata');
  writeFileSync(join(root, 'release/z-extra'), 'extra');
  refuses(verify, {}, 'Artifact must contain exactly one tarball file');
  rmSync(join(root, 'release/z-extra'));
  copyFileSync(env.TARBALL_PATH, join(root, 'saved.tgz'));
  rmSync(env.TARBALL_PATH);
  refuses(verify, {}, 'Artifact must contain exactly one tarball file');
  symlinkSync(join(root, 'saved.tgz'), env.TARBALL_PATH);
  refuses(verify, {}, 'Artifact must contain exactly one tarball file');
  rmSync(env.TARBALL_PATH);
  copyFileSync(join(root, 'saved.tgz'), env.TARBALL_PATH);
  passes(verify);

  const registryCode = registry.split("<<'NODE'\n")[1].split('\nNODE')[0];
  async function registryCheck(bootstrap, status, body, version = '1.2.3') {
    await runInNewContext(`(async () => { ${registryCode} })()`, {
      process: { env: { BOOTSTRAP: bootstrap, PACKAGE_NAME: pkg.name, PACKAGE_VERSION: version } },
      AbortSignal, fetch: async () => ({ status, json: async () => body }),
    });
  }
  await registryCheck('true', 404, { error: 'Not found' });
  await assert.rejects(registryCheck('true', 200, { name: pkg.name, versions: { '0.1.0': {} } }), /Bootstrap requires an absent package/);
  await assert.rejects(registryCheck('true', 500, { error: 'Not found' }), /Bootstrap requires an absent package/);
  await assert.rejects(registryCheck('false', 404, { error: 'Not found' }), /Trusted publishing requires existing/);
  for (const versions of [undefined, {}, [], 'bad']) {
    await assert.rejects(registryCheck('false', 200, { name: pkg.name, versions }), /Trusted publishing requires existing/);
  }
  await assert.rejects(registryCheck('false', 503, { name: pkg.name, versions: { '1.0.0': {} } }), /Trusted publishing requires existing/);
  await assert.rejects(registryCheck('false', 200, { name: 'wrong', versions: { '1.0.0': {} } }), /Trusted publishing requires existing/);
  await registryCheck('false', 200, { name: pkg.name, versions: { '1.2.2': {}, '1.2.3-rc.1': {} } });
  for (const previous of ['1.2.3', '1.2.3+build', '1.2.4', '2.0.0', '1.10.0']) {
    await assert.rejects(registryCheck('false', 200, { name: pkg.name, versions: { [previous]: {} } }), /newer than every published/);
  }
  for (const previous of ['01.2.3', '1.2.3-01', '1.2.3-a..b', 'bad']) {
    await assert.rejects(registryCheck('false', 200, { name: pkg.name, versions: { [previous]: {} } }), /Malformed registry version/);
  }
  await assert.rejects(registryCheck('', 200, { name: pkg.name, versions: { '1.0.0': {} } }), /Trusted publishing requires existing/);
  console.log('Publish workflow gates passed (no publication or OIDC requests).');
} finally {
  rmSync(root, { recursive: true, force: true });
}
