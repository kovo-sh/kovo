const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { readFileSync } = require('node:fs');
const { createRequire } = require('node:module');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');

// Exercise the installed npm's tarball/provenance libraries. Replace both
// network boundaries before loading them: no registry writes or signing calls.
const root = spawnSync('npm', ['root', '--global'], { encoding: 'utf8' });
assert.equal(root.status, 0, root.stderr);
const npmRequire = createRequire(join(root.stdout.trim(), 'npm/package.json'));
assert.equal(npmRequire('./package.json').version, '11.5.1');
Object.assign(process.env, {
  GITHUB_ACTIONS: 'true', GITHUB_SERVER_URL: 'https://github.com',
  GITHUB_REPOSITORY: 'kovo-sh/kovo-cli',
  GITHUB_WORKFLOW_REF: 'kovo-sh/kovo-cli/.github/workflows/publish.yml@refs/heads/main',
  GITHUB_REF: 'refs/heads/main', GITHUB_SHA: 'a'.repeat(40),
  GITHUB_EVENT_NAME: 'workflow_dispatch', RUNNER_ENVIRONMENT: 'github-hosted',
  GITHUB_RUN_ID: '123', GITHUB_RUN_ATTEMPT: '1',
  ACTIONS_ID_TOKEN_REQUEST_URL: 'https://example.invalid/never-called',
});
let statement;
let uploaded;
const fetchId = npmRequire.resolve('npm-registry-fetch');
const realFetch = npmRequire('npm-registry-fetch');
const fakeFetch = async (name, options) => {
  assert.equal(name, '@kovo-security%2fcli');
  assert.equal(options.method, 'PUT');
  uploaded = options.body;
  return {};
};
fakeFetch.pickRegistry = realFetch.pickRegistry;
fakeFetch.json = () => { throw new Error('Unexpected network lookup'); };
require.cache[fetchId].exports = fakeFetch;
const sigstoreId = npmRequire.resolve('sigstore');
require.cache[sigstoreId] = { id: sigstoreId, filename: sigstoreId, loaded: true, exports: {
  attest: async (payload, type) => {
    assert.equal(type, 'application/vnd.in-toto+json');
    statement = JSON.parse(payload);
    return { mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json',
      dsseEnvelope: { payload: payload.toString('base64') },
      verificationMaterial: { tlogEntries: [] } };
  },
} };
(async () => {
  const filename = process.argv[2];
  const bytes = readFileSync(filename);
  const packed = await npmRequire('libnpmpack')(filename, { ignoreScripts: true, dryRun: true });
  assert.ok(packed.equals(bytes));
  const manifest = await npmRequire('pacote').manifest(filename, { ignoreScripts: true });
  await npmRequire('libnpmpublish').publish(manifest, packed, {
    provenance: true, access: 'public', registry: 'https://registry.npmjs.org',
  });
  assert.deepEqual(statement.subject, [{ name: `pkg:npm/%40kovo-security/cli@${manifest.version}`,
    digest: { sha512: createHash('sha512').update(bytes).digest('hex') } }]);
  assert.deepEqual(statement.predicate.buildDefinition.externalParameters.workflow, {
    ref: 'refs/heads/main', repository: 'https://github.com/kovo-sh/kovo-cli',
    path: '.github/workflows/publish.yml',
  });
  assert.deepEqual(statement.predicate.buildDefinition.resolvedDependencies, [{
    uri: 'git+https://github.com/kovo-sh/kovo-cli@refs/heads/main', digest: { gitCommit: 'a'.repeat(40) },
  }]);
  const attachment = Object.values(uploaded._attachments).find(item => item.content_type === 'application/octet-stream');
  assert.deepEqual(Buffer.from(attachment.data, 'base64'), bytes);
  console.log('npm 11.5.1 tarball provenance passed with mocked registry and signing boundaries.');
})().catch(error => { console.error(error); process.exitCode = 1; });
