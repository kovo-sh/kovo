# Kovo CLI

This repository is the published source of `@kovo-security/cli`, the Kovo
command-line tool (`kovo`). Source is synced from Kovo's main repository for
release and published to npm with provenance.

After installing the package in an npm project, verify its signatures and
provenance with:

```sh
npm audit signatures
```

Once the exported source has been synced, build with `npm ci --ignore-scripts`
and `npm run build`. Smoke test with `node dist/kovo.js --version`.
The release contains `dist/kovo.js` and its `dist/kovo.js.sha256` checksum.

For issues, contact Kovo support at https://kovo.sh.
Use of the Kovo CLI is governed by the Kovo terms of service. See [LICENSE](LICENSE).

Releases are dispatched manually from `main` using the Publish workflow and the
`npm-publish` environment. `bootstrap: true` is for the first package publication
only; later releases use npm OIDC trusted publishing with `bootstrap: false`.
Versions must be stable `X.Y.Z` versions, and subsequent versions must be newer
than every published version. After a successful publication, the release
operator creates the corresponding `vX.Y.Z` tag on the published commit.
