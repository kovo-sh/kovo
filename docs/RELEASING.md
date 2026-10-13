# Releasing the Kovo CLI

This document is maintained with the release workflows. The source exporter
owns the root README, LICENSE, package metadata, build script, and exported
source; source syncs leave this document and `.github/workflows` intact.

The Publish workflow runs only through `workflow_dispatch` on `main`, using the
`npm-publish` environment. The environment permits `main`, so publishing does
not run on a version-tag push. The package version must be a stable `X.Y.Z`
version. An unprivileged build job builds `dist/kovo.js`, verifies `dist/kovo.js.sha256`, runs
`node dist/kovo.js --version`, and packs a tarball with lifecycle scripts disabled.
The `npm-publish` job downloads that tarball, verifies its SHA-256 against the
build output, revalidates its package metadata, and publishes that exact file
with npm provenance and public access. It installs and builds no package
dependencies. The tarball artifact is retained for one day. The package must retain `"license": "SEE LICENSE IN LICENSE"` and zero
runtime dependencies.

The owner and release operator perform these steps after review and merge:

1. Sync the reviewed exported source into `main` with the intended package
   version, and require successful build CI.
2. For the first publication only, dispatch Publish from `main` with
   `bootstrap: true`. The workflow refuses if the package already exists and
   uses the environment's `NPM_CLI_BOOTSTRAP_TOKEN` only in the publishing step.
3. Configure npm trusted publishing for `kovo-sh/kovo-cli`, workflow
   `publish.yml`, and environment `npm-publish`. Disallow publishing tokens and
   revoke the bootstrap token.
4. For subsequent versions, dispatch Publish from `main` with
   `bootstrap: false`. This uses OIDC only and requires a version newer than
   every published version. A registry error refuses publication.
5. Tag after publish: only after npm shows the intended version, create the matching `vX.Y.Z` tag
   on the workflow's published commit. Tags are release records and do not
   trigger publishing. An existing matching tag must identify that same commit;
   do not move a tag.
6. Verify `npx @kovo-security/cli --version` in a clean worker. Install the
   package into an npm project and run `npm audit signatures` to verify its
   signatures and provenance.

Publish runs are serialized without cancellation. If a run fails after npm
accepts the version, check the registry and workflow result before retrying;
the version gate refuses publishing that version again. Never overwrite a
published version. Host installation remains an owner step.
