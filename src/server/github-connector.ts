/**
 * Thin facade barrel for GitHub authentication, vault credentials, installation/repo discovery,
 * shallow git cloning, dependency parsing, and commit-diff mining.
 *
 * Implementations live in:
 * - `./github-auth.ts`: OAuth Device Flow, PAT/App vault credentials, appSlug/installUrl, `/user/installations` & repo listing
 * - `./github-repo-sync.ts`: shallow git clone, file classification, manifest/lockfile parsers, commit-diff mining
 */

export {
  DEFAULT_GITHUB_API_BASE_URL,
  DEFAULT_GITHUB_BASE_URL,
  DEFAULT_GITHUB_MAX_AUTO_SELECT,
  DEFAULT_GITHUB_PAT_PATH,
  cancelGithubDeviceFlow,
  classifyGithubPatKind,
  clearGithubPat,
  defaultSelectedRepoNames,
  getGithubAuthStatus,
  getGithubPatStatus,
  githubAppInstallUrl,
  hasGithubPat,
  listAccessibleGithubRepos,
  pollGithubDeviceFlow,
  readGithubVaultCredential,
  resolveGithubAppSlug,
  resolveGithubClientId,
  resolveGithubPatPath,
  saveGithubClientId,
  saveGithubPat,
  saveGithubVaultCredential,
  startGithubDeviceFlow,
} from './github-auth.ts'

export type {
  AccessibleGithubRepo,
  GithubAppInstallationSummary,
  GithubAuthKind,
  GithubAuthStatus,
  GithubPatKind,
  GithubPatSource,
  GithubPatStatus,
  ListAccessibleGithubReposOptions,
  ListAccessibleGithubReposResult,
  PollGithubDeviceFlowOptions,
  PollGithubDeviceFlowResult,
  StartGithubDeviceFlowOptions,
  StartGithubDeviceFlowResult,
  StoredGithubVaultCredential,
} from './github-auth.ts'

export {
  cloneGithubRepos,
  listMountedRepos,
  parseDependenciesFromFile,
  projectReposDir,
  readRepoCommitDiffs,
  syncGithubRepos,
} from './github-repo-sync.ts'

export type {
  GithubSyncOptions,
  RepoCommitDiffMining,
  RepoDependency,
  SyncedGithubRepo,
  SyncedRepoFile,
  SyncedRepoSpec,
} from './github-repo-sync.ts'
