import { repoFilePathSchema } from "@kovo/contracts/primitives";
import type { SabotageTarget } from "@kovo/contracts";
import { validateDiscovery } from "./validation.js";

// Discovery's sabotage-target *proposals* from the repository's file layout (SPEC `Recipe`
// `sabotageTargets`). They are hints only: nothing mutates them since the owner removed
// calibration, whose sabotage selection validated them against trusted evidence.

const PER_KIND = 3;

const NOT_SOURCE =
  /(?:^|\/)(?:node_modules|dist|build|coverage|\.next|out|__tests__|__mocks__|test|tests|e2e)\/|\.(?:test|spec|stories|d)\.[cm]?[jt]sx?$/;

/** Application entry files, most specific first. */
const ENTRY_PATTERNS: readonly RegExp[] = [
  /^(?:src\/)?app\/layout\.[jt]sx?$/,
  /^(?:src\/)?app\/page\.[jt]sx?$/,
  /^(?:src\/)?pages\/_app\.[jt]sx?$/,
  /^(?:src\/)?pages\/index\.[jt]sx?$/,
  /^src\/(?:index|server|app|main)\.[cm]?[jt]sx?$/,
  /^(?:index|server|app|main)\.[cm]?[jt]s$/,
  /^src\/App\.[jt]sx$/,
];

/** Request handlers: Next.js route handlers and API routes, Express-style route modules. */
const ROUTE_PATTERNS: readonly RegExp[] = [
  /^(?:src\/)?app\/(?:.+\/)?route\.[jt]s$/,
  /^(?:src\/)?pages\/api\/.+\.[jt]s$/,
  /^(?:src\/)?routes\/.+\.[cm]?[jt]s$/,
  /^(?:src\/)?(?:controllers|handlers)\/.+\.[cm]?[jt]s$/,
];

/** Library modules whose return values tests or types are likely to pin. */
const RETURN_PATTERNS: readonly RegExp[] = [
  /^(?:src\/)?(?:lib|utils|services|domain)\/.+\.[cm]?[jt]sx?$/,
];

function pick(tree: readonly string[], patterns: readonly RegExp[]): string[] {
  const out: string[] = [];
  for (const pattern of patterns) {
    for (const path of tree.filter((candidate) => pattern.test(candidate)).toSorted()) {
      if (out.length >= PER_KIND) return out;
      validateDiscovery(repoFilePathSchema, path, "unsafe_path_reference");
      if (!out.includes(path)) out.push(path);
    }
  }
  return out;
}

/** Proposed sabotage targets for a repository tree (paths only). */
export function proposeSabotageTargets(
  tree: readonly string[],
  hasDependencies: boolean,
): SabotageTarget[] {
  const source = tree.filter((path) => !NOT_SOURCE.test(path));
  return [
    ...pick(source, ENTRY_PATTERNS).map((path) => ({ kind: "break_entry_import" as const, path })),
    ...pick(source, ROUTE_PATTERNS).map((path) => ({ kind: "throw_in_route" as const, path })),
    ...pick(source, RETURN_PATTERNS).map((path) => ({
      kind: "corrupt_covered_return" as const,
      path,
    })),
    ...(hasDependencies ? [{ kind: "pin_bad_dep" as const, path: "package.json" }] : []),
  ];
}
