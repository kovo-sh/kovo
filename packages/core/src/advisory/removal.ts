import type { PackageName } from "@kovo/contracts";

import type { TargetInstance } from "./target.js";

// SPEC "Fix ladder and agent": "A rollback requires evidence that the chosen version is outside all
// known malicious/affected ranges; older does not automatically mean safe. If no safe version is
// known, alert immediately and prepare a reviewed removal only when feasible, otherwise request
// human action. Never guess a replacement package." Rung M: "Evidenced rollback/removal for
// malicious package | Human review".
//
// A removal is feasible when deleting the package's own entry from the manifest removes every
// locked copy: each copy is reached only as a direct dependency of the root (every dependency path
// is the package itself). A copy some other package depends on would need that parent changed or
// replaced, which is guessing a replacement, so it is not a removal Kovo prepares; a person acts.

/** Whether a reviewed removal of `pkg` is feasible over its locked instances. */
export function reviewedRemovalFeasible(
  pkg: PackageName,
  instances: readonly Pick<TargetInstance, "depPaths">[],
): boolean {
  if (instances.length === 0) return false;
  return instances.every(
    (instance) =>
      instance.depPaths.length > 0 &&
      instance.depPaths.every((path) => path.length === 1 && path[0] === pkg),
  );
}
