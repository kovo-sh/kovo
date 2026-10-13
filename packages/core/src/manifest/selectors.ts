import { hasControlCharacter, packageNameSchema, type PackageName } from "@kovo/contracts";
import semver from "semver";

// Override selectors (npm `overrides` keys, pnpm `pnpm.overrides`/`resolutions` keys and
// pnpm-lock.yaml `overrides` keys). They come from hostile files, so they are parsed strictly and
// bounded before anything uses or reports them.

/** Longest override selector step or pnpm selector accepted (a name plus a short range). */
const MAX_SELECTOR_LENGTH = 512;

/** Parses `name` or `name@range` (an override selector step). */
export function parseSelectorStep(step: string): PackageName | null {
  if (step.length > MAX_SELECTOR_LENGTH || hasControlCharacter(step)) return null;
  const at = step.indexOf("@", step.startsWith("@") ? 1 : 0);
  const name = at === -1 ? step : step.slice(0, at);
  const range = at === -1 ? null : step.slice(at + 1);
  const parsed = packageNameSchema.safeParse(name);
  if (!parsed.success) return null;
  if (range !== null && semver.validRange(range) === null) return null;
  return parsed.data;
}

/** A parsed pnpm override selector: `name`, `name@range`, `parent>name` or `parent@range>name`. */
export interface PnpmSelector {
  readonly steps: readonly string[];
  /** The package the rule overrides (the last step, without its range). */
  readonly target: PackageName;
}

/**
 * Parses a pnpm override selector (`pnpm.overrides`, `resolutions` and pnpm-lock.yaml
 * `overrides` keys), or returns null. pnpm accepts at most one parent step.
 */
export function parsePnpmSelector(key: string): PnpmSelector | null {
  if (key.length > MAX_SELECTOR_LENGTH) return null;
  // `resolutions` also accepts yarn's `**/` prefixes, which pnpm strips.
  const steps = key.replace(/^(?:\*\*\/)+/, "").split(">");
  if (steps.length > 2) return null;
  const names = steps.map(parseSelectorStep);
  const target = names[names.length - 1];
  if (target === null || target === undefined || names.includes(null)) return null;
  return { steps, target };
}

/** Classic resolutions use package-name paths and `*`/`**`, never npm parent@version selectors. */
export function parseYarnSelector(key: string): PnpmSelector | null {
  if (key.length > MAX_SELECTOR_LENGTH || hasControlCharacter(key)) return null;
  const steps = key.match(/(?:@[^/]+\/[^/]+|[^/]+)/g);
  if (steps === null || steps.join("/") !== key || steps.length > 32) return null;
  const target = packageNameSchema.safeParse(steps[steps.length - 1]);
  if (!target.success || /[*!()]/.test(target.data)) return null;
  if (
    steps.some(
      (step) =>
        step !== "*" &&
        step !== "**" &&
        (/[*!()]/.test(step) || !packageNameSchema.safeParse(step).success),
    )
  )
    return null;
  return { steps, target: target.data };
}
