import { discoveryValidationRuleOf, type DiscoveryValidationRule } from "@kovo/contracts";
import { repoFilePathSchema } from "@kovo/contracts/primitives";
import type { z } from "zod";
import { parseScript } from "./shell/parse.js";

/** No rejected input, issue path or message survives this boundary. */
export class DiscoveryValidationError extends Error {
  readonly validationRule: DiscoveryValidationRule;
  constructor(rule: unknown) {
    const token = discoveryValidationRuleOf(rule);
    super(token);
    this.name = "DiscoveryValidationError";
    this.validationRule = token;
  }
}

export function validateDiscovery<S extends z.ZodType>(
  schema: S,
  input: unknown,
  rule: DiscoveryValidationRule,
): z.output<S> {
  const parsed = schema.safeParse(input);
  if (!parsed.success) throw new DiscoveryValidationError(rule);
  return parsed.data;
}

/** Decode shell quoting before checking a command's references to opaque tree names. */
export function assertSafeTreeCommandReferences(
  runs: readonly string[],
  tree: readonly string[],
): void {
  const unsafe = new Set(tree.filter((path) => !repoFilePathSchema.safeParse(path).success));
  if (unsafe.size === 0) return;
  for (const run of runs) {
    for (const command of parseScript(run).commands) {
      for (const word of command.argv) {
        const value =
          word.startsWith("--") && word.includes("=") ? word.slice(word.indexOf("=") + 1) : word;
        const path = value.startsWith("./") ? value.slice(2) : value;
        if (unsafe.has(path)) validateDiscovery(repoFilePathSchema, path, "unsafe_path_reference");
      }
    }
  }
}
