import { z } from "zod";

// Well-known public npm packages whose names (and, in a toolchain fingerprint, resolved versions)
// Kovo may record as diagnostic facts about a repository (docs/decisions/recipes.md "Toolchain
// fingerprints and failure categories"). An explicit list, never a scope or pattern: a private
// package can never be named by a diagnostic, whatever its registry or scope. SPEC Sandbox B:
// "Capture only exit codes, durations, counts, failure codes and hashes"; a name from this list is a
// fixed code, not text taken from a repository or its output.

export const WELL_KNOWN_PACKAGES = [
  // Frameworks and UI runtimes.
  "next",
  "react",
  "react-dom",
  "react-router",
  "react-router-dom",
  "@remix-run/dev",
  "vue",
  "nuxt",
  "svelte",
  "@sveltejs/kit",
  "astro",
  "@angular/core",
  "@angular/cli",
  "@nestjs/core",
  "@nestjs/cli",
  "express",
  "@tanstack/react-query",
  "@tanstack/react-router",
  "@tanstack/react-start",
  "@tanstack/react-table",
  "@tanstack/router-plugin",
  "@tanstack/start",
  // Build tools and bundlers.
  "vite",
  "@vitejs/plugin-react",
  "webpack",
  "rollup",
  "esbuild",
  "tsup",
  "@swc/core",
  "@babel/core",
  "turbo",
  "nx",
  "lerna",
  "tailwindcss",
  "postcss",
  // Languages and runners.
  "typescript",
  "tsx",
  "ts-node",
  // Linters and formatters.
  "eslint",
  "eslint-config-next",
  "@next/eslint-plugin-next",
  "@eslint/js",
  "@eslint/eslintrc",
  "typescript-eslint",
  "@typescript-eslint/parser",
  "@typescript-eslint/eslint-plugin",
  "eslint-config-prettier",
  "eslint-plugin-react",
  "eslint-plugin-react-hooks",
  "prettier",
  "@biomejs/biome",
  "oxlint",
  "stylelint",
  // Test runners.
  "jest",
  "ts-jest",
  "babel-jest",
  "vitest",
  "@vitest/coverage-v8",
  "@playwright/test",
  "playwright",
  "cypress",
  "mocha",
  "ava",
  "@testing-library/react",
  // Native or install-time tools that commonly fail installs.
  "node-gyp",
  "sharp",
  "prisma",
  "@prisma/client",
  "drizzle-kit",
  "husky",
] as const;
export const wellKnownPackageSchema = z.enum(WELL_KNOWN_PACKAGES);
export type WellKnownPackage = z.infer<typeof wellKnownPackageSchema>;

const WELL_KNOWN: ReadonlySet<string> = new Set(WELL_KNOWN_PACKAGES);

/**
 * The well-known package a module specifier or registry path names (`next/dist/server` → `next`,
 * `@tanstack/react-query/build` → `@tanstack/react-query`), or null for anything else: a relative
 * or absolute path, a Node builtin, any package not on the list.
 */
export function wellKnownPackageOf(specifier: string): WellKnownPackage | null {
  const parts = specifier.split("/");
  const name = specifier.startsWith("@") ? parts.slice(0, 2).join("/") : (parts[0] ?? "");
  return WELL_KNOWN.has(name) ? wellKnownPackageSchema.parse(name) : null;
}
