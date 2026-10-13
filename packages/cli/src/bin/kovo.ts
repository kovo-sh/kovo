#!/usr/bin/env node
// The `kovo` executable: the entry point esbuild bundles into dist/kovo.mjs.
import { setTimeout as sleep } from "node:timers/promises";

import { runCli } from "../cli.js";

const INTERRUPTS = ["SIGINT", "SIGTERM", "SIGHUP"] as const;

process.exitCode = await runCli(process.argv.slice(2), {
  cwd: process.cwd(),
  env: process.env,
  stdout: (text) => process.stdout.write(text),
  stderr: (text) => process.stderr.write(text),
  fetch: globalThis.fetch,
  sleep: (ms) => sleep(ms),
  now: () => new Date(),
  onInterrupt: (handler) => {
    for (const signal of INTERRUPTS) process.on(signal, handler);
    return () => {
      for (const signal of INTERRUPTS) process.off(signal, handler);
    };
  },
});
