import { spawn, type ChildProcess } from "node:child_process";

import { usageError } from "../errors.js";

// The package manager as a child process. The resolve step runs quietly (its output is discarded:
// the CLI never prints another program's raw output, and nothing it says is needed); the install,
// the frozen install, the fetched tool and read-only commands run with the terminal's stdio, as if
// the user had run them.

/** The environment a package manager gets: the caller's, without the Kovo API key. */
export function packageManagerEnvironment(
  env: Readonly<Record<string, string | undefined>>,
): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const [name, value] of Object.entries(env))
    if (value !== undefined && name !== "KOVO_API_KEY") out[name] = value;
  return out;
}

export interface ChildExit {
  /** The exit status, or null when a signal ended it. */
  readonly status: number | null;
}

/**
 * Runs `command args` in `cwd` and waits for it. `onStart` gets the child (to stop it on an
 * interrupt). Error (exit 2): the program is not installed or cannot be started.
 */
export function runChild(
  command: string,
  args: readonly string[],
  options: {
    readonly cwd: string;
    readonly env: NodeJS.ProcessEnv;
    readonly stdio: "quiet" | "inherit";
    readonly onStart?: (child: ChildProcess) => void;
  },
): Promise<ChildExit> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: options.stdio === "inherit" ? "inherit" : "ignore",
    });
    options.onStart?.(child);
    child.on("error", (error: NodeJS.ErrnoException) => {
      reject(
        error.code === "ENOENT"
          ? usageError("package_manager_missing", `${command} is not installed or not on PATH.`)
          : usageError("package_manager_failed", `${command} could not be started.`),
      );
    });
    child.on("close", (status) => resolve({ status }));
  });
}

/** A child's exit as the wrapper's own: its status, 1 for a signal; never 0 for a failure. */
export function exitOf(exit: ChildExit): number {
  return exit.status ?? 1;
}
