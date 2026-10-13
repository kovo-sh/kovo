import { z } from "zod";

// Identifiers of a deployment that several packages validate: the environment a process runs in
// (`KOVO_ENV`, the name `@kovo/config` selects the checked-in file by and telemetry reports) and the
// release an image was built as (`KOVO_VERSION`, OpenTelemetry's `service.version`, Sentry's
// release). The configuration, the telemetry adapters and the web app's error reporting accept the
// same values because they share these definitions (docs/decisions/config-and-secrets.md).
//
// It also lists the environment variables a Kovo process reads at all (`RUNTIME_VARIABLES`): the
// configuration, the control plane's platform variables, the web server's listener and release, and
// the release tool read their process's environment only through `runtimeVariablesOf`, so every
// other variable is invisible to them. The list lives here because every one of those readers may
// import this package (ARCHITECTURE §2: `@kovo/adapters` may not import `@kovo/config`); docs/decisions/config-and-secrets.md "Only allowlisted environment reads
// remain".

/**
 * An environment's name: lower case, 2–16 characters (`local`, `test`, `prod`, …). The list
 * of environments is configuration data (`@kovo/config`), never an enum here.
 */
export const environmentNameSchema = z
  .string()
  .regex(/^[a-z][a-z0-9-]{1,15}$/, { error: "must be a lower-case environment name" });

/** A release identifier (`2026.09.28-1`, `r1-0123456789ab`); `dev` outside a release image. */
export const releaseIdSchema = z
  .string()
  .regex(/^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/, { error: "must be a release identifier" });
export type ReleaseId = z.infer<typeof releaseIdSchema>;

/**
 * Every environment variable a Kovo process (api, worker, proxy, the web server, the migrate job,
 * the release tool, the local fake-vendor hub) reads, and why. Configuration is the checked-in file
 * `KOVO_ENV` selects and secrets come from GCP Secret Manager (read with Application Default
 * Credentials, which google-auth-library finds itself: not a Kovo read); what remains is what the
 * platform, the image or one execution tells a process. The image's entrypoint script also reads `KOVO_WORKER_HEAP_MB`
 * (the worker's `--max-old-space-size`), which no process sees as a setting.
 */
export const RUNTIME_VARIABLES = {
  KOVO_ENV: "the environment whose checked-in configuration the process loads (@kovo/config)",
  KOVO_CONFIG_OVERRIDES:
    "a developer's JSON adjustments to the configuration, accepted by the local environment only (@kovo/config)",
  K_SERVICE:
    "set by Cloud Run in a service's containers: a local or test environment is refused where it is set (@kovo/config)",
  CLOUD_RUN_JOB:
    "set by Cloud Run in a job's containers: a local or test environment is refused where it is set (@kovo/config)",
  CLOUD_RUN_WORKER_POOL:
    "set by Cloud Run in a worker pool's containers: a local or test environment is refused where it is set (@kovo/config)",
  PORT: "the port the platform (or a dev script) tells the process to listen on",
  KOVO_VERSION: "the release the image was built as (its build argument; telemetry and Sentry)",
  KOVO_ENTRYPOINT:
    "the backend process kind the image's entrypoint runs (the instrument file names the telemetry service by it)",
  KOVO_RELEASE_RECORD_B64:
    "the release record one `release record` execution carries (the release tool's input, not configuration)",
} as const;

/** The name of an environment variable a Kovo process reads. */
export type RuntimeVariable = keyof typeof RUNTIME_VARIABLES;

/** The runtime variables of a process's environment, each as it was set; nothing else. */
export type RuntimeVariables = { readonly [Name in RuntimeVariable]?: string };

/**
 * The shape of a Zod schema parsed from `RuntimeVariables` (`satisfies` it: a key that is not a
 * runtime variable does not compile).
 */
export type RuntimeVariablesShape = { readonly [Name in RuntimeVariable]?: z.ZodType };

/**
 * Variables Cloud Run sets in every container it runs (its container contract): a service's
 * `K_SERVICE`, a job's `CLOUD_RUN_JOB`, a worker pool's `CLOUD_RUN_WORKER_POOL`. Their presence means
 * the process runs deployed, whatever `KOVO_ENV` says.
 */
export const CLOUD_RUN_VARIABLES = [
  "K_SERVICE",
  "CLOUD_RUN_JOB",
  "CLOUD_RUN_WORKER_POOL",
] as const satisfies readonly RuntimeVariable[];

const RUNTIME_VARIABLE_NAMES = Object.keys(RUNTIME_VARIABLES).filter(
  (name): name is RuntimeVariable => Object.hasOwn(RUNTIME_VARIABLES, name),
);

/**
 * The runtime variables out of a process's environment (its own, or one a test passes):
 * every other variable is dropped, so a reader of the result cannot see one, whatever it asks for.
 */
export function runtimeVariablesOf(
  env: Readonly<Record<string, string | undefined>>,
): RuntimeVariables {
  const variables: { [Name in RuntimeVariable]?: string } = {};
  for (const name of RUNTIME_VARIABLE_NAMES) {
    const value = env[name];
    if (value !== undefined) variables[name] = value;
  }
  return variables;
}
