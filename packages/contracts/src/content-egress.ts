import { z } from "zod";
import { accountIdSchema, repoIdSchema } from "./ids.js";

export type ContentEgressDestination = "openrouter" | "model-relay";
declare const authorizedContentEgress: unique symbol;
/** Local authority, issued after existing authorization succeeds; never a wire or DBOS value. */
export type ContentEgressAuthorizationGrant<
  D extends ContentEgressDestination = ContentEgressDestination,
> = {
  readonly [authorizedContentEgress]: D;
};

const authorityBase = {
  accountId: accountIdSchema,
  repoId: repoIdSchema,
  jobId: z.string().min(1).max(256),
};
const authoritySchema = z.discriminatedUnion("destination", [
  z.strictObject({
    ...authorityBase,
    destination: z.literal("openrouter"),
    model: z.string().min(1).max(256),
  }),
  z.strictObject({ ...authorityBase, destination: z.literal("model-relay") }),
]);
export type ContentEgressAuthority = z.infer<typeof authoritySchema>;
const grants = new WeakMap<object, ContentEgressAuthority>();
const researchGrants = new WeakMap<
  object,
  { sourceUrl: string; fetchRecordId: string; pageSha256: string }
>();

/** Internal registration; exposed only through the restricted research issuer subpath. */
export function registerResearchEgressGrant(record: {
  sourceUrl: string;
  fetchRecordId: string;
  pageSha256: string;
}): ContentEgressAuthorizationGrant<"openrouter"> {
  const parsed = z
    .strictObject({
      sourceUrl: z.url().max(2048),
      fetchRecordId: z.uuid(),
      pageSha256: z.string().regex(/^[a-f0-9]{64}$/),
    })
    .parse(record);
  const grant = Object.freeze({});
  researchGrants.set(grant, Object.freeze(parsed));
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion
  return grant as ContentEgressAuthorizationGrant<"openrouter">;
}

/** Tenant/job grants and research grants are disjoint runtime authority. */
export function researchEgressAuthorized(
  grant: unknown,
  record: { sourceUrl: string; fetchRecordId: string; pageSha256: string },
): boolean {
  if (grant === null || typeof grant !== "object") return false;
  const expected = researchGrants.get(grant);
  return (
    expected !== undefined &&
    expected.sourceUrl === record.sourceUrl &&
    expected.fetchRecordId === record.fetchRecordId &&
    expected.pageSha256 === record.pageSha256
  );
}

/** Internal registration; deliberately absent from the package's public exports. */
export function registerContentEgressGrant<D extends ContentEgressDestination, T extends object>(
  value: T,
  authority: ContentEgressAuthority & { destination: D },
): T & ContentEgressAuthorizationGrant<D> {
  const grant = Object.freeze({ ...value });
  grants.set(grant, Object.freeze(authoritySchema.parse(authority)));
  // The only assertion that mints the opaque type; runtime authority is held in the private map.
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion
  return grant as T & ContentEgressAuthorizationGrant<D>;
}

/** A cast, copied/serialized object, wrong destination or another job never carries authority. */
export function contentEgressAuthorized(
  grant: unknown,
  destination: ContentEgressDestination,
  request: {
    readonly jobId: string;
    readonly model?: string;
    readonly accountId?: string;
    readonly repoId?: string;
  },
): boolean {
  if (grant === null || typeof grant !== "object") return false;
  const authority = grants.get(grant);
  return (
    authority !== undefined &&
    authority.destination === destination &&
    authority.jobId === request.jobId &&
    (request.accountId === undefined || authority.accountId === request.accountId) &&
    (request.repoId === undefined || authority.repoId === request.repoId) &&
    (authority.destination === "model-relay" || authority.model === request.model)
  );
}
