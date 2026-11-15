import { z } from "zod";

// Reader-only copies of the pinned Zod 4 schemas. Writers keep the original strict contracts.
// Only strict object's extra-key handling changes; enums, refinements, codecs and limits survive.
const readers = new WeakMap<z.ZodType, z.ZodType>();
const persistedReaders = new WeakMap<z.ZodType, z.ZodType>();
const enumDefaults = new WeakSet<z.ZodType>();

/** Architecture inventory uses schema identity, so aliases and wrappers cannot hide defaults. */
export function hasPersistedEnumDefault(schema: z.ZodType): boolean {
  return enumDefaults.has(schema);
}

/** Unknown persisted values refuse every mutation without retaining the value in the error. */
export class PersistedEnumUnknownError extends Error {
  readonly reason = "persisted_enum_unknown";
  constructor() {
    super("Unknown persisted enum value");
    this.name = "PersistedEnumUnknownError";
  }
}

function classic(schema: unknown): z.ZodType {
  if (schema instanceof z.ZodType) return schema;
  throw new TypeError("Tolerant readers require a classic Zod schema");
}

function readerFor(schema: z.ZodType, preserve = false): z.ZodType {
  const cache = preserve ? persistedReaders : readers;
  const cached = cache.get(schema);
  if (cached !== undefined) return cached;
  if (preserve && schema instanceof z.ZodEnum) {
    // Report an ordinary branch failure first: throwing here would prevent a union
    // from trying another branch whose enum recognizes this existing value.
    const reader = schema.clone({ ...schema.def, error: () => "persisted_enum_unknown" });
    cache.set(schema, reader);
    enumDefaults.add(reader);
    return reader;
  }
  const definition: z.core.$ZodTypeDef & Record<string, unknown> = { ...schema.def };

  if (schema instanceof z.ZodObject) {
    definition["shape"] = Object.fromEntries(
      Object.entries(schema.shape).map(([name, member]) => [
        name,
        readerFor(classic(member), preserve),
      ]),
    );
    if (schema.def.catchall instanceof z.ZodNever) {
      if (preserve) definition["catchall"] = z.unknown();
      else delete definition["catchall"];
    }
  }
  if (schema instanceof z.ZodLazy)
    definition["getter"] = () => readerFor(classic(schema.unwrap()), preserve);

  // Zod's wrappers, collections, intersections and pipes/codecs use these child slots.
  for (const key of [
    "innerType",
    "element",
    "keyType",
    "valueType",
    "left",
    "right",
    "in",
    "out",
    "rest",
    "catchall",
  ]) {
    const child: unknown = definition[key];
    if (child instanceof z.ZodType) definition[key] = readerFor(child, preserve);
  }
  for (const key of ["options", "items"]) {
    const children: unknown = definition[key];
    if (Array.isArray(children))
      definition[key] = children.map((child: unknown) =>
        child instanceof z.ZodType ? readerFor(child, preserve) : child,
      );
  }
  const reader = schema.clone(definition);
  cache.set(schema, reader);
  return reader;
}

/**
 * Ignores unknown object fields without relaxing any known value. Does not mutate input or the
 * writer schema. Never use this for persisted read/modify/write: stripped keys would be lost.
 */
export function tolerantReader<T extends z.ZodType>(schema: T): T {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- clone preserves the schema's constructor, known output types and every check; only extra object keys are stripped.
  return readerFor(schema) as T;
}

/** Persisted read/modify/write: recursively retain extra members; unknown enums refuse.
 * Use the returned reader for write-back encoding too. Strict writer schemas remain unchanged.
 */
export function persistedReader<T extends z.ZodType>(schema: T): T {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- known types and checks are preserved; extra keys survive at runtime.
  return readerFor(schema, true) as T;
}

const unknownEnum = (issues: readonly z.core.$ZodIssue[]): boolean =>
  issues.some(
    (issue) =>
      issue.message === "persisted_enum_unknown" ||
      (issue.code === "invalid_union" && issue.errors.some(unknownEnum)),
  );

/** Convert a whole-boundary enum refusal to a sanitized stable reason after union selection. */
export function parsePersisted<T extends z.ZodType>(schema: T, input: unknown): z.output<T> {
  try {
    return persistedReader(schema).parse(input);
  } catch (error) {
    if (error instanceof z.ZodError && unknownEnum(error.issues))
      throw new PersistedEnumUnknownError();
    throw error;
  }
}

/** Encode with the same sanitized unknown-enum refusal as persisted decoding. */
export function encodePersisted<T extends z.ZodType>(schema: T, input: z.output<T>): z.input<T> {
  try {
    return persistedReader(schema).encode(input);
  } catch (error) {
    if (error instanceof z.ZodError && unknownEnum(error.issues))
      throw new PersistedEnumUnknownError();
    throw error;
  }
}

const object = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value) && !(value instanceof Date);

/** Restore only unknown members after a strict known-field transformation.
 * Array correspondence belongs to the caller: removed/reordered entries must never
 * inherit another entry's extensions. Unmatched new entries have no stored extras.
 */
export function retainPersistedUnknown<T extends z.ZodType>(
  schema: T,
  previous: z.output<T>,
  updated: z.output<T>,
  arrayMatch: (path: string, item: unknown, index: number, previous: readonly unknown[]) => number,
): z.output<T> {
  const known = tolerantReader(schema).parse(tolerantReader(schema).encode(previous));
  const strict = schema.parse(schema.encode(updated));
  function merge(full: unknown, old: unknown, next: unknown, path: string): unknown {
    if (Array.isArray(next) && Array.isArray(old) && Array.isArray(full))
      return next.map((item: unknown, index: number) => {
        const prior = arrayMatch(path, item, index, old);
        return merge(full[prior], old[prior], item, `${path}[]`);
      });
    if (!object(next) || !object(old) || !object(full)) return next;
    return Object.fromEntries([
      ...Object.entries(full).filter(([key]) => !Object.hasOwn(old, key)),
      ...Object.entries(next).map(([key, value]) => [
        key,
        merge(full[key], old[key], value, `${path}.${key}`),
      ]),
    ]);
  }
  // Validate known fields and all refinements again after restoring opaque extensions.
  // Encoding validates decoded codec outputs without interpreting them as wire inputs.
  const merged = merge(previous, known, strict, "$");
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- merged keeps strict decoded fields; only opaque object members are restored.
  return parsePersisted(schema, encodePersisted(schema, merged as z.output<T>));
}
