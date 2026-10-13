import { z } from "zod";

export interface CompatibilityOptions {
  representation?: "json" | "dbos";
  /** Serialized values emitted by this release; defaults to the reader's input language. */
  writer?: z.ZodType;
  /** Named limits and custom validations which JSON Schema cannot express. */
  constraints?: Record<string, unknown>;
}

const boundaries = new Map<
  string,
  {
    kind: "persisted" | "wire";
    reader: z.ZodType;
    writer: z.ZodType;
    constraints: Record<string, unknown>;
    representation: "json" | "dbos";
  }
>();

const shadowed = new Map<string, NonNullable<ReturnType<typeof boundaries.get>>[]>();

const customRepresentations = new WeakMap<object, { schema: z.ZodType; name: string }>();

const pinnedWriters = new WeakMap<object, z.ZodType>();

/** Tooling-only inventory of the actual registered readers, without changing their identity. */
export function persistedReaderSchemas(): ReadonlyMap<string, z.ZodType> {
  return new Map(
    [...boundaries]
      .filter(([, entry]) => entry.kind === "persisted")
      .map(([name, entry]) => [name, entry.reader]),
  );
}

/**
 * Reader first (docs/decisions/schema-compatibility.md "Reader-first sequencing"): `schema` already
 * accepts values this release does not emit yet. Wherever `schema` appears in a boundary's writer,
 * at its root or nested, the snapshot describes `writer` instead, until the writer PR drops the pin.
 * The runtime parser keeps its identity and its full reader language.
 */
export function writerPinned<S extends z.ZodType>(schema: S, writer: z.ZodType): S {
  pinnedWriters.set(schema, writer);
  return schema;
}

/** Explicitly describe a custom predicate whose accepted language is an existing schema. */
export function represented<S extends z.ZodType>(schema: S, name: string, input: z.ZodType): S {
  customRepresentations.set(schema, { schema: input, name });
  return schema;
}

function register<S extends z.ZodType>(
  kind: "persisted" | "wire",
  name: string,
  schema: S,
  options: CompatibilityOptions,
): S {
  if (!/^[A-Za-z][A-Za-z0-9_.-]+$/.test(name))
    throw new Error("invalid compatibility boundary name");
  const prior = boundaries.get(name);
  if (prior) shadowed.set(name, [...(shadowed.get(name) ?? []), prior]);
  boundaries.set(name, {
    kind,
    reader: schema,
    writer: options.writer ?? schema,
    constraints: options.constraints ?? {},
    representation: options.representation ?? "json",
  });
  return schema;
}

/** Records the existing parser without wrapping it or changing its identity. */
export function persisted<S extends z.ZodType>(
  name: string,
  schema: S,
  options: CompatibilityOptions = {},
): S {
  return register("persisted", name, schema, options);
}

export function wire<S extends z.ZodType>(
  name: string,
  schema: S,
  options: CompatibilityOptions = {},
): S {
  return register("wire", name, schema, options);
}

/** Input mode describes serialized codec values, rather than Date/bigint outputs. */
export function compatibilitySnapshot() {
  for (const [name, priors] of shadowed) {
    const current = boundaries.get(name);
    if (!current) throw new Error("missing registered boundary");
    const expected = serializeBoundary(name, current);
    for (const prior of priors) {
      if (expected !== serializeBoundary(name, prior))
        throw new Error(`Conflicting compatibility registrations: ${name}`);
    }
  }
  return {
    version: 1 as const,
    entries: Object.fromEntries(
      [...boundaries]
        .toSorted(([a], [b]) => a.localeCompare(b))
        .map(([name, boundary]) => [
          name,
          {
            kind: boundary.kind,
            reader: namedSchema(name, boundary.reader, boundary.representation, "reader"),
            writer: namedSchema(name, boundary.writer, boundary.representation, "writer"),
            constraints: { ...boundary.constraints, representation: boundary.representation },
          },
        ]),
    ),
  };
}

function toSchema(
  schema: z.ZodType,
  representation: "json" | "dbos",
  side: "reader" | "writer",
): Record<string, unknown> {
  // DBOS uses SuperJSON: Date and bigint have distinct serialized type tags.
  // These schemas describe the decoded value language plus its tag, not the envelope.
  return z.toJSONSchema(schema, {
    io: "input",
    unrepresentable: "any",
    override: ({ zodSchema, jsonSchema }) => {
      // Zod toJSONSchema exposes core schema internals to its override hook.
      // oxlint-disable-next-line eslint/no-underscore-dangle
      const type = zodSchema._zod.def.type;
      const custom = customRepresentations.get(zodSchema);
      const pinned = side === "writer" ? pinnedWriters.get(zodSchema) : undefined;
      if (pinned !== undefined) {
        const described = toSchema(pinned, representation, side);
        delete described["$schema"];
        for (const key of Object.keys(jsonSchema)) delete jsonSchema[key];
        Object.assign(jsonSchema, described);
      } else if (custom)
        Object.assign(jsonSchema, z.toJSONSchema(custom.schema, { io: "input" }), {
          "x-custom-validation": custom.name,
        });
      else if (type === "date")
        Object.assign(
          jsonSchema,
          representation === "dbos"
            ? { type: "string", format: "date-time", "x-dbos-type": "Date" }
            : { not: {}, "x-in-memory-only": "Date" },
        );
      else if (type === "bigint")
        Object.assign(
          jsonSchema,
          representation === "dbos"
            ? { type: "string", pattern: "^-?[0-9]+$", "x-dbos-type": "bigint" }
            : { not: {}, "x-in-memory-only": "bigint" },
        );
      else if (
        ["custom", "transform", "map", "set", "symbol", "function", "undefined", "nan"].includes(
          type,
        )
      ) {
        throw new Error(`Unsupported DBOS compatibility schema: ${type}`);
      }
    },
  });
}

function namedSchema(
  name: string,
  schema: z.ZodType,
  representation: "json" | "dbos",
  side: "reader" | "writer",
) {
  try {
    return toSchema(schema, representation, side);
  } catch (error) {
    throw new Error(
      `Compatibility boundary ${name}: ${error instanceof Error ? error.message : "unsupported schema"}`,
      { cause: error },
    );
  }
}

function serializeBoundary(name: string, boundary: NonNullable<ReturnType<typeof boundaries.get>>) {
  return JSON.stringify({
    kind: boundary.kind,
    reader: namedSchema(name, boundary.reader, boundary.representation, "reader"),
    writer: namedSchema(name, boundary.writer, boundary.representation, "writer"),
    constraints: boundary.constraints,
    representation: boundary.representation,
  });
}
