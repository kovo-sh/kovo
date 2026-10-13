import { z } from "zod";

// Money (ARCHITECTURE §3 "Money"; SPEC "Persist money at fixed-point micro-USD precision, sum
// eligible costs and markup before rounding invoice totals to cents"). Every amount is an integer
// number of micro-USD held in a `bigint`; nothing here ever touches a JS `number` fraction.

export const MICRO_USD_PER_USD = 1_000_000n;
export const MICRO_USD_PER_CENT = 10_000n;

/** Postgres `bigint` range: every amount must fit the column it is stored in. */
export const MICRO_USD_MIN = -(2n ** 63n);
export const MICRO_USD_MAX = 2n ** 63n - 1n;

/** A signed amount of micro-USD (1 USD = 1_000_000). */
export const microUsdSchema = z.bigint().min(MICRO_USD_MIN).max(MICRO_USD_MAX).brand<"MicroUsd">();
export type MicroUsd = z.infer<typeof microUsdSchema>;

/** A non-negative amount (costs, prices, limits). Same brand as {@link microUsdSchema}. */
export const nonNegativeMicroUsdSchema = z.bigint().min(0n).max(MICRO_USD_MAX).brand<"MicroUsd">();

const SIGNED_DECIMAL = /^-?(?:0|[1-9]\d{0,18})$/;
const UNSIGNED_DECIMAL = /^(?:0|[1-9]\d{0,18})$/;

/**
 * Wire codec: JSON carries micro-USD as a canonical decimal integer string (`"20000000"`), because
 * `JSON.stringify(1n)` throws and JSON numbers lose precision past 2^53. Leading zeros, `+`, `-0`,
 * whitespace and exponents are rejected so every amount has exactly one spelling.
 */
export const microUsdWireSchema = z.codec(
  z
    .string()
    .regex(SIGNED_DECIMAL, { error: "must be a decimal integer string of micro-USD" })
    .refine((text) => text !== "-0", { error: "must not be negative zero" }),
  microUsdSchema,
  { decode: (text) => BigInt(text), encode: (amount) => amount.toString() },
);

/** Wire codec for non-negative amounts. */
export const nonNegativeMicroUsdWireSchema = z.codec(
  z.string().regex(UNSIGNED_DECIMAL, {
    error: "must be a non-negative decimal integer string of micro-USD",
  }),
  nonNegativeMicroUsdSchema,
  { decode: (text) => BigInt(text), encode: (amount) => amount.toString() },
);

/**
 * A per-token price as micro-USD per million tokens: OpenRouter lists USD per token as decimal
 * strings and its `max_price` takes USD per million tokens. Integers, so a price ceiling and the
 * relay's worst-case projection compare exactly (one definition for the model adapter and
 * `@kovo/core/billing` `decideModelRequest`).
 */
export const tokenPricingSchema = z.strictObject({
  promptPerMillion: nonNegativeMicroUsdSchema,
  completionPerMillion: nonNegativeMicroUsdSchema,
});
export type TokenPricing = z.infer<typeof tokenPricingSchema>;

/** Brands an integer micro-USD amount; throws `RangeError` outside the Postgres `bigint` range. */
export function microUsd(amount: bigint): MicroUsd {
  const result = microUsdSchema.safeParse(amount);
  if (!result.success) {
    throw new RangeError(`micro-USD amount ${amount} is outside the bigint column range`);
  }
  return result.data;
}

/** Whole US dollars to micro-USD (`usd(20n)` is `$20.00`). */
export function usd(dollars: bigint): MicroUsd {
  return microUsd(dollars * MICRO_USD_PER_USD);
}

/** Integer cents to micro-USD (exact). */
export function centsToMicroUsd(cents: bigint): MicroUsd {
  return microUsd(cents * MICRO_USD_PER_CENT);
}

export const ZERO_MICRO_USD: MicroUsd = microUsd(0n);

// ---- SPEC "Plans, billing, and usage" constants ----

/** Kovo Plus: "$20/month", "3 included". */
export const PLUS_BASE: MicroUsd = usd(20n);
/** "Plus additional capacity: $10/month per additional repo". */
export const EXTRA_REPO: MicroUsd = usd(10n);
/** Protected repositories included in the Plus base price. */
export const INCLUDED_REPOS = 3;
/** "Free has one active slot." */
export const FREE_REPOS = 1;

/** A non-negative rational multiplier with a positive denominator. */
export interface Ratio {
  readonly numerator: bigint;
  readonly denominator: bigint;
}

/** "Overages are actual approved model + sandbox cost × 1.20" = 6/5 in integers. */
export const OVERAGE_MARKUP: Ratio = { numerator: 6n, denominator: 5n };
/** "The billing-cycle internal cost allowance is 1× the account's paid subscription amount". */
export const ALLOWANCE_MULTIPLIER: Ratio = { numerator: 1n, denominator: 1n };
/** "Usage approaching allowance: At 80%, once per cycle". */
export const USAGE_WARNING_THRESHOLD: Ratio = { numerator: 4n, denominator: 5n };

// ---- Rounding ----

/**
 * - `floor`: toward −∞. `ceil`: toward +∞. `trunc`: toward zero.
 * - `half_up`: to nearest, ties away from zero (commercial rounding; for non-negative amounts ties
 *   round up).
 * - `half_even`: to nearest, ties to the even neighbour (banker's rounding).
 */
export const ROUNDING_MODES = ["floor", "ceil", "trunc", "half_up", "half_even"] as const;
export const roundingModeSchema = z.enum(ROUNDING_MODES);
export type RoundingMode = z.infer<typeof roundingModeSchema>;

/** Integer division `numerator / denominator` rounded with `mode`. Throws on a zero denominator. */
export function divideRounded(numerator: bigint, denominator: bigint, mode: RoundingMode): bigint {
  if (denominator === 0n) throw new RangeError("division by zero");
  const n = denominator < 0n ? -numerator : numerator;
  const d = denominator < 0n ? -denominator : denominator;
  const quotient = n / d; // BigInt division truncates toward zero
  const remainder = n % d; // same sign as n
  if (remainder === 0n) return quotient;
  const awayFromZero = n < 0n ? quotient - 1n : quotient + 1n;
  const twiceRemainder = (remainder < 0n ? -remainder : remainder) * 2n;
  const halfUp = twiceRemainder >= d ? awayFromZero : quotient;
  const evenNeighbour = quotient % 2n === 0n ? quotient : awayFromZero;
  const rounded: Record<RoundingMode, bigint> = {
    trunc: quotient,
    floor: n < 0n ? quotient - 1n : quotient,
    ceil: n > 0n ? quotient + 1n : quotient,
    half_up: halfUp,
    // Only an exact tie differs from half_up.
    half_even: twiceRemainder === d ? evenNeighbour : halfUp,
  };
  return rounded[mode];
}

/** `amount × ratio`, rounded to a whole micro-USD with an explicit rounding mode. */
export function mulRatio(amount: MicroUsd, ratio: Ratio, mode: RoundingMode): MicroUsd {
  if (ratio.denominator <= 0n) throw new RangeError("ratio denominator must be positive");
  if (ratio.numerator < 0n) throw new RangeError("ratio numerator must be non-negative");
  return microUsd(divideRounded(amount * ratio.numerator, ratio.denominator, mode));
}

/**
 * The post-markup overage charge for an approved base cost (× 6/5). Apply it to the *summed* base
 * of a batch, not per item. Use `ceil` when projecting charges against the post-markup spending
 * limit (never under-count), `half_up` for the recorded charge.
 */
export function applyMarkup(base: MicroUsd, mode: RoundingMode): MicroUsd {
  return mulRatio(base, OVERAGE_MARKUP, mode);
}

// ---- Arithmetic (range-checked; results stay within the bigint column range) ----

export function addMicroUsd(a: MicroUsd, b: MicroUsd): MicroUsd {
  return microUsd(a + b);
}

export function subMicroUsd(a: MicroUsd, b: MicroUsd): MicroUsd {
  return microUsd(a - b);
}

export function sumMicroUsd(amounts: Iterable<MicroUsd>): MicroUsd {
  let total = 0n;
  for (const amount of amounts) total += amount;
  return microUsd(total);
}

export function minMicroUsd(a: MicroUsd, b: MicroUsd): MicroUsd {
  return a <= b ? a : b;
}

export function maxMicroUsd(a: MicroUsd, b: MicroUsd): MicroUsd {
  return a >= b ? a : b;
}

/** `a − b`, floored at zero (remaining allowance, remaining authorized spend). */
export function subMicroUsdFloorZero(a: MicroUsd, b: MicroUsd): MicroUsd {
  return a > b ? microUsd(a - b) : ZERO_MICRO_USD;
}

export function compareMicroUsd(a: MicroUsd, b: MicroUsd): -1 | 0 | 1 {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}

/**
 * Invoice total in integer cents: sums every amount first, then rounds half-up once (SPEC: "sum
 * eligible costs and markup before rounding invoice totals to cents").
 */
export function toInvoiceCents(amounts: readonly MicroUsd[]): bigint {
  return divideRounded(sumMicroUsd(amounts), MICRO_USD_PER_CENT, "half_up");
}

// ---- Text ----

const USD_TEXT = /^(0|[1-9]\d{0,12})(?:\.(\d{1,6}))?$/;

/**
 * Parses a non-negative dollar amount typed by a person (`"12.34"`, `"0.000001"`, `"50"`) into
 * micro-USD. At most six decimals and no sign, currency symbol, separators or exponent.
 */
export function parseUsd(text: string): MicroUsd {
  const match = USD_TEXT.exec(text);
  if (match === null) throw new RangeError(`not a dollar amount: ${JSON.stringify(text)}`);
  const whole = BigInt(match[1] ?? "0");
  const fraction = BigInt((match[2] ?? "").padEnd(6, "0"));
  return microUsd(whole * MICRO_USD_PER_USD + fraction);
}

function groupThousands(digits: string): string {
  return digits.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

export interface FormatUsdOptions {
  /**
   * `cents` (default) rounds half-up to two decimals. `micro` shows the exact amount with trailing
   * zeros trimmed but at least two decimals (`$0.0042`).
   */
  readonly precision?: "cents" | "micro";
}

/** Display formatting: `$1,234.56`, `-$0.50`. Never uses floating point. */
export function formatUsd(amount: MicroUsd, options: FormatUsdOptions = {}): string {
  const precision = options.precision ?? "cents";
  let fractionDigits: string;
  let whole: bigint;
  let negative: boolean;
  if (precision === "cents") {
    const cents = divideRounded(amount, MICRO_USD_PER_CENT, "half_up");
    negative = cents < 0n;
    const magnitude = negative ? -cents : cents;
    whole = magnitude / 100n;
    fractionDigits = (magnitude % 100n).toString().padStart(2, "0");
  } else {
    const raw: bigint = amount;
    negative = raw < 0n;
    const magnitude = negative ? -raw : raw;
    whole = magnitude / MICRO_USD_PER_USD;
    fractionDigits = (magnitude % MICRO_USD_PER_USD)
      .toString()
      .padStart(6, "0")
      .replace(/0{1,4}$/, "");
  }
  return `${negative ? "-" : ""}$${groupThousands(whole.toString())}.${fractionDigits}`;
}
