// A bounded, conservative parser for the POSIX shell commands recipes carry (CI `run:` blocks,
// package.json scripts). It splits a script into simple commands at top-level control operators
// and returns each command's words with quotes removed. It never evaluates anything: expansions
// (`$VAR`, `$(…)`, backticks, globs) stay literal text, and constructs it cannot represent as a
// flat list of simple commands (subshells, groups, heredocs, process substitution, control flow)
// mark the script `complex`, so callers treat it as opaque instead of guessing.

/** The operator that ends a simple command. */
export type CommandTerminator = "&&" | "||" | ";" | "|" | "&" | "newline" | "end";

export interface SimpleCommand {
  /** Leading `NAME=value` assignments, verbatim. */
  readonly assignments: readonly string[];
  /** Command words with quotes removed; expansions left as literal text. */
  readonly argv: readonly string[];
  /** The operator after this command. */
  readonly terminator: CommandTerminator;
  /** Byte range of this command in the (normalized) script, for rewriting. */
  readonly start: number;
  readonly end: number;
}

export interface ParsedScript {
  readonly commands: readonly SimpleCommand[];
  /** True when the script uses constructs this parser does not model (see file comment). */
  readonly complex: boolean;
  /**
   * True when the script exceeded the parser's bounds (64 KiB, 2,000 commands) and was not read
   * to the end: `commands` is incomplete.
   */
  readonly truncated: boolean;
}

const MAX_SCRIPT_LENGTH = 64 * 1024;
const MAX_COMMANDS = 2_000;

const RESERVED = new Set([
  "if",
  "then",
  "else",
  "elif",
  "fi",
  "for",
  "while",
  "until",
  "do",
  "done",
  "case",
  "esac",
  "function",
  "select",
  "{",
  "}",
  "!",
  "[[",
  "]]",
]);

const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

/** Keywords that may precede a command inside control flow (`then npm ci`, `if ! npm test`). */
const LEADING_KEYWORDS = new Set(["if", "then", "else", "elif", "while", "until", "do", "!", "{"]);

/**
 * A command's words without leading shell keywords, so a command inside control flow can still be
 * recognized (`then npm ci` runs `npm ci`).
 */
export function withoutKeywords(argv: readonly string[]): readonly string[] {
  let index = 0;
  while (index < argv.length && LEADING_KEYWORDS.has(argv[index] ?? "")) index += 1;
  return argv.slice(index);
}

interface Cursor {
  readonly text: string;
  index: number;
  complex: boolean;
}

function isBlank(ch: string): boolean {
  return ch === " " || ch === "\t";
}

function isWordEnd(ch: string): boolean {
  return (
    ch === "" ||
    isBlank(ch) ||
    ch === "\n" ||
    ch === ";" ||
    ch === "&" ||
    ch === "|" ||
    ch === "(" ||
    ch === ")" ||
    ch === "<" ||
    ch === ">"
  );
}

/** Reads `$(…)`, `${…}` or `$((…))` verbatim, tracking nesting and quotes. */
function readDollarGroup(cursor: Cursor, open: string, close: string): string {
  const { text } = cursor;
  const begin = cursor.index;
  let depth = 0;
  while (cursor.index < text.length) {
    const ch = text[cursor.index] ?? "";
    if (ch === "\\") {
      cursor.index += 2;
      continue;
    }
    if (ch === "'") {
      const closeQuote = text.indexOf("'", cursor.index + 1);
      cursor.index = closeQuote === -1 ? text.length : closeQuote + 1;
      continue;
    }
    if (ch === open) depth += 1;
    if (ch === close) {
      depth -= 1;
      if (depth === 0) {
        cursor.index += 1;
        return text.slice(begin, cursor.index);
      }
    }
    cursor.index += 1;
  }
  cursor.complex = true;
  return text.slice(begin);
}

/** Reads one word starting at the cursor; returns null at a word boundary. */
function readWord(cursor: Cursor): string | null {
  const { text } = cursor;
  let value = "";
  let started = false;
  while (cursor.index < text.length) {
    const ch = text[cursor.index] ?? "";
    if (isWordEnd(ch)) break;
    started = true;
    if (ch === "\\") {
      const next = text[cursor.index + 1] ?? "";
      cursor.index += 2;
      if (next !== "\n") value += next; // a backslash-newline is a line continuation
      continue;
    }
    if (ch === "'") {
      const closeQuote = text.indexOf("'", cursor.index + 1);
      if (closeQuote === -1) {
        cursor.complex = true;
        value += text.slice(cursor.index + 1);
        cursor.index = text.length;
        break;
      }
      value += text.slice(cursor.index + 1, closeQuote);
      cursor.index = closeQuote + 1;
      continue;
    }
    if (ch === '"') {
      cursor.index += 1;
      let closed = false;
      while (cursor.index < text.length) {
        const inner = text[cursor.index] ?? "";
        if (inner === '"') {
          cursor.index += 1;
          closed = true;
          break;
        }
        if (inner === "\\") {
          const next = text[cursor.index + 1] ?? "";
          if (next === "$" || next === "`" || next === '"' || next === "\\") value += next;
          else if (next !== "\n") value += `\\${next}`;
          cursor.index += 2;
          continue;
        }
        if (inner === "$" && (text[cursor.index + 1] === "(" || text[cursor.index + 1] === "{")) {
          const open = text[cursor.index + 1] ?? "(";
          cursor.index += 1;
          value += `$${readDollarGroup(cursor, open, open === "(" ? ")" : "}")}`;
          continue;
        }
        if (inner === "`") cursor.complex = true;
        value += inner;
        cursor.index += 1;
      }
      if (!closed) cursor.complex = true;
      continue;
    }
    if (ch === "$" && (text[cursor.index + 1] === "(" || text[cursor.index + 1] === "{")) {
      const open = text[cursor.index + 1] ?? "(";
      cursor.index += 1;
      value += `$${readDollarGroup(cursor, open, open === "(" ? ")" : "}")}`;
      continue;
    }
    if (ch === "`") {
      cursor.complex = true;
      const closeTick = text.indexOf("`", cursor.index + 1);
      const stop = closeTick === -1 ? text.length : closeTick + 1;
      value += text.slice(cursor.index, stop);
      cursor.index = stop;
      continue;
    }
    value += ch;
    cursor.index += 1;
  }
  return started ? value : null;
}

/** Skips a redirection operator and its target word (`> out.log`, `2>&1`, `&>/dev/null`). */
function skipRedirection(cursor: Cursor): void {
  const { text } = cursor;
  if (text.startsWith("<<", cursor.index)) {
    // Heredocs carry the following lines as data: never model them.
    cursor.complex = true;
  }
  if (text.startsWith("<(", cursor.index) || text.startsWith(">(", cursor.index)) {
    cursor.complex = true;
  }
  while (text[cursor.index] === "<" || text[cursor.index] === ">" || text[cursor.index] === "&") {
    cursor.index += 1;
  }
  while (isBlank(text[cursor.index] ?? "")) cursor.index += 1;
  readWord(cursor);
}

/** Parses `script` into top-level simple commands. */
export function parseScript(script: string): ParsedScript {
  if (script.length > MAX_SCRIPT_LENGTH) return { commands: [], complex: true, truncated: true };
  const text = script.replaceAll("\r\n", "\n");
  const cursor: Cursor = { text, index: 0, complex: false };
  const commands: SimpleCommand[] = [];
  let assignments: string[] = [];
  let argv: string[] = [];
  let start = -1;

  const finish = (terminator: CommandTerminator, end: number): void => {
    if (argv.length > 0 || assignments.length > 0) {
      if (RESERVED.has(argv[0] ?? "")) cursor.complex = true;
      commands.push({ assignments, argv, terminator, start, end });
    } else if (terminator === "&&" || terminator === "||" || terminator === "|") {
      cursor.complex = true; // an operator without a command before it
    }
    assignments = [];
    argv = [];
    start = -1;
    if (commands.length > MAX_COMMANDS) cursor.complex = true;
  };

  while (cursor.index < text.length && commands.length <= MAX_COMMANDS) {
    const ch = text[cursor.index] ?? "";
    if (isBlank(ch)) {
      cursor.index += 1;
      continue;
    }
    if (text.startsWith("\\\n", cursor.index)) {
      cursor.index += 2; // a line continuation between words
      continue;
    }
    if (ch === "#") {
      // Words are consumed whole, so a `#` here starts a word: a comment to the end of the line.
      const newline = text.indexOf("\n", cursor.index);
      cursor.index = newline === -1 ? text.length : newline;
      continue;
    }
    const end = cursor.index;
    if (ch === "\n") {
      cursor.index += 1;
      finish("newline", end);
      continue;
    }
    if (text.startsWith("&&", cursor.index) || text.startsWith("||", cursor.index)) {
      cursor.index += 2;
      finish(ch === "&" ? "&&" : "||", end);
      continue;
    }
    if (text.startsWith(";;", cursor.index) || ch === "(" || ch === ")") {
      cursor.complex = true;
      cursor.index += ch === ";" ? 2 : 1;
      finish(";", end);
      continue;
    }
    if (ch === ";") {
      cursor.index += 1;
      finish(";", end);
      continue;
    }
    if (text.startsWith("|&", cursor.index)) {
      cursor.index += 2;
      finish("|", end);
      continue;
    }
    if (ch === "|") {
      cursor.index += 1;
      finish("|", end);
      continue;
    }
    if (ch === "&" && text[cursor.index + 1] !== ">") {
      cursor.index += 1;
      finish("&", end);
      continue;
    }
    if (
      ch === "<" ||
      ch === ">" ||
      ch === "&" ||
      (/\d/.test(ch) && />|</.test(text[cursor.index + 1] ?? ""))
    ) {
      if (start === -1) start = cursor.index;
      if (/\d/.test(ch)) cursor.index += 1;
      skipRedirection(cursor);
      continue;
    }
    if (start === -1) start = cursor.index;
    const word = readWord(cursor);
    if (word === null) {
      cursor.index += 1;
      continue;
    }
    if (argv.length === 0 && ASSIGNMENT.test(word)) assignments.push(word);
    else argv.push(word);
  }
  const truncated = commands.length > MAX_COMMANDS;
  if (!truncated) finish("end", text.length);
  return { commands, complex: cursor.complex || truncated, truncated };
}
