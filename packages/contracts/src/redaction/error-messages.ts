// Only KovoError, PortError and ConfigError constructors register messages. Keep identity and the original
// message private: copying a name, prototype or enumerable properties grants nothing, and a
// later mutation of a registered error cannot introduce new content into its message.
const messages = new WeakMap<Error, string>();

/** Constructor-only opt-in for the value-free application error families. */
export function registerErrorMessage(error: Error): void {
  if (!messages.has(error)) messages.set(error, error.message);
}

/** The constructor's message, or undefined when the thrown value has not opted in. */
export function registeredErrorMessage(error: unknown): string | undefined {
  return error instanceof Error ? messages.get(error) : undefined;
}

export const ERROR_MESSAGE_MARKER = "[REDACTED:error message]";
