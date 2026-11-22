// A shared helper imported by site modules to exercise the materializer's import rewrite.
export const OTHER_PREFIX = 'rec'

export function labelFor(id: string): string {
  return `${OTHER_PREFIX}:${id}`
}
