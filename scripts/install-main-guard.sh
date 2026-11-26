#!/usr/bin/env bash
# R3-01 (`plans/claude_quality_3.md` §1) — Install local main-ref guard.
#
# Configures `core.hooksPath=.githooks`, ensures `.githooks/reference-transaction` is executable,
# and stamps `${KOVO_GATE_STATE_DIR:-$HOME/.config/kovo}/main-guard-installed` so
# `scripts/parallel-pulse.sh` audits all `main` reflog entries after guard installation.
#
# Usage:
#   scripts/install-main-guard.sh [--repo <path>]
set -euo pipefail

REPO_ARG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      REPO_ARG="${2:?--repo requires a path}"
      shift 2
      ;;
    -h|--help)
      sed -n '2,10p' "$0"
      exit 0
      ;;
    *)
      echo "install-main-guard: unknown option: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -n "$REPO_ARG" ]]; then
  REPO_ROOT="$(git -C "$REPO_ARG" rev-parse --show-toplevel 2>/dev/null)" || {
    echo "install-main-guard: FAIL — '${REPO_ARG}' is not a git repository" >&2
    exit 2
  }
else
  REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    echo "install-main-guard: FAIL — not inside a git repository" >&2
    exit 2
  }
fi

HOOK_PATH="${REPO_ROOT}/.githooks/reference-transaction"
if [[ ! -f "$HOOK_PATH" ]]; then
  echo "install-main-guard: FAIL — missing hook file: ${HOOK_PATH}" >&2
  exit 1
fi

chmod +x "$HOOK_PATH"
git -C "$REPO_ROOT" config core.hooksPath .githooks

STATE_DIR="${KOVO_GATE_STATE_DIR:-${HOME}/.config/kovo}"
mkdir -p "$STATE_DIR"
STAMP_FILE="${STATE_DIR}/main-guard-installed"
NOW_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
NOW_EPOCH="$(date +%s)"
MAIN_SHA="$(git -C "$REPO_ROOT" rev-parse --verify refs/heads/main 2>/dev/null || echo unknown)"
printf 'installed_at=%s\ninstalled_epoch=%s\nmain_sha=%s\nrepo=%s\n' \
  "$NOW_ISO" "$NOW_EPOCH" "$MAIN_SHA" "$REPO_ROOT" >"$STAMP_FILE"

echo "install-main-guard: PASS (core.hooksPath=.githooks, hook=${HOOK_PATH}, main=${MAIN_SHA:0:8}, stamp=${STAMP_FILE})"
