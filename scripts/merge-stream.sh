#!/usr/bin/env bash
# Merged-tree fast merge queue (`R2-03`, plans/claude_quality_2.md §3).
#
# Merges a stream branch/commit onto a temporary detached worktree at `<base>` (default: `main`),
# runs the fast (<60s) `scripts/worker-gate.sh` on the MERGED TREE (including docs/tests-only
# branches), fast-forwards `<base>` ONLY on PASS, cleans up the temporary worktree cleanly, and
# refuses merges while an external red-main lock file exists unless `--clear-red-lock` is passed
# and the merged tree passes.
#
# Usage:
#   scripts/merge-stream.sh <branch-or-commit> [options]
#   scripts/merge-stream.sh --clear-red-lock [--base <ref>]
#   scripts/merge-stream.sh --set-red-lock [reason]
#
# Options:
#   --base <ref>             Target base branch to merge onto (default: main)
#   --dry-run                Merge + run gate on merged tree, do NOT fast-forward base branch
#   --clear-red-lock         Allow running while red-main lock exists; removes lock ONLY on PASS
#   --set-red-lock [reason]  Create external red-main lock file and exit 0
#   --gate-cmd <cmd>         Override gate command (default: bash scripts/worker-gate.sh)
#   --skip-ci-check          Skip querying GitHub Actions verify.yml status via gh
#   --no-ff                  Create a merge commit even if fast-forward is possible
#   --json                   Emit machine-readable JSON summary to stdout
#   -h, --help               Show usage
#
# Environment:
#   KOVO_GATE_STATE_DIR      Directory for main-red.lock (default: $HOME/.config/kovo)
#   KOVO_MERGE_GATE_CMD      Override default gate command
#   KOVO_MERGE_SKIP_CI_CHECK Set to 1 to skip GitHub Actions verify.yml check
#   KOVO_GH_BIN              Override gh CLI binary (default: gh)
set -euo pipefail

BASE_REF="main"
STREAM_REF=""
DRY_RUN=0
CLEAR_RED_LOCK=0
SET_RED_LOCK=0
SET_RED_REASON=""
SKIP_CI_CHECK="${KOVO_MERGE_SKIP_CI_CHECK:-0}"
NO_FF=0
JSON_OUT=0
GATE_CMD="${KOVO_MERGE_GATE_CMD:-bash scripts/worker-gate.sh}"
GH_BIN="${KOVO_GH_BIN:-gh}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base)
      BASE_REF="${2:?--base requires a branch/ref}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --clear-red-lock)
      CLEAR_RED_LOCK=1
      shift
      ;;
    --set-red-lock)
      SET_RED_LOCK=1
      if [[ $# -ge 2 && "${2}" != -* ]]; then
        SET_RED_REASON="$2"
        shift 2
      else
        SET_RED_REASON="main marked red"
        shift
      fi
      ;;
    --gate-cmd)
      GATE_CMD="${2:?--gate-cmd requires a command}"
      shift 2
      ;;
    --skip-ci-check)
      SKIP_CI_CHECK=1
      shift
      ;;
    --no-ff)
      NO_FF=1
      shift
      ;;
    --json)
      JSON_OUT=1
      shift
      ;;
    -h|--help)
      sed -n '2,30p' "$0"
      exit 0
      ;;
    -*)
      echo "merge-stream: unknown option: $1" >&2
      exit 2
      ;;
    *)
      if [[ -n "$STREAM_REF" ]]; then
        echo "merge-stream: unexpected extra positional argument: $1" >&2
        exit 2
      fi
      STREAM_REF="$1"
      shift
      ;;
  esac
done

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "merge-stream: FAIL — not inside a git repository" >&2
  exit 2
}

STATE_DIR="${KOVO_GATE_STATE_DIR:-${HOME}/.config/kovo}"
LOCK_FILE="${STATE_DIR}/main-red.lock"

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/}"
  printf '%s' "$s"
}

emit_result() {
  local status="$1"
  local ok="$2"
  local reason="$3"
  local old_sha="$4"
  local new_sha="$5"
  local elapsed="$6"
  local lock_cleared="$7"
  if (( JSON_OUT == 1 )); then
    printf '{"ok":%s,"status":"%s","base":"%s","stream":"%s","oldSha":"%s","newSha":"%s","dryRun":%s,"redLockFile":"%s","redLockCleared":%s,"elapsedSeconds":%s,"reason":"%s"}\n' \
      "$ok" \
      "$(json_escape "$status")" \
      "$(json_escape "$BASE_REF")" \
      "$(json_escape "$STREAM_REF")" \
      "$(json_escape "$old_sha")" \
      "$(json_escape "$new_sha")" \
      "$([[ $DRY_RUN -eq 1 ]] && echo true || echo false)" \
      "$(json_escape "$LOCK_FILE")" \
      "$lock_cleared" \
      "$elapsed" \
      "$(json_escape "$reason")"
  else
    if [[ "$ok" == "true" ]]; then
      printf 'merge-stream: %s (base=%s %s..%s, stream=%s, elapsed=%ss%s)\n' \
        "$status" "$BASE_REF" "${old_sha:0:8}" "${new_sha:0:8}" "${STREAM_REF:-$BASE_REF}" "$elapsed" \
        "$([[ "$lock_cleared" == "true" ]] && echo ', red-lock=cleared' || echo '')"
    else
      printf 'merge-stream: %s — %s (base=%s %s, stream=%s, elapsed=%ss)\n' \
        "$status" "$reason" "$BASE_REF" "${old_sha:0:8}" "${STREAM_REF:-$BASE_REF}" "$elapsed" >&2
    fi
  fi
}

t0="$(date +%s)"

if (( SET_RED_LOCK == 1 )); then
  mkdir -p "$STATE_DIR"
  base_sha_now="$(git -C "$REPO_ROOT" rev-parse --verify "${BASE_REF}^{commit}" 2>/dev/null || echo unknown)"
  printf 'locked_at=%s\nbase=%s\nsha=%s\nreason=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$BASE_REF" "$base_sha_now" "$SET_RED_REASON" >"$LOCK_FILE"
  elapsed=$(( $(date +%s) - t0 ))
  emit_result "LOCKED_RED" "true" "$SET_RED_REASON" "$base_sha_now" "$base_sha_now" "$elapsed" "false"
  exit 0
fi

if [[ -z "$STREAM_REF" && "$CLEAR_RED_LOCK" -eq 0 ]]; then
  echo "merge-stream: missing <branch-or-commit> argument (use --help for usage)" >&2
  exit 2
fi

BASE_SHA="$(git -C "$REPO_ROOT" rev-parse --verify "refs/heads/${BASE_REF}^{commit}" 2>/dev/null || git -C "$REPO_ROOT" rev-parse --verify "${BASE_REF}^{commit}" 2>/dev/null || true)"
if [[ -z "$BASE_SHA" ]]; then
  elapsed=$(( $(date +%s) - t0 ))
  emit_result "FAIL" "false" "base ref '${BASE_REF}' not found" "" "" "$elapsed" "false"
  exit 2
fi

if [[ -n "$STREAM_REF" ]]; then
  STREAM_SHA="$(git -C "$REPO_ROOT" rev-parse --verify "${STREAM_REF}^{commit}" 2>/dev/null || true)"
  if [[ -z "$STREAM_SHA" ]]; then
    elapsed=$(( $(date +%s) - t0 ))
    emit_result "FAIL" "false" "stream ref '${STREAM_REF}' not found" "$BASE_SHA" "" "$elapsed" "false"
    exit 2
  fi
else
  STREAM_SHA="$BASE_SHA"
fi

# 0. Query GitHub Actions verify.yml status on BASE_REF and auto-set main-red.lock on failure.
if [[ "$CLEAR_RED_LOCK" -eq 0 && "$SKIP_CI_CHECK" != "1" ]]; then
  if command -v "$GH_BIN" >/dev/null 2>&1 || [[ -x "$GH_BIN" ]]; then
    set +e
    ci_raw="$("$GH_BIN" run list --workflow verify.yml --branch "$BASE_REF" --limit 1 --json conclusion,status,databaseId 2>/dev/null)"
    ci_rc=$?
    set -e
    if (( ci_rc == 0 )) && [[ -n "$ci_raw" ]]; then
      ci_parsed="$(node -e '
        try {
          const runs = JSON.parse(process.argv[1]);
          if (Array.isArray(runs) && runs.length > 0) {
            const r = runs[0] || {};
            console.log(`${r.conclusion || ""}|${r.status || ""}|${r.databaseId || ""}`);
          }
        } catch {}
      ' "$ci_raw" 2>/dev/null || true)"
      if [[ -n "$ci_parsed" ]]; then
        IFS='|' read -r ci_conclusion ci_status ci_run_id <<< "$ci_parsed"
        if [[ "$ci_conclusion" == "failure" ]]; then
          mkdir -p "$STATE_DIR"
          ci_reason="CI verify.yml run #${ci_run_id:-unknown} concluded failure on ${BASE_REF}"
          printf 'locked_at=%s\nbase=%s\nsha=%s\nreason=%s\nsource=ci_check\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$BASE_REF" "$BASE_SHA" "$ci_reason" >"$LOCK_FILE"
        fi
      fi
    else
      echo "merge-stream: notice — skipping CI check (gh unavailable/offline or no GitHub remote for '${BASE_REF}')" >&2
    fi
  else
    echo "merge-stream: notice — skipping CI check ('${GH_BIN}' not found)" >&2
  fi
fi

# 1. External red-main lock check (blocks ALL merges until resolved and re-verified with --clear-red-lock).
if [[ -f "$LOCK_FILE" && "$CLEAR_RED_LOCK" -eq 0 ]]; then
  lock_summary="$(tr '\n' '; ' <"$LOCK_FILE" | sed 's/; $//')"
  elapsed=$(( $(date +%s) - t0 ))
  emit_result "BLOCKED_RED_MAIN" "false" "main is locked red (${LOCK_FILE}: ${lock_summary}); fix base and re-run with --clear-red-lock" "$BASE_SHA" "$BASE_SHA" "$elapsed" "false"
  exit 1
fi

# 2. Create temporary detached worktree at BASE_SHA and ensure guaranteed cleanup.
WORKTREE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kovo-merge-stream-XXXXXX")"
cleanup() {
  if [[ -n "${WORKTREE_DIR:-}" && -e "$WORKTREE_DIR" ]]; then
    git -C "$REPO_ROOT" worktree remove --force "$WORKTREE_DIR" >/dev/null 2>&1 || true
    rm -rf "$WORKTREE_DIR" >/dev/null 2>&1 || true
    git -C "$REPO_ROOT" worktree prune >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

git -C "$REPO_ROOT" worktree add --quiet --detach "$WORKTREE_DIR" "$BASE_SHA"

# Reuse node_modules when present in the repo checkout (gitignored; avoids slow npm ci in temp worktree).
if [[ -e "${REPO_ROOT}/node_modules" && ! -e "${WORKTREE_DIR}/node_modules" ]]; then
  nm_target="$(readlink -f "${REPO_ROOT}/node_modules" 2>/dev/null || echo "${REPO_ROOT}/node_modules")"
  ln -s "$nm_target" "${WORKTREE_DIR}/node_modules"
fi
if [[ -e "${REPO_ROOT}/worker/node_modules" && -d "${WORKTREE_DIR}/worker" && ! -e "${WORKTREE_DIR}/worker/node_modules" ]]; then
  wnm_target="$(readlink -f "${REPO_ROOT}/worker/node_modules" 2>/dev/null || echo "${REPO_ROOT}/worker/node_modules")"
  ln -s "$wnm_target" "${WORKTREE_DIR}/worker/node_modules"
fi

# 3. Merge candidate branch/commit onto BASE_SHA inside the temporary worktree.
MERGED_SHA="$BASE_SHA"
if [[ -n "$STREAM_REF" && "$STREAM_SHA" != "$BASE_SHA" ]]; then
  if git -C "$WORKTREE_DIR" merge-base --is-ancestor "$STREAM_SHA" "$BASE_SHA" 2>/dev/null; then
    MERGED_SHA="$BASE_SHA"
  else
    merge_args=(merge --no-edit)
    if (( NO_FF == 1 )); then
      merge_args+=(--no-ff)
    fi
    if [[ "$JSON_OUT" -eq 1 ]]; then
      if ! git -C "$WORKTREE_DIR" "${merge_args[@]}" "$STREAM_REF" >/dev/null 2>&1; then
        git -C "$WORKTREE_DIR" merge --abort >/dev/null 2>&1 || true
        elapsed=$(( $(date +%s) - t0 ))
        emit_result "CONFLICT" "false" "merge conflict merging '${STREAM_REF}' onto '${BASE_REF}'; base untouched" "$BASE_SHA" "$BASE_SHA" "$elapsed" "false"
        exit 1
      fi
    else
      if ! git -C "$WORKTREE_DIR" "${merge_args[@]}" "$STREAM_REF"; then
        git -C "$WORKTREE_DIR" merge --abort >/dev/null 2>&1 || true
        elapsed=$(( $(date +%s) - t0 ))
        emit_result "CONFLICT" "false" "merge conflict merging '${STREAM_REF}' onto '${BASE_REF}'; base untouched" "$BASE_SHA" "$BASE_SHA" "$elapsed" "false"
        exit 1
      fi
    fi
    MERGED_SHA="$(git -C "$WORKTREE_DIR" rev-parse HEAD)"
  fi
fi

# 3b. Prepare build/ before worker-gate.sh so parallel Playwright suites never race on `npm run build`.
# Rebuild when the merged diff touches frontend/SSR build inputs or REPO_ROOT/build is missing;
# otherwise symlink REPO_ROOT/build (matching node_modules reuse above).
if [[ -f "${WORKTREE_DIR}/package.json" && -e "${WORKTREE_DIR}/node_modules" && ! -e "${WORKTREE_DIR}/build" ]]; then
  need_build=0
  if [[ ! -f "${REPO_ROOT}/build/server/server.js" || ! -d "${REPO_ROOT}/build/client" ]]; then
    need_build=1
  elif [[ "$MERGED_SHA" != "$BASE_SHA" ]]; then
    if git -C "$WORKTREE_DIR" diff --name-only "$BASE_SHA..$MERGED_SHA" \
      | grep -Eq '^src/(components|routes|styles|root\.tsx|app\.css|entry\.|findings-view)|^(vite|react-router|tsconfig)\.config|^package\.json'; then
      need_build=1
    fi
  fi
  if (( need_build == 1 )); then
    build_rc=0
    set +e
    if (( JSON_OUT == 1 )); then
      (cd "$WORKTREE_DIR" && npm run build) >&2
      build_rc=$?
    else
      echo "== merge-stream: building client/SSR bundle once in temp worktree"
      (cd "$WORKTREE_DIR" && npm run build)
      build_rc=$?
    fi
    set -e
    if (( build_rc != 0 )); then
      elapsed=$(( $(date +%s) - t0 ))
      emit_result "GATE_FAILED" "false" "pre-gate npm run build exited ${build_rc}; '${BASE_REF}' left untouched at ${BASE_SHA:0:8}" "$BASE_SHA" "$MERGED_SHA" "$elapsed" "false"
      exit "$build_rc"
    fi
  else
    build_target="$(readlink -f "${REPO_ROOT}/build" 2>/dev/null || echo "${REPO_ROOT}/build")"
    ln -s "$build_target" "${WORKTREE_DIR}/build"
  fi
fi

# 4. Run the fast gate on the MERGED TREE (never skipped for tests/docs-only branches).
gate_rc=0
set +e
if (( JSON_OUT == 1 )); then
  (
    cd "$WORKTREE_DIR"
    export KOVO_CONTRACT_BASE="$BASE_SHA"
    export KOVO_MERGE_STREAM_BASE="$BASE_REF"
    bash -c "$GATE_CMD"
  ) >&2
  gate_rc=$?
else
  printf '== merge-stream: running fast gate on merged tree (%s + %s -> %s)\n' \
    "$BASE_REF" "${STREAM_REF:-$BASE_REF}" "${MERGED_SHA:0:8}"
  (
    cd "$WORKTREE_DIR"
    export KOVO_CONTRACT_BASE="$BASE_SHA"
    export KOVO_MERGE_STREAM_BASE="$BASE_REF"
    bash -c "$GATE_CMD"
  )
  gate_rc=$?
fi
set -e

if (( gate_rc != 0 )); then
  elapsed=$(( $(date +%s) - t0 ))
  emit_result "GATE_FAILED" "false" "merged-tree gate exited ${gate_rc}; '${BASE_REF}' left untouched at ${BASE_SHA:0:8}" "$BASE_SHA" "$MERGED_SHA" "$elapsed" "false"
  exit "$gate_rc"
fi

# 5. Dry-run returns PASS without advancing BASE_REF or clearing the lock.
if (( DRY_RUN == 1 )); then
  elapsed=$(( $(date +%s) - t0 ))
  emit_result "PASS_DRY_RUN" "true" "merged tree passed gate (dry-run; base not updated)" "$BASE_SHA" "$MERGED_SHA" "$elapsed" "false"
  exit 0
fi

# 5.5 Stamp refs/notes/merge-gate on MERGED_SHA BEFORE fast-forwarding BASE_REF so
#     .githooks/reference-transaction verifies the merged tree passed the gate.
MERGED_TREE_SHA="$(git -C "$REPO_ROOT" rev-parse --verify "${MERGED_SHA}^{tree}")"
GATE_DIGEST="$(
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s|%s|%s|%s' "$BASE_SHA" "$MERGED_SHA" "$MERGED_TREE_SHA" "$GATE_CMD" | sha256sum | awk '{print $1}'
  else
    node -e 'const c=require("node:crypto");console.log(c.createHash("sha256").update(process.argv[1]).digest("hex"))' "${BASE_SHA}|${MERGED_SHA}|${MERGED_TREE_SHA}|${GATE_CMD}"
  fi
)"
git -C "$REPO_ROOT" notes --ref=refs/notes/merge-gate add -f -m "merge-gate: PASS ${GATE_DIGEST} ${MERGED_TREE_SHA}" "$MERGED_SHA" >/dev/null 2>&1

# 6. Fast-forward BASE_REF ONLY on PASS (with CAS check against concurrent base movement).
if [[ "$MERGED_SHA" != "$BASE_SHA" ]]; then
  current_base_sha="$(git -C "$REPO_ROOT" rev-parse --verify "refs/heads/${BASE_REF}^{commit}" 2>/dev/null || true)"
  if [[ -z "$current_base_sha" ]]; then
    elapsed=$(( $(date +%s) - t0 ))
    emit_result "FAIL" "false" "base ref 'refs/heads/${BASE_REF}' is not a local branch; cannot fast-forward" "$BASE_SHA" "$MERGED_SHA" "$elapsed" "false"
    exit 1
  fi
  if [[ "$current_base_sha" != "$BASE_SHA" ]]; then
    elapsed=$(( $(date +%s) - t0 ))
    emit_result "BASE_MOVED" "false" "'${BASE_REF}' moved from ${BASE_SHA:0:8} to ${current_base_sha:0:8} while gate ran; re-run merge-stream.sh" "$BASE_SHA" "$MERGED_SHA" "$elapsed" "false"
    exit 1
  fi

  # Find if refs/heads/$BASE_REF is checked out in any worktree.
  base_wt=""
  wt_path=""
  while IFS= read -r line; do
    case "$line" in
      worktree\ *)
        wt_path="${line#worktree }"
        ;;
      branch\ *)
        if [[ "${line#branch }" == "refs/heads/${BASE_REF}" ]]; then
          base_wt="$wt_path"
          break
        fi
        ;;
      "")
        wt_path=""
        ;;
    esac
  done < <(git -C "$REPO_ROOT" worktree list --porcelain)

  if [[ -n "$base_wt" ]]; then
    if [[ "$JSON_OUT" -eq 1 ]]; then
      git -C "$base_wt" merge --ff-only "$MERGED_SHA" >/dev/null 2>&1 || {
        elapsed=$(( $(date +%s) - t0 ))
        emit_result "FF_FAILED" "false" "git merge --ff-only failed in worktree '${base_wt}'" "$BASE_SHA" "$MERGED_SHA" "$elapsed" "false"
        exit 1
      }
    else
      git -C "$base_wt" merge --ff-only "$MERGED_SHA" || {
        elapsed=$(( $(date +%s) - t0 ))
        emit_result "FF_FAILED" "false" "git merge --ff-only failed in worktree '${base_wt}'" "$BASE_SHA" "$MERGED_SHA" "$elapsed" "false"
        exit 1
      }
    fi
  else
    git -C "$REPO_ROOT" update-ref -m "merge-stream: Fast-forward ${STREAM_REF:-$BASE_REF}" "refs/heads/${BASE_REF}" "$MERGED_SHA" "$BASE_SHA"
  fi
fi

# 7. Clear red-main lock ONLY after verifying green.
LOCK_CLEARED="false"
if (( CLEAR_RED_LOCK == 1 )) && [[ -f "$LOCK_FILE" ]]; then
  rm -f "$LOCK_FILE"
  LOCK_CLEARED="true"
fi

elapsed=$(( $(date +%s) - t0 ))
emit_result "PASS" "true" "merged tree passed gate and fast-forwarded ${BASE_REF}" "$BASE_SHA" "$MERGED_SHA" "$elapsed" "$LOCK_CLEARED"
exit 0
