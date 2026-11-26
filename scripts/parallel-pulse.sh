#!/usr/bin/env bash
# Parallel pulse: what is active, what is mergeable, what is blocked, what is unmeasured.
# Read-only. Coordinator runs it every ~30 minutes (see AGENTS.md "Parallel pulse").
#
# Usage: scripts/parallel-pulse.sh [--json]
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT" || exit 1

json=0
[[ "${1:-}" == "--json" ]] && json=1
now_epoch="$(date +%s)"
now="$(date '+%Y-%m-%d %H:%M:%S')"
main_rev="$(git rev-parse --short main 2>/dev/null || echo unknown)"
STATE_DIR="${KOVO_GATE_STATE_DIR:-${HOME}/.config/kovo}"
GH_BIN="${KOVO_GH_BIN:-gh}"

# Audit main reflog since guard install / last pulse for non-queue merges.
installed_epoch=0
installed_main_sha=""
guard_stamp="${STATE_DIR}/main-guard-installed"
if [[ -f "$guard_stamp" ]]; then
  installed_epoch="$(awk -F= '/^installed_epoch=/{print $2; exit}' "$guard_stamp" 2>/dev/null || echo 0)"
  installed_main_sha="$(awk -F= '/^main_sha=/{print $2; exit}' "$guard_stamp" 2>/dev/null || true)"
  case "$installed_epoch" in ''|*[!0-9]*) installed_epoch=0;; esac
fi
last_pulse_epoch=0
pulse_stamp="${STATE_DIR}/last-pulse"
if [[ -f "$pulse_stamp" ]]; then
  last_pulse_epoch="$(cat "$pulse_stamp" 2>/dev/null || echo 0)"
  case "$last_pulse_epoch" in ''|*[!0-9]*) last_pulse_epoch=0;; esac
fi
if [[ -n "${KOVO_PULSE_SINCE_EPOCH:-}" ]]; then
  since_epoch="$KOVO_PULSE_SINCE_EPOCH"
elif (( installed_epoch > 0 || last_pulse_epoch > 0 )); then
  since_epoch=$(( installed_epoch > last_pulse_epoch ? installed_epoch : last_pulse_epoch ))
else
  since_epoch=$(( now_epoch - 86400 ))
fi
stop_sha="${KOVO_PULSE_SINCE_SHA:-$installed_main_sha}"

non_queue_rows=""
non_queue_count=0
checked_reflog=0
if git rev-parse --verify refs/heads/main >/dev/null 2>&1; then
  while IFS='|' read -r entry_sha entry_gd entry_subject; do
    [[ -z "${entry_sha:-}" ]] && continue
    checked_reflog=$((checked_reflog + 1))
    if (( checked_reflog > 50 )); then break; fi
    if [[ -n "$stop_sha" && "$stop_sha" != "unknown" && "$entry_sha" == "$stop_sha" ]]; then
      break
    fi
    entry_epoch=""
    if [[ "$entry_gd" =~ \{([0-9]+)\} ]]; then
      entry_epoch="${BASH_REMATCH[1]}"
    fi
    if [[ -n "$entry_epoch" && "$since_epoch" -gt 0 ]] && (( entry_epoch < since_epoch )); then
      break
    fi
    is_ff=0
    if [[ "$entry_subject" == *[Ff]ast-forward* ]]; then
      is_ff=1
    fi
    has_valid_note=0
    expected_tree="$(git rev-parse --verify "${entry_sha}^{tree}" 2>/dev/null || true)"
    note_body="$(git notes --ref=refs/notes/merge-gate show "$entry_sha" 2>/dev/null || true)"
    if [[ -n "$expected_tree" && -n "$note_body" ]]; then
      while IFS= read -r note_line; do
        if [[ "$note_line" =~ ^merge-gate:\ PASS\ ([a-f0-9]{16,64})\ ([a-f0-9]{40})$ ]] && [[ "${BASH_REMATCH[2]}" == "$expected_tree" ]]; then
          has_valid_note=1
          break
        fi
      done <<< "$note_body"
    fi
    if (( is_ff == 0 || has_valid_note == 0 )); then
      reason=""
      (( is_ff == 0 )) && reason="not-fast-forward"
      if (( has_valid_note == 0 )); then
        reason="${reason:+${reason},}missing-merge-gate-note"
      fi
      non_queue_count=$((non_queue_count + 1))
      non_queue_rows+="${entry_sha:0:8}|${entry_subject}|${reason}"$'\n'
    fi
  done < <(git reflog show --date=unix --format='%H|%gd|%gs' main 2>/dev/null || true)
fi

# Query latest GitHub Actions verify.yml status on main.
ci_state="unavailable"
ci_conclusion=""
ci_run_id=""
ci_head_sha=""
if [[ "${KOVO_PULSE_SKIP_CI_CHECK:-0}" != "1" ]] && { command -v "$GH_BIN" >/dev/null 2>&1 || [[ -x "$GH_BIN" ]]; }; then
  ci_raw="$("$GH_BIN" run list --workflow verify.yml --branch main --limit 1 --json conclusion,status,databaseId,headSha 2>/dev/null || true)"
  if [[ -n "$ci_raw" ]]; then
    ci_parsed="$(node -e '
      try {
        const runs = JSON.parse(process.argv[1]);
        if (Array.isArray(runs) && runs.length > 0) {
          const r = runs[0] || {};
          console.log(`${r.conclusion || ""}|${r.status || ""}|${r.databaseId || ""}|${r.headSha || ""}`);
        }
      } catch {}
    ' "$ci_raw" 2>/dev/null || true)"
    if [[ -n "$ci_parsed" ]]; then
      IFS='|' read -r ci_conclusion ci_status_raw ci_run_id ci_head_sha <<< "$ci_parsed"
      if [[ "$ci_conclusion" == "failure" ]]; then
        ci_state="red"
      elif [[ "$ci_conclusion" == "success" ]]; then
        ci_state="green"
      elif [[ -n "$ci_status_raw" ]]; then
        ci_state="$ci_status_raw"
      fi
    fi
  fi
fi

rows=""
active=0
mergeable=0
blocked=0
merge_now=""
stale_dirty=
while IFS= read -r wt; do
  [[ -z "$wt" ]] && continue
  [[ "$wt" == "$ROOT" ]] && continue
  branch="$(git -C "$wt" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
  [[ "$branch" == "HEAD" || -z "$branch" ]] && continue
  # Archived/abandoned streams and other orchestrators' worktrees are not actionable.
  case "$branch" in
    agents/engine-port|agents/hybrid|m7-realistic|swarm-*|proto/*) continue;;
  esac
  ahead="$(git rev-list --count "main..$branch" 2>/dev/null || echo 0)"
  dirty="clean"
  [[ -n "$(git -C "$wt" status --porcelain 2>/dev/null | head -1)" ]] && dirty="dirty"
  last="$(git -C "$wt" log -1 --format=%ct 2>/dev/null || echo 0)"
  age=$(( now_epoch - last ))
  # Active = unmerged commits or uncommitted work. Merged clean branches are noise here.
  if [[ "$ahead" == "0" && "$dirty" == "clean" ]]; then continue; fi
  active=$((active+1))
  if [[ "$ahead" != "0" && "$dirty" == "clean" ]]; then
    mergeable=$((mergeable+1))
    if (( age >= 900 )); then merge_now+="  $branch (committed $((age/60))m ago, clean, +$ahead)"$'\n'; fi
  fi
  if [[ "$dirty" == "dirty" ]]; then
    blocked=$((blocked+1))
    if (( age >= 1800 )); then stale_dirty+="  $branch (dirty, last commit $((age/60))m ago)"$'\n'; fi
  fi
  rows+="$branch|$ahead|$dirty|$((age/60))m|$wt"$'\n'
done < <(git worktree list --porcelain | awk '/^worktree / {print $2}')

if (( json )); then
  node -e '
    const rows=process.argv[1].trim();
    const nq=process.argv[4].trim();
    const parse=s=>s? s.split("\n").map(l=>{const p=l.split("|");return {branch:p[0],commitsAhead:Number(p[1]),state:p[2],lastCommitAge:p[3],worktree:p[4]}}):[];
    const parseNq=s=>s? s.split("\n").map(l=>{const p=l.split("|");return {sha:p[0],subject:p[1],reason:p[2]}}):[];
    console.log(JSON.stringify({
      when:process.argv[2],
      main:process.argv[3],
      active:parse(rows),
      nonQueueMerges:parseNq(nq),
      ci:{state:process.argv[5],conclusion:process.argv[6]||null,runId:process.argv[7]||null,headSha:process.argv[8]||null}
    },null,1));
  ' "$rows" "$now" "$main_rev" "$non_queue_rows" "$ci_state" "$ci_conclusion" "$ci_run_id" "$ci_head_sha"
  exit 0
fi

printf 'parallel pulse %s  (main %s)\n' "$now" "$main_rev"
if [[ "$ci_state" == "red" ]]; then
  printf 'CI RED: latest verify.yml run #%s on main concluded failure (sha %s)\n' "${ci_run_id:-unknown}" "${ci_head_sha:0:8}"
elif [[ "$ci_state" == "green" ]]; then
  printf 'CI status: GREEN (verify.yml run #%s)\n' "${ci_run_id:-unknown}"
elif [[ "$ci_state" != "unavailable" ]]; then
  printf 'CI status: %s (verify.yml run #%s)\n' "$ci_state" "${ci_run_id:-unknown}"
else
  printf 'CI status: unavailable (gh check skipped)\n'
fi
if (( non_queue_count > 0 )); then
  printf '%s' "$non_queue_rows" | while IFS='|' read -r sha subj reason; do
    [[ -z "$sha" ]] && continue
    printf 'ACTION NON-QUEUE MERGE: %s (%s) — %s\n' "$sha" "$subj" "$reason"
  done
fi
if [[ -z "$rows" ]]; then
  printf 'active streams: none\n'
else
  printf 'active streams (%d):\n' "$active"
  printf '%s' "$rows" | while IFS='|' read -r b a s age w; do
    printf '  %-30s +%-3s %-6s last commit %-5s %s\n' "$b" "$a" "$s" "$age" "$w"
  done
fi
printf 'mergeable (ahead, clean): %d    dirty/in-progress: %d\n' "$mergeable" "$blocked"
if [[ -n "$merge_now" ]]; then
  printf 'ACTION MERGE NOW (clean + ahead >=15m):\n%s' "$merge_now"
fi
if [[ -n "$stale_dirty" ]]; then
  printf 'ACTION CHECKPOINT/SPLIT (dirty >=30m):\n%s' "$stale_dirty"
fi
ready_count="$(grep -c 'status: ready' plans/STREAM-BACKLOG.md 2>/dev/null || true)"
ready_count="${ready_count:-0}"
if (( active < 3 && ready_count > 0 )); then
  printf 'ACTION UNDER-PARALLELIZED: %d active stream(s), %d ready backlog task(s) — dispatch disjoint work now\n' "$active" "$ready_count"
fi

printf 'leases held by active streams:\n'
printf '%s' "$rows" | while IFS='|' read -r b a s age w; do
  [[ -z "$b" ]] && continue
  files="$(git -C "$w" diff --name-only main...HEAD 2>/dev/null | head -6 | tr '\n' ' ')"
  printf '  %-30s %s\n' "$b" "${files:-<no committed files yet>}"
done

stamp="${HOME}/.config/guardian/last-consult"
if [[ -f "$stamp" ]]; then
  last="$(cat "$stamp" 2>/dev/null || echo 0)"
  case "$last" in ''|*[!0-9]*) last=0;; esac
  age_h=$(( (now_epoch - last) / 3600 ))
  age_m=$(( ((now_epoch - last) % 3600) / 60 ))
  if (( now_epoch - last > 3600 )); then
    printf 'GEMINI CHECK-IN OVERDUE: last consult %sh%sm ago — run the hillclimb-consult skill now\n' "$age_h" "$age_m"
  else
    printf 'last Gemini check-in: %sh%sm ago\n' "$age_h" "$age_m"
  fi
else
  printf 'GEMINI CHECK-IN OVERDUE: no recorded consult — run the hillclimb-consult skill now\n'
fi

printf 'stale benchmark processes (>25 min; a 600 s cell should never run this long):\n'
stale="$(ps -eo pid,etimes,args 2>/dev/null | grep -E 'benchmark-(realistic|recall|reason)|floor-repeat' | grep -v grep | awk '$2>1500 {print "  pid " $1 " age " int($2/60) "m"}')"
if [[ -n "$stale" ]]; then printf '%s\n' "$stale"; else printf '  none\n'; fi

cat <<'CHECK'
pulse questions:
  1. Any active stream clean and ahead? Merge it, run worker-gate, push.
  2. Any P0 item unstarted on a free lease? Launch that stream now.
  3. Is a P0 item blocked only by a file lease? Park the holder and reclaim the file.
  4. Are acceptance gates unmeasured (realism / anti-heuristic / agentic-vs-floor / chains)? Start the measurement.
  5. Nothing actionable? Say so and stop. Do not invent work.
CHECK
