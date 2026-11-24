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

rows=""
active=0
mergeable=0
blocked=0
while IFS= read -r wt; do
  [[ -z "$wt" ]] && continue
  [[ "$wt" == "$ROOT" ]] && continue
  branch="$(git -C "$wt" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
  [[ "$branch" == "HEAD" || -z "$branch" ]] && continue
  ahead="$(git rev-list --count "main..$branch" 2>/dev/null || echo 0)"
  dirty="clean"
  [[ -n "$(git -C "$wt" status --porcelain 2>/dev/null | head -1)" ]] && dirty="dirty"
  last="$(git -C "$wt" log -1 --format=%ct 2>/dev/null || echo 0)"
  age=$(( now_epoch - last ))
  # Active = unmerged commits or uncommitted work. Merged clean branches are noise here.
  if [[ "$ahead" == "0" && "$dirty" == "clean" ]]; then continue; fi
  active=$((active+1))
  if [[ "$ahead" != "0" && "$dirty" == "clean" ]]; then mergeable=$((mergeable+1)); fi
  if [[ "$dirty" == "dirty" ]]; then blocked=$((blocked+1)); fi
  rows+="$branch|$ahead|$dirty|$((age/60))m|$wt"$'\n'
done < <(git worktree list --porcelain | awk '/^worktree / {print $2}')

if (( json )); then
  node -e '
    const rows=process.argv[1].trim();
    const parse=s=>s? s.split("\n").map(l=>{const p=l.split("|");return {branch:p[0],commitsAhead:Number(p[1]),state:p[2],lastCommitAge:p[3],worktree:p[4]}}):[];
    console.log(JSON.stringify({when:process.argv[2],main:process.argv[3],active:parse(rows)},null,1));
  ' "$rows" "$now" "$main_rev"
  exit 0
fi

printf 'parallel pulse %s  (main %s)\n' "$now" "$main_rev"
if [[ -z "$rows" ]]; then
  printf 'active streams: none\n'
else
  printf 'active streams (%d):\n' "$active"
  printf '%s' "$rows" | while IFS='|' read -r b a s age w; do
    printf '  %-30s +%-3s %-6s last commit %-5s %s\n' "$b" "$a" "$s" "$age" "$w"
  done
fi
printf 'mergeable (ahead, clean): %d    dirty/in-progress: %d\n' "$mergeable" "$blocked"

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
