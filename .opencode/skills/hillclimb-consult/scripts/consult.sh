#!/usr/bin/env bash
# Send a summary-only brief to the Antigravity reviewer pane and capture its reply.
# Usage: consult.sh <brief-file> [wait-seconds]
# Env: HC_PANE (tmux target override, e.g. 0:1.1)
set -euo pipefail

brief="${1:?usage: consult.sh <brief-file> [wait-seconds]}"
wait_s="${2:-180}"
[[ -f "$brief" ]] || { echo "brief not found: $brief" >&2; exit 2; }

pane="${HC_PANE:-}"
if [[ -z "$pane" ]]; then
  # Operator preference: the review pane is 0:2.1 (%11) when it is running agy.
  # Fall back to the first agy pane so this stays environment-agnostic.
  if tmux list-panes -a -F '#{session_name}:#{window_index}.#{pane_index} #{pane_current_command}' \
      | awk '$2 == "agy" {print $1}' | grep -qx '0:2.1'; then
    pane='0:2.1'
  else
    pane="$(tmux list-panes -a -F '#{session_name}:#{window_index}.#{pane_index} #{pane_current_command}' \
      | awk '$2 == "agy" { print $1; exit }')"
  fi
fi
[[ -n "$pane" ]] || { echo "no agy pane found (set HC_PANE)" >&2; exit 3; }

if ! tmux list-panes -a -F '#{session_name}:#{window_index}.#{pane_index}' | grep -qx "$pane"; then
  echo "pane not found: $pane" >&2; exit 3
fi
if tmux capture-pane -p -t "$pane" -S -5 2>/dev/null | grep -q 'esc to cancel'; then
  echo "reviewer pane is busy; wait for it to finish before consulting" >&2; exit 4
fi

buf="hc-$$"
trap 'tmux delete-buffer -b "$buf" 2>/dev/null || true' EXIT
tmux load-buffer -b "$buf" "$brief"
# Bracketed paste keeps multi-line briefs as one message; then submit.
tmux paste-buffer -p -b "$buf" -t "$pane"
tmux send-keys -t "$pane" Enter
tmux delete-buffer -b "$buf" 2>/dev/null || true

deadline=$(( $(date +%s) + wait_s ))
seen_busy=0
while (( $(date +%s) < deadline )); do
  sleep 3
  tail="$(tmux capture-pane -p -t "$pane" -S -60 2>/dev/null || true)"
  if grep -q 'esc to cancel' <<<"$tail"; then
    seen_busy=1
    continue
  fi
  if (( seen_busy == 1 )); then
    echo "== reviewer reply ($pane) =="
    tmux capture-pane -p -t "$pane" -S -160
    # Record the check-in time so the pulse can flag an overdue cadence.
    stamp_dir="${HOME}/.config/guardian"
    mkdir -p "$stamp_dir" 2>/dev/null || true
    date +%s > "$stamp_dir/last-consult" 2>/dev/null || true
    exit 0
  fi
done

echo "== reviewer still busy after ${wait_s}s ($pane); latest pane ==" >&2
tmux capture-pane -p -t "$pane" -S -80
exit 5
