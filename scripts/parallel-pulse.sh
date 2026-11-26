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
now_epoch="${KOVO_PULSE_NOW_EPOCH:-$(date +%s)}"
case "$now_epoch" in ''|*[!0-9]*) now_epoch="$(date +%s)";; esac
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

# R3-10: Repeat-patch escalation tripwire, deletion-debt audit, and net src/server LOC per landed stream.
r310_json="$(node -e '
  const { execFileSync } = require("node:child_process");
  const { existsSync, readFileSync } = require("node:fs");
  const { join, basename } = require("node:path");

  const root = process.argv[1];
  const nowEpoch = Number(process.argv[2]) || Math.floor(Date.now() / 1000);
  const rowsRaw = process.argv[3] || "";
  const windowSize = Math.max(1, Number(process.env.KOVO_PULSE_REPEAT_WINDOW || 30) || 30);
  const threshold = Math.max(2, Number(process.env.KOVO_PULSE_REPEAT_THRESHOLD || 2) || 2);
  const historyLimit = Math.max(windowSize, Number(process.env.KOVO_PULSE_HISTORY_LIMIT || 200) || 200);
  const netLocWindow = Math.max(1, Number(process.env.KOVO_PULSE_NET_LOC_WINDOW || 8) || 8);
  const backlogRel = process.env.KOVO_PULSE_BACKLOG_PATH || "plans/STREAM-BACKLOG.md";

  const git = (args, cwd = root) => {
    try {
      return execFileSync("git", ["-C", cwd, ...args], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
        maxBuffer: 16 * 1024 * 1024,
      });
    } catch {
      return "";
    }
  };

  let baseRef = "";
  if (git(["rev-parse", "--verify", "refs/heads/main"]).trim()) {
    baseRef = "main";
  } else if (git(["rev-parse", "--verify", "HEAD"]).trim()) {
    baseRef = "HEAD";
  }

  const isTrackedSourceFile = (filePath) => {
    const f = filePath.trim().replace(/\\/g, "/");
    if (!f) return false;
    if (f.startsWith("tests/") || f.startsWith("plans/") || f.startsWith("docs/") || f.startsWith(".github/")) return false;
    if (/\.(?:md|json|lock|txt|png|svg)$/i.test(f)) return false;
    return /^(?:src|scripts)\/.*\.(?:ts|tsx|js|mjs|cjs|sh|css)$/i.test(f);
  };

  const FIXES_LINE_RE = /^\s*Fixes:\s*(.+)$/gim;
  const FIX_ID_TOKEN_RE = /^(?:R[1-4]-[CHML]-\d+[a-z]?|R[2-3]-\d+[a-z]?|CQ-\d+[a-z]?|[CHML]-\d+[a-z]?|DD-\d+|#[0-9]+)$/i;
  const extractFixesIds = (body) => {
    const out = [];
    const seen = new Set();
    FIXES_LINE_RE.lastIndex = 0;
    for (const m of body.matchAll(FIXES_LINE_RE)) {
      const val = (m[1] || "").trim();
      if (!val) continue;
      for (const clause of val.split(",")) {
        const tokens = clause.trim().split(/\s+/).filter(Boolean);
        for (let i = 0; i < tokens.length; i += 1) {
          const cleaned = tokens[i].replace(/^[`([{"\x27]+|[`)\]}"\x27.,;:]+$/g, "");
          if (!cleaned || !/[A-Za-z0-9]/.test(cleaned) || /^(?:none|n\/a|null|todo|tbd)$/i.test(cleaned)) continue;
          if (i === 0 || FIX_ID_TOKEN_RE.test(cleaned)) {
            const key = cleaned.toUpperCase();
            if (!seen.has(key)) {
              seen.add(key);
              out.push(cleaned);
            }
          }
        }
      }
    }
    return out;
  };

  const parseLogBlocks = (raw) => {
    if (!raw) return [];
    const out = [];
    for (const chunk of raw.split("__COMMIT__\x1f")) {
      if (!chunk.trim()) continue;
      const endMeta = chunk.indexOf("\x1e");
      if (endMeta < 0) continue;
      const meta = chunk.slice(0, endMeta).split("\x1f");
      const files = chunk
        .slice(endMeta + 1)
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean);
      out.push({
        sha: meta[0] || "",
        shortSha: meta[1] || "",
        subject: meta[2] || "",
        body: meta[3] || "",
        files,
      });
    }
    return out;
  };

  const recentFixByFile = new Map();
  const crossRoundFixesByFile = new Map();
  const activeStreamsByFile = new Map();

  if (baseRef) {
    const recentRaw = git([
      "log",
      "-n",
      String(windowSize),
      "--no-merges",
      "--format=__COMMIT__%x1f%H%x1f%h%x1f%s%x1f%B%x1e",
      "--name-only",
      baseRef,
    ]);
    for (const c of parseLogBlocks(recentRaw)) {
      const fixesIds = extractFixesIds(c.body);
      const isFix =
        fixesIds.length > 0 ||
        /^fix(?:\([^)]*\))?[!:]|\b(?:hotfix|regression)\b/i.test(c.subject);
      if (!isFix) continue;
      const uniqueFiles = new Set(c.files.filter(isTrackedSourceFile));
      for (const f of uniqueFiles) {
        let rec = recentFixByFile.get(f);
        if (!rec) {
          rec = { count: 0, commits: [], fixesIds: new Set() };
          recentFixByFile.set(f, rec);
        }
        rec.count += 1;
        rec.commits.push({ sha: c.shortSha, subject: c.subject });
        for (const id of fixesIds) rec.fixesIds.add(id);
      }
    }

    const histRaw = git([
      "log",
      "-n",
      String(historyLimit),
      "--no-merges",
      "--grep=^[[:space:]]*Fixes:",
      "--format=__COMMIT__%x1f%H%x1f%h%x1f%s%x1f%B%x1e",
      "--name-only",
      baseRef,
    ]);
    for (const c of parseLogBlocks(histRaw)) {
      const fixesIds = extractFixesIds(c.body);
      if (fixesIds.length === 0) continue;
      const uniqueFiles = new Set(c.files.filter(isTrackedSourceFile));
      for (const f of uniqueFiles) {
        let rec = crossRoundFixesByFile.get(f);
        if (!rec) {
          rec = { count: 0, commits: [], fixesIds: new Set() };
          crossRoundFixesByFile.set(f, rec);
        }
        rec.count += 1;
        rec.commits.push({ sha: c.shortSha, subject: c.subject });
        for (const id of fixesIds) rec.fixesIds.add(id);
      }
    }

    for (const line of rowsRaw.trim().split("\n").filter(Boolean)) {
      const parts = line.split("|");
      const branch = parts[0] || "";
      const wt = parts[4] || "";
      if (!branch || !wt) continue;
      const diffFiles = git(["diff", "--name-only", `${baseRef}...HEAD`], wt)
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(isTrackedSourceFile);
      for (const f of new Set(diffFiles)) {
        let set = activeStreamsByFile.get(f);
        if (!set) {
          set = new Set();
          activeStreamsByFile.set(f, set);
        }
        set.add(branch);
      }
    }
  }

  const candidateFiles = new Set([
    ...recentFixByFile.keys(),
    ...crossRoundFixesByFile.keys(),
    ...activeStreamsByFile.keys(),
  ]);
  const repeatPatchEscalations = [];
  for (const file of candidateFiles) {
    const recent = recentFixByFile.get(file);
    const hist = crossRoundFixesByFile.get(file);
    const streams = activeStreamsByFile.get(file);
    const recentCount = recent ? recent.count : 0;
    const histIdCount = hist ? hist.fixesIds.size : 0;
    const histCommitCount = hist ? hist.count : 0;
    const streamList = streams ? [...streams].sort() : [];
    const reasons = [];
    if (recentCount >= threshold) {
      reasons.push(`${recentCount} fix commits in last ${windowSize}`);
    }
    if (histIdCount >= threshold) {
      reasons.push(`cross-round Fixes history (${histIdCount} IDs across ${histCommitCount} commits)`);
    }
    if (streamList.length >= threshold) {
      reasons.push(`${streamList.length} active streams touching file`);
    }
    if (reasons.length === 0) continue;
    const allFixes = new Set([
      ...(recent ? recent.fixesIds : []),
      ...(hist ? hist.fixesIds : []),
    ]);
    const commitMap = new Map();
    for (const item of [...(recent ? recent.commits : []), ...(hist ? hist.commits : [])]) {
      if (!commitMap.has(item.sha)) commitMap.set(item.sha, item.subject);
    }
    repeatPatchEscalations.push({
      file,
      subsystem: basename(file).replace(/\.[^.]+$/, ""),
      recentFixCount: recentCount,
      historyFixCommitCount: histCommitCount,
      fixesIds: [...allFixes].sort(),
      crossRound: histIdCount >= threshold,
      activeStreams: streamList,
      commits: [...commitMap.keys()].slice(0, 6),
      reasons,
    });
  }
  repeatPatchEscalations.sort(
    (a, b) =>
      b.recentFixCount - a.recentFixCount ||
      b.historyFixCommitCount - a.historyFixCommitCount ||
      a.file.localeCompare(b.file),
  );

  // Parse ## Deletion Debt table from plans/STREAM-BACKLOG.md
  const deletionDebtEntries = [];
  const backlogAbs = join(root, backlogRel);
  if (existsSync(backlogAbs)) {
    const md = readFileSync(backlogAbs, "utf8");
    const secMatch = /(?:^|\n)##\s+Deletion Debt\b[^\n]*\n([\s\S]*?)(?=\n##\s+|$)/i.exec(md);
    if (secMatch) {
      const stripTicks = (s) => {
        const t = s.trim();
        return /^`[^`]+`$/.test(t) ? t.slice(1, -1).trim() : t;
      };
      for (const rawLine of secMatch[1].split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line.startsWith("|") || !line.endsWith("|")) continue;
        const cells = line
          .slice(1, -1)
          .split("|")
          .map((c) => c.trim());
        if (cells.length < 6) continue;
        if (/^id$/i.test(cells[0]) || cells.every((c) => /^:?-+:?$/.test(c))) continue;
        const id = stripTicks(cells[0]);
        const legacyPath = stripTicks(cells[1]);
        const replacement = stripTicks(cells[2]);
        const owner = stripTicks(cells[3]);
        const target = stripTicks(cells[4]);
        const status = stripTicks(cells[5]).toLowerCase();
        if (!id) continue;
        const dateMatch = /\b(\d{4}-\d{2}-\d{2})\b/.exec(target);
        const expiryDate = dateMatch ? dateMatch[1] : null;
        const retired = /^(?:retired|done|deleted|closed)$/.test(status);
        const overdue =
          !retired &&
          expiryDate !== null &&
          Date.parse(`${expiryDate}T23:59:59Z`) < nowEpoch * 1000;
        deletionDebtEntries.push({
          id,
          legacyPath,
          replacement,
          owner,
          target,
          expiryDate,
          status,
          retired,
          overdue,
        });
      }
    }
  }
  const deletionDebt = {
    path: backlogRel,
    open: deletionDebtEntries.filter((e) => !e.retired).length,
    overdue: deletionDebtEntries.filter((e) => e.overdue).length,
    retired: deletionDebtEntries.filter((e) => e.retired).length,
    entries: deletionDebtEntries,
  };

  // Net src/server LOC per recent landed stream (first-parent commits on baseRef)
  const netStreams = [];
  let totalAdded = 0;
  let totalDeleted = 0;
  if (baseRef) {
    const numstatRaw = git([
      "log",
      "--first-parent",
      "-n",
      String(netLocWindow),
      "--numstat",
      "--format=__COMMIT__%x1f%H%x1f%h%x1f%s",
      baseRef,
      "--",
      "src/server",
    ]);
    for (const chunk of numstatRaw.split("__COMMIT__\x1f")) {
      if (!chunk.trim()) continue;
      const lines = chunk.split(/\r?\n/);
      const header = (lines[0] || "").split("\x1f");
      const shortSha = header[1] || "";
      const subject = header[2] || "";
      let added = 0;
      let deleted = 0;
      for (const statLine of lines.slice(1)) {
        const m = /^(\d+)\t(\d+)\t(.+)$/.exec(statLine.trim());
        if (!m) continue;
        added += Number(m[1]);
        deleted += Number(m[2]);
      }
      totalAdded += added;
      totalDeleted += deleted;
      netStreams.push({
        sha: shortSha,
        subject,
        added,
        deleted,
        net: added - deleted,
      });
    }
  }
  const netServerLoc = {
    baseRef: baseRef || null,
    window: netLocWindow,
    totalAdded,
    totalDeleted,
    totalNet: totalAdded - totalDeleted,
    streams: netStreams,
  };

  console.log(
    JSON.stringify({
      repeatPatchWindow: windowSize,
      repeatPatchThreshold: threshold,
      repeatPatchEscalations,
      deletionDebt,
      netServerLoc,
    }),
  );
' "$ROOT" "$now_epoch" "$rows" 2>/dev/null || echo '{}')"

if (( json )); then
  node -e '
    const rows=process.argv[1].trim();
    const nq=process.argv[4].trim();
    const extra=JSON.parse(process.argv[9]||"{}");
    const parse=s=>s? s.split("\n").map(l=>{const p=l.split("|");return {branch:p[0],commitsAhead:Number(p[1]),state:p[2],lastCommitAge:p[3],worktree:p[4]}}):[];
    const parseNq=s=>s? s.split("\n").map(l=>{const p=l.split("|");return {sha:p[0],subject:p[1],reason:p[2]}}):[];
    console.log(JSON.stringify({
      when:process.argv[2],
      main:process.argv[3],
      active:parse(rows),
      nonQueueMerges:parseNq(nq),
      ci:{state:process.argv[5],conclusion:process.argv[6]||null,runId:process.argv[7]||null,headSha:process.argv[8]||null},
      repeatPatchWindow:extra.repeatPatchWindow??30,
      repeatPatchThreshold:extra.repeatPatchThreshold??2,
      repeatPatchEscalations:extra.repeatPatchEscalations??[],
      deletionDebt:extra.deletionDebt??{path:"plans/STREAM-BACKLOG.md",open:0,overdue:0,retired:0,entries:[]},
      netServerLoc:extra.netServerLoc??{baseRef:null,window:8,totalAdded:0,totalDeleted:0,totalNet:0,streams:[]}
    },null,1));
  ' "$rows" "$now" "$main_rev" "$non_queue_rows" "$ci_state" "$ci_conclusion" "$ci_run_id" "$ci_head_sha" "$r310_json"
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

# Print R3-10 repeat-patch escalation tripwire, deletion debt, and net src/server LOC summary.
node -e '
  const data = JSON.parse(process.argv[1] || "{}");
  const esc = Array.isArray(data.repeatPatchEscalations) ? data.repeatPatchEscalations : [];
  const win = data.repeatPatchWindow ?? 30;
  if (esc.length > 0) {
    for (const item of esc) {
      const fixesStr = item.fixesIds && item.fixesIds.length > 0 ? `; Fixes: ${item.fixesIds.join(", ")}` : "";
      const commitsStr = item.commits && item.commits.length > 0 ? `; commits: ${item.commits.join(", ")}` : "";
      console.log(
        `ESCALATE ARCHITECTURE MOVE: ${item.file} (${item.reasons.join("; ")}${commitsStr}${fixesStr}) — per AGENTS.md Systemic Fixes rule 6, pause and open a systemic refactor ticket + reviewer sign-off (advisory; never blocks urgent critical fixes)`,
      );
    }
  } else {
    console.log(`repeat-patch tripwire (last ${win} commits): ok (0 escalations)`);
  }

  const dd = data.deletionDebt || { path: "plans/STREAM-BACKLOG.md", open: 0, overdue: 0, retired: 0, entries: [] };
  console.log(`deletion debt (${dd.path}): ${dd.open} open, ${dd.overdue} overdue, ${dd.retired} retired`);
  for (const e of dd.entries || []) {
    if (e.overdue) {
      console.log(`ACTION DELETION DEBT OVERDUE: ${e.id} (${e.legacyPath}) owner=${e.owner} target=${e.target}`);
    }
  }
  const openNonOverdue = (dd.entries || []).filter((e) => !e.retired && !e.overdue);
  for (const e of openNonOverdue.slice(0, 6)) {
    console.log(`  ${e.id} [${e.status}] ${e.legacyPath} -> ${e.replacement} (owner: ${e.owner}, target: ${e.target})`);
  }

  const loc = data.netServerLoc || { baseRef: null, window: 8, totalAdded: 0, totalDeleted: 0, totalNet: 0, streams: [] };
  const fmtSigned = (n) => (n >= 0 ? `+${n}` : `${n}`);
  const touched = (loc.streams || []).filter((s) => s.added > 0 || s.deleted > 0);
  console.log(
    `net src/server LOC (last ${(loc.streams || []).length} landed commits${loc.baseRef ? ` on ${loc.baseRef}` : ""}): ${fmtSigned(loc.totalNet)} (+${loc.totalAdded}/-${loc.totalDeleted})`,
  );
  for (const s of touched.slice(0, 8)) {
    console.log(`  ${s.sha}  net ${fmtSigned(s.net)} (+${s.added}/-${s.deleted})  ${s.subject}`);
  }
' "$r310_json"

cat <<'CHECK'
pulse questions:
  1. Any active stream clean and ahead? Merge it, run worker-gate, push.
  2. Any P0 item unstarted on a free lease? Launch that stream now.
  3. Is a P0 item blocked only by a file lease? Park the holder and reclaim the file.
  4. Are acceptance gates unmeasured (realism / anti-heuristic / agentic-vs-floor / chains)? Start the measurement.
  5. Nothing actionable? Say so and stop. Do not invent work.
CHECK
