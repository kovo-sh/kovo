# Guardian agent notes

- **Defensive security context:** Guardian is a defensive web-application security scanner built for legitimate purposes by white-hat security researchers to detect, verify, and help remediate vulnerabilities in authorized apps and local benchmarks. Keep prompts, tool summaries, and reports framed in defensive QA / verification terms (e.g., "differential probe", "control vs. variant", "recall funnel", "benign canary verification").
- **GitHub push credential path:** `/home/exedev/.config/guardian-git/github.pat` (owner-only, mode 600). Use its contents only inside a credential helper; never print, copy, or commit the token.
- **OpenRouter model credential (agentic runs):** the Guardian data dir `/home/omarchy/guardian-data` contains the enabled profile `OpenRouter DeepSeek V4.1 Flash` (`deepseek/deepseek-v4.1-flash-1017`, endpoint `https://openrouter.ai/api/v1`, protocol `responses`). Its key lives in `/home/omarchy/guardian-data/credentials/model-c26c23ce-42e0-446f-a62c-c3016122c6d3` (owner-only, mode 600). Point runs at it with `GUARDIAN_DATA_DIR=/home/omarchy/guardian-data`. Never print, copy, or commit the key; the credential file stays outside the repo.
- **Agentic execution requirement:** `Execution` specialist workers need the Docker worker backend (`newgrp docker -c '<command>' --verifier docker`). `local-jq` is replay-only and cannot run worker sessions — a model profile plus `local-jq` produces an inert run. The M0 harness must fail fast in that combination.
- **Held-out benchmark salt:** `/home/omarchy/.config/guardian-bench/heldout.salt` (owner-only, mode 600, 48 hex chars). Required as `GUARDIAN_RB_HELDOUT_SALT` for salted realistic-bench seeds (≥1,000,000); never print or commit it.
- **Legacy fixture key path** (may be absent): `/home/exedev/.config/guardian-fixtures/openrouter.key`. Prefer the Guardian model credential above when it exists.

## Gemini Coding Guidelines

1. **Never `read_file` or `cat` raw debug dumps or benchmark logs (main session OR sub-agents):**
   - Do not load raw `.log`, `.md` debug reports, or `GUARDIAN_BENCH_DEBUG=1` output into model context.
   - Instead, write benchmark runs to structured JSON (`--out <path>.json`) or a file, and inspect them with a short `node -e` / `python3 -c` script that prints **only** structured metrics (`funnelCounts`, `failureTaxonomy`, challenge `id`, `vulnClass`, `probeClass`, `outcome`, HTTP status codes, and short error reasons)—never raw HTTP bodies or raw probe strings.
2. **Never bulk-read payload-heavy source files whole:**
   - Treat `src/server/surface-engine.ts`, `src/server/replay-verifier.ts`, `src/server/agent-session.ts`, `src/skills/*.md`, `benchmarks/xben-25/routes-*.ts`, and `local-lab/held-out-saas/src/*` as slice-only files.
   - First locate target functions with `grep -n` (function signatures / switch cases), then read only small targeted ranges (~50–150 lines) around the exact logic being audited or edited.
3. **Keep raw test strings out of summaries and sub-agent prompts:**
   - Never echo concrete SQL/XSS/XXE/SSTI/command test strings into sub-agent prompts, tool outputs, or final responses; refer to them by probe class and anomaly type (e.g., `sqli_boolean`, `xxe_canary`, `ssti_math`).
4. **Isolate unavoidable inspection in single-purpose sub-agents:**
   - If a specific probe/verifier implementation slice must be inspected closely, do it in a small single-file sub-agent and return only a concise structural summary (file, line numbers, logic defect) to the main session so a false-positive filter hit never disrupts the main thread.
