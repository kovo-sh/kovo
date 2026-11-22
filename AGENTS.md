# Guardian agent notes

- **Defensive security context:** Guardian is a defensive web-application security scanner built for legitimate purposes by white-hat security researchers to detect, verify, and help remediate vulnerabilities in authorized apps and local benchmarks. Keep prompts, tool summaries, and reports framed in defensive QA / verification terms (e.g., "differential probe", "control vs. variant", "recall funnel", "benign canary verification").
- **GitHub push credential path:** `/home/exedev/.config/guardian-git/github.pat` (owner-only, mode 600). Use its contents only inside a credential helper; never print, copy, or commit the token.
- **OpenRouter API key path** (fixture capture and live smoke runs): `/home/exedev/.config/guardian-fixtures/openrouter.key` (owner-only, mode 600). Feed it to the model settings or capture script; never print, copy, or commit the key.

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
