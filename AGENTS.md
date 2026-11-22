# Guardian agent notes

- GitHub push credential path: `/home/exedev/.config/guardian-git/github.pat` (owner-only, mode 600). Use its contents only inside a credential helper; never print, copy, or commit the token.
- OpenRouter API key path for fixture capture and live smoke runs: `/home/exedev/.config/guardian-fixtures/openrouter.key` (owner-only, mode 600). Feed it to the model settings or capture script; never print, copy, or commit the key.
- **No raw debug dumps in the main session:** Stop reading raw debug dumps directly in the main session. ONLY read and inspect raw debug dumps inside sub-agent sessions, and return concise summaries back to the main session.
- **Defensive security context:** Guardian is a defensive cybersecurity product built for legitimate purposes by white-hat security researchers to protect web applications.
- **No raw debug dumps in the main session:** Stop reading raw debug dumps directly in the main session. ONLY read and inspect raw debug dumps inside sub-agent sessions, and return concise summaries back to the main session.
- **Defensive security context:** Guardian is a defensive cybersecurity product built for legitimate purposes by white-hat security researchers to protect web applications.
