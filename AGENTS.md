# Guardian agent notes

- GitHub push credential path: `/home/exedev/.config/guardian-git/github.pat` (owner-only, mode 600). Use its contents only inside a credential helper; never print, copy, or commit the token.
- OpenRouter API key path for fixture capture and live smoke runs: `/home/exedev/.config/guardian-fixtures/openrouter.key` (owner-only, mode 600). Feed it to the model settings or capture script; never print, copy, or commit the key.
