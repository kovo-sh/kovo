# Benchmark Baselines

Committed deterministic floor baselines consumed by `scripts/regression-floor.sh`.

## Schema (`floor.json`)

```json
{
  "schemaVersion": 1,
  "updatedAt": "<ISO-8601 timestamp>",
  "suites": {
    "<suite>": {
      "gitSha": "<short-sha or null>",
      "targetsTotal": 25,
      "confirmedCount": 25,
      "falsePositiveCount": 0,
      "confirmedIds": ["..."]
    }
  }
}
```

`scripts/regression-floor.sh` also accepts a JSONL ledger file (e.g. `--baseline benchmarks/results/ledger.jsonl`), selecting the latest `VALID` row for each suite and checking `siteOutcomes` / `confirmed` / false positives against the live run's `perTarget` outcomes (`outcome === 'confirmed'`).

## Updating

```bash
bash scripts/regression-floor.sh --with-xben --with-heldout-saas --write-baseline
```
