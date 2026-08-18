# Schemas

## Normalized adapter row

Adapters write one JSON object per line under `data/normalized/<source>.jsonl`:

```json
{
  "id": "atomicredteam-000042",
  "source": "atomicredteam",
  "layer": "command",
  "actions": [{"type": "shell", "content": "example command"}],
  "context": null,
  "policy": null,
  "label": {
    "verdict": "deny",
    "source_label": "T1059.004",
    "rationale": null
  },
  "metadata": {
    "provenance": {
      "primary_source": "Atomic Red Team (Red Canary)",
      "edited": "description of transformations"
    }
  }
}
```

`allow` maps to not risky and `deny` maps to risky for v0.1. The upstream label remains available in `source_label`.

## Prepared split row

`shellrisk_bench.prepare` writes simplified rows to `data/splits/{train,test}.jsonl`:

```json
{
  "id": "sha256:<full command digest>",
  "source": "atomicredteam",
  "upstream_id": "atomicredteam-000042",
  "command": "example command",
  "label": "risky"
}
```

The SHA-256 identifier is derived from the normalized command string and is stable across builds.

## Prediction row

```json
{"id":"sha256:<full command digest>","prediction":"risky"}
```

Accepted predictions are `risky`/`not_risky`, `deny`/`allow`, or `1`/`0`.

