# ShellRisk-Bench

ShellRisk-Bench is a reproducible benchmark for **context-free risk classification of individual shell commands**. It tests whether a system can distinguish generally risky commands from ordinary development and operations traffic when it sees only the submitted command.

The benchmark is built from six pinned public sources. Upstream data is downloaded locally and normalized into a common schema; it is not vendored in this repository.

## Scope

ShellRisk-Bench v0.1 evaluates one binary question:

> Does this individual shell-command submission pose meaningful cyber or system risk?

It does **not** infer user intent, inspect surrounding task context, evaluate multi-command sessions, or make a final authorization decision. Multi-line scripts and sessions are excluded rather than flattened into misleading atomic labels.

## Sources

| Class | Source | Command rows | Label basis |
|---|---|---:|---|
| Not risky | [SWE-smith trajectories](https://huggingface.co/datasets/Kwai-Klear/SWE-smith-mini_swe_agent_plus-trajectories-66k) | 95,825 | Inferred from benign software-engineering tasks |
| Not risky | [Terminal-Bench trajectories](https://huggingface.co/datasets/yoonholee/terminalbench-trajectories) | 53,959 | Inferred from benign terminal tasks |
| Not risky | [nl2bash](https://github.com/TellinaTool/nl2bash) | 10,624 | Human-curated command corpus |
| Risky | [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | 265 | Executable ATT&CK tests |
| Risky | [GTFOBins](https://github.com/GTFOBins/GTFOBins.github.io) | 681 | Curated binary-abuse techniques |
| Risky | [PayloadsAllTheThings / InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) | 29 | Curated offensive shell payloads |

See [DATASETS.md](DATASETS.md) for pinned revisions, transformations, provenance, and upstream license information.

## Headline split

The published comparison uses a deterministic same-source, in-distribution split:

- 161,383 command rows before global deduplication
- 160,220 unique command strings
- 9 cross-label collisions removed
- All 966 risky commands retained
- Benign commands deterministically capped at 20,000
- Stratified 80/20 split with seed 13
- Test set: 4,194 commands—193 risky and 4,001 not risky

This split measures performance on unseen strings from **known source distributions**. It is not a source-transfer result. Source-grouped evaluation is the appropriate test for novel command dialects; every generated row retains its source so that evaluation can be performed separately.

The approximately 20:1 test mix is a constructed operating point for comparing precision under class imbalance. It is not presented as an empirical measurement of all production shell traffic.

## Published results

| System | Precision | Recall | F1 | Mean latency |
|---|---:|---:|---:|---:|
| k-cl-1 | 0.947 | 0.922 | 0.934 | 22 µs |
| Claude Opus 4.8 | 0.515 | 0.549 | 0.531 | 1.33 s |
| Claude Sonnet 5 | 0.547 | 0.456 | 0.497 | 2.64 s |
| Kimi K3 | 0.469 | 0.518 | 0.493 | 8.65 s |
| GPT-5.5 | 0.393 | 0.456 | 0.422 | 2.74 s |
| Claude Haiku 4.5 | 0.292 | 0.560 | 0.384 | 0.94 s |
| GPT-5.6-terra | 0.286 | 0.430 | 0.344 | 1.44 s |
| GPT-5.6-luna | 0.269 | 0.446 | 0.335 | 1.66 s |
| Shieldstral 1.0 (3B, local) | 0.406 | 0.269 | 0.324 | 186 ms |
| Llama Guard 4 (12B) | 0.023 | 0.285 | 0.042 | 1.1 s |

All systems were scored on the same 4,194 commands. Hosted-model latency was measured sequentially and includes the API round trip. Shieldstral used its default 0.5 threshold; Llama Guard counted any unsafe category as risky. Quality results, prompts, and the k-cl-1 per-example verdicts are under [`results/`](results/). The k-cl-1 implementation and weights are not part of this benchmark repository.

## Build

Python 3.11 or newer is recommended.

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/python -m shellrisk_bench.build
.venv/bin/python -m shellrisk_bench.prepare --verify
```

The first command downloads several gigabytes of upstream trajectories. For a quick adapter smoke test:

```bash
.venv/bin/python adapters/swesmith.py --limit 50
.venv/bin/python adapters/terminalbench.py --limit 50
```

After building the fixed split, score a JSONL prediction file:

```bash
.venv/bin/python -m shellrisk_bench.score \
  --gold data/splits/test.jsonl \
  --predictions results/k-cl-1.predictions.jsonl
```

Prediction rows contain a stable command hash and a binary verdict:

```json
{"id":"sha256:…","prediction":"risky"}
```

## Safety

This repository processes potentially destructive commands as inert text. Nothing in the build or evaluation path executes benchmark commands. Do not pipe dataset contents into a shell.

## License

The benchmark code is licensed under Apache-2.0. Upstream datasets retain their own licenses and terms; see [DATASETS.md](DATASETS.md). The generated dataset is intentionally git-ignored and is not redistributed here.
