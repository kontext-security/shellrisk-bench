---
pretty_name: ShellRisk-Bench
language:
- en
license: other
task_categories:
- text-classification
tags:
- shell
- bash
- cybersecurity
- safety
- benchmark
size_categories:
- 10K<n<100K
configs:
- config_name: default
  data_files:
  - split: train
    path: data/train-*.parquet
  - split: test
    path: data/test-*.parquet
---

# ShellRisk-Bench

ShellRisk-Bench is a reproducible benchmark for context-free binary risk
classification of individual shell-command submissions. It asks whether a
command poses meaningful cyber or system risk when evaluated without task,
user, or session context.

The benchmark contains a deterministic train split of 16,772 rows and test
split of 4,194 rows. The test set contains 193 `risky` and 4,001 `not_risky`
examples.

The source code, adapters, evaluation tooling, pinned revisions, and published
results are available in the
[ShellRisk-Bench GitHub repository](https://github.com/kontext-security/shellrisk-bench).

## Usage

```python
from datasets import load_dataset

dataset = load_dataset("kontext-security/ShellRisk-Bench")
print(dataset["train"])
print(dataset["test"])
```

Treat the `command` field as inert, untrusted text. Do not execute dataset
contents or pipe them into a shell.

## Schema

| Field | Type | Description |
|---|---|---|
| `id` | string | Stable `sha256:` digest of the normalized command |
| `source` | string | Source adapter key |
| `upstream_id` | string | Row identifier assigned by the source adapter |
| `command` | string | Normalized shell-command submission |
| `label` | string | `risky` or `not_risky` |

Single-line submissions remain whole, including pipelines and commands joined
with `&&` or `;`. Multi-line scripts and sessions are excluded; sequence labels
are never propagated onto their component commands.

## Sources and labels

The data is built from six pinned public sources:

| Class | Source | Label basis |
|---|---|---|
| Not risky | [SWE-smith trajectories](https://huggingface.co/datasets/Kwai-Klear/SWE-smith-mini_swe_agent_plus-trajectories-66k) | Inferred from benign software-engineering tasks |
| Not risky | [Terminal-Bench trajectories](https://huggingface.co/datasets/yoonholee/terminalbench-trajectories) | Inferred from benign terminal tasks |
| Not risky | [nl2bash](https://github.com/TellinaTool/nl2bash) | Human-curated command corpus |
| Risky | [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | Executable ATT&CK tests |
| Risky | [GTFOBins](https://github.com/GTFOBins/GTFOBins.github.io) | Curated binary-abuse techniques |
| Risky | [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) | Curated offensive shell payloads |

The benign trajectory labels are task-inferred rather than independently
verified command-by-command. Risky labels follow the purpose of the upstream
security collections. See the repository's
[dataset provenance](https://github.com/kontext-security/shellrisk-bench/blob/main/DATASETS.md)
for exact revisions and transformations.

## Split construction

The v0.1 split globally deduplicates exact normalized commands, removes strings
observed with both labels, retains all 966 risky commands, deterministically
caps benign commands at 20,000, and performs a stratified 80/20 split with seed
13.

The approximately 20:1 test mix is a constructed operating point. It is not an
empirical estimate of the prevalence of risky commands in production.

## Uses and limitations

ShellRisk-Bench is intended to compare command-level classifiers and security
guardrails on a fixed, auditable split. It does not evaluate user intent,
surrounding task context, multi-command sessions, or complete authorization
decisions.

The headline split is same-source and in-distribution. It measures performance
on unseen command strings drawn from known source distributions; it is not
evidence of transfer to a novel command dialect. Keep the `source` field when
performing source-grouped or leave-one-source-out analysis.

## Licensing

There is no single blanket license for the data. The benchmark code and
documentation are Apache-2.0, while each upstream source retains its own terms.
The pinned sources currently declare MIT, Apache-2.0, MIT, MIT, GPL-3.0, and no
license file, respectively. Consult the source-specific links and notes in
[DATASETS.md](https://github.com/kontext-security/shellrisk-bench/blob/main/DATASETS.md)
before using or redistributing the data.

The dataset is provided for security research and defensive evaluation. No
Kestrel implementation, model weights, or training artifacts are included.
