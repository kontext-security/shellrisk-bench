# Dataset provenance

ShellRisk-Bench downloads six upstream sources at pinned revisions and writes normalized JSONL locally. No upstream command data is committed to this repository.

The repository's Apache-2.0 license applies only to ShellRisk-Bench code and documentation. It does not relicense upstream datasets or generated data. Users are responsible for complying with upstream terms.

| Key | Class | Pinned revision | Command rows | Upstream license | Transformation and label basis |
|---|---|---|---:|---|---|
| `swesmith` | Not risky | `750b2c11239fd5e32f97e6cfb9bf80fb9a9a2983` | 95,825 | [MIT](https://huggingface.co/datasets/Kwai-Klear/SWE-smith-mini_swe_agent_plus-trajectories-66k/blob/750b2c11239fd5e32f97e6cfb9bf80fb9a9a2983/README.md) | Extract fenced Bash submissions from benign SWE-smith agent trajectories. Exact deduplication, shape cap, and heredoc cap. Label is task-inferred, not human-verified. |
| `terminalbench` | Not risky | `04e8940f5b6736a7ce8d22224fe2f2af74163ed2` | 53,959 | [Apache-2.0](https://huggingface.co/datasets/yoonholee/terminalbench-trajectories/tree/04e8940f5b6736a7ce8d22224fe2f2af74163ed2) | Keep literal `execute_bash` calls from benign terminal-task trajectories. Label is task-inferred, not human-verified. |
| `nl2bash` | Not risky | `d6b9f5bdff45621d190134e31ab63b7bf7002190` | 10,624 | [MIT for `data/bash`](https://github.com/TellinaTool/nl2bash/blob/d6b9f5bdff45621d190134e31ab63b7bf7002190/README.md) | Use the command side of human-curated NL→Bash pairs; exact deduplication. |
| `atomicredteam` | Risky | `5cdeb06642dbdfb3c595d4096cb9eea5f6434d8b` | 265 | [MIT](https://github.com/redcanaryco/atomic-red-team/blob/5cdeb06642dbdfb3c595d4096cb9eea5f6434d8b/LICENSE.txt) | Keep Bash/sh executors, substitute declared defaults, and scrub source-identifying markers. ATT&CK technique is retained as the source label. |
| `gtfobins` | Risky | `acd524623f9c406acedd2754ebd9c2431f3675ad` | 681 | [GPL-3.0](https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/LICENSE) | Extract curated abuse snippets and scrub documentation-only placeholders. Function type is retained as the source label. |
| `payloads` | Risky | `203bb0c0b290bf7c9158c32d43523b8d66f292c1` | 29 | No license file declared at the pinned revision | Extract Linux/interpreter code fences from InternalAllTheThings, the successor linked from PayloadsAllTheThings, and remove prompts/prose. The repository downloads at build time and does not redistribute the upstream content. |

## Structural routing

Single-line submissions are assigned to the `command` layer and kept whole, including pipelines and `&&`/`;` chains. Multi-line scripts are assigned to `session` and excluded from v0.1 evaluation.

A sequence label is never propagated onto its component commands. A harmless `cd` does not become risky merely because it appeared inside an attacker session.

## Shared normalization

Every source receives the same deterministic substitutions:

- URLs → `http://example.com`
- IPv4-looking strings → `1.1.1.1`
- Base64-looking blobs of 40 or more characters → `BASE64`

These transformations abstract incidental hosts and payload bytes without removing the surrounding command structure.

## Global cleaning and split

The split builder operates on `layer == "command"` only. It globally deduplicates exact command strings, removes commands observed with both labels, retains all risky commands, deterministically samples 20,000 benign commands, and performs an 80/20 stratified split with seed 13.

The benchmark contains source-provided and inferred labels, not an independent expert relabeling of every command. This limitation is part of the benchmark and should accompany reported results.
