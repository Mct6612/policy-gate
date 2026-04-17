# Verification & Testing

Verification is a first-class part of the project, not an afterthought.

## Automated CI checks

- Rust test suite (`cargo test -p firewall-core`)
- Clippy with `-D warnings`
- Smoke + conformance tests for Node and Python bindings
- Fuzz targets in `crates/firewall-fuzz`
- Harmful prompt regression (720 prompts from JailbreakBench + AdvBench)
- False-positive rate measurement (150 legitimate prompts, must be 0.0%)
- Daily `cargo audit` for CVEs

## Formal verification (Z3)

SMT2 proof obligations for critical invariants:

```bash
pip install z3-solver
python verification/run_proofs.py
```

Models:
- [`verification/channel_a.smt2`](../verification/channel_a.smt2)
- [`verification/voter.smt2`](../verification/voter.smt2)
- [`verification/rule_engine.smt2`](../verification/rule_engine.smt2)

## Pattern-change tripwire

Detects any modification to intent patterns or semantic centroids:

```bash
python verification/check_pattern_hash.py
```

Fails CI if the centroid hash changes without an explicit re-approval.

## Regression datasets

```bash
cargo build --release -p firewall-cli
python verification/benchmark_datasets.py   # JailbreakBench + AdvBench
python verification/fp_rate_test.py         # False-positive rate
```

## Operator review tooling

| Tool | Description |
|---|---|
| [`operator_review.py`](../verification/operator_review.py) | Interactive CLI for `DiagnosticDisagreement` events — clustering, Z3 dry-run, Git-Ops auto-commit |
| [`suggest_pattern.py`](../verification/suggest_pattern.py) | Generates regex patterns, SMT2 proof obligations, and Safety Manual snippets |
| [`fuzz_regex.py`](../verification/fuzz_regex.py) | Bypass fuzzer — SQLi/XSS/PromptInjection probes against new allowlist patterns |
| [`disagreement_analytics.py`](../verification/disagreement_analytics.py) | Batch analytics and FP rate reporting |

**One-keypress release cycle:**
```
False Positive → [R]/[S] → Z3 Dry-Run → Fuzz Check → Accept → TOML Patch → Safety Manual → git commit
```
