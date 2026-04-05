# Project Structure

## Workspace Layout

```
policy-gate/
├── Cargo.toml                  # Workspace root — shared deps, release profile
├── firewall.example.toml       # Reference config for firewall.toml
├── deployment.md               # Production deployment requirements (SA-022, SA-073)
├── channel_a.smt2              # Z3 proof obligations for Channel A FSM
├── audit_chain.seal            # Audit chain integrity marker
├── index.ts                    # TypeScript wrapper (Node.js public API)
├── SAFETY_MANUAL.md            # Full safety design documentation and action log
├── RED_TEAM.md                 # Red-team test documentation
│
├── crates/
│   ├── firewall-core/          # Safety function boundary (the only safety-critical crate)
│   │   ├── src/
│   │   │   ├── lib.rs          # Public API: evaluate(), evaluate_raw(), init(), egress
│   │   │   ├── orchestrator.rs # Wires Channel A + B + C + D → Voter → Verdict
│   │   │   ├── voter.rs        # 1oo2D voting logic
│   │   │   ├── types.rs        # All canonical types (PromptInput, Verdict, BlockReason…)
│   │   │   ├── fsm/            # Channel A: FSM + allowlist regex
│   │   │   │   ├── mod.rs      # FSM states, watchdog, ChannelA::evaluate()
│   │   │   │   ├── states.rs   # FsmState enum
│   │   │   │   ├── intent_patterns.rs  # Allowlist regex patterns (IP-0xx)
│   │   │   │   └── egress.rs   # Channel E: FSM-based PII/leakage detection
│   │   │   ├── rule_engine/    # Channel B: deterministic rule engine (no regex/ML)
│   │   │   │   ├── mod.rs      # ChannelB::evaluate(), watchdog
│   │   │   │   ├── rules.rs    # RULE_TABLE — static structural/lexical rules (RE-001…RE-099)
│   │   │   │   └── egress.rs   # Channel F: entropy/framing detection
│   │   │   ├── advisory.rs     # Channel C: non-safety advisory opinions
│   │   │   ├── semantic.rs     # Channel D: ONNX embeddings (feature = "semantic")
│   │   │   ├── ingress.rs      # Pre-evaluation guards (size, init)
│   │   │   ├── egress.rs       # Egress evaluation entry point
│   │   │   ├── audit.rs        # HMAC-chained audit entry construction
│   │   │   ├── config.rs       # firewall.toml loader (SA-048)
│   │   │   ├── init.rs         # OnceLock init, profile management
│   │   │   ├── profile.rs      # FirewallProfile — multi-tenant intent allowlists
│   │   │   ├── session.rs      # SA-076: SessionManager, multi-turn escalation detection
│   │   │   ├── conversation.rs # evaluate_messages() / evaluate_messages_windowed()
│   │   │   ├── pre_scan.rs     # Fast pre-scan before full FSM evaluation
│   │   │   ├── verdict_build.rs # Final Verdict assembly
│   │   │   └── review.rs       # DiagnosticAgreement review queue
│   │   ├── tests/              # Integration and property-based tests
│   │   ├── benches/            # Criterion benchmarks (channel_a, channel_b, voter…)
│   │   └── firewall.toml       # Local dev config (overrides defaults)
│   │
│   ├── firewall-napi/          # Node.js binding (napi-rs) — NOT safety-critical
│   ├── firewall-pyo3/          # Python binding (pyo3) — NOT safety-critical
│   ├── firewall-wasm/          # WASM/Edge binding (wasm-bindgen) — NOT safety-critical
│   ├── firewall-cli/           # CLI binary — NOT safety-critical
│   └── firewall-fuzz/          # Fuzz targets (cargo-fuzz)
│
├── verification/               # Formal verification and analytics tooling
│   ├── channel_a.smt2          # Z3: FSM proof obligations (PO-A1…PO-A16)
│   ├── voter.smt2              # Z3: Voter proof obligations (PO-V1…PO-V10)
│   ├── rule_engine.smt2        # Z3: Rule engine proof obligations (PO-RE1…PO-RE8)
│   ├── run_proofs.py           # Proof runner (requires: pip install z3-solver)
│   ├── check_pattern_hash.py   # Allowlist change tripwire
│   ├── operator_review.py      # Interactive DiagnosticDisagreement review tool
│   ├── disagreement_analytics.py # Audit log analysis
│   ├── benchmark_datasets.py   # JailbreakBench + AdvBench regression runner
│   ├── fp_rate_test.py         # False-positive rate measurement
│   └── conformance_corpus.json # Cross-language reference test corpus
│
├── scripts/                    # Smoke, conformance, and utility scripts
├── policy-hub/                 # Pre-built TOML profiles and presets
│   ├── profiles/               # research-agent, code-assistant, customer-support
│   └── presets/                # strict.toml, permissive.toml
├── fuzz/corpus/                # Persistent fuzz corpus (libFuzzer)
└── docs/                       # Revision history and supplementary docs
```

## Key Conventions

- All safety-critical code lives exclusively in `firewall-core`. Binding crates (`napi`, `pyo3`, `wasm`) are marshalling layers only.
- `#![forbid(unsafe_code)]` and `#![deny(clippy::all)]` are enforced at the `firewall-core` crate level.
- Safety Actions are referenced inline as `SA-NNN`, gaps as `DC-GAP-NN`, fault modes as `FM-NN`. Always preserve these references when modifying related code.
- Dependency versions in `Cargo.toml` that use `=x.y.z` (exact pins) must not be bumped without a documented safety review — see comments in `Cargo.toml`.
- New intent patterns go in `fsm/intent_patterns.rs` (Channel A) and a corresponding rule in `rule_engine/rules.rs` (Channel B) to maintain channel diversity.
- Custom runtime patterns belong in `firewall.toml` using `[[intents]]` entries, not hardcoded in source.
- Tests in `crates/firewall-core/tests/` use `proptest` for property-based boundary testing. New features should include proptest coverage.
- The `firewall.toml` at the workspace root is for production; the one inside `crates/firewall-core/` is for local dev/test overrides.
- Z3 proof obligations live in `verification/`. Adding intent patterns without updating the Z3 models will fail the `z3_tripwire_pattern_count` test.
- The `verification/conformance_corpus.json` is the cross-language reference corpus — changes must remain consistent across Rust, Node, and Python bindings.
- `policy-hub/` contains pre-built TOML profiles for common use cases (research-agent, code-assistant, customer-support) and presets (strict, permissive). Prefer these over custom configs where possible.
- `operator_review.py` is the primary tool for reviewing `DiagnosticDisagreement` events; it supports auto-regex generation and auto-write to `firewall.toml`.
