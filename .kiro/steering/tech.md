# Tech Stack

## Language & Build System

- Rust (edition 2021), Cargo workspace with resolver = "2"
- Release profile: `lto = true`, `codegen-units = 1` (safety-critical path optimisation)

## Crates

| Crate | Purpose |
|-------|---------|
| `firewall-core` | Safety function library — the only safety-critical boundary |
| `firewall-napi` | Node.js binding via `napi-rs` |
| `firewall-pyo3` | Python binding via `pyo3` (module name: `policy_gate`) |
| `firewall-wasm` | WASM/Edge binding via `wasm-bindgen` |
| `firewall-cli` | CLI wrapper |
| `firewall-fuzz` | Fuzz targets (cargo-fuzz / libFuzzer) |

## Key Dependencies (workspace-pinned)

- `regex = "=1.12.3"` — pinned; version changes could silently alter Channel A pattern matching (DC-GAP-01)
- `unicode-normalization = "=0.1.25"` — pinned; Unicode version updates must not silently change NFKC behaviour (DC-GAP-03)
- `sha2 = "=0.10.9"`, `hmac = "=0.12.1"` — pinned for audit chain stability
- `proptest` — property-based testing (dev-dependency)
- `criterion` — statistical benchmarks (dev-dependency)

## Optional Features (`firewall-core`)

- `semantic` — Channel D: ONNX Runtime embeddings (`ort`, `ndarray`)
- `parallel` — batch evaluation via `rayon`
- `fips` — FIPS 140-3 SHA-256 via `aws-lc-rs` (uses C FFI; excluded from `#![forbid(unsafe_code)]`)

## Common Commands

```bash
# Build
cargo build -p firewall-core
cargo build -p firewall-core --release
cargo build -p firewall-core --features semantic,parallel

# Test
cargo test -p firewall-core
cargo test -p firewall-core -- --nocapture   # show println output

# Benchmarks
cargo bench -p firewall-core
cargo bench -p firewall-core --bench channel_a
cargo bench -p firewall-core --bench integration

# Fuzz (requires cargo-fuzz, Linux/Docker only)
cargo fuzz run fuzz_normalise
# Docker-based fuzz (recommended on Windows):
# docker compose -f fuzz/docker-compose.yml --profile normalise up

# Clippy (CI gate — all lints are errors)
cargo clippy -p firewall-core -- -D warnings

# Check WASM target
cargo build -p firewall-wasm --target wasm32-unknown-unknown

# Semantic feature compile check
cargo check -p firewall-core --features semantic

# FIPS build (requires C toolchain)
cargo build -p firewall-core --features fips
```

## Node.js / TypeScript Commands

```bash
npm install
npm run build:native   # builds firewall-napi, copies to native/index.node
npm run build          # compiles index.ts → dist/
npm run smoke          # basic wrapper smoke test
npm run conformance    # runs verification/conformance_corpus.json
```

## Python Commands

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install maturin
python -m maturin develop --manifest-path crates/firewall-pyo3/Cargo.toml
python scripts/smoke.py
python scripts/conformance.py
```

## Formal Verification

```bash
# Run all 36 Z3 proof obligations (channel_a, voter, rule_engine)
python verification/run_proofs.py

# Check allowlist pattern hash tripwire
python verification/check_pattern_hash.py

# Regression datasets (JailbreakBench + AdvBench — 707 harmful prompts)
cargo build --release -p firewall-cli
python verification/benchmark_datasets.py
python verification/fp_rate_test.py
```

## Configuration

Runtime config is loaded from `firewall.toml` at `init()` time (SA-048). Supports:
- `forbidden_keywords` — additional block keywords
- `[[intents]]` — custom intent patterns (id, intent, regex)
- `audit_detail_level` — `"basic"` (default) or `"detailed"`
- `context_window` — lookback window for session-aware evaluation (default: 3)

See `firewall.example.toml` for a full reference.

## Performance

- Single-threaded: ~100 req/s (~9–10 ms per request)
- Parallel (`rayon`): scales with CPU cores
- Node.js async: napi-rs runs evaluations on worker threads automatically
- Target latencies: Channel A < 100 µs, Channel B < 50 µs, Voter < 1 µs, full pipeline < 200 µs

## Channel D: Semantic (advisory)

Uses 8 learned attack centroids derived from AdvBench + JailbreakBench via MiniLM + K-Means, 384-dimensional embeddings (`sentence-transformers/all-MiniLM-L6-v2`). A centroid hash tripwire (`EXPECTED_CENTROID_HASH`) ensures semantic boundary changes are detected in CI. Advisory-only — never gates Pass/Block. See `scripts/generate_centroids.py` for the centroid generation pipeline.

## CI

- `.github/workflows/safety-verification.yml` — Z3 proofs, Rust tests, semantic compile check, Node/Python binding checks, FP rate, harmful regression
- `.github/workflows/security.yml` — `cargo-audit` (DC-GAP-01 / SA-064)

## Fuzz Targets (Docker, Linux only)

| Target | What is fuzzed | Invariants |
|--------|---------------|------------|
| `fuzz_normalise` | NFKC→NFD→strip Mn→NFC pipeline | No panics, output always valid UTF-8 |
| `fuzz_evaluate_raw` | Full evaluation pipeline | `is_pass()` consistent, block always has `block_reason` |
| `fuzz_channel_a` | FSM in isolation | No panics, watchdog budget never exceeded |
