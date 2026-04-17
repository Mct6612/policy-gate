# Performance & High-Throughput

## Benchmarks

| Mode | Throughput | Latency |
|---|---|---|
| Sequential (cached) | 250+ req/s | <100µs |
| Sequential (cold) | — | ~3–4ms |
| Parallel / Rayon (8-core) | 1,000+ req/s | — |
| Channel D semantic | — | ~31µs |

## Node.js (async / concurrent)

napi-rs automatically runs evaluations on worker threads — `Promise.all` gives you free parallelism:

```ts
import { Firewall } from "policy-gate";

const firewall = await Firewall.create();

const results = await Promise.all(
  ["What is the capital of France?", "Write a function", "Hello!"]
    .map(p => firewall.evaluate(p))
);
```

## Rust (parallel batch)

Enable the `parallel` feature for Rayon-based batch evaluation:

```toml
# Cargo.toml
firewall-core = { path = "./crates/firewall-core", features = ["parallel"] }
```

```rust
use firewall_core::evaluate_batch_parallel;

let results = evaluate_batch_parallel(vec![
    "What is the capital of France?".to_string(),
    "Write a function".to_string(),
], 0);
```

## Running benchmarks

```bash
# All benchmark groups
cargo bench -p firewall-core

# Individual groups
cargo bench -p firewall-core --bench channel_a    # FSM + allowlist
cargo bench -p firewall-core --bench channel_b    # Rule engine
cargo bench -p firewall-core --bench voter        # 1oo2D decision logic
cargo bench -p firewall-core --bench integration  # Full pipeline
cargo bench -p firewall-core --bench normalise    # Unicode normalization
```

See [`crates/firewall-core/BENCHMARKS.md`](../crates/firewall-core/BENCHMARKS.md) for detailed results.

## BERT semantic mode (optional)

For deeper semantic analysis at the cost of 5–20ms latency:

```bash
pip install huggingface_hub
python scripts/setup_bert.py
```

Downloads required model files to `models/`. Enable in `firewall.toml` via `engine_mode = "bert"`.
