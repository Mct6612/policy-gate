# Performance Benchmarks

This document describes the performance benchmark suite for `firewall-core`.

## Overview

The benchmark suite uses [criterion](https://github.com/bheisler/criterion.rs) for statistical benchmarking with HTML report generation. Benchmarks are organized by component to enable targeted performance analysis.

## Running Benchmarks

### Run all benchmarks

```bash
cargo bench -p firewall-core
```

### Run specific benchmark group

```bash
# Channel A only
cargo bench -p firewall-core --bench channel_a

# Channel B only
cargo bench -p firewall-core --bench channel_b

# Voter only
cargo bench -p firewall-core --bench voter

# Integration (full pipeline)
cargo bench -p firewall-core --bench integration

# Normalization pipeline
cargo bench -p firewall-core --bench normalise
```

### Run with custom sample size

```bash
cargo bench -p firewall-core -- --sample-size 100
```

### Save baseline for comparison

```bash
cargo bench -p firewall-core -- --save-baseline my_baseline
```

### Compare against baseline

```bash
cargo bench -p firewall-core -- --baseline my_baseline
```

## Benchmark Groups

### 1. Channel A: FSM + Allowlist (`channel_a.rs`)

Tests the finite state machine with allowlist matching.

**Groups:**
- `channel_a_pass` — Pass scenarios (factual questions, code requests, greetings)
- `channel_a_block` — Block scenarios (malware keywords, SQL injection, control chars)
- `channel_a_tokenization` — Tokenization performance with varying input sizes (256–8192 bytes)
- `channel_a_edge_cases` — Edge cases (overlong character runs)

**Key metrics:**
- Latency per evaluation (microseconds)
- Throughput (bytes/second) for scaling tests

### 2. Channel B: Rule Engine (`channel_b.rs`)

Tests the deterministic rule engine without regex or ML.

**Groups:**
- `channel_b_pass` — Pass scenarios (factual questions, code requests, greetings)
- `channel_b_block` — Block scenarios (malware keywords, SQL injection, privilege escalation)
- `channel_b_scaling` — Scaling behavior with varying input sizes (256–8192 bytes)

**Key metrics:**
- Latency per evaluation (microseconds)
- Throughput (bytes/second) for scaling tests

### 3. Voter: 1oo2D Decision Logic (`voter.rs`)

Tests the redundant voting logic.

**Groups:**
- `voter_agreement` — Agreement scenarios (both Pass, both Block)
- `voter_disagreement` — Disagreement scenarios (Pass vs Block)
- `voter_fault` — Fault handling (WatchdogFired, both channels faulted)

**Key metrics:**
- Latency per decision (nanoseconds) — voter is extremely lightweight

### 4. Integration: Full Pipeline (`integration.rs`)

Tests the complete evaluation flow from raw input to verdict.

**Groups:**
- `evaluate_pass` — Pass scenarios through full pipeline
- `evaluate_block` — Block scenarios through full pipeline
- `evaluate_scaling` — Scaling behavior with varying input sizes (256–8192 bytes)
- `evaluate_normalization` — Normalization edge cases (mixed case, confusables, Zalgo)
- `evaluate_raw_vs_structured` — Comparison of `evaluate_raw()` vs `evaluate()` with pre-normalized input

**Key metrics:**
- End-to-end latency (microseconds)
- Throughput (bytes/second) for scaling tests

### 5. Normalization Pipeline (`normalise.rs`)

Tests the Unicode normalization pipeline (NFKC→NFD→strip Mn→NFC).

**Groups:**
- `normalise_pipeline` — ASCII vs Zalgo inputs at various sizes

**Key metrics:**
- Latency per normalization (microseconds)
- Throughput (bytes/second)

## Interpreting Results

### HTML Reports

Criterion generates HTML reports in `target/criterion/`. Open `target/criterion/report/index.html` in a browser to view:

- Statistical analysis (mean, median, standard deviation)
- Outlier detection
- Regression detection (when comparing against baseline)
- Throughput plots

### Key Performance Indicators

| Component | Target Latency | Notes |
|-----------|---------------|-------|
| Channel A | < 100 µs | Includes regex matching, tokenization |
| Channel B | < 50 µs | Pure structural/lexical analysis |
| Voter | < 1 µs | Simple pattern matching |
| Full Pipeline | < 200 µs | End-to-end including normalization |

### Scaling Behavior

The benchmarks test scaling with input sizes from 256 to 8192 bytes. Expected behavior:

- **Linear scaling**: Most operations are O(n) in input length
- **Bounded by watchdog**: 50 ms deadline in release builds
- **Tokenization overhead**: Proportional to token count, not just byte count

## Adding New Benchmarks

1. Create a new file in `crates/firewall-core/benches/`
2. Add the benchmark to `Cargo.toml`:

```toml
[[bench]]
name = "your_benchmark"
harness = false
```

3. Use the criterion API:

```rust
use criterion::{criterion_group, criterion_main, Criterion};

pub fn bench_your_function(c: &mut Criterion) {
    firewall_core::init().expect("init failed");
    
    let mut group = c.benchmark_group("your_group");
    
    group.bench_function("test_name", |b| {
        b.iter(|| {
            // Your benchmark code
        });
    });
    
    group.finish();
}

criterion_group!(benches, bench_your_function);
criterion_main!(benches);
```

## Performance Regression Testing

### CI Integration

Add to your CI pipeline:

```yaml
- name: Run benchmarks
  run: cargo bench -p firewall-core -- --save-baseline current

- name: Compare against main
  run: cargo bench -p firewall-core -- --baseline main
```

### Threshold Configuration

Criterion can be configured to fail on regression:

```rust
// In your benchmark file
use criterion::Criterion;

let mut criterion = Criterion::default()
    .significance_level(0.01)  // 1% regression threshold
    .noise_threshold(0.05);    // 5% noise threshold
```

## Profiling

For detailed profiling beyond criterion's statistical analysis:

### CPU Profiling (Linux)

```bash
perf record --call-graph=dwarf cargo bench -p firewall-core --bench integration
perf report
```

### Flamegraphs

```bash
cargo flamegraph --bench integration
```

### Memory Profiling

```bash
valgrind --tool=massif cargo bench -p firewall-core --bench integration
ms_print massif.out.*
```

## Troubleshooting

### Slow First Run

The first benchmark run may be slower due to:
- Regex compilation (OnceLock warmup in `init()`)
- CPU cache warming
- File system caching

Run `init()` before benchmarks to warm up regex patterns.

### High Variance

If variance is high (> 10%):
- Increase sample size: `--sample-size 200`
- Run on a quiet system
- Disable CPU frequency scaling
- Use `taskset` to pin to a specific CPU core

### Watchdog Timeouts

If benchmarks hit the 50 ms watchdog:
- Check for pathological inputs
- Review regex complexity
- Consider increasing `WATCHDOG_DEADLINE_US` for benchmarks only

## References

- [Criterion User Guide](https://bheisler.github.io/criterion.rs/book/)
- [Rust Performance Book](https://nnethercote.github.io/perf-book/)
- [Flamegraph Tools](https://github.com/flamegraph-rs/flamegraph)
