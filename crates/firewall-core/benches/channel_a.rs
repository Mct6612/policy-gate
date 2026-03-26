use criterion::{criterion_group, criterion_main, Criterion, Throughput};

/// Channel A benchmarks via public API
///
/// Since Channel A is internal, we benchmark it by observing the full pipeline
/// with inputs designed to exercise specific Channel A paths:
///
/// - Pass scenarios: factual questions, code requests, greetings (Channel A allowlist match)
/// - Block scenarios: malware keywords, SQL injection (Channel A forbidden patterns)
/// - Edge cases: overlong runs, control characters (Channel A structural checks)

fn factual_question() -> &'static str {
    "What is the capital of France?"
}

fn code_request() -> &'static str {
    "Write a function that sorts an array"
}

fn greeting() -> &'static str {
    "Hello, how are you today?"
}

fn malware_keyword() -> &'static str {
    "How to create malware for testing"
}

fn sql_injection() -> &'static str {
    "Perform sql injection attack on the database"
}

fn long_valid_input(len: usize) -> String {
    "What is the capital of France? "
        .repeat(len / 30 + 1)
        .chars()
        .take(len)
        .collect()
}

fn many_tokens(count: usize) -> String {
    (0..count)
        .map(|i| format!("word{}", i))
        .collect::<Vec<_>>()
        .join(" ")
}

fn overlong_run(len: usize) -> String {
    "a".repeat(len)
}

pub fn bench_channel_a_pass(c: &mut Criterion) {
    firewall_core::init().expect("init failed");

    let mut group = c.benchmark_group("channel_a_pass");

    group.bench_function("factual_question", |b| {
        b.iter(|| firewall_core::evaluate_raw(factual_question(), 0));
    });

    group.bench_function("code_request", |b| {
        b.iter(|| firewall_core::evaluate_raw(code_request(), 0));
    });

    group.bench_function("greeting", |b| {
        b.iter(|| firewall_core::evaluate_raw(greeting(), 0));
    });

    group.finish();
}

pub fn bench_channel_a_block(c: &mut Criterion) {
    firewall_core::init().expect("init failed");

    let mut group = c.benchmark_group("channel_a_block");

    group.bench_function("malware_keyword", |b| {
        b.iter(|| firewall_core::evaluate_raw(malware_keyword(), 0));
    });

    group.bench_function("sql_injection", |b| {
        b.iter(|| firewall_core::evaluate_raw(sql_injection(), 0));
    });

    group.finish();
}

pub fn bench_channel_a_tokenization(c: &mut Criterion) {
    firewall_core::init().expect("init failed");

    let mut group = c.benchmark_group("channel_a_tokenization");

    for size in [256, 1024, 4096, 8192] {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("long_valid", size), &size, |b, &s| {
            let input = long_valid_input(s);
            b.iter(|| firewall_core::evaluate_raw(&input, 0));
        });

        group.bench_with_input(BenchmarkId::new("many_tokens", size / 10), &(size / 10), |b, &s| {
            let input = many_tokens(s);
            b.iter(|| firewall_core::evaluate_raw(&input, 0));
        });
    }

    group.finish();
}

pub fn bench_channel_a_edge_cases(c: &mut Criterion) {
    firewall_core::init().expect("init failed");

    let mut group = c.benchmark_group("channel_a_edge_cases");

    for size in [201, 500, 1000] {
        group.bench_with_input(BenchmarkId::new("overlong_run", size), &size, |b, &s| {
            let input = overlong_run(s);
            b.iter(|| firewall_core::evaluate_raw(&input, 0));
        });
    }

    group.finish();
}

use criterion::BenchmarkId;
criterion_group!(
    benches,
    bench_channel_a_pass,
    bench_channel_a_block,
    bench_channel_a_tokenization,
    bench_channel_a_edge_cases,
);
criterion_main!(benches);
