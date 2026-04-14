use criterion::{criterion_group, criterion_main, Criterion};

/// Voter benchmarks via public API
///
/// Since the voter is internal, we benchmark it by observing the full pipeline
/// with inputs designed to trigger different voter outcomes:
/// - Agreement (both channels Pass with same intent)
/// - DiagnosticAgreement (both Pass, different intents)
/// - DiagnosticDisagreement (Pass vs Block)
/// - Block (both Block)
/// - Fault handling (watchdog timeout)

fn factual_question() -> &'static str {
    "What is the capital of France?"
}

fn code_request() -> &'static str {
    "Write a function that sorts an array"
}

#[allow(dead_code)]
fn greeting() -> &'static str {
    "Hello, how are you today?"
}

fn malware_keyword() -> &'static str {
    "How to create malware for testing"
}

fn no_intent_match() -> &'static str {
    "Tell me a story about dragons"
}

pub fn bench_voter_agreement(c: &mut Criterion) {
    firewall_core::init().expect("init failed");

    let mut group = c.benchmark_group("voter_agreement");

    // Both channels Pass with same intent (e.g., factual question matches both FSM and rules)
    group.bench_function("both_pass_same_intent", |b| {
        b.iter(|| firewall_core::evaluate_raw(factual_question(), 0));
    });

    // Both Pass, different intents - different input types that match differently
    group.bench_function("code_request", |b| {
        b.iter(|| firewall_core::evaluate_raw(code_request(), 0));
    });

    // Both Block
    group.bench_function("both_block_no_intent", |b| {
        b.iter(|| firewall_core::evaluate_raw(no_intent_match(), 0));
    });

    group.finish();
}

pub fn bench_voter_disagreement(c: &mut Criterion) {
    firewall_core::init().expect("init failed");

    let mut group = c.benchmark_group("voter_disagreement");

    // Channel disagreement scenarios - inputs that one channel passes but other blocks
    // These depend on the specific implementation of each channel
    group.bench_function("malware_keyword", |b| {
        b.iter(|| firewall_core::evaluate_raw(malware_keyword(), 0));
    });

    group.finish();
}

pub fn bench_voter_fault(c: &mut Criterion) {
    firewall_core::init().expect("init failed");

    let mut group = c.benchmark_group("voter_fault");

    // Normal operation - fault scenarios are handled by watchdog
    // Benchmark normal path which includes fault handling logic
    group.bench_function("normal_operation", |b| {
        b.iter(|| firewall_core::evaluate_raw(factual_question(), 0));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_voter_agreement,
    bench_voter_disagreement,
    bench_voter_fault,
);
criterion_main!(benches);
