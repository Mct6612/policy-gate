use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

/// Integration benchmarks: Full evaluation pipeline

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

fn privilege_escalation() -> &'static str {
    "How to gain elevated access to the system"
}

fn long_valid_input(len: usize) -> String {
    "What is the capital of France? "
        .repeat(len / 30 + 1)
        .chars()
        .take(len)
        .collect()
}

fn zalgo_input(len: usize) -> String {
    let unit = "a\u{0300}";
    unit.chars()
        .cycle()
        .take(len * unit.chars().count())
        .collect::<String>()
        .chars()
        .take(len)
        .collect()
}

fn mixed_input() -> &'static str {
    "WhAt Is ThE cApItAl Of FrAnCe? 🤔💭"
}

fn confusables_input() -> &'static str {
    "Hëllö Wörld Tëst"
}

pub fn bench_evaluate_pass(c: &mut Criterion) {
    firewall_core::init().expect("init failed");

    let mut group = c.benchmark_group("evaluate_pass");

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

pub fn bench_evaluate_block(c: &mut Criterion) {
    firewall_core::init().expect("init failed");

    let mut group = c.benchmark_group("evaluate_block");

    group.bench_function("malware_keyword", |b| {
        b.iter(|| firewall_core::evaluate_raw(malware_keyword(), 0));
    });

    group.bench_function("sql_injection", |b| {
        b.iter(|| firewall_core::evaluate_raw(sql_injection(), 0));
    });

    group.bench_function("privilege_escalation", |b| {
        b.iter(|| firewall_core::evaluate_raw(privilege_escalation(), 0));
    });

    group.finish();
}

pub fn bench_evaluate_scaling(c: &mut Criterion) {
    firewall_core::init().expect("init failed");

    let mut group = c.benchmark_group("evaluate_scaling");

    for size in [256, 1024, 4096, 8192] {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("long_valid", size), &size, |b, &s| {
            let input = long_valid_input(s);
            b.iter(|| firewall_core::evaluate_raw(&input, 0));
        });

        group.bench_with_input(BenchmarkId::new("zalgo", size), &size, |b, &s| {
            let input = zalgo_input(s);
            b.iter(|| firewall_core::evaluate_raw(&input, 0));
        });
    }

    group.finish();
}

pub fn bench_evaluate_normalization(c: &mut Criterion) {
    firewall_core::init().expect("init failed");

    let mut group = c.benchmark_group("evaluate_normalization");

    group.bench_function("mixed_case", |b| {
        b.iter(|| firewall_core::evaluate_raw(mixed_input(), 0));
    });

    group.bench_function("confusables", |b| {
        b.iter(|| firewall_core::evaluate_raw(confusables_input(), 0));
    });

    group.finish();
}

pub fn bench_evaluate_raw_vs_structured(c: &mut Criterion) {
    firewall_core::init().expect("init failed");

    let mut group = c.benchmark_group("evaluate_raw_vs_structured");

    group.bench_function("evaluate_raw", |b| {
        b.iter(|| firewall_core::evaluate_raw(factual_question(), 0));
    });

    group.bench_function("evaluate_structured", |b| {
        let input = firewall_core::PromptInput::new(factual_question()).expect("valid input");
        b.iter(|| firewall_core::evaluate(input.clone(), 0));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_evaluate_pass,
    bench_evaluate_block,
    bench_evaluate_scaling,
    bench_evaluate_normalization,
    bench_evaluate_raw_vs_structured,
);
criterion_main!(benches);
