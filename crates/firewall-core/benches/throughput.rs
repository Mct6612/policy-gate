use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Instant;

/// Throughput benchmarks: measure requests per second - including parallel

fn factual_question() -> &'static str {
    "What is the capital of France?"
}

fn code_request() -> &'static str {
    "Write a function that sorts an array"
}

fn greeting() -> &'static str {
    "Hello, how are you today?"
}

fn generate_test_batch(size: usize) -> Vec<String> {
    let inputs = [factual_question(), code_request(), greeting()];
    (0..size)
        .map(|i| inputs[i % inputs.len()].to_string())
        .collect()
}

/// Sequential baseline: single-threaded throughput
fn bench_sequential_throughput(c: &mut Criterion) {
    firewall_core::init().expect("init failed");

    let mut group = c.benchmark_group("throughput_sequential");

    for batch_size in [10, 50, 100] {
        let batch = generate_test_batch(batch_size);
        
        group.bench_with_input(
            criterion::BenchmarkId::new("batch", batch_size),
            &batch_size,
            |b, &size| {
                b.iter(|| {
                    for input in batch.iter().take(size) {
                        let _ = firewall_core::evaluate_raw(input, 0);
                    }
                });
            },
        );
    }

    group.finish();
}

/// Parallel batch evaluation using Rayon (when parallel feature is enabled)
#[cfg(feature = "parallel")]
fn bench_parallel_throughput(c: &mut Criterion) {
    firewall_core::init().expect("init failed");

    let mut group = c.benchmark_group("throughput_parallel_rayon");

    for batch_size in [10, 50, 100, 500, 1000] {
        let batch = generate_test_batch(batch_size);
        
        group.bench_with_input(
            criterion::BenchmarkId::new("batch", batch_size),
            &batch_size,
            |b, &size| {
                let inputs: Vec<String> = batch.iter().take(size).cloned().collect();
                b.iter(|| {
                    firewall_core::evaluate_batch_parallel(inputs.clone(), 0);
                });
            },
        );
    }

    group.finish();
}

/// Estimate throughput (requests per second)
fn bench_throughput_estimate(c: &mut Criterion) {
    firewall_core::init().expect("init failed");

    let mut group = c.benchmark_group("throughput_estimate");

    // Single request latency -> estimated max throughput
    group.bench_function("single_request_latency", |b| {
        b.iter(|| {
            let start = Instant::now();
            let _ = firewall_core::evaluate_raw(factual_question(), 0);
            let elapsed = start.elapsed().as_secs_f64();
            // 1 / latency = max requests per second (single-threaded)
            criterion::black_box(1.0 / elapsed);
        });
    });

    // Batch processing throughput
    group.bench_function("batch_100_latency", |b| {
        let batch = generate_test_batch(100);
        b.iter(|| {
            let start = Instant::now();
            for input in &batch {
                let _ = firewall_core::evaluate_raw(input, 0);
            }
            let elapsed = start.elapsed().as_secs_f64();
            // requests / second
            criterion::black_box(100.0 / elapsed);
        });
    });

    // Parallel batch throughput
    #[cfg(feature = "parallel")]
    group.bench_function("parallel_batch_1000_latency", |b| {
        let batch = generate_test_batch(1000);
        b.iter(|| {
            let start = Instant::now();
            firewall_core::evaluate_batch_parallel(batch.clone(), 0);
            let elapsed = start.elapsed().as_secs_f64();
            // requests / second
            criterion::black_box(1000.0 / elapsed);
        });
    });

    group.finish();
}

#[cfg(not(feature = "parallel"))]
criterion_group!(
    benches,
    bench_sequential_throughput,
    bench_throughput_estimate,
);

#[cfg(feature = "parallel")]
criterion_group!(
    benches,
    bench_sequential_throughput,
    bench_parallel_throughput,
    bench_throughput_estimate,
);

criterion_main!(benches);
