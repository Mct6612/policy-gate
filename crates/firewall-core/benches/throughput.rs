use criterion::{criterion_group, criterion_main, Criterion};
use std::sync::Arc;
use std::time::Instant;

/// Throughput benchmarks: measure requests per second under concurrent load

fn factual_question() -> &'static str {
    "What is the capital of France?"
}

fn generate_test_batch(size: usize) -> Vec<String> {
    (0..size)
        .map(|i| if i % 2 == 0 { factual_question() } else { "Write a function" })
        .map(|s| s.to_string())
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

/// Concurrent throughput using std::thread
fn bench_concurrent_threads(c: &mut Criterion) {
    firewall_core::init().expect("init failed");

    let mut group = c.benchmark_group("throughput_parallel");

    // Simpler concurrent test
    let batch = Arc::new(generate_test_batch(100));
    
    group.bench_function("10_threads_100_requests", |b| {
        let batch_clone = batch.clone();
        b.iter(|| {
            let handles: Vec<_> = (0..10)
                .map(|_| {
                    let batch = batch_clone.clone();
                    std::thread::spawn(move || {
                        for input in batch.iter().take(10) {
                            let _ = firewall_core::evaluate_raw(input, 0);
                        }
                    })
                })
                .collect();
            for h in handles {
                h.join().unwrap();
            }
        });
    });

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
            1.0 / elapsed
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
            100.0 / elapsed
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_sequential_throughput,
    bench_concurrent_threads,
    bench_throughput_estimate,
);
criterion_main!(benches);
