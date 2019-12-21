use criterion::{black_box, criterion_group, criterion_main, Criterion};

use xorfilter::*;

fn bench_xor_contains(c: &mut Criterion) {
    let xor = Xor8::new((0..100_000_000).collect::<Vec<u64>>().as_ref());

    c.bench_function("xor_contains", |b| b.iter(|| xor.contains(57_402_124)));
}

criterion_group!(benches, bench_xor_contains);
criterion_main!(benches);
