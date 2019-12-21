use criterion::{black_box, criterion_group, criterion_main, Criterion};

use xorfilter::*;

fn bench_xor_contains(c: &mut Criterion) {
    c.bench_function("contains", |b| {
        b.iter_with_setup(
            || Xor8::new((0..1_000).collect::<Vec<u64>>().as_ref()),
            |xor| xor.contains(124),
        )
    });
}

criterion_group!(benches, bench_xor_contains);
criterion_main!(benches);
