use ark_bn254::{Bn254, Fr};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::Rng;

use bbs_plus::key_gen::SecretKey;

pub fn keygen_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("keygen");

    for size in [32, 64, 128, 256, 512, 1024].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            // generating random key_material and key_info
            let mut rng = rand::thread_rng();
            let mut key_material: Vec<u8> = (0..size).map(|_| rng.gen::<u8>()).collect();
            let key_dst = b"BBS-SIG-KEYGEN-SALT-";
            let key_info: Vec<u8> = (0..size).map(|_| rng.gen::<u8>()).collect();

            b.iter(|| {
                SecretKey::<Fr>::key_gen::<Bn254>(
                    black_box(&mut key_material),
                    black_box(&key_info),
                    black_box(key_dst),
                )
            });
        });
    }

    group.finish();
}

criterion_group!(benches, keygen_benchmark);
criterion_main!(benches);
