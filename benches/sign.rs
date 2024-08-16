use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use rand::Rng;
use bbs_plus::key_gen::SecretKey;

// benchmarking signing on single message with varying message length
pub fn sign_benchmark_single_msg(c: &mut Criterion) {

    let mut key_material: [u8;32] = [1;32];
    let key_dst = b"BBS-SIG-KEYGEN-SALT-";
    let sk = SecretKey::key_gen(&mut key_material, &[], key_dst).unwrap();

    let mut group = c.benchmark_group("sign_single_msg");

    // message size
    for size in [128, 256, 512, 1024, 2048, 4096].iter() {

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {

        let mut rng = rand::thread_rng();
        let msg: Vec<u8> = (0..size).map(|_| rng.gen::<u8>()).collect(); // generating random message

        b.iter(|| sk.sign(black_box(&[&msg]), &[]));

        });
    }

    group.finish();
}

// benchmarking signing on multiple messages each of length 32bytes
pub fn sign_benchmark_multiple_msgs(c: &mut Criterion) {

    let mut key_material: [u8;32] = [1;32];
    let key_dst = b"BBS-SIG-KEYGEN-SALT-";
    let sk = SecretKey::key_gen(&mut key_material, &[], key_dst).unwrap();

    let mut group = c.benchmark_group("sign_multiple_msgs");

    // numer of messages
    for size in [1, 2, 4, 8, 16, 32, 64, 128].iter() {

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {

        let random_msgs_vecs: Vec<Vec<u8>> = (0..size)
        .map(|_| {
            let mut rng = rand::thread_rng();
            // each msg length of 32 bytes
            (0..32).map(|_| rng.gen::<u8>()).collect()
        })
        .collect();

        let msg_slices: Vec<&[u8]> = random_msgs_vecs.iter().map(|v| v.as_slice()).collect();
        let msgs: &[&[u8]] = &msg_slices;

        b.iter(|| sk.sign(black_box(msgs), &[]));

        });
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);  // Decrease sample size to 10
    targets = sign_benchmark_single_msg, sign_benchmark_multiple_msgs
}
criterion_main!(benches);

