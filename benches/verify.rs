use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use rand::Rng;
use bbs_plus::key_gen::{PublicKey, SecretKey};
use ark_bn254::{Fr, Bn254};
use bbs_plus::{constants::Bn254Const, utils::interface_utilities::HashToCurveBn254};

// benchmarking signature verification on single message with varying message length
pub fn verify_benchmark_single_msg(c: &mut Criterion) {

    let mut key_material: [u8;32] = [1;32];
    let key_dst = b"BBS-SIG-KEYGEN-SALT-";
    let sk = SecretKey::<Fr>::key_gen::<Bn254>(&mut key_material, &[], key_dst).unwrap();
    let pk: PublicKey<Bn254> = SecretKey::sk_to_pk(&sk);

    let mut group = c.benchmark_group("verify_single_msg");

    // message size
    for size in [128, 256, 512, 1024, 2048, 4096].iter() {

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {

        let mut rng = rand::thread_rng();
        let msg: Vec<u8> = (0..size).map(|_| rng.gen::<u8>()).collect(); // generating random message
        let signature = sk.sign::<Bn254, Bn254Const, HashToCurveBn254>(&[&msg], &[]).unwrap();

        b.iter(|| pk.verify::<Fr, HashToCurveBn254, Bn254Const>(signature, &[], black_box(&[&msg])));

        });
    }

    group.finish();
}

// benchmarking signature verification on multiple messages each of length 32bytes
pub fn verify_benchmark_multiple_msgs(c: &mut Criterion) {

    let mut key_material: [u8;32] = [1;32];
    let key_dst = b"BBS-SIG-KEYGEN-SALT-";
    let sk = SecretKey::<Fr>::key_gen::<Bn254>(&mut key_material, &[], key_dst).unwrap();
    let pk: PublicKey<Bn254> = sk.sk_to_pk();

    let mut group = c.benchmark_group("verify_multiple_msgs");

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

        let signature = sk.sign::<Bn254, Bn254Const, HashToCurveBn254>(msgs, &[]).unwrap();

        b.iter(|| pk.verify::<Fr, HashToCurveBn254, Bn254Const>(signature, &[], black_box(msgs)));

        });
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);  // Decrease sample size to 10
    targets = verify_benchmark_single_msg, verify_benchmark_multiple_msgs
}
criterion_main!(benches);

