use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use rand::Rng;
use bbs_plus::key_gen::SecretKey;
use bbs_plus::proof_gen::proof_gen;
use ark_bn254::{Fr, Bn254};
use bbs_plus::key_gen::PublicKey;
use bbs_plus::constants::Bn254Const;
use bbs_plus::utils::interface_utilities::HashToCurveBn254;

// benchmarking proof generation on single message with varying message length
pub fn proof_gen_benchmark_single_msg(c: &mut Criterion) {

    let mut key_material: [u8;32] = [1;32];
    let key_dst = b"BBS-SIG-KEYGEN-SALT-";
    let sk = SecretKey::<Fr>::key_gen::<Bn254>(&mut key_material, &[], key_dst).unwrap();
    let pk: PublicKey<Bn254> = sk.sk_to_pk();

    let mut group = c.benchmark_group("proof_gen_single_msg");

    // message size
    for size in [32, 64, 128, 256, 512, 1024, 2048].iter() {

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {

        let mut rng = rand::thread_rng();
        let msg: Vec<u8> = (0..size).map(|_| rng.gen::<u8>()).collect(); // generating random message
        let signature = sk.sign::<Bn254, Bn254Const, HashToCurveBn254>(&[&msg], &[]).unwrap();
        assert!(pk.verify::<Fr, HashToCurveBn254, Bn254Const>(signature, &[], black_box(&[&msg])).unwrap());

        b.iter(|| proof_gen::<Bn254, Fr, HashToCurveBn254, Bn254Const>(pk.clone(), signature, &[], &[],&[&msg], &[]));

        });
    }

    group.finish();
}

// benchmarking proof generation on multiple messages each of length 32bytes
pub fn proof_gen_benchmark_multiple_msgs(c: &mut Criterion) {

    let mut key_material: [u8;32] = [1;32];
    let key_dst = b"BBS-SIG-KEYGEN-SALT-";
    let sk = SecretKey::<Fr>::key_gen::<Bn254>(&mut key_material, &[], key_dst).unwrap();
    let pk: PublicKey<Bn254> = sk.sk_to_pk();

    let mut group = c.benchmark_group("proof_gen_multiple_msgs");

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
        assert!(pk.verify::<Fr, HashToCurveBn254, Bn254Const>(signature, &[], black_box(msgs)).unwrap());

        b.iter(|| proof_gen::<Bn254, Fr, HashToCurveBn254, Bn254Const>(pk.clone(), signature, &[], &[],msgs, &[]));

        });
    }

    group.finish();
}

// benchmarking proof generation on multiple disclosed indices with each msg of length 32bytes
pub fn proof_gen_benchmark_multiple_disclosed_indices(c: &mut Criterion) {

    let mut key_material: [u8;32] = [1;32];
    let key_dst = b"BBS-SIG-KEYGEN-SALT-";
    let sk = SecretKey::<Fr>::key_gen::<Bn254>(&mut key_material, &[], key_dst).unwrap();
    let pk: PublicKey<Bn254> = sk.sk_to_pk();

    // random msgs of length 32 each msg of length 32
    let random_msgs_vecs: Vec<Vec<u8>> = (0..32)
        .map(|_| {
            let mut rng = rand::thread_rng();
            // each msg length of 32 bytes
            (0..32).map(|_| rng.gen::<u8>()).collect()
        })
        .collect();
    
    let msg_slices: Vec<&[u8]> = random_msgs_vecs.iter().map(|v| v.as_slice()).collect();
    let msgs: &[&[u8]] = &msg_slices;
    
    let signature = sk.sign::<Bn254, Bn254Const, HashToCurveBn254>(msgs, &[]).unwrap();
    assert!(pk.verify::<Fr, HashToCurveBn254, Bn254Const>(signature, &[], black_box(msgs)).unwrap());

    let mut group = c.benchmark_group("proof_gen_multiple_disclosed_indices");

    // indices
    for indices in [1, 2, 4, 8, 16, 32].iter() {

        group.throughput(Throughput::Bytes(*indices as u64));
        group.bench_with_input(BenchmarkId::from_parameter(indices), indices, |b, &indices| {
        
        b.iter(|| proof_gen::<Bn254, Fr, HashToCurveBn254, Bn254Const>(pk.clone(), signature, &[], &[],msgs, (0..indices).collect::<Vec<_>>().as_slice()));

        });
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);  // Decrease sample size to 10
    targets = proof_gen_benchmark_single_msg, proof_gen_benchmark_multiple_msgs, proof_gen_benchmark_multiple_disclosed_indices
}
criterion_main!(benches);

