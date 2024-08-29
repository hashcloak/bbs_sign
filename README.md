# BBS+ Signature Scheme over BN254 & BLS12-381 Pairing

## Warning!!!

*This code is unaudited and has not yet been tested against test vectors. Use it with caution and do not rely on it for production use without thorough testing and review.*

## Overview

This repository implements the BBS+ signature scheme supporting over both the BN254(arkworks) and BLS12381(arkworks) pairing curve. BBS+ is a cryptographic scheme that supports efficient multi-message signing, selective disclosure, and proof of knowledge, making it suitable for privacy-preserving applications such as anonymous credentials and digital signatures.

The implementation follows the specifications outlined in the [IETF draft for BBS signatures](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html) and leverages the BN254 & BLS12-381 pairing-friendly curve for cryptographic operations.

## Features

- **Key Generation**: Generate public and secret keys using secure cryptographic methods as mentioned in the draft.
- **Signature Generation**: Sign multiple messages using the BBS+ signature scheme.
- **Selective Disclosure**: Support for creating zero-knowledge proofs to disclose specific signed messages without revealing others.
- **Signature Verification**: Verify both the full signature and selectively disclosed signatures.
- **Security**: Built using the BN254 pairing-friendly curve, which provides efficient and secure cryptographic operations.

## Usage

Add the following library under dependencies in the Cargo.toml of your project:
```rust
[dependencies]
bbs_plus ={ git = "https://github.com/hashcloak/bbs_sign.git"}
ark-bn254 = "0.4.0" # For BBS over BN254
ark-bls12-381 = "0.4.0" # For BBS over BLS12-381
```
and then use as shown below for key-gen, signing and verifying, proof generation and verification(both full and selectively disclosed msg)

```rust
use bbs_plus::{
    key_gen::{SecretKey, PublicKey},
    proof_gen::proof_gen,
    proof_verify::proof_verify,
    constants::{
        Bn254Const, // For BBS over BN254
        Bls12381Const   // For BBS over BLS12-381
    },
    utils::interface_utilities::{ 
        HashToG1Bn254,  // For BBS over BN254
        HashToG1Bls12381    // For BBS over BLS12-381
    },
};
use ark_bn254::{Bn254, Fr as FrBn254};  // For BBS over BN254
use ark_bls12_381::{Bls12_381, Fr as FrBls12381};    // For BBS over BLS12-381

fn main() {
    
    // ----------------------------BBS over BN254------------------------------------- 
    
    // ensure that key_meterial is at least 32 bytes, otherwise it will panic
    let mut key_material = [5u8; 32];
    let key_dst = b"BBS-SIG-KEYGEN-SALT-";

    // secret and public key
    let sk: SecretKey<FrBn254> = SecretKey::<FrBn254>::key_gen::<Bn254>(&mut key_material, &[], key_dst.as_slice()).unwrap();
    let pk: PublicKey<Bn254> = sk.sk_to_pk();

    let msgs: &[&[u8]] = &[b"message1", b"message2", b"msg3", b"msg4"];

    // signature
    let sig = sk.sign::<Bn254, Bn254Const, HashToG1Bn254>(msgs, &[]);
    assert!(sig.is_ok());

    let sig = sig.unwrap();

    // verify
    let res = pk.clone().verify::<FrBn254, HashToG1Bn254, Bn254Const>(sig, &[], msgs);
    assert!(res.is_ok());
    assert!(res.unwrap());

    // disclose specific messages
    let disclosed_indices = [0, 2];
    let disclosed_msgs = [msgs[0], msgs[2]];

    let proof = proof_gen::<Bn254, FrBn254, HashToG1Bn254, Bn254Const>(pk.clone(), sig, &[], &[], msgs, disclosed_indices.as_slice());
    assert!(proof.is_ok());
    let proof = proof.unwrap();

    assert!(proof_verify::<Bn254, FrBn254, HashToG1Bn254, Bn254Const>(pk, proof, &[], &[], disclosed_msgs.as_slice(), disclosed_indices.as_slice()).unwrap());


    // ----------------------------BBS over BLS12-381------------------------------------- 

    // ensure that key_meterial is at least 32 bytes, otherwise it will panic
    let mut key_material = [5u8; 32];
    let key_dst = b"BBS-SIG-KEYGEN-SALT-";

    // secret and public key
    let sk: SecretKey<FrBls12381> = SecretKey::<FrBls12381>::key_gen::<Bls12_381>(&mut key_material, &[], key_dst.as_slice()).unwrap();
    let pk: PublicKey<Bls12_381> = sk.sk_to_pk();

    let msgs: &[&[u8]] = &[b"message1", b"message2", b"msg3", b"msg4"];

    // signature
    let sig = sk.sign::<Bls12_381, Bls12381Const, HashToG1Bls12381>(msgs, &[]);
    assert!(sig.is_ok());

    let sig = sig.unwrap();

    // verify
    let res = pk.clone().verify::<FrBls12381, HashToG1Bls12381, Bls12381Const>(sig, &[], msgs);
    assert!(res.is_ok());
    assert!(res.unwrap());

    // disclose specific messages
    let disclosed_indices = [0, 2];
    let disclosed_msgs = [msgs[0], msgs[2]];

    let proof = proof_gen::<Bls12_381, FrBls12381, HashToG1Bls12381, Bls12381Const>(pk.clone(), sig, &[], &[], msgs, disclosed_indices.as_slice());
    assert!(proof.is_ok());
    let proof = proof.unwrap();

    assert!(proof_verify::<Bls12_381, FrBls12381, HashToG1Bls12381, Bls12381Const>(pk, proof, &[], &[], disclosed_msgs.as_slice(), disclosed_indices.as_slice()).unwrap());

}

```
## Benchmarking with Criterion

benchmarking for the BBS+ signature scheme is done using [Criterion.rs](https://github.com/bheisler/criterion.rs), a powerful framework for benchmarking Rust code. The benchmarks cover the key generation, message signing, signature verification, proof generation and proof verification processes. Currenlty, the benchmark is done only over BN254.

To run all the benchmarks:
```rust
cargo bench
```
Running entire benchmark will take some significant time! You can also run specific benchmarks using `--bench` flag.
```rust
cargo bench --bench <benchmark_target>
```
The following benchmark targets are availabe: `keygen`, `sign`, `verify`, `proof_gen` and `proof_verify`(e.g., `cargo bench --bench keygen`).

The benchmarks evaluate the following different scenarios:
- `keygen`: 
    - varying length of `key_material`
- `sign` and `verify`: 
    - single message with varying message lengths 
    - multiple messages each of a fixed length(32 bytes)
- `proof_gen` and `proof_verify`: 
    - single message with varying message lengths with no disclosed indices
    - multiple messages each of a fixed length(32 bytes) with no disclosed indices 
    - multiple messages each of a fixed length(32 bytes) with varying disclosed indices