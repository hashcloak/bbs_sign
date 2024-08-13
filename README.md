# BBS+ Signature Scheme over BN254 Pairing

## Warning!!!

*This code is unaudited and has not yet been tested against test vectors. Use it with caution and do not rely on it for production use without thorough testing and review.*

## Overview

This repository implements the BBS+ signature scheme over the BN254 elliptic curve pairing. BBS+ is a cryptographic scheme that supports efficient multi-message signing, selective disclosure, and proof of knowledge, making it suitable for privacy-preserving applications such as anonymous credentials and digital signatures.

The implementation follows the specifications outlined in the [IETF draft for BBS signatures](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html) and leverages the BN254 pairing-friendly curve for cryptographic operations.

## Features

- **Key Generation**: Generate public and secret keys using secure cryptographic methods as mentioned in the draft.
- **Signature Generation**: Sign multiple messages using the BBS+ signature scheme.
- **Selective Disclosure**: Support for creating zero-knowledge proofs to disclose specific signed messages without revealing others.
- **Signature Verification**: Verify both the full signature and selectively disclosed signatures.
- **Security**: Built using the BN254 pairing-friendly curve, which provides efficient and secure cryptographic operations.

## Usage

Add this library under dependencies in the Cargo.toml of your project:
```rust
[dependencies]
bbs_plus ={ git = "https://github.com/hashcloak/bbs_sign.git"}
```
and then use as shown below for key-gen, signing and verifying(both full and selectively disclosed msg)

```rust
use bbs_plus::key_gen::SecretKey;
use bbs_plus::proof_gen::proof_gen;
use bbs_plus::proof_verify::proof_verify;

fn main() {
    
    let mut key_material = [5u8; 32];
    let key_dst = b"BBS-SIG-KEYGEN-SALT-";

    let sk = SecretKey::key_gen(&mut key_material, &[], key_dst);
    assert!(sk.is_ok());

    // secret and public key
    let sk = sk.unwrap();
    let pk = sk.sk_to_pk();

    let msgs: &[&[u8]] = &[b"message1", b"message2", b"msg3", b"msg4"];

    // signature
    let sig = sk.sign(msgs, &[]);
    assert!(sig.is_ok());

    let sig = sig.unwrap();

    // verify
    let res = pk.clone().verify(sig, &[], msgs);
    assert!(res.is_ok());
    assert!(res.unwrap());

    // disclose specific messages
    let disclosed_indices = [0, 2];
    let disclosed_msgs = [msgs[0], msgs[2]];

    let proof = proof_gen(pk.clone(), sig, &[], &[], msgs, disclosed_indices.as_slice());
    assert!(proof.is_ok());
    let proof = proof.unwrap();

    assert!(proof_verify(pk, proof, &[], &[], disclosed_msgs.as_slice(), disclosed_indices.as_slice()).unwrap());
}
```
