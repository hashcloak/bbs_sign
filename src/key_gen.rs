
use crate::traits_helper::*;
use rand::prelude::*;
use ark_bn254::{fr::Fr, G1Affine as G1, g1::G1_GENERATOR_X, g1::G1_GENERATOR_Y};
use digest::generic_array::{GenericArray, typenum::U48};

#[derive(Debug)]
pub struct PublicKey {
    pub pub_key: G1
}

#[derive(Debug)]
pub struct SecretKey {
    pub priv_key: Fr,
    pub pub_key: PublicKey,
}

pub fn generate_keypair () -> SecretKey {

    let mut rng = thread_rng();
    let mut s = vec![0u8, 32];
    rng.fill_bytes(s.as_mut_slice());

    let sk = gen_sk(s.as_slice());
    let mut pk: G1 = G1::new_unchecked(G1_GENERATOR_X, G1_GENERATOR_Y);
    pk = (pk * sk).into();

    SecretKey { priv_key: sk, pub_key: PublicKey {
        pub_key: pk
    } }
}

pub fn gen_sk(msg: &[u8]) -> Fr {
    const SALT: &[u8] = b"BBS-SIG-KEYGEN-SALT-";
    // copy of `msg` with appended zero byte
    let mut msg_prime = Vec::<u8>::with_capacity(msg.as_ref().len() + 1);
    msg_prime.extend_from_slice(msg.as_ref());
    msg_prime.extend_from_slice(&[0]);
    // `result` has enough length to hold the output from HKDF expansion
    let mut result = GenericArray::<u8, U48>::default();
    assert!(hkdf::Hkdf::<sha2::Sha256>::new(Some(SALT), &msg_prime[..])
        .expand(&[0, 48], &mut result)
        .is_ok());
    let result_array: [u8;48] = result.as_slice().try_into().expect("wrong length!");
    Fr::from_okm(&result_array)
}
