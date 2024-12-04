use ark_bls12_381::{g1::Config as BlsConfig, Fq, G1Affine as G1Bls12_381};
use ark_bn254::g1::Config as BnConfig;
use ark_ec::{pairing::Pairing, short_weierstrass::Projective};
use ark_ff::{Field, PrimeField};
use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    G1Affine, G1Projective,
};
use bn254_hash2curve::hash2g1::HashToG1;
use sha2::Sha256;

use crate::utils::{
    core_utilities::hash_to_scalar,
    utilities_helper::{expand_message, FromOkm},
};

pub trait HashToG1<E: Pairing> {
    fn hash_to_g1(msg: &[u8], dst: &[u8]) -> E::G1;
}

pub struct HashToG1Bn254;
pub struct HashToG1Bls12381;

impl<E: Pairing<G1 = Projective<BnConfig>>> HashToG1<E> for HashToG1Bn254 {
    fn hash_to_g1(message: &[u8], dst: &[u8]) -> E::G1 {
        HashToG1(message, dst).into()
    }
}

impl<E: Pairing<G1 = Projective<BlsConfig>>> HashToG1<E> for HashToG1Bls12381 {
    fn hash_to_g1(message: &[u8], dst: &[u8]) -> E::G1 {
        // https://github.com/zkcrypto/bls12_381/blob/main/tests/hash_to_curve_g1.rs#L158
        let g = <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve([message], dst);

        let aff = G1Affine::from(g);
        let g_uncompressed = aff.to_uncompressed();

        G1Bls12_381::new(
            Fq::from_be_bytes_mod_order(&g_uncompressed[0..48]),
            Fq::from_be_bytes_mod_order(&g_uncompressed[48..]),
        )
        .into()
    }
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#section-4.1.1
pub fn create_generators<E, H>(count: usize, api_id: &[u8]) -> Vec<E::G1>
where
    E: Pairing,
    H: HashToG1<E>,
{
    let seed_dst = [api_id, b"SIG_GENERATOR_SEED_"].concat();
    let generator_dst = [api_id, b"SIG_GENERATOR_DST_"].concat();
    let generator_seed = [api_id, b"MESSAGE_GENERATOR_SEED"].concat();

    let mut generators: Vec<E::G1> = Vec::new();

    // expand_len aka len_in_bytes = 48: Must be defined to be at least ceil((ceil(log2(r))+k)/8), where log2(r) and k are defined by each ciphersuite
    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-additional-parameters
    let mut v = expand_message(generator_seed.as_slice(), seed_dst.as_slice(), 48);

    for i in 0..count {
        let mut msg = Vec::<u8>::with_capacity(v.len() + 8);
        msg.extend_from_slice(&v);
        msg.extend_from_slice(&(i + 1).to_be_bytes());

        v = expand_message(&msg, seed_dst.as_slice(), 48);

        generators.push(H::hash_to_g1(v.as_slice(), generator_dst.as_slice()));
    }

    generators
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-messages-to-scalars
pub fn msg_to_scalars<E, F, const L: usize>(messages: &[&[u8]], api_id: &[u8]) -> Vec<F>
where
    E: Pairing,
    F: Field + FromOkm<L, F>,
{
    let mut msg_scalars = Vec::new();
    let map_dst = [api_id, b"MAP_MSG_TO_SCALAR_AS_HASH_"].concat();
    for &msg in messages {
        msg_scalars.push(hash_to_scalar(msg, map_dst.as_slice()));
    }

    msg_scalars
}
