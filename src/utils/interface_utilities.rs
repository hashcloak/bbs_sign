use ark_ff::Field;
use bn254_hash2curve::hash2g1::HashToG1;
use ark_ec::pairing::Pairing;

use super::utilities_helper::expand_message;
use super::core_utilities::hash_to_scalar;
use crate::utils::utilities_helper;
use ark_bls12_381::G1Affine as G1Bls12_381;

pub trait HashToG1<E: Pairing> {
    fn hash_to_g1(msg: &[u8], dst: &[u8]) -> E::G1;
}

pub struct HashToCurveBn254;
pub struct HashToCurveBls12381;

impl <E: Pairing<G1 = ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>>>HashToG1<E> for HashToCurveBn254 {

    fn hash_to_g1(message: &[u8], dst: &[u8]) -> E::G1 {
        HashToG1(message, dst).into()
    }
}

impl <E: Pairing<G1 = ark_ec::short_weierstrass::Projective<ark_bls12_381::g1::Config>>>HashToG1<E> for HashToCurveBls12381 {

    fn hash_to_g1(_message: &[u8], _dst: &[u8]) -> E::G1 {

        //TODO: Implement this
        G1Bls12_381::identity().into()
    }
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#section-4.1.1
pub fn create_generators<E: Pairing, H: HashToG1<E>>(count: usize, api_id: &[u8]) -> Vec<E::G1> {

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
        msg.extend_from_slice(&i.to_be_bytes());

        v = expand_message(&msg, seed_dst.as_slice(), 48);

        generators.push(H::hash_to_g1(v.as_slice(), generator_dst.as_slice()));
    }

    generators
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-messages-to-scalars
pub fn msg_to_scalars<E, F, const L: usize>(messages: &[&[u8]] , api_id: &[u8]) -> Vec<F> 
where 
    E: Pairing,
    F: Field + utilities_helper::FromOkm<L, F>, 
{
    let mut msg_scalars = Vec::new();
    for &msg in messages {
        msg_scalars.push(hash_to_scalar(msg, api_id));
    }

    msg_scalars
}