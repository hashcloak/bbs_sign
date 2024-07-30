use ark_bn254::{G1Affine as G1, Fr};
use bn254_hash2curve::hash2g1::HashToG1;

use super::utilities_helper::expand_message;
use super::core_utilities::hash_to_scalar;

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#section-4.1.1
pub fn create_generators(count: usize, api_id: &[u8]) -> Vec<G1> {

    let seed_dst = [api_id, b"SIG_GENERATOR_SEED_"].concat();
    let generator_dst = [api_id, b"SIG_GENERATOR_DST_"].concat();
    let generator_seed = [api_id, b"MESSAGE_GENERATOR_SEED"].concat();

    let mut generators: Vec<G1> = Vec::new();

    //TODO: len_in_bytes should be 48?
    let mut v = expand_message(generator_seed.as_slice(), seed_dst.as_slice(), 48);

    for i in 0..count {

        let mut msg = Vec::<u8>::with_capacity(v.len() + 8);
        msg.extend_from_slice(&v);
        msg.extend_from_slice(&i.to_be_bytes());

        v = expand_message(&msg, seed_dst.as_slice(), 48);

        generators.push(HashToG1(v.as_slice(), generator_dst.as_slice()));
    }

    generators
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-messages-to-scalars
pub fn msg_to_scalars(messages: &[&[u8]] , api_id: &[u8]) -> Vec<Fr> {
    let mut msg_scalars = Vec::new();
    for &msg in messages {
        msg_scalars.push(hash_to_scalar(msg, api_id));
    }

    msg_scalars
}