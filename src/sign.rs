use ark_bn254::{
    fr::Fr,
    g1::G1Affine as G1
};
use crate::traits_helper::{
    hash_to_scalar,
    expand_message
};
use crate::key_gen::{
    PublicKey, SecretKey
};

use bn254_hash2curve::hash2g1::HashToG1;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

// signature
#[derive(Debug, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signature {
    pub a: G1,
    pub e: Fr,
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-messages-to-scalars
pub fn msg_to_scalars(messages: &[&[u8]] , api_id: &[u8]) -> Vec<Fr> {
    let mut msg_scalars = Vec::new();
    for &msg in messages {
        msg_scalars.push(hash_to_scalar(msg, api_id));
    }

    msg_scalars
}

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

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-signature-generation-sign
pub fn sign(secret_key: &SecretKey, messages: &[&[u8]], api_id: &[u8]) -> Signature {
    //TODO:
    Signature::default()
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-coresign
pub fn core_sign(secret_key: &SecretKey, messages: &[&[u8]], api_id: &[u8]) -> Signature {
    //TODO:
    Signature::default()
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-domain-calculation
pub fn calculate_domain(pk: PublicKey, q_1: G1, h_points: &[G1], header: &[u8], api_id: &[u8]) -> Fr {
    
    let l = h_points.len();
    let mut dom_octs = Vec::new();
    dom_octs.extend_from_slice(&l.to_be_bytes());

    let mut compressed_bytes = Vec::new();
    q_1.serialize_compressed(&mut compressed_bytes).unwrap();
    dom_octs.extend_from_slice(&compressed_bytes);

    for h in h_points {

        let mut compressed_bytes = Vec::new();
        h.serialize_compressed(&mut compressed_bytes).unwrap();
        dom_octs.extend_from_slice(&compressed_bytes);
    }

    let mut compressed_bytes = Vec::new();
    pk.serialize_compressed(&mut compressed_bytes).unwrap();

    let mut dom_input = Vec::new();
    dom_input.extend_from_slice(&compressed_bytes);
    dom_input.extend_from_slice(&dom_octs);
    dom_input.extend_from_slice(&header.len().to_be_bytes());
    dom_input.extend_from_slice(header);

    let hash_to_scalar_dst = [api_id, b"H2S_"].concat();

    hash_to_scalar(&dom_input, &hash_to_scalar_dst)

}