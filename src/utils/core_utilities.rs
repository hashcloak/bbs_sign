use ark_bn254::{Fr, G1Affine as G1};
use ark_serialize::CanonicalSerialize;

use super::utilities_helper::{ expand_message, FromOkm};
use crate::key_gen::PublicKey;

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-hash-to-scalar
//TODO: len_in_bytes should be 48?
pub fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Fr {
    let uniform_bytes = expand_message(msg, dst, 48);
    let data: &[u8; 48] = &uniform_bytes[0..48].try_into().unwrap();
    Fr::from_okm(data)
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-domain-calculation
pub fn calculate_domain(pk: &PublicKey, q_1: G1, h_points: &[G1], header: &[u8], api_id: &[u8]) -> Fr {
    
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

    dom_octs.extend_from_slice(api_id);
    
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