use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_serialize::CanonicalSerialize;

use crate::{
    key_gen::PublicKey,
    utils::utilities_helper::{expand_message, FromOkm},
};

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-hash-to-scalar
pub fn hash_to_scalar<const L: usize, F>(msg: &[u8], dst: &[u8]) -> F
where
    F: Field + FromOkm<L, F>,
{
    // expand_len aka len_in_bytes = 48: Must be defined to be at least ceil((ceil(log2(r))+k)/8), where log2(r) and k are defined by each ciphersuite
    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-additional-parameters
    let uniform_bytes = expand_message(msg, dst, L);

    let data: &[u8; L] = &uniform_bytes[..L].try_into().unwrap();
    F::from_okm(data)
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-domain-calculation
pub fn calculate_domain<E, F, const L: usize>(
    pk: &PublicKey<E>,
    q_1: E::G1,
    h_points: &[E::G1],
    header: &[u8],
    api_id: &[u8],
) -> F
where
    E: Pairing,
    F: Field + FromOkm<L, F>,
{
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
    pk.pk.serialize_compressed(&mut compressed_bytes).unwrap();

    let mut dom_input = Vec::new();
    dom_input.extend_from_slice(&compressed_bytes);
    dom_input.extend_from_slice(&dom_octs);
    dom_input.extend_from_slice(&header.len().to_be_bytes());
    dom_input.extend_from_slice(header);

    let hash_to_scalar_dst = [api_id, b"H2S_"].concat();

    hash_to_scalar::<L, F>(&dom_input, &hash_to_scalar_dst)
}

fn get_random(len: usize) -> Vec<u8> {
    (0..len).map(|_| rand::random::<u8>()).collect()
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-random-scalars
pub fn calculate_random_scalars<const L: usize, F>(count: usize) -> Vec<F>
where
    F: Field + FromOkm<L, F>,
{
    let mut result = Vec::with_capacity(count);

    for _ in 0..count {
        let data: &[u8; L] = &get_random(L)[..].try_into().unwrap();
        result.push(F::from_okm(data));
    }
    result
}

// for testing only
pub fn seeded_random_scalars<const L: usize, F>(seed: &[u8], dst: &[u8], count: usize) -> Vec<F>
where
    F: Field + FromOkm<L, F>,
{
    let out_len = L * count;
    let v = expand_message(seed, dst, out_len);
    let mut result = Vec::with_capacity(count);

    for i in 0..count {
        let start_idx = L * i;
        let end_idx = (i + 1) * L;
        let r_i: &[u8; L] = &v[start_idx..end_idx].try_into().unwrap();
        let scalar = F::from_okm(r_i);
        result.push(scalar);
    }
    result
}

// for testing only
pub fn mocked_calculate_random_scalars<F: Field + FromOkm<48, F>>(count: usize) -> Vec<F> {
    // let api_id = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_".as_slice();
    let dst = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_MOCK_RANDOM_SCALARS_DST_".as_slice();
    seeded_random_scalars::<48, F>(
        hex::decode("332e313431353932363533353839373933323338343632363433333833323739")
            .unwrap()
            .as_slice(),
        &dst,
        count,
    )
}
