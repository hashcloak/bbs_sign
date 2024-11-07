use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_serialize::CanonicalSerialize;

use crate::{
    utils::utilities_helper::{ expand_message, FromOkm},
    key_gen::PublicKey
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
pub fn calculate_domain<E, F, const L: usize> (pk: &PublicKey<E>, q_1: E::G1, h_points: &[E::G1], header: &[u8], api_id: &[u8]) -> F 
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
    F: Field + FromOkm<L, F>
{
    let mut result = Vec::with_capacity(count);

    for _ in 0..count {
        let data: &[u8; L] = &get_random(L)[..].try_into().unwrap();
        result.push(F::from_okm(data));
    }
    result
}


#[test]
fn test_hash_to_scalar_testvector() {
    let msg = hex::decode("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02").unwrap();
    let dst = hex::decode("4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f4832535f").unwrap();

    let scalar = hash_to_scalar::<48, ark_bls12_381::Fr>(&msg, &dst);

    let mut compressed_bytes: Vec<u8> = Vec::new();
    scalar.serialize_uncompressed(&mut compressed_bytes).unwrap();

    let expected_scalar_bytes = hex::decode("0f90cbee27beb214e6545becb8404640d3612da5d6758dffeccd77ed7169807c").unwrap();

    // probably the arkworks serealization is reversed
    compressed_bytes.reverse();
    assert_eq!(compressed_bytes, expected_scalar_bytes);
    
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-signature-fixtures-2
#[test]
fn test_calculate_domain_testvector() {
    use ark_bls12_381::{Fr, Bls12_381};
    use crate::key_gen;
    use crate::utils::interface_utilities::HashToG1Bls12381;
    use std::str::FromStr;
    use crate::key_gen::SecretKey;
    use crate::utils::interface_utilities::create_generators;

    let sk = SecretKey::<Fr>::from(key_gen::SecretKey { sk: Fr::from_str("43827200940696190687007874407982393189563963510129946831635449820772190743036").unwrap() });
    let pk: key_gen::PublicKey<Bls12_381> = SecretKey::sk_to_pk(&sk);

    let binding = hex::decode("11223344556677889900aabbccddeeff").unwrap();
    let header = binding.as_slice();

    let api_id = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_";
    let generators = create_generators::<Bls12_381, HashToG1Bls12381>(2, &api_id.as_slice());

    let domain: Fr = calculate_domain::<Bls12_381, Fr, 48>(&pk, generators[0], &generators[1..], header, api_id);

    let expected_domain_bytes = hex::decode("25d57fab92a8274c68fde5c3f16d4b275e4a156f211ae34b3ab32fbaf506ed5c").unwrap();
    let mut compressed_bytes: Vec<u8> = Vec::new();
    domain.serialize_uncompressed(&mut compressed_bytes).unwrap();
    compressed_bytes.reverse();
    assert_eq!(compressed_bytes, expected_domain_bytes);
}