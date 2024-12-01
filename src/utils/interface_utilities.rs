use ark_ff::{Field, PrimeField};
use bn254_hash2curve::hash2g1::HashToG1;
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::Projective
};
use ark_bls12_381::{
    g1::Config as BlsConfig, Fq, G1Affine as G1Bls12_381
};
use ark_bn254::g1::Config as BnConfig;
use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve}, G1Affine, G1Projective
};
use sha2::Sha256;

use crate::utils::{
    utilities_helper::{expand_message, FromOkm},
    core_utilities::hash_to_scalar
};

pub trait HashToG1<E: Pairing> {
    fn hash_to_g1(msg: &[u8], dst: &[u8]) -> E::G1;
}

pub struct HashToG1Bn254;
pub struct HashToG1Bls12381;

impl <E: Pairing<G1 = Projective<BnConfig>>>HashToG1<E> for HashToG1Bn254 {

    fn hash_to_g1(message: &[u8], dst: &[u8]) -> E::G1 {
        HashToG1(message, dst).into()
    }
}

impl <E: Pairing<G1 = Projective<BlsConfig>>>HashToG1<E> for HashToG1Bls12381 {

    fn hash_to_g1(message: &[u8], dst: &[u8]) -> E::G1 {

        // https://github.com/zkcrypto/bls12_381/blob/main/tests/hash_to_curve_g1.rs#L158
        let g = <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve([message],dst,);
        
        let aff = G1Affine::from(g);
        let g_uncompressed = aff.to_uncompressed();

        G1Bls12_381::new(Fq::from_be_bytes_mod_order(&g_uncompressed[0..48]), Fq::from_be_bytes_mod_order(&g_uncompressed[48..])).into()
    }
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#section-4.1.1
pub fn create_generators<E, H>(count: usize, api_id: &[u8]) -> Vec<E::G1> 
where 
    E: Pairing,
    H: HashToG1<E>
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
        msg.extend_from_slice(&(i+1).to_be_bytes());

        v = expand_message(&msg, seed_dst.as_slice(), 48);

        generators.push(H::hash_to_g1(v.as_slice(), generator_dst.as_slice()));
    }

    generators
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-messages-to-scalars
pub fn msg_to_scalars<E, F, const L: usize>(messages: &[&[u8]] , api_id: &[u8]) -> Vec<F> 
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

#[test]
fn test_msg_to_scalars_testvector() {
    use ark_bls12_381::Fr;
    use ark_serialize::CanonicalSerialize;

    let dst = hex::decode("4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f4d41505f4d53475f544f5f5343414c41525f41535f484153485f").unwrap();
    let msg = hex::decode("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02").unwrap();
    let msg_scalar: Fr = hash_to_scalar::<48, Fr>(&msg, &dst);

    let mut msg_scalar_bytes = Vec::new();
    msg_scalar.serialize_compressed(&mut msg_scalar_bytes).unwrap();

    // probably the arkworks serealization is reversed
    msg_scalar_bytes.reverse();

    let expected_msg_scalar_bytes = hex::decode("1cb5bb86114b34dc438a911617655a1db595abafac92f47c5001799cf624b430").unwrap();

    assert_eq!(msg_scalar_bytes, expected_msg_scalar_bytes);

    let m_10 = hex::decode("").unwrap();
    let m_10_scalar: Fr = hash_to_scalar::<48, Fr>(&m_10, &dst);
    let mut m_10_scalar_bytes = Vec::new();
    m_10_scalar.serialize_compressed(&mut m_10_scalar_bytes).unwrap();
    m_10_scalar_bytes.reverse();
    let expected_m10_bytes = hex::decode("08e3afeb2b4f2b5f907924ef42856616e6f2d5f1fb373736db1cca32707a7d16").unwrap();
    assert_eq!(m_10_scalar_bytes, expected_m10_bytes);

}

#[test]
fn test_create_generators_testvector() {
    use ark_bls12_381::Bls12_381;
    use ark_serialize::CanonicalSerialize;
    use ark_ec::CurveGroup;

    let generators = create_generators::<Bls12_381, HashToG1Bls12381>(11, b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_");

    let generator_0 = generators[0];

    let mut generator_0_bytes = Vec::new();
    generator_0.into_affine().serialize_compressed(&mut generator_0_bytes).unwrap();

    let expected_generator0_bytes = hex::decode("a9ec65b70a7fbe40c874c9eb041c2cb0a7af36ccec1bea48fa2ba4c2eb67ef7f9ecb17ed27d38d27cdeddff44c8137be").unwrap();
    assert_eq!(expected_generator0_bytes, generator_0_bytes);

    let generator_1 = generators[1];

    let mut generator_1_bytes = Vec::new();
    generator_1.into_affine().serialize_compressed(&mut generator_1_bytes).unwrap();

    let expected_generator1_bytes = hex::decode("98cd5313283aaf5db1b3ba8611fe6070d19e605de4078c38df36019fbaad0bd28dd090fd24ed27f7f4d22d5ff5dea7d4").unwrap();
    assert_eq!(expected_generator1_bytes, generator_1_bytes);

    let generator_2 = generators[2];

    let mut generator_2_bytes = Vec::new();
    generator_2.into_affine().serialize_compressed(&mut generator_2_bytes).unwrap();

    let expected_generator2_bytes = hex::decode("a31fbe20c5c135bcaa8d9fc4e4ac665cc6db0226f35e737507e803044093f37697a9d452490a970eea6f9ad6c3dcaa3a").unwrap();
    assert_eq!(expected_generator2_bytes, generator_2_bytes);

    let generator_10 = generators[10];

    let mut generator_10_bytes = Vec::new();
    generator_10.into_affine().serialize_compressed(&mut generator_10_bytes).unwrap();

    let expected_generator10_bytes = hex::decode("a1f229540474f4d6f1134761b92b788128c7ac8dc9b0c52d59493132679673032ac7db3fb3d79b46b13c1c41ee495bca").unwrap();
    assert_eq!(expected_generator10_bytes, generator_10_bytes);

}

#[test]
fn test_msg_to_scalar_testvector() {
    use ark_serialize::CanonicalSerialize;
    use ark_bls12_381::Bls12_381;
    
    let msg = hex::decode("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02").unwrap();
    let api_id = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_";
    let scalar = msg_to_scalars::<Bls12_381, ark_bls12_381::Fr, 48>(&[&msg], &api_id.as_slice());

    let mut compressed_bytes: Vec<u8> = Vec::new();
    scalar[0].serialize_uncompressed(&mut compressed_bytes).unwrap();

    let expected_scalar_bytes = hex::decode("1cb5bb86114b34dc438a911617655a1db595abafac92f47c5001799cf624b430").unwrap();

    // probably the arkworks serealization is reversed
    compressed_bytes.reverse();
    assert_eq!(compressed_bytes, expected_scalar_bytes);
    
}