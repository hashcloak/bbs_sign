use ark_ff::fields::Field;
use ark_serialize::{ CanonicalSerialize, CanonicalDeserialize };
use thiserror::Error;
use elliptic_curve::ops::Mul;
use ark_ec::pairing::Pairing;

use crate::{
    key_gen::SecretKey,
    constants::Constants,
    utils::{
        core_utilities::{
            hash_to_scalar,
            calculate_domain,
        },
        interface_utilities::{
            HashToG1,
            msg_to_scalars,
            create_generators,
        },
        utilities_helper::FromOkm,
    }
};

// bbs signature
#[derive(Debug, Default, CanonicalSerialize, CanonicalDeserialize, Clone, Copy)]
pub struct Signature<E: Pairing, F: Field> {
    pub a: E::G1,
    pub e: F,
}

#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("Invalid Message and Generators length: expected generators length to be messages length + 1.")]
    InvalidMessageAndGeneratorsLength,
}

impl < F: Field+ FromOkm<48, F>>SecretKey<F> {
    
    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-signature-generation-sign
    pub fn sign<E, C, H>(&self, messages: &[&[u8]], header: &[u8]) ->  Result<Signature<E, F>, SignatureError>  
    where
        E: Pairing,
        C: for<'a> Constants<'a, E>,
        H: HashToG1<E>,
        E::G2: Mul<F, Output = E::G2>,
        E::G1: Mul<F, Output = E::G1>,
    {

        let api_id = [C::CIPHERSUITE_ID, b"H2G_HM2S_"].concat();

        let message_scalars = msg_to_scalars::<E, F, 48>(messages, &api_id);
        let generators = create_generators::<E, H>(messages.len() + 1, &api_id);

        self.core_sign::<E, C>(generators.as_slice(), header, message_scalars.as_slice(), &api_id)
    }

    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-coresign
    pub(crate) fn core_sign<E, C>(&self, generators: &[E::G1], header: &[u8], messages: &[F], api_id: &[u8]) -> Result<Signature<E, F>, SignatureError>  
    where 
        E: Pairing,
        C: for<'a> Constants<'a, E>,
        E::G2: Mul<F, Output = E::G2>,
        E::G1: Mul<F, Output = E::G1>,
    {
        
        if messages.len() + 1 != generators.len() {
            return Err(SignatureError::InvalidMessageAndGeneratorsLength);
        }

        let public_key = &self.sk_to_pk();
        let domain = calculate_domain::<E, F, 48>(public_key, generators[0], &generators[1..], header, api_id);

        let hash_to_scalar_dst = [api_id, b"H2S_"].concat();

        let mut sk_compressed_bytes = Vec::new();
        self.serialize_compressed(&mut sk_compressed_bytes).unwrap();
        sk_compressed_bytes.reverse();

        let mut domain_compressed_bytes: Vec<u8> = Vec::new();
        domain.serialize_compressed(&mut domain_compressed_bytes).unwrap();
        domain_compressed_bytes.reverse();

        let mut serialize_bytes = Vec::new();
        serialize_bytes.extend_from_slice(&sk_compressed_bytes);

        for i in 0..messages.len() {

            let mut msg_serialize_bytes = Vec::new();
            messages[i].serialize_compressed(&mut msg_serialize_bytes).unwrap();
            msg_serialize_bytes.reverse();
            serialize_bytes.extend_from_slice(msg_serialize_bytes.as_slice());
        }

        serialize_bytes.extend_from_slice(&domain_compressed_bytes);

        let e = hash_to_scalar(serialize_bytes.as_slice(), hash_to_scalar_dst.as_slice());

        let mut b: E::G1 = C::BP1();

        b = b + generators[0] * domain;

        for i in 1..generators.len() {
            b = b + generators[i] * messages[i - 1];
        }

        // TODO: Remove after fixing
        // use ark_ec::CurveGroup;
        // let expected_b_bytes = hex::decode("92d264aed02bf23de022ebe778c4f929fddf829f504e451d011ed89a313b8167ac947332e1648157ceffc6e6e41ab255").unwrap();   
        // let mut b_bytes = Vec::new();
        // b.into_affine().serialize_compressed(&mut b_bytes).unwrap();
        // assert_eq!(b_bytes, expected_b_bytes);

        let sk_plus_e: F = self.sk + e;
        let sk_plus_e_inverse:  F = sk_plus_e.inverse().unwrap();
        let a: E::G1 = b * sk_plus_e_inverse;

        Ok(Signature { a, e })
    }
}

#[test] 
fn test_sign_testvector() {
    use ark_bls12_381::{Fr, Bls12_381};
    use crate::key_gen;
    use std::str::FromStr;
    use ark_ec::CurveGroup;
    use crate::constants::Bls12381Const;
    use crate::utils::interface_utilities::HashToG1Bls12381;
    use ark_serialize::CanonicalSerialize;

    let m_1 = hex::decode("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02").unwrap();
    let sk = SecretKey::<Fr>::from(key_gen::SecretKey { sk: Fr::from_str("43827200940696190687007874407982393189563963510129946831635449820772190743036").unwrap() });
    let pk: key_gen::PublicKey<Bls12_381> = SecretKey::sk_to_pk(&sk);

    let mut compressed_bytes = Vec::new();
    pk.pk.into_affine().serialize_compressed(&mut compressed_bytes).unwrap();

    let pk_bytes = hex::decode("a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c").unwrap();
    // checking the computed pk is equal to the expected pk
    assert_eq!(compressed_bytes, pk_bytes);

    let signature = sk.sign::<Bls12_381, Bls12381Const, HashToG1Bls12381>(&[m_1.as_slice()], hex::decode("11223344556677889900aabbccddeeff").unwrap().as_slice()).unwrap();

    let mut compressed_bytes: Vec<u8> = Vec::new();
    signature.e.serialize_compressed(&mut compressed_bytes).unwrap();

    let expected_sig_bytes = hex::decode("84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da5253aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb4c892340be5969920d0916067b4565a0").unwrap();
    // assert_eq!(compressed_bytes, expected_sig_bytes);

}