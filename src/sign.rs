use ark_bn254::{ fr::Fr, g1::G1Affine as G1, G1Projective};
use ark_ff::fields::Field;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_ec::AffineRepr;
use thiserror::Error;
use elliptic_curve::ops::Mul;

use crate::key_gen::SecretKey;
use crate::utils::core_utilities::hash_to_scalar;
use crate::utils::core_utilities::calculate_domain;
use crate::constants::P1;
use crate::constants::CIPHERSUITE_ID;
use crate::utils::interface_utilities::msg_to_scalars;
use crate::utils::interface_utilities::create_generators;
use ark_ec::pairing::Pairing;
use crate::utils::utilities_helper;

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

impl < F: Field+ utilities_helper::FromOkm<48, F>>SecretKey<F> {
    
    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-signature-generation-sign
    pub fn sign<E: Pairing>(&self, messages: &[&[u8]], header: &[u8]) ->  Result<Signature<E, F>, SignatureError>  {

        let api_id = [CIPHERSUITE_ID, b"H2G_HM2S_"].concat();

        let message_scalars = msg_to_scalars::<E, F, 48>(messages, &api_id);
        let generators = create_generators(messages.len() + 1, &api_id);

        self.core_sign::<E,F>(generators.as_slice(), header, message_scalars.as_slice(), &api_id)
    }

    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-coresign
    pub(crate) fn core_sign<E: Pairing>(&self, generators: &[E::G1], header: &[u8], messages: &[F], api_id: &[u8]) -> Result<Signature<E, F>, SignatureError>  
    
    where <E as Pairing>::G2: Mul<F>, <E as Pairing>::G2: From<<<E as Pairing>::G2 as Mul<F>>::Output>
    {
        
        if messages.len() + 1 != generators.len() {
            return Err(SignatureError::InvalidMessageAndGeneratorsLength);
        }

        let public_key = &self.sk_to_pk();
        let domain = calculate_domain::<E, F, 48>(public_key, generators[0], &generators[1..], header, api_id);

        let hash_to_scalar_dst = [api_id, b"H2S_"].concat();

        let mut sk_compressed_bytes = Vec::new();
        self.serialize_compressed(&mut sk_compressed_bytes).unwrap();

        let mut domain_compressed_bytes: Vec<u8> = Vec::new();
        domain.serialize_compressed(&mut domain_compressed_bytes).unwrap();

        let mut serialize_bytes = Vec::new();
        serialize_bytes.extend_from_slice(&sk_compressed_bytes);

        for msg in messages {

            let mut msg_serialize_bytes = Vec::new();
            let _ = msg.0.serialize_compressed(&mut msg_serialize_bytes);
            serialize_bytes.extend_from_slice(msg_serialize_bytes.as_slice());
        }

        serialize_bytes.extend_from_slice(&domain_compressed_bytes);

        let e = hash_to_scalar(serialize_bytes.as_slice(), hash_to_scalar_dst.as_slice());

        let mut b: G1Projective = P1.into_group();

        b = b + generators[0] * domain;

        for i in 1..generators.len() {
            b = b + generators[i] * messages[i - 1];
        }

        let sk_plus_e_inverse = (self.sk + e).inverse().unwrap();
        let a: G1 = (b * sk_plus_e_inverse).into();

        Ok(Signature { a, e })
    }
}