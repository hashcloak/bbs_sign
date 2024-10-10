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
        self.serialize_uncompressed(&mut sk_compressed_bytes).unwrap();

        let mut domain_compressed_bytes: Vec<u8> = Vec::new();
        domain.serialize_uncompressed(&mut domain_compressed_bytes).unwrap();

        let mut serialize_bytes = Vec::new();
        serialize_bytes.extend_from_slice(&sk_compressed_bytes);

        for msg in messages {

            let mut msg_serialize_bytes = Vec::new();
            let _ = msg.serialize_uncompressed(&mut msg_serialize_bytes);
            serialize_bytes.extend_from_slice(msg_serialize_bytes.as_slice());
        }

        serialize_bytes.extend_from_slice(&domain_compressed_bytes);

        let e = hash_to_scalar(serialize_bytes.as_slice(), hash_to_scalar_dst.as_slice());

        let mut b: E::G1 = C::BP1();

        b = b + generators[0] * domain;

        for i in 1..generators.len() {
            b = b + generators[i] * messages[i - 1];
        }

        let sk_plus_e: F = self.sk + e;
        let sk_plus_e_inverse:  F = sk_plus_e.inverse().unwrap();
        let a: E::G1 = b * sk_plus_e_inverse;

        Ok(Signature { a, e })
    }
}