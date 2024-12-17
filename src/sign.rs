use ark_ec::pairing::Pairing;
use ark_ff::fields::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use elliptic_curve::ops::Mul;
use thiserror::Error;

use crate::{
    constants::Constants,
    key_gen::SecretKey,
    utils::{
        core_utilities::{calculate_domain, hash_to_scalar},
        interface_utilities::{create_generators, msg_to_scalars, HashToG1},
        utilities_helper::FromOkm,
    },
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

impl<F: Field + FromOkm<48, F>> SecretKey<F> {
    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-signature-generation-sign
    pub fn sign<E, C, H>(
        &self,
        messages: &[&[u8]],
        header: &[u8],
    ) -> Result<Signature<E, F>, SignatureError>
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

        self.core_sign::<E, C>(
            generators.as_slice(),
            header,
            message_scalars.as_slice(),
            &api_id,
        )
    }

    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-coresign
    pub(crate) fn core_sign<E, C>(
        &self,
        generators: &[E::G1],
        header: &[u8],
        messages: &[F],
        api_id: &[u8],
    ) -> Result<Signature<E, F>, SignatureError>
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
        let domain = calculate_domain::<E, F, 48>(
            public_key,
            generators[0],
            &generators[1..],
            header,
            api_id,
        );

        let hash_to_scalar_dst = [api_id, b"H2S_"].concat();

        let mut sk_compressed_bytes = Vec::new();
        self.sk
            .serialize_compressed(&mut sk_compressed_bytes)
            .unwrap();
        sk_compressed_bytes.reverse();

        let mut domain_compressed_bytes: Vec<u8> = Vec::new();
        domain
            .serialize_compressed(&mut domain_compressed_bytes)
            .unwrap();
        domain_compressed_bytes.reverse();

        let mut serialize_bytes = Vec::new();
        serialize_bytes.extend_from_slice(&sk_compressed_bytes);

        for i in 0..messages.len() {
            let mut msg_serialize_bytes = Vec::new();
            messages[i]
                .serialize_compressed(&mut msg_serialize_bytes)
                .unwrap();
            msg_serialize_bytes.reverse();
            serialize_bytes.extend_from_slice(&msg_serialize_bytes);
        }

        serialize_bytes.extend_from_slice(&domain_compressed_bytes);

        let e = hash_to_scalar(serialize_bytes.as_slice(), hash_to_scalar_dst.as_slice());

        let mut b = C::P1();

        b = b + generators[0] * domain;

        for i in 1..generators.len() {
            b = b + generators[i] * messages[i - 1];
        }

        let sk_plus_e: F = self.sk + e;
        let sk_plus_e_inverse: F = sk_plus_e.inverse().unwrap();
        let a: E::G1 = b * sk_plus_e_inverse;

        Ok(Signature { a, e })
    }
}
