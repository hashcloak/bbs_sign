use ark_bn254::{ fr::Fr, g1::G1Affine as G1, G1Projective};
use ark_ff::fields::Field;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_ec::AffineRepr;

use crate::key_gen::SecretKey;
use crate::utils::core_utilities::hash_to_scalar;
use crate::utils::core_utilities::calculate_domain;
use crate::constants::P1;
use crate::constants::CIPHERSUITE_ID;
use crate::utils::interface_utilities::msg_to_scalars;
use crate::utils::interface_utilities::create_generators;

// bbs signature
#[derive(Debug, Default, CanonicalSerialize, CanonicalDeserialize, Clone, Copy)]
pub struct Signature {
    pub a: G1,
    pub e: Fr,
}

impl SecretKey {
    
    #[allow(unused_variables)]
    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-signature-generation-sign
    pub fn sign(&self, messages: &[&[u8]], header: &[u8]) -> Signature {
        
        let pk = self.sk_to_pk();
        let api_id = [CIPHERSUITE_ID, b"H2G_HM2S_"].concat();

        let message_scalars = msg_to_scalars(messages, &api_id);
        let generators = create_generators(messages.len() + 1, &api_id);

        self.core_sign(generators.as_slice(), header, message_scalars.as_slice(), &api_id)
    }

    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-coresign
    pub fn core_sign(&self, generators: &[G1], header: &[u8], messages: &[Fr], api_id: &[u8]) -> Signature {
        
        assert!(messages.len() + 1 == generators.len());

        let public_key = &self.sk_to_pk();
        let domain = calculate_domain(public_key, generators[0], &generators[1..], header, api_id);

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

        Signature { a, e }
    }
}