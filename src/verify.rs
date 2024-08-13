use ark_bn254::{ G1Affine as G1, Fr, G1Projective, Fq12, Bn254};
use ark_ec::{ pairing::Pairing, AffineRepr};
use ark_ff::fields::Field;

use crate::key_gen::PublicKey;
use crate::sign::{SignatureError, Signature};
use crate::utils::core_utilities::calculate_domain;
use crate::constants::{P1, BP2, CIPHERSUITE_ID};
use crate::utils::interface_utilities::msg_to_scalars;
use crate::utils::interface_utilities::create_generators;

impl PublicKey {

    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-signature-verification-veri
    pub fn verify(&self, signature: Signature, header: &[u8], messages: &[&[u8]]) -> Result<bool, SignatureError> {
        
        let api_id = [CIPHERSUITE_ID, b"H2G_HM2S_"].concat();
        let message_scalars = msg_to_scalars(messages, &api_id);
        let generators = create_generators(messages.len() + 1, &api_id);

        self.core_verify(signature, generators.as_slice(), header, &message_scalars, &api_id)
    }
    
    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-coreverify
    pub(crate) fn core_verify(&self, signature: Signature, generators: &[G1], header: &[u8], messages: &[Fr], api_id: &[u8]) -> Result<bool, SignatureError> {
        
        if messages.len() + 1 != generators.len() {
            return Err(SignatureError::InvalidMessageAndGeneratorsLength);
        }

        let domain = calculate_domain(self, generators[0], &generators[1..], header, api_id);

        let mut b: G1Projective = P1.into_group();
        b = b + generators[0] * domain;

        for i in 1..generators.len() {
            b = b + generators[i] * messages[i - 1];
        }

        Ok(Bn254::pairing(signature.a, self.pk + BP2.into_group() * signature.e).0 * Bn254::pairing(b, -BP2.into_group()).0 == Fq12::ONE)
    }
}
