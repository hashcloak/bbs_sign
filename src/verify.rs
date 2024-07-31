use ark_bn254::{ G1Affine as G1, Fr, G1Projective, Fq12, Bn254};
use ark_ec::{ pairing::Pairing, AffineRepr};
use ark_ff::fields::Field;

use crate::key_gen::PublicKey;
use crate::sign::Signature;
use crate::utils::core_utilities::calculate_domain;
use crate::constants::{P1, BP2};

impl PublicKey {

    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-coreverify
    pub fn core_verify(&self, signature: Signature, generators: &[G1], header: &[u8], messages: &[Fr], api_id: &[u8]) -> bool {
        
        assert!(messages.len() + 1 == generators.len());

        let domain = calculate_domain(self, generators[0], &generators[1..], header, api_id);

        let mut b: G1Projective = P1.into_group();
        b = b + generators[0] * domain;

        for i in 1..generators.len() {
            b = b + generators[i] * messages[i - 1];
        }

        Bn254::pairing(signature.a, self.pk + BP2.into_group() * signature.e).0 * Bn254::pairing(b, -BP2.into_group()).0 == Fq12::ONE
    }
}
