use ark_bn254::{ G1Affine as G1, G2Affine as G2, Fr, G1Projective, Fq12, Bn254};
use ark_ec::{ pairing::Pairing, AffineRepr};
use ark_ff::fields::Field;

use crate::key_gen::PublicKey;
use crate::sign::Signature;
use crate::utils::core_utilities::calculate_domain;

impl PublicKey {

    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-coreverify
    pub fn core_verify(&self, signature: Signature, generators: &[G1], header: &[u8], messages: &[Fr], api_id: &[u8]) -> bool {
        
        assert!(messages.len() + 1 == generators.len());

        // TODO: Parameters:
        // - P1, fixed point of G1, defined by the ciphersuite.
        #[allow(non_snake_case)]
        let P1 = G1::generator();

        // TODO:
        // BP1, BP2
        // base (constant) points on the G1 and G2 subgroups respectively
        #[allow(non_snake_case)]
        let BP2 = G2::generator();

        let domain = calculate_domain(self, generators[0], &generators[1..], header, api_id);

        let mut b: G1Projective = P1.into();
        b = b + generators[0] * domain;

        for i in 1..generators.len() {
            b = b + generators[i] * messages[i - 1];
        }

        let res = Bn254::pairing(signature.a, self.pk + BP2 * signature.e).0 * Bn254::pairing(b, -BP2).0;

        res == Fq12::ONE
        
    }
}
