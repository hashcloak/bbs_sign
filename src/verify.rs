use crate::key_gen::PublicKey;
use crate::sign::Signature;
use crate::sign::calculate_domain;

use ark_bn254::{
    g1::G1Affine as G1,
    g2::G2Affine as G2,
    fr::Fr,
};
use ark_bn254::Fq12;
use ark_ec::pairing::Pairing;
use ark_bn254::Bn254;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ff::fields::Field;

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-coreverify
pub fn core_verify(pk: &PublicKey, signature: Signature, generators: &[G1], header: &[u8], messages: &[Fr], api_id: &[u8]) -> bool {
    
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

    let domain = calculate_domain(pk, generators[0], &generators[1..], header, api_id);

    let mut b = P1;
    b = (b + generators[0] * domain).into_affine();

    for i in 1..generators.len() {
        b = (b + generators[i] * messages[i - 1]).into_affine();
    }

    let res = Bn254::pairing(signature.a, pk.pk + BP2 * signature.e).0 * Bn254::pairing(b, -BP2).0;

    res == Fq12::ONE
    
}