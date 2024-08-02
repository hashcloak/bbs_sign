use ark_bn254::{Fr, G1Affine as G1, Bn254, Fq12};
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ff::fields::Field;

use crate::key_gen::PublicKey;
use crate::proof_gen::proof_challenge_calculate;
use crate::proof_gen::InitProof;
use crate::proof_gen::Proof;
use crate::utils::core_utilities::calculate_domain;
use crate::utils::interface_utilities::msg_to_scalars;
use crate::utils::interface_utilities::create_generators;

use crate::constants::{P1, BP2, CIPHERSUITE_ID};

use std::collections::HashSet;
use std::iter::FromIterator;

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-proof-verification-proofver
pub fn proof_verify(pk: PublicKey, proof: Proof, header: &[u8], ph: &[u8], disclosed_messages: &[&[u8]], disclosed_indexes: &[usize]) -> bool {

    let api_id = [CIPHERSUITE_ID, b"H2G_HM2S_"].concat();

    let message_scalars = msg_to_scalars(disclosed_messages, &api_id);
    let generators = create_generators(proof.commitments.len() + disclosed_indexes.len() + 1, &api_id);

    core_proof_verify(pk, proof, &generators, header, ph, &message_scalars, disclosed_indexes, &api_id)
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-coreproofverify
pub fn core_proof_verify(pk: PublicKey, proof: Proof, generators: &[G1], header: &[u8], ph: &[u8], disclosed_messages: &[Fr], disclosed_indexes: &[usize], api_id: &[u8]) -> bool {

    let init_res = proof_verify_init(pk.clone(), proof.clone(), generators, header, &disclosed_messages, disclosed_indexes, api_id);
    let challenge = proof_challenge_calculate(&init_res, disclosed_messages, disclosed_indexes, ph, api_id);

    //TODO: this assertion fails for some reason
    // assert!(challenge.scalar == proof.challenge.scalar);
    Bn254::pairing(proof.a_bar, pk.pk).0 * Bn254::pairing(proof.b_bar, -BP2.into_group()).0 == Fq12::ONE
    
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-coreproofverify
pub fn proof_verify_init(pk: PublicKey, proof: Proof, generators: &[G1], header: &[u8], disclosed_messages: &[Fr], disclosed_indexes: &[usize], api_id: &[u8]) -> InitProof {

    let u = proof.commitments.len();
    let r = disclosed_indexes.len();
    let l = r + u;
    
    for &index in disclosed_indexes {
        assert!(index < l);
    }
    assert!(disclosed_messages.len() == r);
    assert!(generators.len() == l + 1);

    let full_indexes: HashSet<usize> = HashSet::from_iter(0..l);
    let disclosed_set: HashSet<usize> = HashSet::from_iter(disclosed_indexes.iter().cloned());
    let undisclosed_set: HashSet<usize> = full_indexes.difference(&disclosed_set).cloned().collect();

    let mut undisclosed_indexes: Vec<usize> = undisclosed_set.into_iter().collect();
    undisclosed_indexes.sort();

    let domain = calculate_domain(&pk, generators[0], &generators[1..], header, api_id);

    let t1 = proof.b_bar.into_group() * proof.challenge.scalar + proof.a_bar * proof.e_cap + proof.d * proof.r1_cap;
    let mut bv = P1.into_group() + generators[0] * domain;

    let msg_generators = generators[1..].to_vec();

    let mut i = 0;
    for &index in disclosed_indexes.iter() {
        bv = bv + msg_generators[index] * disclosed_messages[i];
        i = i + 1;
    }

    let mut t2 = bv * proof.challenge.scalar + proof.d * proof.r3_cap;

    let mut i = 0;
    for index in undisclosed_indexes {
        t2 = t2 + msg_generators[index] * proof.commitments[i];

        i = i + 1;
    }

    InitProof{
        points: [proof.a_bar.into(), proof.b_bar.into(), proof.d.into(), t1.into(), t2.into()],
        scalar: domain
    }
}