use ark_ec::pairing::Pairing;
use ark_ff::fields::Field;
use elliptic_curve::ops::Mul;
use std::{collections::HashSet, iter::FromIterator};

use crate::{
    constants::Constants,
    key_gen::PublicKey,
    proof_gen::{proof_challenge_calculate, InitProof, Proof, ProofGenError},
    utils::{
        core_utilities::calculate_domain,
        interface_utilities::{create_generators, msg_to_scalars, HashToG1},
        utilities_helper::FromOkm,
    },
};

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-proof-verification-proofver
// disclosed_messages and disclosed_indexes should be in same(increasing) order otherwise the proof will fail
pub fn proof_verify<E, F, H, C>(
    pk: PublicKey<E>,
    proof: Proof<E, F>,
    header: &[u8],
    ph: &[u8],
    disclosed_messages: &[&[u8]],
    disclosed_indexes: &[usize],
) -> Result<bool, ProofGenError>
where
    E: Pairing,
    F: Field + FromOkm<48, F>,
    C: for<'a> Constants<'a, E>,
    H: HashToG1<E>,
    E::G2: Mul<F, Output = E::G2>,
    E::G1: Mul<F, Output = E::G1>,
{
    let api_id = [C::CIPHERSUITE_ID, b"H2G_HM2S_"].concat();

    let message_scalars = msg_to_scalars::<E, F, 48>(disclosed_messages, &api_id);
    let generators = create_generators::<E, H>(
        proof.commitments.len() + disclosed_indexes.len() + 1,
        &api_id,
    );

    core_proof_verify::<E, F, C>(
        pk,
        proof,
        &generators,
        header,
        ph,
        &message_scalars,
        disclosed_indexes,
        &api_id,
    )
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-coreproofverify
pub(crate) fn core_proof_verify<E, F, C>(
    pk: PublicKey<E>,
    proof: Proof<E, F>,
    generators: &[E::G1],
    header: &[u8],
    ph: &[u8],
    disclosed_messages: &[F],
    disclosed_indexes: &[usize],
    api_id: &[u8],
) -> Result<bool, ProofGenError>
where
    E: Pairing,
    F: Field + FromOkm<48, F>,
    C: for<'a> Constants<'a, E>,
    E::G2: Mul<F, Output = E::G2>,
    E::G1: Mul<F, Output = E::G1>,
{
    let init_res = proof_verify_init::<E, F, C>(
        pk.clone(),
        proof.clone(),
        generators,
        header,
        &disclosed_messages,
        disclosed_indexes,
        api_id,
    );

    if init_res.is_err() {
        return Err(init_res.unwrap_err());
    }

    let challenge = proof_challenge_calculate(
        &init_res.unwrap(),
        disclosed_messages,
        disclosed_indexes,
        ph,
        api_id,
    );

    if challenge.is_err() {
        return Err(challenge.unwrap_err());
    }
    let challenge = challenge.unwrap();

    if challenge.scalar != proof.challenge.scalar {
        return Ok(false);
    }

    Ok(
        E::pairing(proof.a_bar, pk.pk).0 * E::pairing(proof.b_bar, -C::BP2()).0
            == E::TargetField::ONE,
    )
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-coreproofverify
pub(crate) fn proof_verify_init<E, F, C>(
    pk: PublicKey<E>,
    proof: Proof<E, F>,
    generators: &[E::G1],
    header: &[u8],
    disclosed_messages: &[F],
    disclosed_indexes: &[usize],
    api_id: &[u8],
) -> Result<InitProof<E, F>, ProofGenError>
where
    E: Pairing,
    F: Field + FromOkm<48, F>,
    C: for<'a> Constants<'a, E>,
    E::G2: Mul<F, Output = E::G2>,
    E::G1: Mul<F, Output = E::G1>,
{
    let u = proof.commitments.len();
    let r = disclosed_indexes.len();
    let l = r + u;

    for &index in disclosed_indexes {
        if index >= l {
            return Err(ProofGenError::InvalidDisclosedIndex);
        }
    }
    if disclosed_messages.len() != r {
        return Err(ProofGenError::InvalidIndicesAndMessagesLength);
    }

    if generators.len() != l + 1 {
        return Err(ProofGenError::InvalidMessageAndGeneratorsLength);
    }

    let full_indexes: HashSet<usize> = HashSet::from_iter(0..l);
    let disclosed_set: HashSet<usize> = HashSet::from_iter(disclosed_indexes.iter().cloned());
    let undisclosed_set: HashSet<usize> =
        full_indexes.difference(&disclosed_set).cloned().collect();

    let mut undisclosed_indexes: Vec<usize> = undisclosed_set.into_iter().collect();
    undisclosed_indexes.sort();

    let domain = calculate_domain::<E, F, 48>(&pk, generators[0], &generators[1..], header, api_id);

    let t1 =
        proof.b_bar * proof.challenge.scalar + proof.a_bar * proof.e_cap + proof.d * proof.r1_cap;
    let mut bv = C::P1() + generators[0] * domain;

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

    Ok(InitProof {
        points: [proof.a_bar, proof.b_bar, proof.d, t1, t2],
        scalar: domain,
    })
}
