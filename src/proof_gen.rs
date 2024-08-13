use ark_bn254::{Fr, G1Affine as G1, G1Projective};
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize};
use ark_ec::AffineRepr;
use ark_ff::Field;
use std::collections::HashSet;
use std::iter::FromIterator;
use thiserror::Error;

use crate::utils::core_utilities::{calculate_domain, hash_to_scalar, calculate_random_scalars};
use crate::utils::interface_utilities::{msg_to_scalars, create_generators};
use crate::key_gen::PublicKey;
use crate::sign::Signature;
use crate::constants::{P1, CIPHERSUITE_ID};

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, Default)]
pub struct InitProof {
    pub points: [G1;5],
    pub scalar: Fr,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, Default)]
pub struct Challenge {
    pub scalar: Fr,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, Default)]
pub struct Proof {
    
    pub a_bar: G1,
    pub b_bar: G1,
    pub d: G1,
    pub e_cap: Fr,
    pub r1_cap: Fr,
    pub r3_cap: Fr,
    pub commitments: Vec<Fr>,
    pub challenge: Challenge,
}

#[derive(Debug, Error)]
pub enum ProofGenError {
    #[error("Invalid disclosed indices length: The disclosed indexes length must less or equal to the messages length.")]
    InvalidDisclosedIndicesLength,
    #[error("Invalid disclosed index: The disclosed index cannot be greater than the messages length.")]
    InvalidDisclosedIndex,
    #[error("Invalid Message and Generators length: expected generators length to be messages length + 1.")]
    InvalidMessageAndGeneratorsLength,
    #[error("Invalid Scalars and undisclosed indices length: scalar length must be equal to undisclosed indices length + 5.")]
    InvalidRandomScalarsAndUndisclosedIndicesLength,
    #[error("Invalid undisclosed index: The undisclosed index cannot be greater than the messages length.")]
    InvalidUndisclosedIndicesLength,
    #[error("Invalid indices and messages length: The (un)disclosed indices lenth and the (un)disclosed messages length must be equal.")]
    InvalidIndicesAndMessagesLength,
    
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-proof-generation-proofgen
pub fn proof_gen(pk: PublicKey, signature: Signature, header: &[u8], ph: &[u8], messages: &[&[u8]], disclosed_indexes: &[usize]) -> Result<Proof, ProofGenError> {

    let api_id = [CIPHERSUITE_ID, b"H2G_HM2S_"].concat();
    let message_scalars = msg_to_scalars(messages, &api_id);
    let generators = create_generators(messages.len() + 1, &api_id);

    core_proof_gen(pk, signature, header, &generators, ph, &message_scalars, disclosed_indexes, &api_id)
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-coreproofgen
pub(crate) fn core_proof_gen(pk: PublicKey, signature: Signature, header: &[u8], generators: &[G1], ph: &[u8], messages: &[Fr], disclosed_indexes: &[usize], api_id: &[u8]) -> Result<Proof, ProofGenError> {

    let l = messages.len();
    let r = disclosed_indexes.len();
    if r > l {
        return Err(ProofGenError::InvalidDisclosedIndicesLength);
    }

    for &index in disclosed_indexes.iter() {
        if index >= l {
            return Err(ProofGenError::InvalidDisclosedIndex);
        }
    }

    let random_scalars = calculate_random_scalars(5 + l - r);

    let full_indexes: HashSet<usize> = HashSet::from_iter(0..l);
    let disclosed_set: HashSet<usize> = HashSet::from_iter(disclosed_indexes.iter().cloned());

    let mut disclosed_indexes: Vec<usize> = disclosed_set.clone().into_iter().collect();
    disclosed_indexes.sort();

    let undisclosed_set: HashSet<usize> = full_indexes.difference(&disclosed_set).cloned().collect();

    let mut undisclosed_indexes: Vec<usize> = undisclosed_set.into_iter().collect();
    undisclosed_indexes.sort();

    let init_res = proof_init(
        pk,
        signature,
        generators,
        random_scalars.as_slice(),
        header,
        messages,
        undisclosed_indexes.as_slice(),
        api_id
    );

    if init_res.is_err() {
        return Err(init_res.unwrap_err());
    }
    let init_res = init_res.unwrap();

    let disclosed_messages: Vec<Fr> = disclosed_indexes
    .iter()
    .filter_map(|&i| messages.get(i).cloned())
    .collect();


    let undisclosed_messages: Vec<Fr> = undisclosed_indexes
    .iter()
    .filter_map(|&i| messages.get(i).cloned())
    .collect();

    let challenge = proof_challenge_calculate(&init_res, disclosed_messages.as_slice(), disclosed_indexes.as_slice(), ph, api_id);

    if challenge.is_err() {
        return Err(challenge.unwrap_err());
    }
    let challenge = challenge.unwrap();
    proof_finalize(&init_res, &challenge, signature.e, &random_scalars, undisclosed_messages.as_slice())
    
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-proof-initialization
pub(crate) fn proof_init(pk: PublicKey, signature: Signature, generators: &[G1], random_scalars: &[Fr], header: &[u8], messages: &[Fr], undisclosed_indexes: &[usize], api_id: &[u8]) -> Result<InitProof, ProofGenError> {

    if messages.len() + 1 != generators.len() {
        return Err(ProofGenError::InvalidMessageAndGeneratorsLength);
    }

    if random_scalars.len() != undisclosed_indexes.len() + 5 {
        return Err(ProofGenError::InvalidRandomScalarsAndUndisclosedIndicesLength);
    }

    if undisclosed_indexes.len() > messages.len() {
        return Err(ProofGenError::InvalidUndisclosedIndicesLength);
    }

    let domain = calculate_domain(&pk, generators[0], &generators[1..], header, api_id);

    let mut b: G1Projective = P1.into_group() + generators[0] * domain;

    for i in 0..messages.len() {
        b = b + (generators[i+1] * messages[i]);
    }
    let d = b * random_scalars[1];
    let a_bar = signature.a * (random_scalars[0] * random_scalars[1]);
    let b_bar = d * random_scalars[0] - a_bar * signature.e;
    let t1 = a_bar * random_scalars[2] + d * random_scalars[3];
    let mut t2 = d * random_scalars[4];

    let msg_generators = generators[1..].to_vec();
    for i in 5..random_scalars.len() {
        t2 = t2 + msg_generators[undisclosed_indexes[i - 5]] * random_scalars[i];
    }

    Ok(InitProof{
        points: [a_bar.into(), b_bar.into(), d.into(), t1.into(), t2.into()],
        scalar: domain,
    })   
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-challenge-calculation
pub(crate) fn proof_challenge_calculate(init_res: &InitProof, disclosed_messages: &[Fr], disclosed_indexes: &[usize], ph: &[u8], api_id: &[u8]) -> Result<Challenge, ProofGenError> {
    
    if disclosed_messages.len() != disclosed_indexes.len() {
        return Err(ProofGenError::InvalidIndicesAndMessagesLength);
    }

    let hash_to_scalar_dst = [api_id, b"H2S_"].concat();

    let mut serialize_bytes = Vec::new();
    
    serialize_bytes.extend_from_slice(&disclosed_indexes.len().to_be_bytes());

    for i in 0..disclosed_indexes.len(){

        let mut compressed_bytes = Vec::new();
        disclosed_messages[i].serialize_compressed(&mut compressed_bytes).unwrap();

        serialize_bytes.extend_from_slice(&disclosed_indexes[i].to_be_bytes());
        serialize_bytes.extend_from_slice(&compressed_bytes);
    }

    for points in init_res.points.iter() {
        
        let mut compressed_bytes = Vec::new();
        points.serialize_compressed(&mut compressed_bytes).unwrap();

        serialize_bytes.extend_from_slice(&compressed_bytes);
    }

    let mut compressed_bytes = Vec::new();
    init_res.scalar.serialize_compressed(&mut compressed_bytes).unwrap();

    serialize_bytes.extend_from_slice(&compressed_bytes);

    serialize_bytes.extend_from_slice(&ph.len().to_be_bytes());
    serialize_bytes.extend_from_slice(&ph);

    Ok(Challenge { 
        scalar: hash_to_scalar(&serialize_bytes, &hash_to_scalar_dst) 
    })

}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-proof-finalization
pub(crate) fn proof_finalize(init_res: &InitProof, challenge: &Challenge, e_value: Fr, random_scalars: &[Fr], undisclosed_messages: &[Fr]) -> Result<Proof, ProofGenError> {

    if random_scalars.len() != undisclosed_messages.len() + 5 {
        return Err(ProofGenError::InvalidRandomScalarsAndUndisclosedIndicesLength);
    }

    let r3 = random_scalars[1].inverse().unwrap();
    let e_cap = random_scalars[2] + e_value * challenge.scalar;
    let r1_cap = random_scalars[3] - random_scalars[0] * challenge.scalar;
    let r3_cap = random_scalars[4] - r3 * challenge.scalar;
    let mut commitments = Vec::new();
    for i in 0..undisclosed_messages.len() {
        commitments.push(random_scalars[i + 5] + undisclosed_messages[i] * challenge.scalar);
    }

    Ok(Proof { 
        a_bar: init_res.points[0], 
        b_bar: init_res.points[1],
        d: init_res.points[2], 
        e_cap, 
        r1_cap, 
        r3_cap, 
        commitments, 
        challenge: challenge.clone()
    })
}