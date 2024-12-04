use ark_ec::pairing::Pairing;
use ark_serialize::{ CanonicalSerialize, CanonicalDeserialize };
use ark_ff::Field;
use std::{
    collections::HashSet,
    iter::FromIterator
};
use thiserror::Error;
use elliptic_curve::ops::Mul;

#[allow(unused_imports)]
use crate::utils::{
    core_utilities::{
        calculate_domain, 
        hash_to_scalar, 
        calculate_random_scalars,
        mocked_calculate_random_scalars,
    },
    interface_utilities::{
        HashToG1,
        msg_to_scalars,
        create_generators,
    },
    utilities_helper::FromOkm,
};
use crate::{
    key_gen::PublicKey,
    sign::Signature,
    constants::Constants,
};

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, Default)]
pub struct InitProof<E: Pairing, F: Field> {
    pub points: [E::G1;5],
    pub scalar: F,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, Default)]
pub struct Challenge<F: Field> {
    pub scalar: F,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<E: Pairing, F: Field> {
    
    pub a_bar: E::G1,
    pub b_bar: E::G1,
    pub d: E::G1,
    pub e_cap: F,
    pub r1_cap: F,
    pub r3_cap: F,
    pub commitments: Vec<F>,
    pub challenge: Challenge<F>,
}

impl<E: Pairing, F: Field> Default for Proof<E, F>
where
    E::G1: Default,
    F: Default,
{
    fn default() -> Self {
        Proof {
            a_bar: E::G1::default(),
            b_bar: E::G1::default(),
            d: E::G1::default(),
            e_cap: F::default(),
            r1_cap: F::default(),
            r3_cap: F::default(),
            commitments: Vec::new(),
            challenge: Challenge::default()
        }
    }
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
pub fn proof_gen<E, F, H, C>(pk: PublicKey<E>, signature: Signature<E,F>, header: &[u8], ph: &[u8], messages: &[&[u8]], disclosed_indexes: &[usize]) -> Result<Proof<E, F>, ProofGenError> 
where
    E: Pairing,
    F: Field+ FromOkm<48, F>,
    H: HashToG1<E>,
    C: for<'a> Constants<'a, E>,
    E::G2: Mul<F, Output = E::G2>,
    E::G1: Mul<F, Output = E::G1>,

{

    let api_id = [C::CIPHERSUITE_ID, b"H2G_HM2S_"].concat();
    let message_scalars = msg_to_scalars::<E, F, 48>(messages, &api_id);
    let generators = create_generators::<E, H>(messages.len() + 1, &api_id);

    core_proof_gen::<E, F, C>(pk, signature, header, &generators, ph, &message_scalars, disclosed_indexes, &api_id)
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-coreproofgen
pub(crate) fn core_proof_gen<E, F, C>(pk: PublicKey<E>, signature: Signature<E, F>, header: &[u8], generators: &[E::G1], ph: &[u8], messages: &[F], disclosed_indexes: &[usize], api_id: &[u8]) -> Result<Proof<E, F>, ProofGenError> 

where
    E: Pairing,
    F: Field+ FromOkm<48, F>,
    C: for<'a> Constants<'a, E>,
    E::G2: Mul<F, Output = E::G2>,
    E::G1: Mul<F, Output = E::G1>,

{

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

    let random_scalars = calculate_random_scalars::<48, F>(5 + l - r);

    #[cfg(testvector_bls12_381)]
    let random_scalars = mocked_calculate_random_scalars::<F>(5 + l - r);

    let full_indexes: HashSet<usize> = HashSet::from_iter(0..l);
    let disclosed_set: HashSet<usize> = HashSet::from_iter(disclosed_indexes.iter().cloned());

    let mut disclosed_indexes: Vec<usize> = disclosed_set.clone().into_iter().collect();
    disclosed_indexes.sort();

    let undisclosed_set: HashSet<usize> = full_indexes.difference(&disclosed_set).cloned().collect();

    let mut undisclosed_indexes: Vec<usize> = undisclosed_set.into_iter().collect();
    undisclosed_indexes.sort();

    let init_res = proof_init::<E, F, C>(
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

    let disclosed_messages: Vec<F> = disclosed_indexes
    .iter()
    .filter_map(|&i| messages.get(i).cloned())
    .collect();


    let undisclosed_messages: Vec<F> = undisclosed_indexes
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
pub(crate) fn proof_init<E, F, C>(pk: PublicKey<E>, signature: Signature<E, F>, generators: &[E::G1], random_scalars: &[F], header: &[u8], messages: &[F], undisclosed_indexes: &[usize], api_id: &[u8]) -> Result<InitProof<E, F>, ProofGenError> 
where
    E: Pairing,
    F: Field + FromOkm<48, F>,
    C: for<'a> Constants<'a, E>,
    E::G2: Mul<F, Output = E::G2>,
    E::G1: Mul<F, Output = E::G1>,
{

    if messages.len() + 1 != generators.len() {
        return Err(ProofGenError::InvalidMessageAndGeneratorsLength);
    }

    if random_scalars.len() != undisclosed_indexes.len() + 5 {
        return Err(ProofGenError::InvalidRandomScalarsAndUndisclosedIndicesLength);
    }

    if undisclosed_indexes.len() > messages.len() {
        return Err(ProofGenError::InvalidUndisclosedIndicesLength);
    }

    let domain = calculate_domain::<E, F, 48>(&pk, generators[0], &generators[1..], header, api_id);

    let mut b: E::G1 = C::P1() + generators[0] * domain;

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
        points: [a_bar, b_bar, d, t1, t2],
        scalar: domain,
    })   
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-challenge-calculation
pub(crate) fn proof_challenge_calculate<E,F>(init_res: &InitProof<E, F>, disclosed_messages: &[F], disclosed_indexes: &[usize], ph: &[u8], api_id: &[u8]) -> Result<Challenge<F>, ProofGenError> 
where 
    E: Pairing,
    F: Field + FromOkm<48, F>,
{
    
    if disclosed_messages.len() != disclosed_indexes.len() {
        return Err(ProofGenError::InvalidIndicesAndMessagesLength);
    }

    let hash_to_scalar_dst = [api_id, b"H2S_"].concat();

    let mut serialize_bytes = Vec::new();
    
    serialize_bytes.extend_from_slice(&disclosed_indexes.len().to_be_bytes());

    for i in 0..disclosed_indexes.len(){

        let mut compressed_bytes = Vec::new();
        disclosed_messages[i].serialize_compressed(&mut compressed_bytes).unwrap();
        compressed_bytes.reverse();

        serialize_bytes.extend_from_slice(&disclosed_indexes[i].to_be_bytes());
        serialize_bytes.extend_from_slice(&compressed_bytes);
    }

    for i in 0..init_res.points.len() {
        
        let mut compressed_bytes = Vec::new();
        init_res.points[i].serialize_compressed(&mut compressed_bytes).unwrap();

        serialize_bytes.extend_from_slice(&compressed_bytes);
    }

    let mut compressed_bytes = Vec::new();
    init_res.scalar.serialize_compressed(&mut compressed_bytes).unwrap();
    compressed_bytes.reverse();

    serialize_bytes.extend_from_slice(&compressed_bytes);

    serialize_bytes.extend_from_slice(&ph.len().to_be_bytes());
    serialize_bytes.extend_from_slice(&ph);

    Ok(Challenge { 
        scalar: hash_to_scalar::<48, F>(&serialize_bytes, &hash_to_scalar_dst) 
    })

}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-proof-finalization
pub(crate) fn proof_finalize<E, F>(init_res: &InitProof<E, F>, challenge: &Challenge<F>, e_value: F, random_scalars: &[F], undisclosed_messages: &[F]) -> Result<Proof<E, F>, ProofGenError> 
where
    E: Pairing,
    F: Field,
{

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

    // let mut bytes = Vec::new();
    // random_scalars[4].serialize_compressed(&mut bytes).unwrap();
    // bytes.reverse();
    // assert_eq!(bytes, hex::decode("639e3417007d38e5d34ba8c511e836768ddc2669fdd3faff5c14ad27ac2b2da1").unwrap());

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