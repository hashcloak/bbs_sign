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

    // let random_scalars = calculate_random_scalars::<48, F>(5 + l - r);

    // For testing only
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


#[test]
fn test_proof_testvector() {
    use ark_bls12_381::{Fr, Bls12_381};
    use crate::key_gen::SecretKey;
    use crate::key_gen;
    use ark_ec::CurveGroup;
    use crate::constants::Bls12381Const;
    use crate::utils::interface_utilities::HashToG1Bls12381;
    use ark_serialize::CanonicalSerialize;

    let m_0 = hex::decode("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02").unwrap();
    let header = hex::decode("11223344556677889900aabbccddeeff").unwrap();
    let presentation_header = hex::decode("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501").unwrap();

    let mut key_material = hex::decode("746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579").unwrap();
    let key_info = hex::decode("746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e").unwrap();
    let key_dst = hex::decode("4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f4b455947454e5f4453545f").unwrap();

    let sk = SecretKey::<Fr>::key_gen::<Bls12_381>(&mut key_material.as_mut_slice(), key_info.as_slice(), key_dst.as_slice()).unwrap();
    let pk: key_gen::PublicKey<Bls12_381> = SecretKey::sk_to_pk(&sk);

    let mut compressed_bytes = Vec::new();
    pk.pk.into_affine().serialize_compressed(&mut compressed_bytes).unwrap();
    let pk_bytes = hex::decode("a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c").unwrap();
    // checking the computed pk is equal to the expected pk
    assert_eq!(compressed_bytes, pk_bytes);

    let signature = sk.sign::<Bls12_381, Bls12381Const, HashToG1Bls12381>(&[m_0.as_slice()], &header).unwrap();

    let mut a_compressed_bytes: Vec<u8> = Vec::new();
    signature.a.serialize_compressed(&mut a_compressed_bytes).unwrap();

    let mut e_compressed_bytes: Vec<u8> = Vec::new();
    signature.e.serialize_compressed(&mut e_compressed_bytes).unwrap();
    e_compressed_bytes.reverse();

    // full sig hex bytes (A,e)
    a_compressed_bytes.extend_from_slice(&e_compressed_bytes);
    let expected_sig_bytes = hex::decode("84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da5253aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb4c892340be5969920d0916067b4565a0").unwrap();
    assert_eq!(a_compressed_bytes, expected_sig_bytes);

    let proof = proof_gen::<Bls12_381, Fr, HashToG1Bls12381, Bls12381Const>(pk, signature, &header, &presentation_header, &[m_0.as_slice()], &[0]).unwrap();

    let mut a_bar_bytes = Vec::new();
    proof.a_bar.into_affine().serialize_compressed(&mut a_bar_bytes).unwrap();

    let mut b_bar_bytes = Vec::new();
    proof.b_bar.into_affine().serialize_compressed(&mut b_bar_bytes).unwrap();

    let mut d_bytes = Vec::new();
    proof.d.into_affine().serialize_compressed(&mut d_bytes).unwrap();

    let mut ecap_bytes = Vec::new();
    proof.e_cap.serialize_compressed(&mut ecap_bytes).unwrap();
    ecap_bytes.reverse();

    let mut r1cap_bytes = Vec::new();
    proof.r1_cap.serialize_compressed(&mut r1cap_bytes).unwrap();
    r1cap_bytes.reverse();

    let mut r3cap_bytes = Vec::new();
    proof.r3_cap.serialize_compressed(&mut r3cap_bytes).unwrap();
    r3cap_bytes.reverse();

    let mut challenge = Vec::new();
    proof.challenge.serialize_compressed(&mut challenge).unwrap();
    challenge.reverse();

    let expected_proof_bytes = hex::decode("94916292a7a6bade28456c601d3af33fcf39278d6594b467e128a3f83686a104ef2b2fcf72df0215eeaf69262ffe8194a19fab31a82ddbe06908985abc4c9825788b8a1610942d12b7f5debbea8985296361206dbace7af0cc834c80f33e0aadaeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a49f21d592f5e634f47cee05a025a2f8f94e73a6c15f02301d1178a92873b6e8634bafe4983c3e15a663d64080678dbf29417519b78af042be2b3e1c4d08b8d520ffab008cbaaca5671a15b22c239b38e940cfeaa5e72104576a9ec4a6fad78c532381aeaa6fb56409cef56ee5c140d455feeb04426193c57086c9b6d397d9418").unwrap();

    
    assert_eq!(a_bar_bytes, expected_proof_bytes[0..48]);
    assert_eq!(b_bar_bytes, expected_proof_bytes[48..96]);
    assert_eq!(d_bytes, expected_proof_bytes[96..144]);
    assert_eq!(ecap_bytes, expected_proof_bytes[144..176]);
    assert_eq!(r1cap_bytes, expected_proof_bytes[176..208]);
    assert_eq!(r3cap_bytes, expected_proof_bytes[208..240]);
    assert_eq!(challenge, expected_proof_bytes[240..272]);
}