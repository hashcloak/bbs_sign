#[cfg(test)]
mod tests {
    use ark_bls12_381::{Fr, Bls12_381, G1Affine as G1};
    use test_case::test_case;
    use rand::Rng;

    use crate::{
        key_gen::{PublicKey, SecretKey},
        proof_gen::{proof_gen, Proof},
        proof_verify::proof_verify,
        constants::Bls12381Const,
        utils::interface_utilities::HashToG1Bls12381,
    };
    
    fn generate_key() -> (SecretKey<Fr>, PublicKey<Bls12_381>){

        let mut key_material = [1u8; 32];
        let key_dst = b"BBS-SIG-KEYGEN-SALT-";

        let sk = SecretKey::<Fr>::key_gen::<Bls12_381>(&mut key_material, &[], key_dst.as_slice()).unwrap();
        let pk = SecretKey::sk_to_pk(&sk);

        (sk, pk)
    }

    fn generate_random_msg(num_vectors: usize) -> Vec<Vec<u8>> {
            
        // Generate a random Vec<Vec<u8>> each vector of random length
        let random_vecs: Vec<Vec<u8>> = (0..num_vectors)
            .map(|_| {
                let mut rng = rand::thread_rng();
                // each msg length of 5 bytes
                (0..5).map(|_| rng.gen::<u8>()).collect()
            })
            .collect();
            
        random_vecs
    }

    // happy path
    #[test_case(0, vec![], b"")]
    #[test_case(0, vec![], b"abc")]
    #[test_case(1, vec![0], b"abc")]
    #[test_case(1, vec![], b"abc")]
    #[test_case(10, vec![0,1,2], b"")]
    #[test_case(10, vec![0,4,7,9], b"def")]
    #[test_case(5, vec![0,4], b"defghjsdjdbcjbejd")]
    #[test_case(5, vec![0,1,2,3,4], b"def")]
    fn test_proof_verify(count: usize, disclosed_indexes: Vec<usize>, header: &[u8]) {
        let (sk, pk) = generate_key();

        let messages = generate_random_msg(count);

        let msg_slices: Vec<&[u8]> = messages.iter().map(|v| v.as_slice()).collect();

        let signature = sk.sign::<Bls12_381, Bls12381Const, HashToG1Bls12381>(&msg_slices, header).unwrap();
        assert!(pk.verify::<Fr, HashToG1Bls12381, Bls12381Const>(signature, header, &msg_slices).unwrap());

        let disclosed_msgs: Vec<&[u8]> = disclosed_indexes.iter().map(|i| msg_slices[*i]).collect();

        let proof = proof_gen::<Bls12_381, Fr, HashToG1Bls12381, Bls12381Const>(pk.clone(), signature, header, &[], &msg_slices, disclosed_indexes.as_slice());
        assert!(proof_verify::<Bls12_381, Fr, HashToG1Bls12381, Bls12381Const>(pk, proof.unwrap(), header, &[], disclosed_msgs.as_slice(), disclosed_indexes.as_slice()).unwrap());
    }

    #[test]
    fn test_invalid_proof() {

        let (sk, pk) = generate_key();
        let messages = generate_random_msg(10);
        let msg_slices: Vec<&[u8]> = messages.iter().map(|v| v.as_slice()).collect();
        let signature = sk.sign::<Bls12_381, Bls12381Const, HashToG1Bls12381>(&msg_slices, b"").unwrap();
        let proof = proof_gen::<Bls12_381, Fr, HashToG1Bls12381, Bls12381Const>(pk.clone(), signature, b"", &[], &msg_slices, &[0,1,5]).unwrap();

        // correct proof
        assert!(proof_verify::<Bls12_381, Fr, HashToG1Bls12381, Bls12381Const>(pk.clone(), proof.clone(), b"", &[], &[&msg_slices[0], &msg_slices[1], &msg_slices[5]], &[0,1,5]).unwrap());

        // case 1
        // forged proof
        let mut forged_proof = proof.clone();
        forged_proof.a_bar = G1::identity().into();

        // should fail because of forged a_bar
        assert!(!proof_verify::<Bls12_381, Fr, HashToG1Bls12381, Bls12381Const>(pk.clone(), forged_proof, b"", &[], &[&msg_slices[0], &msg_slices[1], &msg_slices[5]], &[0,1,5]).unwrap());
        
        // case 2
        // default proof should fail
        let forged_proof = Proof::<Bls12_381, Fr>{
            ..Default::default()
        };

        // result into error because of forged proof(commitment length is zero)
        assert!(proof_verify::<Bls12_381, Fr, HashToG1Bls12381, Bls12381Const>(pk.clone(), forged_proof, b"", &[], &[&msg_slices[0], &msg_slices[1], &msg_slices[5]], &[0,1,5]).is_err());

        // case 3
        // forged public key
        let forged_pk = PublicKey{
            ..Default::default()
        };
        assert!(!proof_verify::<Bls12_381, Fr, HashToG1Bls12381, Bls12381Const>(forged_pk, proof, b"", &[], &[&msg_slices[0], &msg_slices[1], &msg_slices[5]], &[0,1,5]).unwrap());

        // case 4
        let forged_proof = Proof{
            commitments: vec![Fr::from(0); 7],  // 10-3 where 3 is the disclosed indexes length
            ..Default::default()
        };
        assert!(!proof_verify::<Bls12_381, Fr, HashToG1Bls12381, Bls12381Const>(pk.clone(), forged_proof, b"", &[], &[&msg_slices[0], &msg_slices[1], &msg_slices[5]], &[0,1,5]).unwrap());
    }
}