#[cfg(test)]
mod tests {

    use crate::key_gen::{PublicKey, SecretKey};
    use crate::proof_gen::proof_gen;
    use crate::proof_verify::proof_verify;
    use rand::Rng;

    fn generate_key() -> (SecretKey, PublicKey){

        let mut key_material = [1u8; 32];
        let key_dst = b"BBS-SIG-KEYGEN-SALT-";

        let sk = SecretKey::key_gen(&mut key_material, &[], key_dst.as_slice());
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

    #[test]
    fn test_proof_verify() {
        let count = 10;
        let header = b"";
        let (sk, pk) = generate_key();

        let messages = generate_random_msg(count);

        let msg_slices: Vec<&[u8]> = messages.iter().map(|v| v.as_slice()).collect();

        let signature = sk.sign(&msg_slices, header);
        assert!(pk.verify(signature, header, &msg_slices));

        let disclosed_indexes: Vec<usize> = vec![0,5];
        let proof = proof_gen(pk.clone(), signature, header, &[], &msg_slices, disclosed_indexes.as_slice());
        assert!(proof_verify(pk, proof, header, &[], &[msg_slices[0], msg_slices[5]], disclosed_indexes.as_slice()));
    }
}