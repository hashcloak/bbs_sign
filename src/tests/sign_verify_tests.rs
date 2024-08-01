#[cfg(test)]
mod tests {

    use crate::key_gen::{PublicKey, SecretKey};
    use ark_bn254::G1Affine as G1;
    use rand::Rng;
    use test_case::test_case;

    fn generate_key() -> (SecretKey, PublicKey){

        let mut key_material: [u8; 32] = rand::random();
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

    // happy path
    #[test_case(5, b"")]
    #[test_case(0, b"")]
    #[test_case(0, b"abc")]
    #[test_case(10, b"")]
    #[test_case(10, b"abc")]
    fn test_sign_and_verify(count: usize, header: &[u8]) {

        let (sk, pk) = generate_key();

        // random messages: Vector of Fr
        let messages = generate_random_msg(count);

        let msg_slices: Vec<&[u8]> = messages.iter().map(|v| v.as_slice()).collect();

        let signature = sk.sign(&msg_slices, header);
        assert!(pk.verify(signature, header, &msg_slices));
    }

    #[test]
    fn test_invalid_signature() {

        let count = 10;
        let header = b"";

        let (sk, pk) = generate_key();

        // random messages: Vector of Fr
        let messages = generate_random_msg(count);
        let msg_slices: Vec<&[u8]> = messages.iter().map(|v| v.as_slice()).collect();

        let signature = sk.sign(&msg_slices, header);

        // valid signature verification
        assert!(pk.verify(signature, header, &msg_slices));
        
        // forged signature
        let mut forged_signature = signature.clone();
        forged_signature.a = G1::identity();
        assert!(!pk.verify(forged_signature, header, &msg_slices));

        // forged header
        let forged_header = b"abc";
        assert!(!pk.verify(signature, forged_header, &msg_slices));

        // forged public key
        let forged_pk = PublicKey::default();
        assert!(!forged_pk.verify(signature, header, &msg_slices));

        // forged messages
        let mut forged_messages = msg_slices.clone();
        forged_messages[0] = &[0,1];
        assert!(!pk.verify(signature, header, &forged_messages));

    }
}
