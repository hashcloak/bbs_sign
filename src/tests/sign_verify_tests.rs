#[cfg(test)]
mod tests {
    use ark_bn254::{Bn254, Fr, G1Affine as G1};
    use rand::Rng;
    use test_case::test_case;

    use crate::{
        constants::Bn254Const, 
        key_gen::{PublicKey, SecretKey},
        utils::interface_utilities::HashToG1Bn254,
    };    

    fn generate_key() -> (SecretKey<Fr>, PublicKey<Bn254>){

        let mut key_material: [u8; 32] = rand::random();
        let key_dst = b"BBS-SIG-KEYGEN-SALT-";

        let sk = SecretKey::<Fr>::key_gen::<Bn254>(&mut key_material, &[], key_dst.as_slice()).unwrap();
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

        let signature = sk.sign::<Bn254, Bn254Const, HashToG1Bn254>(&msg_slices, header).unwrap();
        assert!(pk.verify::<Fr, HashToG1Bn254, Bn254Const>(signature, header, &msg_slices).unwrap());
    }

    #[test]
    fn test_invalid_signature() {

        let count = 10;
        let header = b"";

        let (sk, pk) = generate_key();

        // random messages: Vector of Fr
        let messages = generate_random_msg(count);
        let msg_slices: Vec<&[u8]> = messages.iter().map(|v| v.as_slice()).collect();

        let signature = sk.sign::<Bn254, Bn254Const, HashToG1Bn254>(&msg_slices, header).unwrap();

        // valid signature verification
        assert!(pk.verify::<Fr, HashToG1Bn254, Bn254Const>(signature, header, &msg_slices).unwrap());
        
        // forged signature
        let mut forged_signature = signature.clone();
        forged_signature.a = G1::identity().into();
        assert!(!pk.verify::<Fr, HashToG1Bn254, Bn254Const>(forged_signature, header, &msg_slices).unwrap());

        // forged header
        let forged_header = b"abc";
        assert!(!pk.verify::<Fr, HashToG1Bn254, Bn254Const>(signature, forged_header, &msg_slices).unwrap());

        // forged public key
        let forged_pk = PublicKey::default();
        assert!(!forged_pk.verify::<Fr, HashToG1Bn254, Bn254Const>(signature, header, &msg_slices).unwrap());

        // forged messages
        let mut forged_messages = msg_slices.clone();
        forged_messages[0] = &[0,1];
        assert!(!pk.verify::<Fr, HashToG1Bn254, Bn254Const>(signature, header, &forged_messages).unwrap());

    }
}
