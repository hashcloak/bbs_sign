#[cfg(test)]
mod tests {

    use crate::key_gen::{PublicKey, SecretKey};
    use crate::utils::interface_utilities::create_generators;
    use ark_bn254::{Fr, G1Affine as G1};
    use rand::Rng;
    use test_case::test_case;

    fn generate_key() -> (SecretKey, PublicKey){

        let mut key_material = [1u8; 32];
        let key_dst = b"BBS-SIG-KEYGEN-SALT-";

        let sk = SecretKey::key_gen(&mut key_material, &[], key_dst.as_slice());
        let pk = SecretKey::sk_to_pk(&sk);

        (sk, pk)
    }

    fn generate_random_msg(n: usize) -> Vec<Fr> {
        
        let mut messages = Vec::new();
        let mut rng = rand::thread_rng();

        for _ in 0..n {
            let random_value = rng.gen::<u64>();
            messages.push(Fr::from(random_value));
        }

        messages
    }

    // happy path
    #[test_case(5, b"", b"")]
    #[test_case(0, b"", b"")]
    #[test_case(0, b"abc", b"")]
    #[test_case(0, b"", b"abc")]
    #[test_case(10, b"", b"")]
    #[test_case(10, b"abc", b"def")]
    #[test_case(10, b"", b"def")]
    #[test_case(10, b"abc", b"")]
    fn test_core_sign_and_verify(count: usize, api_id: &[u8], header: &[u8]) {

        let (sk, pk) = generate_key();

        // random messages: Vector of Fr
        let messages = generate_random_msg(count);
        let generators = create_generators(count+1, api_id);

        let signature = sk.core_sign(generators.as_slice(), header, &messages, api_id);
        assert!(pk.core_verify(signature, generators.as_slice(), header, &messages, api_id));
    }

    #[test]
    fn test_invalid_signature() {

        let count = 10;
        let api_id = b"";
        let header = b"";

        let (sk, pk) = generate_key();

        // random messages: Vector of Fr
        let messages = generate_random_msg(count);
        let generators = create_generators(count+1, api_id);

        let signature = sk.core_sign(generators.as_slice(), header, &messages, api_id);

        // valid signature verification
        assert!(pk.core_verify(signature, generators.as_slice(), header, &messages, api_id));
        
        // forged signature
        let mut forged_signature = signature.clone();
        forged_signature.a = G1::identity();
        assert!(!pk.core_verify(forged_signature, generators.as_slice(), header, &messages, api_id));

        // forged api_id
        let forged_api_id = b"abc";
        assert!(!pk.core_verify(signature, generators.as_slice(), header, &messages, forged_api_id));

        // forged header
        let forged_header = b"abc";
        assert!(!pk.core_verify(signature, generators.as_slice(), forged_header, &messages, api_id));

        // forged public key
        let forged_pk = PublicKey::default();
        assert!(!forged_pk.core_verify(signature, generators.as_slice(), header, &messages, api_id));

        // forged messages
        let mut forged_messages = messages.clone();
        forged_messages[0] = Fr::from(0);
        assert!(!pk.core_verify(signature, generators.as_slice(), header, &forged_messages, api_id));

    }
}
