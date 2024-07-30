#[cfg(test)]
mod tests {

    use crate::key_gen::{key_gen, PublicKey, SecretKey};
    use crate::sign::{core_sign, create_generators};
    use crate::verify::core_verify;
    use crate::key_gen::sk_to_pk;
    use ark_bn254::Fr;
    use rand::Rng;
    use test_case::test_case;

    fn generate_key() -> (SecretKey, PublicKey){

        let mut key_material = [0u8; 32];
        let key_dst = b"BBS-SIG-KEYGEN-SALT-";

        let sk = key_gen(&mut key_material, &[], key_dst.as_slice());
        let pk = sk_to_pk(&sk);

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
    fn test_core_sign_verify(count: usize, api_id: &[u8], header: &[u8]) {

        let (sk, pk) = generate_key();

        // random messages: Vector of Fr
        let messages = generate_random_msg(count);
        let generators = create_generators(count+1, api_id);

        let signature = core_sign(&sk, &pk, generators.as_slice(), header, &messages, api_id);
        assert!(core_verify(&pk, signature, generators.as_slice(), header, &messages, api_id));
    }
}
