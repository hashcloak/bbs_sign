#[cfg(test)]
mod tests {

    use crate::constants::Bn254Const;
    use crate::key_gen::{PublicKey, SecretKey};
    use crate::utils::interface_utilities::{create_generators, HashToCurveBn254};
    use ark_bn254::{Bn254, Fr, G1Affine as G1};
    use rand::Rng;
    use test_case::test_case;

    fn generate_key() -> (SecretKey<Fr>, PublicKey<Bn254>){

        let mut key_material = [1u8; 32];
        let key_dst = b"BBS-SIG-KEYGEN-SALT-";

        let sk = SecretKey::<Fr>::key_gen::<Bn254>(&mut key_material, &[], key_dst.as_slice()).unwrap();
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
        let generators = create_generators::<Bn254, HashToCurveBn254>(count+1, api_id);

        let signature = sk.core_sign::<Bn254, Bn254Const>(generators.as_slice(), header, &messages, api_id).unwrap();
        assert!(pk.core_verify::<Fr, Bn254Const, HashToCurveBn254>(signature, generators.as_slice(), header, &messages, api_id).unwrap());
    }

    #[test]
    fn test_invalid_signature() {

        let count = 10;
        let api_id = b"";
        let header = b"";

        let (sk, pk) = generate_key();

        // random messages: Vector of Fr
        let messages = generate_random_msg(count);
        let generators = create_generators::<Bn254, HashToCurveBn254>(count+1, api_id);

        let signature = sk.core_sign::<Bn254, Bn254Const>(generators.as_slice(), header, &messages, api_id).unwrap();

        // valid signature verification
        assert!(pk.core_verify::<Fr, Bn254Const, HashToCurveBn254>(signature, generators.as_slice(), header, &messages, api_id).unwrap());
        
        // forged signature
        let mut forged_signature = signature.clone();
        forged_signature.a = G1::identity().into();
        assert!(!pk.core_verify::<Fr, Bn254Const, HashToCurveBn254>(forged_signature, generators.as_slice(), header, &messages, api_id).unwrap());

        // forged api_id
        let forged_api_id = b"abc";
        assert!(!pk.core_verify::<Fr, Bn254Const, HashToCurveBn254>(signature, generators.as_slice(), header, &messages, forged_api_id).unwrap());

        // forged header
        let forged_header = b"abc";
        assert!(!pk.core_verify::<Fr, Bn254Const, HashToCurveBn254>(signature, generators.as_slice(), forged_header, &messages, api_id).unwrap());

        // forged public key
        let forged_pk: PublicKey<Bn254> = PublicKey::<Bn254>::default();
        assert!(!forged_pk.core_verify::<Fr, Bn254Const, HashToCurveBn254>(signature, generators.as_slice(), header, &messages, api_id).unwrap());

        // forged messages
        let mut forged_messages = messages.clone();
        forged_messages[0] = Fr::from(0);
        assert!(!pk.core_verify::<Fr, Bn254Const, HashToCurveBn254>(signature, generators.as_slice(), header, &forged_messages, api_id).unwrap());

    }
}
