#[cfg(test)]
mod test_vector {
    use crate::constants::{Bls12381Const, Constants};
    use crate::key_gen::{PublicKey, SecretKey};
    #[allow(unused_imports)]
    use crate::proof_gen::proof_gen;
    use crate::utils::core_utilities::{hash_to_scalar, mocked_calculate_random_scalars};
    use crate::utils::interface_utilities::{create_generators, HashToG1Bls12381};
    use ark_bls12_381::{Bls12_381, G1Affine, G2Affine};
    use ark_ec::{pairing::Pairing, CurveGroup};
    use ark_ff::Field;
    use ark_serialize::CanonicalSerialize;

    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-bls12-381-ciphersuites
    // For generating Bls12_381 parameter Point P1
    //  seed_dst = [b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_".as_slice(), b"H2G_HM2S_SIG_GENERATOR_SEED_"].concat();
    //  generator_dst = [b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_".as_slice(), b"H2G_HM2S_SIG_GENERATOR_DST_"].concat();
    //  generator_seed = [b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_".as_slice(), b"H2G_HM2S_BP_MESSAGE_GENERATOR_SEED"].concat();

    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-bls12-381-ciphersuites
    // For generating Bn254 parameter Point P1
    //  seed_dst = [b"BBS_QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_".as_slice(), b"H2G_HM2S_SIG_GENERATOR_SEED_"].concat();
    //  generator_dst = [b"BBS_QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_".as_slice(), b"H2G_HM2S_SIG_GENERATOR_DST_"].concat();
    //  generator_seed = [b"BBS_QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_".as_slice(), b"H2G_HM2S_BP_MESSAGE_GENERATOR_SEED"].concat();

    fn scalar_to_hex<F: Field>(scalar: F) -> String {
        let mut bytes = Vec::new();
        scalar.serialize_compressed(&mut bytes).unwrap();
        bytes.reverse();

        hex::encode(bytes)
    }

    fn g1_to_hex<E: Pairing>(point: E::G1) -> String {
        let mut bytes = Vec::new();
        point
            .into_affine()
            .serialize_compressed(&mut bytes)
            .unwrap();

        hex::encode(bytes)
    }

    fn g2_to_hex<E: Pairing>(point: E::G2) -> String {
        let mut bytes = Vec::new();
        point
            .into_affine()
            .serialize_compressed(&mut bytes)
            .unwrap();

        hex::encode(bytes)
    }

    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-the-bls12-381-curve
    #[test]
    fn test_constants_bls() {
        let bp1: G1Affine = <Bls12381Const as Constants<Bls12_381>>::BP1().into();
        let bp1_hex = g1_to_hex::<Bls12_381>(bp1.into());
        assert_eq!(bp1_hex, "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb");

        let bp2: G2Affine = <Bls12381Const as Constants<Bls12_381>>::BP2().into();
        let bp2_hex = g2_to_hex::<Bls12_381>(bp2.into());
        assert_eq!(bp2_hex, "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8");

        let p1: G1Affine = <Bls12381Const as Constants<Bls12_381>>::P1().into();
        let p1_hex = g1_to_hex::<Bls12_381>(p1.into());
        assert_eq!(p1_hex, "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9");
    }

    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-hash-to-scalar-test-vectors-2
    #[test]
    fn test_hash_to_scalar_testvector() {
        let msg = hex::decode("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02")
            .unwrap();
        let dst = hex::decode("4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f4832535f").unwrap();
        let scalar = hash_to_scalar::<48, ark_bls12_381::Fr>(&msg, &dst);

        assert_eq!(
            scalar_to_hex(scalar),
            "0f90cbee27beb214e6545becb8404640d3612da5d6758dffeccd77ed7169807c"
        );
    }

    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-proof-fixtures-2
    #[test]
    fn test_mocked_calculate_random_scalars_testvector() {
        let scalars = mocked_calculate_random_scalars::<ark_bls12_381::Fr>(10);
        assert_eq!(
            scalar_to_hex(scalars[0]),
            "04f8e2518993c4383957ad14eb13a023c4ad0c67d01ec86eeb902e732ed6df3f"
        );
        assert_eq!(
            scalar_to_hex(scalars[9]),
            "485e2adab17b76f5334c95bf36c03ccf91cef77dcfcdc6b8a69e2090b3156663"
        );
    }

    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-map-messages-to-scalars-2
    #[test]
    fn test_msg_to_scalars_testvector() {
        use ark_bls12_381::Fr;

        let dst = hex::decode("4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f4d41505f4d53475f544f5f5343414c41525f41535f484153485f").unwrap();

        let msg = hex::decode("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02")
            .unwrap();
        let msg_scalar: Fr = hash_to_scalar::<48, Fr>(&msg, &dst);
        assert_eq!(
            scalar_to_hex(msg_scalar),
            "1cb5bb86114b34dc438a911617655a1db595abafac92f47c5001799cf624b430"
        );

        let msg = hex::decode("").unwrap();
        let msg_scalar: Fr = hash_to_scalar::<48, Fr>(&msg, &dst);
        assert_eq!(
            scalar_to_hex(msg_scalar),
            "08e3afeb2b4f2b5f907924ef42856616e6f2d5f1fb373736db1cca32707a7d16"
        );
    }

    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-message-generators-2
    #[test]
    fn test_create_generators_testvector() {
        use ark_bls12_381::Bls12_381;

        let generators = create_generators::<Bls12_381, HashToG1Bls12381>(
            11,
            b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_",
        );

        assert_eq!(g1_to_hex::<Bls12_381>(generators[0]), "a9ec65b70a7fbe40c874c9eb041c2cb0a7af36ccec1bea48fa2ba4c2eb67ef7f9ecb17ed27d38d27cdeddff44c8137be");
        assert_eq!(g1_to_hex::<Bls12_381>(generators[1]), "98cd5313283aaf5db1b3ba8611fe6070d19e605de4078c38df36019fbaad0bd28dd090fd24ed27f7f4d22d5ff5dea7d4");
        assert_eq!(g1_to_hex::<Bls12_381>(generators[2]), "a31fbe20c5c135bcaa8d9fc4e4ac665cc6db0226f35e737507e803044093f37697a9d452490a970eea6f9ad6c3dcaa3a");
        assert_eq!(g1_to_hex::<Bls12_381>(generators[10]), "a1f229540474f4d6f1134761b92b788128c7ac8dc9b0c52d59493132679673032ac7db3fb3d79b46b13c1c41ee495bca");
    }

    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-key-pair-2
    #[test]
    fn test_keygen_testvector() {
        use ark_bls12_381::Fr;

        let mut key_material = hex::decode("746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579").unwrap();
        let key_info = hex::decode("746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e").unwrap();
        let key_dst = hex::decode("4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f4b455947454e5f4453545f").unwrap();

        let sk: SecretKey<Fr> = SecretKey::key_gen::<Bls12_381>(
            &mut key_material.as_mut_slice(),
            key_info.as_slice(),
            key_dst.as_slice(),
        )
        .unwrap();
        assert_eq!(
            scalar_to_hex(sk.sk),
            "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc"
        );

        let pk: PublicKey<Bls12_381> = SecretKey::sk_to_pk(&sk);
        assert_eq!(g2_to_hex::<Bls12_381>(pk.pk), "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c");
    }

    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-signature-fixtures-2
    #[test]
    fn test_sign_testvector() {
        use crate::constants::Bls12381Const;
        use crate::utils::interface_utilities::HashToG1Bls12381;
        use ark_bls12_381::{Bls12_381, Fr};

        let m_1 = hex::decode("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02")
            .unwrap();
        let mut key_material = hex::decode("746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579").unwrap();
        let key_info = hex::decode("746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e").unwrap();
        let key_dst = hex::decode("4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f4b455947454e5f4453545f").unwrap();
        let header = hex::decode("11223344556677889900aabbccddeeff").unwrap();

        let sk = SecretKey::<Fr>::key_gen::<Bls12_381>(
            &mut key_material.as_mut_slice(),
            key_info.as_slice(),
            key_dst.as_slice(),
        )
        .unwrap();

        let signature = sk
            .sign::<Bls12_381, Bls12381Const, HashToG1Bls12381>(&[m_1.as_slice()], &header)
            .unwrap();

        let mut a_hex = g1_to_hex::<Bls12_381>(signature.a);
        let e_hex = scalar_to_hex(signature.e);
        a_hex.push_str(&e_hex);

        assert_eq!(a_hex, "84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da5253aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb4c892340be5969920d0916067b4565a0")
    }

    // The Proof Fixtures uses mocked_calculate_random_scalars instead of calculate_random_scalars for the test vectors
    // used in function core_proof_gen in `proof_gen.rs`
    #[cfg(testvector_bls12_381)]
    #[test]
    fn test_proof_testvector() {
        use crate::constants::Bls12381Const;
        use crate::key_gen;
        use crate::key_gen::SecretKey;
        use crate::utils::interface_utilities::HashToG1Bls12381;
        use ark_bls12_381::{Bls12_381, Fr};

        let m_0 = hex::decode("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02")
            .unwrap();
        let header = hex::decode("11223344556677889900aabbccddeeff").unwrap();
        let presentation_header =
            hex::decode("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501")
                .unwrap();

        let mut key_material = hex::decode("746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579").unwrap();
        let key_info = hex::decode("746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e").unwrap();
        let key_dst = hex::decode("4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f4b455947454e5f4453545f").unwrap();

        let sk = SecretKey::<Fr>::key_gen::<Bls12_381>(
            &mut key_material.as_mut_slice(),
            key_info.as_slice(),
            key_dst.as_slice(),
        )
        .unwrap();
        let pk: key_gen::PublicKey<Bls12_381> = SecretKey::sk_to_pk(&sk);

        let signature = sk
            .sign::<Bls12_381, Bls12381Const, HashToG1Bls12381>(&[m_0.as_slice()], &header)
            .unwrap();
        let proof = proof_gen::<Bls12_381, Fr, HashToG1Bls12381, Bls12381Const>(
            pk,
            signature,
            &header,
            &presentation_header,
            &[m_0.as_slice()],
            &[0],
        )
        .unwrap();

        let a_bar = g1_to_hex::<Bls12_381>(proof.a_bar);
        let b_bar = g1_to_hex::<Bls12_381>(proof.b_bar);
        let d = g1_to_hex::<Bls12_381>(proof.d);
        let e_cap = scalar_to_hex(proof.e_cap);
        let r1_cap = scalar_to_hex(proof.r1_cap);
        let r3_cap = scalar_to_hex(proof.r3_cap);
        let challenge = scalar_to_hex(proof.challenge.scalar);

        let mut proof = String::new();
        proof.push_str(&a_bar);
        proof.push_str(&b_bar);
        proof.push_str(&d);
        proof.push_str(&e_cap);
        proof.push_str(&r1_cap);
        proof.push_str(&r3_cap);
        proof.push_str(&challenge);

        assert_eq!(proof, "94916292a7a6bade28456c601d3af33fcf39278d6594b467e128a3f83686a104ef2b2fcf72df0215eeaf69262ffe8194a19fab31a82ddbe06908985abc4c9825788b8a1610942d12b7f5debbea8985296361206dbace7af0cc834c80f33e0aadaeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a49f21d592f5e634f47cee05a025a2f8f94e73a6c15f02301d1178a92873b6e8634bafe4983c3e15a663d64080678dbf29417519b78af042be2b3e1c4d08b8d520ffab008cbaaca5671a15b22c239b38e940cfeaa5e72104576a9ec4a6fad78c532381aeaa6fb56409cef56ee5c140d455feeb04426193c57086c9b6d397d9418");
    }
}
