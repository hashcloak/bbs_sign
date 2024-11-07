use ark_bn254::{
    G1Affine as G1Bn254, 
    G2Affine as G2Bn254,
    Fr as FrBn254,
    g1::Config as BnG1Config,
    g2::Config as BnG2Config
};
use ark_bls12_381::{
    g1::Config as BlsG1Config, g2::Config as BlsG2Config, Fq, Fr as FrBls12_381, G1Affine as G1Bls12_381, G1Projective, G2Affine as G2Bls12_381
};
use ark_ec::{
    AffineRepr, 
    pairing::Pairing, 
    short_weierstrass::Projective
};
use ark_serialize::CanonicalDeserialize;
use std::str::FromStr;

#[allow(non_snake_case)]
pub trait Constants<'a, E: Pairing> {
    fn BP1() -> E::G1;
    fn BP2() -> E::G2;
    fn P1() -> E::G1;
    fn P2() -> E::G2;

    const CIPHERSUITE_ID: &'a [u8];
    const SEED_DST: &'a [u8];
    const GENERATOR_DST: &'a [u8];
    const GENERATOR_SEED: &'a [u8];
}

pub struct Bn254Const;
pub struct Bls12381Const;

impl <E: Pairing<G1 = Projective<BnG1Config>, G2 = Projective<BnG2Config>>>Constants<'_,E> for Bn254Const {
    fn BP1() -> E::G1 {
        G1Bn254::generator().into()
    }

    fn BP2() -> E::G2 {
        G2Bn254::generator().into()
    }

    //TODO: change according to draft
    fn P1() -> E::G1 {
        G1Bn254::generator() * FrBn254::from(5)
    }

    //TODO: change according to draft
    fn P2() -> E::G2 {
        G2Bn254::generator() * FrBn254::from(7)
    }

    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#section-7
    const CIPHERSUITE_ID: &'static[u8] = b"BBS_QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_";
    const SEED_DST: &'static[u8] = b"BBS_QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_H2G_HM2S_SIG_GENERATOR_SEED_";
    const GENERATOR_DST: &'static[u8] = b"BBS_QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_H2G_HM2S_SIG_GENERATOR_DST_";
    const GENERATOR_SEED: &'static[u8] = b"BBS_QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_H2G_HM2S_BP_MESSAGE_GENERATOR_SEED";

}

impl <E: Pairing<G1 = Projective<BlsG1Config>, G2 = Projective<BlsG2Config>>>Constants<'_,E> for Bls12381Const {
    fn BP1() -> E::G1 {
        G1Bls12_381::generator().into()
    }

    fn BP2() -> E::G2 {
        G2Bls12_381::generator().into()
    }

    fn P1() -> E::G1 {
        G1Bls12_381::new(Fq::from_str("1410402537527345635945028702482408516145852363795832124300296631625232096840353922375022004745284014597560052549461").unwrap(), Fq::from_str("1251567760767528906858606613392545933031311346024368470459490474118606852009565951592434442803881561589183987820039").unwrap()).into()
    }

    //TODO: change according to draft
    fn P2() -> E::G2 {
        G2Bls12_381::generator() * FrBls12_381::from(7)
    }


    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#section-7
    const CIPHERSUITE_ID: &'static[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    const SEED_DST: &'static[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_SIG_GENERATOR_SEED_";
    const GENERATOR_DST: &'static[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_SIG_GENERATOR_DST_";
    const GENERATOR_SEED: &'static[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_BP_MESSAGE_GENERATOR_SEED";

}


#[test]
fn test_constants() {
    use ark_bls12_381::{Bls12_381, G1Affine};
    use ark_serialize::CanonicalSerialize;

    let bp1: G1Affine = <Bls12381Const as Constants<Bls12_381>>::BP1().into();
    let mut bp1_bytes = Vec::new();
    bp1.serialize_compressed(&mut bp1_bytes).unwrap();
    let expected_bp1_bytes = hex::decode("97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb").unwrap();

    assert_eq!(bp1_bytes, expected_bp1_bytes);

    let p1: G1Affine = <Bls12381Const as Constants<Bls12_381>>::P1().into();
    let mut p1_bytes = Vec::new();
    p1.serialize_compressed(&mut p1_bytes).unwrap();
    let expected_p1_bytes = hex::decode("8929dfbc7e6642c4ed9cba0856e493f8b9d7d5fcb0c31ef8fdcd34d50648a56c795e106e9eada6e0bda386b414150755").unwrap();

    assert_eq!(p1_bytes, expected_p1_bytes);
}