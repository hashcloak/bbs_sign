use ark_bn254::{
    G1Affine as G1Bn254, 
    G2Affine as G2Bn254,
    Fr as FrBn254,
    g1::Config as BnG1Config,
    g2::Config as BnG2Config
};
use ark_bls12_381::{
    Fr as FrBls12_381, 
    G1Affine as G1Bls12_381, 
    G2Affine as G2Bls12_381,
    g1::Config as BlsG1Config,
    g2::Config as BlsG2Config
};
use ark_ec::{
    AffineRepr, 
    pairing::Pairing, 
    short_weierstrass::Projective
};

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
    const CIPHERSUITE_ID: &'static[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    const SEED_DST: &'static[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_SIG_GENERATOR_SEED_";
    const GENERATOR_DST: &'static[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_SIG_GENERATOR_DST_";
    const GENERATOR_SEED: &'static[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_BP_MESSAGE_GENERATOR_SEED";

}

impl <E: Pairing<G1 = Projective<BlsG1Config>, G2 = Projective<BlsG2Config>>>Constants<'_,E> for Bls12381Const {
    fn BP1() -> E::G1 {
        G1Bls12_381::generator().into()
    }

    fn BP2() -> E::G2 {
        G2Bls12_381::generator().into()
    }

    //TODO: change according to draft
    fn P1() -> E::G1 {
        G1Bls12_381::generator() * FrBls12_381::from(5)
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
