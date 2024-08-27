use ark_bn254::{
    G1Affine as G1Bn254, 
    G2Affine as G2Bn254
};
use ark_bls12_381::{
    G1Affine as G1Bls12_381, 
    G2Affine as G2Bls12_381
};
use ark_ec::{
    AffineRepr, 
    pairing::Pairing, 
    short_weierstrass::Projective
};

#[allow(non_snake_case)]
pub trait Constants<E: Pairing> {
    fn BP1() -> E::G1;
    fn BP2() -> E::G2;
    fn P1() -> E::G1;
    fn P2() -> E::G2;
}

pub struct Bn254Const;
pub struct Bls12381Const;

impl <E: Pairing<G1 = Projective<ark_bn254::g1::Config>, G2 = Projective<ark_bn254::g2::Config>>>Constants<E> for Bn254Const {
    fn BP1() -> E::G1 {
        G1Bn254::generator().into()
    }

    fn BP2() -> E::G2 {
        G2Bn254::generator().into()
    }

    fn P1() -> E::G1 {
        G1Bn254::generator().into()
    }

    fn P2() -> E::G2 {
        G2Bn254::generator().into()
    }
}

impl <E: Pairing<G1 = Projective<ark_bls12_381::g1::Config>, G2 = Projective<ark_bls12_381::g2::Config>>>Constants<E> for Bls12381Const {
    fn BP1() -> E::G1 {
        G1Bls12_381::generator().into()
    }

    fn BP2() -> E::G2 {
        G2Bls12_381::generator().into()
    }

    fn P1() -> E::G1 {
        G1Bls12_381::generator().into()
    }

    fn P2() -> E::G2 {
        G2Bls12_381::generator().into()
    }
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#section-7
pub const CIPHERSUITE_ID: &[u8] = b"BBS_QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_";
pub const SEED_DST: &[u8] = b"BBS_QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_H2G_HM2S_SIG_GENERATOR_SEED_";
pub const GENERATOR_DST: &[u8] = b"BBS_QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_H2G_HM2S_SIG_GENERATOR_DST_";
pub const GENERATOR_SEED: &[u8] = b"BBS_QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_H2G_HM2S_BP_MESSAGE_GENERATOR_SEED";
