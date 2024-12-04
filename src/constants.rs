use ark_bn254::{
    G1Affine as G1Bn254, 
    G2Affine as G2Bn254,
    g1::Config as BnG1Config,
    g2::Config as BnG2Config,
    Fq as FqBn254
};
use ark_bls12_381::{
    g1::Config as BlsG1Config, g2::Config as BlsG2Config, G1Affine as G1Bls12_381, G2Affine as G2Bls12_381, Fq
};
use ark_ec::{
    AffineRepr, 
    pairing::Pairing, 
    short_weierstrass::Projective
};
use std::str::FromStr;

#[allow(non_snake_case)]
pub trait Constants<'a, E: Pairing> {
    fn BP1() -> E::G1;
    fn BP2() -> E::G2;
    fn P1() -> E::G1;

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

    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-bls12-381-ciphersuites
    fn P1() -> E::G1 {
        G1Bn254::new(FqBn254::from_str("7738860219269362160002109478394842060990190871738832255540382874922375322334").unwrap(), FqBn254::from_str("8255268479661695615178834896135584953541182794935974658059743263102507888551").unwrap()).into()
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
        G1Bls12_381::new(Fq::from_str("1355253221325668152696183518801331769866100080859571110928822005264442742039790254588065001486134245057142899747017").unwrap(), Fq::from_str("2563071790429735027383427649950865259619709115697058137448106859255609577834149037543606665262210555960464099235249").unwrap()).into()
    }

    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#section-7
    const CIPHERSUITE_ID: &'static[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    const SEED_DST: &'static[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_SIG_GENERATOR_SEED_";
    const GENERATOR_DST: &'static[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_SIG_GENERATOR_DST_";
    const GENERATOR_SEED: &'static[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_BP_MESSAGE_GENERATOR_SEED";

}