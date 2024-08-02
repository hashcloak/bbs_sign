use ark_bn254::{Fr, G1Affine as G1, G2Affine as G2};
use ark_ec::AffineRepr;
use once_cell::sync::Lazy;

// BP1, BP2
// base (constant) points on the G1 and G2 subgroups respectively
pub static BP1: Lazy<G1> = Lazy::new(|| G1::generator());
pub static BP2: Lazy<G2> = Lazy::new(|| G2::generator());

// TODO: Parameters: P1, P2: change according to ciphersuite
// P1 and P2, fixed point of G1 and G2, defined by the ciphersuite different from BP1 and BP2.
pub static P1: Lazy<G1> = Lazy::new(|| (G1::generator() * Fr::from(2)).into());
pub static P2: Lazy<G2> = Lazy::new(|| (G2::generator() * Fr::from(3)).into());

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#section-7
pub const CIPHERSUITE_ID: &[u8] = b"BBS_QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_";
pub const SEED_DST: &[u8] = b"BBS_QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_H2G_HM2S_SIG_GENERATOR_SEED_";
pub const GENERATOR_DST: &[u8] = b"BBS_QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_H2G_HM2S_SIG_GENERATOR_DST_";
pub const GENERATOR_SEED: &[u8] = b"BBS_QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_H2G_HM2S_BP_MESSAGE_GENERATOR_SEED";
