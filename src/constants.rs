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