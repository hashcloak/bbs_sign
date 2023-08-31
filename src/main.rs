pub mod key_gen;
pub mod traits_helper;
pub mod hash2G1;
// use ark_bn254::{fq::Fq, fq2::Fq2, fr::Fr, fr::FrConfig, Bn254, Fq12, G1Projective as G1, G2Projective as G2};
// use sha256::{digest, try_digest};
use ark_bn254::{fq::Fq, fq2::Fq2, fr::Fr, Bn254, Fq12, G1Affine as G1, G2Affine as G2, Config, g1::{G1_GENERATOR_X, G1Affine}, g1::G1_GENERATOR_Y, G1Projective};

// use crypto_bigint::{U384, U512};
// use num_bigint::{BigUint};
// use ark_ff::{fields::{Fp256, MontBackend, MontConfig}, Zero};
// use hash2field::*;
use digest::generic_array::{typenum::Unsigned, ArrayLength, GenericArray, typenum::U64};
// use num_integer::Integer;
// use digest::consts::U32;
// use digest::generic_array::{typenum::U48};
use key_gen::*;
// use traits_helper::*;
// use ark_ec::*;
// use crate::traits_helper::Hash2FieldBN254;
use hash2G1::*;

fn main() {

    println!("{:?}", generate_keypair());
    // let sum = G1::new_unchecked(G1_GENERATOR_X, G1_GENERATOR_Y) + G1::new_unchecked(G1_GENERATOR_X, G1_GENERATOR_Y);
    // let sum_affine: G1 = sum.into();
    // println!("{:?}", sum_affine);
    // println!("Expand Message: {:?}", Fq::expand_message(&[1,2,3,4,5,6,7,8,9,10], &[1,2,3,4,5,6,7,8,9,10]));
    let u = Fq::hash_to_field(b"abc", b"QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_");
    println!("{:?}", u[0]);
    println!("{:?}", u[1])
    // println!("Hash2field: {:?}", Fq::hash_to_field(&[97,98,99], b"QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_NU_"));
    // println!("{:?}", hash2G1::MapToCurve1(u[1]));
    // println!("{:?}", std::any::type_name::<GenericArray::<u8, U64>>() );
}


