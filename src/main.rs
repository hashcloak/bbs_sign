pub mod key_gen;
pub mod traits_helper;

// use ark_bn254::{fq::Fq, fq2::Fq2, fr::Fr, fr::FrConfig, Bn254, Fq12, G1Projective as G1, G2Projective as G2};
// use sha256::{digest, try_digest};
use ark_bn254::{fq::Fq, fq2::Fq2, fr::Fr, Bn254, Fq12, G1Affine as G1, G2Affine as G2, Config, g1::{G1_GENERATOR_X, G1Affine}, g1::G1_GENERATOR_Y, G1Projective};

// use crypto_bigint::{U384, U512};
// use num_bigint::{BigUint};
// use ark_ff::{fields::{Fp256, MontBackend, MontConfig}, Zero};
// use hash2field::*;
// use digest::generic_array::{typenum::Unsigned, ArrayLength, GenericArray};
// use num_integer::Integer;
// use digest::consts::U32;
// use digest::generic_array::{typenum::U48};
use key_gen::*;
use traits_helper::*;
// use ark_ec::*;
// use crate::traits_helper::Hash2FieldBN254;


fn main() {

    println!("{:?}", generate_keypair());
    // let sum = G1::new_unchecked(G1_GENERATOR_X, G1_GENERATOR_Y) + G1::new_unchecked(G1_GENERATOR_X, G1_GENERATOR_Y);
    // let sum_affine: G1 = sum.into();
    // println!("{:?}", sum_affine);
    println!("Expand Message: {:?}", Fq::expand_message(&[1,2,3,4,5,6,7,8,9,10], &[1,2,3,4,5,6,7,8,9,10]));
    // let u = Fq::hash_to_field(&[1,2,3,4,5,6,7,8,9,10], &[1,2,3,4,5,6,7,8,9,10]);
    println!("Hash2field: {:?}", Fq::hash_to_field(&[1,2,3,4,5,6,7,8,9,10], &[1,2,3,4,5,6,7,8,9,10]));
    
    // println!("{:?}", ark_ec::hashing::HashToCurve::hash(&sum_affine, &[1,2,3,4,5,6,7,8,9,10]));
}


