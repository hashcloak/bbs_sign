use std::ops::Add;

use ark_bn254::{fr::Fr, fq::Fq, G1Affine as G1, g1::G1Affine, g1::G1_GENERATOR_X, g1::G1_GENERATOR_Y, G1Projective, G2Projective};
use ark_ff::{LegendreSymbol, Field, *};
use ark_ec::*;
use num_bigint::{BigUint};
// use ark_ff::{fields::{Fp256, MontBackend, MontConfig}, Zero};
// use hash2field::*;
use digest::generic_array::{GenericArray};
use num_integer::{Integer, sqrt};
// use digest::consts::U32;
use digest::generic_array::{typenum::U48, typenum::U64, typenum::U32};
pub use hash2field::*;
pub use sha2::{Sha256, digest::Digest};
use subtle::{Choice, ConditionallySelectable, ConditionallyNegatable};
pub use crate::key_gen::{generate_keypair, gen_sk};
use rand::prelude::*;

pub trait From {
    fn from_bytes48(data: GenericArray::<u8, U48>) -> Self;
    fn from_bytes32(data: GenericArray::<u8, U32>) -> Self;
}

impl From for Fr {
    fn from_bytes48(bytes: GenericArray<u8, U48>) -> Self {
        // BigUint::from_bytes_be(bytes.as_slice());
        Fr::from(BigUint::from_bytes_be(bytes.as_slice()))
    }

    fn from_bytes32(bytes: GenericArray<u8, U32>) -> Self {
    // BigUint::from_bytes_be(bytes.as_slice());
    Fr::from(BigUint::from_bytes_be(bytes.as_slice()))
    }
}

impl From for Fq {
    fn from_bytes48(bytes: GenericArray<u8, U48>) -> Self {
        // BigUint::from_bytes_be(bytes.as_slice());
        Fq::from(BigUint::from_bytes_be(bytes.as_slice()))
      }

    fn from_bytes32(bytes: GenericArray<u8, U32>) -> Self {
    // BigUint::from_bytes_be(bytes.as_slice());
    Fq::from(BigUint::from_bytes_be(bytes.as_slice()))
    }
}


pub trait FromOkm<const L: usize>: Sized {
    /// Convert a byte sequence into a scalar
    fn from_okm(data: &[u8; L]) -> Self;
}

const L: usize = 48;
impl FromOkm<L> for Fr {
    fn from_okm(data: &[u8; L]) -> Self {
        let p = BigUint::from_bytes_be(
            &hex::decode("30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001")
                .unwrap(),
        );

        let mut x = BigUint::from_bytes_be(&data[..]);
            x = x.mod_floor(&p);
            let t = x.to_bytes_be();
            // while t.len() < L {
            //     t.insert(0, 0u8);
            // }
            let t = GenericArray::<u8, U32>::clone_from_slice(&t);

            Fr::from_bytes32(t)
    }
}

impl FromOkm<L> for Fq {
    fn from_okm(data: &[u8; L]) -> Self {
        let p = BigUint::from_bytes_be(
            &hex::decode("30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD47")
                .unwrap(),
        );

        let mut x = BigUint::from_bytes_be(&data[..]);
            x = x.mod_floor(&p);
            let t = x.to_bytes_be();
            // while t.len() < L {
            //     t.insert(0, 0u8);
            // }
            let t = GenericArray::<u8, U32>::clone_from_slice(&t);

            Fq::from_bytes32(t)
    }
}


pub trait ExpandMsgSHA256<const LEN_IN_BYTES: usize> {
    /// Expands `msg` to the required number of bytes in `buf`
    fn expand_message(msg: &[u8], dst: &[u8]) -> [u8; LEN_IN_BYTES];
}

const LEN_IN_BYTES: usize = 96;
impl ExpandMsgSHA256<LEN_IN_BYTES> for Fq {
    fn expand_message(msg: &[u8], dst: &[u8]) -> [u8; LEN_IN_BYTES] {
        
        let b_in_bytes: usize = 32;
        let ell = (LEN_IN_BYTES + b_in_bytes - 1 )/ b_in_bytes;

        if ell > 255 {
            panic!("ell was too big in expand_message_xmd");
        }

        //TODO: Needs to be chnaged to actual DST
        // const DST: &[u8] = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_";

        // let mut b0 = Sha256::new();

        let b_0 = Sha256::new()
            .chain_update(GenericArray::<u8, U64>::default())
            .chain_update(msg)
            .chain_update([(LEN_IN_BYTES >> 8) as u8, LEN_IN_BYTES as u8, 0u8])
            .chain_update(dst)
            .chain_update([dst.len() as u8])
            .finalize();

        let mut b_vals = Sha256::new()
            .chain_update(&b_0[..])
            .chain_update([1u8])
            .chain_update(dst)
            .chain_update([dst.len() as u8])
            .finalize();

        let mut buf = [0u8; LEN_IN_BYTES];
        let mut offset = 0;

        for i in 1..ell {
            // b_0 XOR b_(idx - 1)
            let mut tmp = GenericArray::<u8, U64>::default();
            b_0.iter()
                .zip(&b_vals[..])
                .enumerate()
                .for_each(|(j, (b0val, bi1val))| tmp[j] = b0val ^ bi1val);
            for b in b_vals {
                buf[offset % LEN_IN_BYTES].conditional_assign(
                    &b,
                    Choice::from(if offset < LEN_IN_BYTES { 1 } else { 0 }),
                );
                offset += 1;
            }
            b_vals = Sha256::new()
                .chain_update(tmp)
                .chain_update([(i + 1) as u8])
                .chain_update(dst)
                .chain_update([dst.len() as u8])
                .finalize();
        }
        for b in b_vals {
            buf[offset % LEN_IN_BYTES]
            .conditional_assign(&b, Choice::from(if offset < LEN_IN_BYTES { 1 } else { 0 }));
            offset += 1;
        }
        buf
    }
}


pub trait Hash2FieldBN254<const COUNT: usize> {
    fn hash_to_field (msg: &[u8], dst: &[u8]) -> Vec<Self> where Self: Sized;
}


const COUNT: usize = 2;

impl Hash2FieldBN254<COUNT> for Fq {
    
    fn hash_to_field(msg: &[u8], dst: &[u8]) -> Vec<Fq> {

        /*
        - p, the characteristic of F .
        - m, the extension degree of F, m >= 1 (see immediately above).
        - L = ceil((ceil(log2(p)) + k) / 8), where k is the security
            parameter of the suite (e.g., k = 128).
         */

        let len_per_elm = 48;
        // let len_in_bytes = COUNT * len_per_elm;
        let pseudo_random_bytes = Fq::expand_message(msg, dst);
    
        let mut r = Vec::<Fq>::with_capacity(COUNT);
        for i in 0..COUNT {
            let bytes = GenericArray::<u8, U48>::from_slice(
                &pseudo_random_bytes[i * len_per_elm..(i + 1) * len_per_elm],
            );

            let x: [u8; 48] = bytes.as_slice().try_into().expect("Wrong length");

            r.push(Fq::from_okm(&x));
        }

        r
    }
}

// pub trait Hash2CurveG1 {
//     fn hash_to_curve(msg: &[u8], dst: &[u8]) -> Self;
// }


// https://github.com/ConsenSys/gnark-crypto/blob/master/ecc/bn254/hash_to_g1.go
#[allow(non_snake_case)]
pub fn MapToCurve1(u: Fq) -> G1{

	// //constants
	// //c1 = g(Z)
	// //c2 = -Z / 2
	// //c3 = sqrt(-g(Z) * (3 * Z² + 4 * A))     # sgn0(c3) MUST equal 0
	// //c4 = -4 * g(Z) / (3 * Z² + 4 * A)

	// // Z := fp.Element{15230403791020821917, 754611498739239741, 7381016538464732716, 1011752739694698287}
	// // c1 := fp.Element{1248766071674976557, 10548065924188627562, 16242874202584236114, 560012691975822483}
	// // c2 := fp.Element{12997850613838968789, 14304628359724097447, 2950087706404981016, 1237622763554136189}
	// // c3 := fp.Element{8972444824031832946, 5898165201680709844, 10690697896010808308, 824354360198587078}
	// // c4 := fp.Element{12077013577332951089, 1872782865047492001, 13514471836495169457, 415649166299893576}

    // let z: Fq = Fq::from_bytes32(
    //     GenericArray::<u8, U32>::clone_from_slice(
    //         &vec![14, 10, 119, 193, 154, 7, 223, 47, 102, 110, 163, 111, 120, 121, 70, 44, 10, 120, 235, 40, 245, 199, 11, 61, 211, 93, 67, 141, 197, 143, 13, 157]
    //         )
    //     );
    
    // let c1: Fq = Fq::from_bytes32(
    //     GenericArray::<u8, U32>::clone_from_slice(
    //         &vec![7, 197, 144, 147, 134, 237, 220, 147, 225, 106, 72, 7, 96, 99, 192, 82, 146, 98, 66, 18, 110, 170, 98, 106, 17, 84, 130, 32, 61, 191, 57, 45]
    //         )
    //     );

    // let c2: Fq = Fq::from_bytes32(
    //     GenericArray::<u8, U32>::clone_from_slice(
    //         &vec! [17, 44, 235, 88, 163, 148, 224, 125, 40, 240, 209, 35, 132, 132, 9, 24, 198, 132, 63, 180, 57, 85, 95, 167, 180, 97, 164, 68, 137, 118, 247, 213]
    //         )
    //     );
    
    // let c3: Fq = Fq::from_bytes32(
    //     GenericArray::<u8, U32>::clone_from_slice(
    //         &vec! [11, 112, 177, 236, 72, 174, 98, 198, 148, 92, 253, 24, 60, 189, 123, 244, 81, 218, 126, 0, 72, 191, 184, 212, 124, 132, 135, 7, 135, 53, 171, 114]
    //         )
    //     );

    // let c4: Fq = Fq::from_bytes32(
    //     GenericArray::<u8, U32>::clone_from_slice(
    //         &vec! [5, 196, 174, 182, 236, 126, 15, 72, 187, 141, 12, 136, 85, 80, 199, 177, 25, 253, 118, 23, 228, 152, 21, 161, 167, 154, 43, 220, 160, 128, 8, 49]
    //         )
    //     );

    // let mut tv1: Fq = u.square();
    // tv1 = tv1 * c1;
    // let tv2: Fq = Fq::from(1) + tv1;
    // println!("tv2 = {:?}", tv2);

    // tv1 = Fq::from(1) - tv1;
    // let mut tv3: Fq = tv1 * tv2;
    
    // tv3 = tv3.inverse().unwrap();
    // let mut tv4: Fq = u * tv1;
    // tv4 = tv4 * tv3;
    // tv4 = tv4 * c3;
    // let x1: Fq = c2 - tv4;
    
    // let mut gx1: Fq = x1.square();
    // gx1 = gx1 * x1;
    // gx1 = gx1 + Fq::from(3);

    // let gx1NotSquare: i32 = if gx1.legendre().is_qr() {0} else {-1};
    
    // let x2: Fq = c2 + tv4;
    // let mut gx2: Fq = x2.square();
    // gx2 = gx2 * x2;
    // gx2 = gx2 + Fq::from(3);
	// // {
	// // 	gx2NotSquare := gx2.Legendre() >> 1              // gx2Square = 0 if gx2 is a square, -1 otherwise
	// // 	gx1SquareOrGx2Not = gx2NotSquare | ^gx1NotSquare //    21.  e2 = is_square(gx2) AND NOT e1   # Avoid short-circuit logic ops
	// // }
    // // #[allow(non_snake_case)]
    // // let gx2NotSquare: i32 = if gx2.legendre().is_qr() {0} else {-1}; 

    // // #[allow(non_snake_case)]
    // // let gx1SquareOrGx2Not = gx2NotSquare | !gx1NotSquare;

    // let mut x3: Fq = tv2.square();
    // x3 = x3 * tv3;
    // x3 = x3.square();
    // x3 = x3 * c4;

    // x3 = x3 + z;
    // let mut x: Fq = Fq::from(0);
    
    // //TODO: ConditionalSelect for Fq
    // if gx1.legendre().is_qr() { x = x1 } else {x = x3}

    // if gx2.legendre().is_qr() && !gx1.legendre().is_qr() { x = x2 }
    
    // let mut gx = x.square();
    // gx = gx * x;
    // // println!("gx ={:?}", gx.legendre().is_qr());

    // gx = gx + Fq::from(3);
    
    
    // println!("gx ={:?}", gx.legendre().is_qr());
    // let mut y: Fq = gx.sqrt().unwrap();
    // // let t = gx.sqrt();
    // // let mut y = Fq::from(0);
    // // match t {
    // //     None => {
    // //         println!("error")
    // //     }
    // //     Some(a) => {
    // //         y = a;
    // //         println!("sadf {:?}", a);
    // //     }
    // // }

    // #[allow(non_snake_case)]
    // let signsNotEqual = g1Sgn0(u) == g1Sgn0(y);

    // tv1 = Fq::from(0) - y;
    // //TODO: conditionallySelect
    // if !signsNotEqual {y = y} else {y = tv1}
    // println!("x = {:?}, y = {:?}", x, y);
    // G1::new(x, y)

    //TODO: currenctly hash2curve does not work
    // Returning random curve point from hash2curve
    // Implementation will be done later
    generate_random()
    
}

#[allow(non_snake_case)]
fn g1Sgn0(x: Fq) -> u64 {
    let t: BigUint = x.into();
    *BigUint::to_bytes_be(&t).get(0).unwrap() as u64
}


//temporary for hash2curve
pub fn generate_random () -> G1 {

    let mut rng = thread_rng();
    let mut s = vec![0u8, 32];
    rng.fill_bytes(s.as_mut_slice());

    let sk = gen_sk(s.as_slice());
    let mut pk: G1 = G1::new_unchecked(G1_GENERATOR_X, G1_GENERATOR_Y);
    (pk * sk).into()

}

// impl Hash2CurveG1 for G1 {
//     fn hash_to_curve( msg: &[u8], dst: &[u8]) -> Self {
//     }
// }
