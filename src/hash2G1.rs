
use ark_bn254::{fr::Fr, fq::Fq, G1Affine as G1, g1::G1Affine, g1::G1_GENERATOR_X, g1::G1_GENERATOR_Y, G1Projective, G2Projective};
use ark_ff::{LegendreSymbol, Field, *};
// use ark_ec::*;
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

        if dst.len() > 255 {
            panic!("dst size is invalid");
        }

        let b_0 = Sha256::new()
            .chain_update([0u8; 64])    // s_in_bytes for sha256 = 64
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
            let mut tmp = GenericArray::<u8, U32>::default();
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

	//constants
	//c1 = g(Z)
	//c2 = -Z / 2
	//c3 = sqrt(-g(Z) * (3 * Z² + 4 * A))     # sgn0(c3) MUST equal 0
	//c4 = -4 * g(Z) / (3 * Z² + 4 * A)

	// Z := fp.Element{15230403791020821917, 754611498739239741, 7381016538464732716, 1011752739694698287}
	// c1 := fp.Element{1248766071674976557, 10548065924188627562, 16242874202584236114, 560012691975822483}
	// c2 := fp.Element{12997850613838968789, 14304628359724097447, 2950087706404981016, 1237622763554136189}
	// c3 := fp.Element{8972444824031832946, 5898165201680709844, 10690697896010808308, 824354360198587078}
	// c4 := fp.Element{12077013577332951089, 1872782865047492001, 13514471836495169457, 415649166299893576}

    let z: Fq = Fq::from_bytes32(
        GenericArray::<u8, U32>::clone_from_slice(
            &vec![14, 10, 119, 193, 154, 7, 223, 47, 102, 110, 163, 111, 120, 121, 70, 44, 10, 120, 235, 40, 245, 199, 11, 61, 211, 93, 67, 141, 197, 143, 13, 157]
            )
        );
    
    let c1: Fq = Fq::from_bytes32(
        GenericArray::<u8, U32>::clone_from_slice(
            &vec![7, 197, 144, 147, 134, 237, 220, 147, 225, 106, 72, 7, 96, 99, 192, 82, 146, 98, 66, 18, 110, 170, 98, 106, 17, 84, 130, 32, 61, 191, 57, 45]
            )
        );

    let c2: Fq = Fq::from_bytes32(
        GenericArray::<u8, U32>::clone_from_slice(
            &vec! [17, 44, 235, 88, 163, 148, 224, 125, 40, 240, 209, 35, 132, 132, 9, 24, 198, 132, 63, 180, 57, 85, 95, 167, 180, 97, 164, 68, 137, 118, 247, 213]
            )
        );
    
    let c3: Fq = Fq::from_bytes32(
        GenericArray::<u8, U32>::clone_from_slice(
            &vec! [11, 112, 177, 236, 72, 174, 98, 198, 148, 92, 253, 24, 60, 189, 123, 244, 81, 218, 126, 0, 72, 191, 184, 212, 124, 132, 135, 7, 135, 53, 171, 114]
            )
        );

    let c4: Fq = Fq::from_bytes32(
        GenericArray::<u8, U32>::clone_from_slice(
            &vec! [5, 196, 174, 182, 236, 126, 15, 72, 187, 141, 12, 136, 85, 80, 199, 177, 25, 253, 118, 23, 228, 152, 21, 161, 167, 154, 43, 220, 160, 128, 8, 49]
            )
        );

    let mut tv1: Fq = u.square();       //    1.  tv1 = u²
    tv1 = tv1 * c1;                     //    2.  tv1 = tv1 * c1
    let tv2: Fq = Fq::from(1) + tv1;    //    3.  tv2 = 1 + tv1
    tv1 = Fq::from(1) - tv1;            //    4.  tv1 = 1 - tv1
    let mut tv3: Fq = tv1 * tv2;        //    5.  tv3 = tv1 * tv2 
    
    tv3 = tv3.inverse().unwrap();       //    6.  tv3 = inv0(tv3)
    let mut tv4: Fq = u * tv1;          //    7.  tv4 = u * tv1  
    tv4 = tv4 * tv3;                    //    8.  tv4 = tv4 * tv3
    tv4 = tv4 * c3;                     //    9.  tv4 = tv4 * c3
    let x1: Fq = c2 - tv4;              //    10.  x1 = c2 - tv4
    
    let mut gx1: Fq = x1.square();      //    11. gx1 = x1²
    //12. gx1 = gx1 + A  It is crucial to include this step if the curve has nonzero A coefficient.
    gx1 = gx1 * x1;                     //    13. gx1 = gx1 * x1    
    gx1 = gx1 + Fq::from(3);            //    14. gx1 = gx1 + B

    let gx1NotSquare: i32 = if gx1.legendre().is_qr() {0} else {-1};    //    15.  e1 = is_square(gx1)
    // gx1NotSquare = 0 if gx1 is a square, -1 otherwise

    let x2: Fq = c2 + tv4;              //    16.  x2 = c2 + tv4
    let mut gx2: Fq = x2.square();      //    17. gx2 = x2²
    //    18. gx2 = gx2 + A     See line 12
    gx2 = gx2 * x2;                     //    19. gx2 = gx2 * x2
    gx2 = gx2 + Fq::from(3);            //    20. gx2 = gx2 + B
	
    #[allow(non_snake_case)]
    let gx2NotSquare: i32 = if gx2.legendre().is_qr() {0} else {-1}; // gx2Square = 0 if gx2 is a square, -1 otherwise

    #[allow(non_snake_case)]
    let gx1SquareOrGx2Not = gx2NotSquare & !gx1NotSquare;       //  21.  e2 = is_square(gx2) AND NOT e1   # Avoid short-circuit logic ops

    let mut x3: Fq = tv2.square();      //    22.  x3 = tv2²
    x3 = x3 * tv3;                      //    23.  x3 = x3 * tv3
    x3 = x3.square();                   //    24.  x3 = x3²
    x3 = x3 * c4;                       //    25.  x3 = x3 * c4

    x3 = x3 + z;                        //    26.  x3 = x3 + Z
    let mut x: Fq = Fq::from(0);  
    // x = ConditionallySelectable::conditional_select(&x1, &x3, gx1NotSquare);  
    //NOTE!!! must be replaced by conditional_select
    //TODO: ConditionalSelect for Fq

    if gx1.legendre().is_qr() { x = x1 } else {x = x3}  //    27.   x = CMOV(x3, x1, e1)   # x = x1 if gx1 is square, else x = x3
	// Select x1 iff gx1 is square iff gx1NotSquare = 0

    if gx2.legendre().is_qr() && !gx1.legendre().is_qr() { x = x2 } //    28.   x = CMOV(x, x2, e2)    # x = x2 if gx2 is square and gx1 is not
	// Select x2 iff gx2 is square and gx1 is not, iff gx1SquareOrGx2Not = 0
    
    let mut gx = x.square();    //    29.  gx = x²
    //    30.  gx = gx + A
    gx = gx * x;                //    31.  gx = gx * x
    gx = gx + Fq::from(3);      //    32.  gx = gx + B
    
    let mut y: Fq = gx.sqrt().unwrap();     //    33.   y = sqrt(gx)

    #[allow(non_snake_case)]
    let signsNotEqual = g1Sgn0(u) == g1Sgn0(y);

    tv1 = Fq::from(0) - y;
    //TODO: conditionallySelect
    if !signsNotEqual {y = y} else {y = tv1}
    G1::new(x, y)

    //TODO: currenctly hash2curve does not work
    // Returning random curve point from hash2curve
    // Implementation will be done later
    // generate_random()
    
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
