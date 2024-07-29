use ark_bn254::{fr::Fr, fq::Fq, G1Affine as G1, g1::G1_GENERATOR_X, g1::G1_GENERATOR_Y};
use num_bigint::BigUint;
use digest::generic_array::GenericArray;
use num_integer::Integer;
use digest::generic_array::{typenum::U48, typenum::U64, typenum::U32};
pub use hash2field::*;
pub use sha2::{Sha256, digest::Digest};
use subtle::{Choice, ConditionallySelectable};
pub use crate::key_gen::{generate_keypair, gen_sk};
use rand::prelude::*;

pub trait From {
    fn from_bytes48(data: GenericArray::<u8, U48>) -> Self;
    fn from_bytes32(data: GenericArray::<u8, U32>) -> Self;
}

impl From for Fr {
    fn from_bytes48(bytes: GenericArray<u8, U48>) -> Self {
        Fr::from(BigUint::from_bytes_be(bytes.as_slice()))
    }

    fn from_bytes32(bytes: GenericArray<u8, U32>) -> Self {
    Fr::from(BigUint::from_bytes_be(bytes.as_slice()))
    }
}

impl From for Fq {
    fn from_bytes48(bytes: GenericArray<u8, U48>) -> Self {
        Fq::from(BigUint::from_bytes_be(bytes.as_slice()))
      }

    fn from_bytes32(bytes: GenericArray<u8, U32>) -> Self {
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

//temporary for hash2curve
pub fn generate_random () -> G1 {

    let mut rng = thread_rng();
    let mut s = vec![0u8, 32];
    rng.fill_bytes(s.as_mut_slice());

    let sk = gen_sk(s.as_slice());
    let pk: G1 = G1::new_unchecked(G1_GENERATOR_X, G1_GENERATOR_Y);
    (pk * sk).into()

}
