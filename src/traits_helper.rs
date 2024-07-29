use std::usize;
use ark_bn254::{fr::Fr, fq::Fq};
use num_bigint::BigUint;
use digest::generic_array::GenericArray;
use num_integer::Integer;
use digest::generic_array::typenum::U32;
pub use sha2::{Sha256, digest::Digest};
use subtle::{Choice, ConditionallySelectable};

pub trait From {
    fn from_bytes32(data: GenericArray::<u8, U32>) -> Self;
}

impl From for Fr {
    fn from_bytes32(bytes: GenericArray<u8, U32>) -> Self {
    Fr::from(BigUint::from_bytes_be(bytes.as_slice()))
    }
}

impl From for Fq {
    fn from_bytes32(bytes: GenericArray<u8, U32>) -> Self {
        Fq::from(BigUint::from_bytes_be(bytes.as_slice()))
    }
}


pub trait FromOkm<const L: usize>: Sized {
    /// Convert a byte sequence into a scalar
    fn from_okm(data: &[u8; L]) -> Self;
}

impl<const L: usize> FromOkm<L> for Fr {
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

impl<const L: usize> FromOkm<L> for Fq {
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

pub fn expand_message(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
        
    let b_in_bytes: usize = 32;
    let ell = (len_in_bytes + b_in_bytes - 1 )/ b_in_bytes;

    if ell > 255 {
        panic!("ell was too big in expand_message_xmd");
    }

    if dst.len() > 255 {
        panic!("dst size is invalid");
    }

    let b_0 = Sha256::new()
        .chain_update([0u8; 64])    // s_in_bytes for sha256 = 64
        .chain_update(msg)
        .chain_update([(len_in_bytes >> 8) as u8, len_in_bytes as u8, 0u8])
        .chain_update(dst)
        .chain_update([dst.len() as u8])
        .finalize();

    let mut b_vals = Sha256::new()
        .chain_update(&b_0[..])
        .chain_update([1u8])
        .chain_update(dst)
        .chain_update([dst.len() as u8])
        .finalize();

    let mut buf = [0u8; 4 * 48];
    let mut offset = 0;

    for i in 1..ell {
        // b_0 XOR b_(idx - 1)
        let mut tmp = GenericArray::<u8, U32>::default();
        b_0.iter()
            .zip(&b_vals[..])
            .enumerate()
            .for_each(|(j, (b0val, bi1val))| tmp[j] = b0val ^ bi1val);
        for b in b_vals {
            buf[offset % len_in_bytes].conditional_assign(
                &b,
                Choice::from(if offset < len_in_bytes { 1 } else { 0 }),
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
        buf[offset % len_in_bytes]
        .conditional_assign(&b, Choice::from(if offset < len_in_bytes { 1 } else { 0 }));
        offset += 1;
    }
    buf.into()
}

//TODO: len_in_bytes should be 48?
pub fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Fr {
    let uniform_bytes = expand_message(msg, dst, 48);
    let data: &[u8; 48] = &uniform_bytes[0..48].try_into().unwrap();
    Fr::from_okm(data)
}
