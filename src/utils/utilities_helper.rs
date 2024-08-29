use ark_bn254::Fr;
use ark_ff::{Field, PrimeField, BigInt};
use num_bigint::BigUint;
use num_integer::Integer;
use sha2::{Sha256, digest::Digest};
use subtle::{Choice, ConditionallySelectable};
use ark_bls12_381::Fr as FrBls12_381;
use digest::generic_array::{
    GenericArray, 
    typenum::U32
};

pub trait FromOkm<const L: usize, F: Field>: Sized {
    /// Convert a byte sequence into a scalar
    fn from_okm(data: &[u8; L]) -> Self;
}

impl<const L: usize, F: Field> FromOkm<L, F> for Fr {
    fn from_okm(data: &[u8; L]) -> Self {
        let p = BigUint::from_bytes_be(
            &hex::decode("30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001")
                .unwrap(),
        );

        let mut x = BigUint::from_bytes_be(&data[..]);
            x = x.mod_floor(&p);

            Fr::from(x)
    }
}

#[allow(non_snake_case)]
impl<const L: usize, F: Field> FromOkm<L, F> for FrBls12_381 {
    fn from_okm(data: &[u8; L]) -> Self {

        const F_2_192_BIG_INT: BigInt<4> = BigInt::new([
            0x59476ebc41b4528fu64,
            0xc5a30cb243fcc152u64,
            0x2b34e63940ccbd72u64,
            0x1e179025ca247088u64,
        ]);

        let F_2_192 = FrBls12_381::new(F_2_192_BIG_INT);
        
        let mut elm_array = [0u8; 32];
        elm_array[8..].copy_from_slice(data[0..24].as_ref());

        let mut elm = FrBls12_381::from_be_bytes_mod_order(&elm_array);
        elm = elm * F_2_192;
        
        let mut elm_array = [0u8; 32];
        elm_array[8..].copy_from_slice(data[24..48].as_ref());
        let elm2 = FrBls12_381::from_be_bytes_mod_order(&elm_array);

        elm + elm2
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


