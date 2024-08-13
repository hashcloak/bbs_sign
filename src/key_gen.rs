use ark_bn254::{ Fr, G2Affine as G2};
use ark_ec::{ CurveGroup, AffineRepr };
use zeroize::{Zeroize, ZeroizeOnDrop};
use digest::generic_array::{GenericArray, typenum::U48};
use ark_serialize::{ CanonicalSerialize, CanonicalDeserialize };
use thiserror::Error;

use crate::utils::utilities_helper::FromOkm;
use crate::utils::core_utilities::hash_to_scalar;

// Public Key
#[derive(Debug, Default,CanonicalDeserialize, CanonicalSerialize, Clone)]
pub struct PublicKey{
    pub pk: G2
}

// Secret Key
#[derive(Debug, Default, Zeroize, ZeroizeOnDrop, CanonicalDeserialize, CanonicalSerialize)]
pub struct SecretKey{
    pub sk: Fr
}

#[derive(Debug, Error)]
pub enum KeyGenError {
    #[error("Invalid key material length: expected at least 32 bytes.")]
    InvalidKeyMaterialLength,
    #[error("Invalid key info length: maximum allowed is 65535 bytes.")]
    InvalidKeyInfoLength,
    #[error("Generated secret key is invalid (zero scalar).")]
    InvalidSecretKey,
    
}

impl SecretKey {

    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-secret-key
    pub fn key_gen(key_material: &mut [u8], key_info: &[u8],key_dst: &[u8]) -> Result<Self, KeyGenError> {

        if key_material.len() < 32 {
            return Err(KeyGenError::InvalidKeyMaterialLength);
        }

        if key_info.len() > 65535 {
            return Err(KeyGenError::InvalidKeyInfoLength);
        }

        let mut derive_input = Vec::<u8>::with_capacity(key_material.len() + 2 + key_info.len());

        derive_input.extend_from_slice(key_material.as_ref());
        derive_input.extend_from_slice(&[(key_info.len() >> 8) as u8]);
        derive_input.extend_from_slice(&[(key_info.len() & 0xff) as u8]);
        derive_input.extend_from_slice(key_info.as_ref());

        let sk = hash_to_scalar(&derive_input, key_dst);

        // zeroize key_material after use
        key_material.zeroize();

        if sk == Fr::from(0) {
            return Err(KeyGenError::InvalidSecretKey);
        }

        Ok(SecretKey{
            sk
        })
    }

    pub fn sk_to_pk(&self) -> PublicKey {
        PublicKey{
            pk: (G2::generator() * self.sk).into_affine()}
    }

    // TODO: may not be required. `key_gen` implements the generation of secret key according to the spec
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#name-keygen
    // https://github.com/mattrglobal/bbs-signatures/blob/e0ae711ce8da425d671c748201106a5d1bf2bd5b/src/bls12381.rs#L354
    pub fn gen_sk(msg: &[u8]) -> Self {
        const SALT: &[u8] = b"BBS-SIG-KEYGEN-SALT-";
        // copy of `msg` with appended zero byte
        let mut msg_prime = Vec::<u8>::with_capacity(msg.as_ref().len() + 1);
        msg_prime.extend_from_slice(msg.as_ref());
        msg_prime.extend_from_slice(&[0]);
        // `result` has enough length to hold the output from HKDF expansion
        let mut result = GenericArray::<u8, U48>::default();
        assert!(hkdf::Hkdf::<sha2::Sha256>::new(Some(SALT), &msg_prime[..])
            .expand(&[0, 48], &mut result)
            .is_ok());
        let result_array: [u8;48] = result.as_slice().try_into().expect("wrong length!");
        
        Self{sk: Fr::from_okm(&result_array)}
    }

}

#[cfg(test)]
mod tests {
    use crate::key_gen::SecretKey;
    use zeroize::Zeroize;
    use ark_bn254::Fr;

    #[test]
    fn test_key_gen() {
        let mut key_material1 = [1u8; 32];
        let mut key_material2 = [1u8; 32];
        let key_dst = b"BBS-SIG-KEYGEN-SALT-";

        // key_info and key_dst are optional
        let sk1 = SecretKey::key_gen(&mut key_material1, &[], key_dst.as_slice()).unwrap();
        let sk2 = SecretKey::key_gen(&mut key_material2, &[], key_dst.as_slice()).unwrap();
        let pk1 = SecretKey::sk_to_pk(&sk1);
        let pk2 = SecretKey::sk_to_pk(&sk2);

        // check sk is non-zero
        assert!(sk1.sk != Fr::from(0));

        // check key_material is zeroid after use
        assert!(key_material1 == [0u8; 32]);
        assert!(key_material2 == [0u8; 32]);

        // check pk is generated deterministically
        assert_eq!(pk1.pk, pk2.pk);
    }

    #[test]
    fn test_zeroize() {
        let mut key_material = [1u8; 32];
        let key_dst = b"BBS-SIG-KEYGEN-SALT-";

        // key_info and key_dst are optional
        let mut sk = SecretKey::key_gen(&mut key_material, &[], key_dst.as_slice()).unwrap();
        let _ = SecretKey::sk_to_pk(&sk);
        
        // zeroize the secret key after generating public key
        sk.zeroize();

        // check sk is zeroid
        assert!(sk.sk == Fr::from(0));
        assert!(key_material == [0u8; 32]);
    }

    #[test]
    fn test_invalid_key_gen() {

        // key_material length should be at least 32
        let mut key_material = [1u8; 30];
        let key_dst = b"BBS-SIG-KEYGEN-SALT-";

        // key_info and key_dst are optional
        let sk1 = SecretKey::key_gen(&mut key_material, &[], key_dst.as_slice());
        assert!(sk1.is_err());


        let mut key_material = [1u8; 32];
        // key_info should be at most 65535
        let key_info_arr = [1u8; 65536];

        let sk1 = SecretKey::key_gen(&mut key_material, key_info_arr.as_slice(), key_dst.as_slice());
        assert!(sk1.is_err());
    }

}