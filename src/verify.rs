use ark_ec::pairing::Pairing;
use ark_ff::fields::Field;
use elliptic_curve::ops::Mul;

use crate::{
    key_gen::PublicKey,
    constants::Constants,
    sign::{
        Signature,
        SignatureError,
    },
    utils::{
        core_utilities::calculate_domain,
        interface_utilities::{ HashToG1, msg_to_scalars, create_generators },
        utilities_helper::FromOkm,
    }
};

impl <E: Pairing>PublicKey<E> {

    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-signature-verification-veri
    pub fn verify<F, H, C>(&self, signature: Signature<E, F>, header: &[u8], messages: &[&[u8]]) -> Result<bool, SignatureError> 
    where 
        F: Field+ FromOkm<48, F>,
        H: HashToG1<E>,
        C: for<'a> Constants<'a, E>,
        E::G2: Mul<F, Output = E::G2>,
        E::G1: Mul<F, Output = E::G1>,
    {
        
        let api_id = [C::CIPHERSUITE_ID, b"H2G_HM2S_"].concat();
        let message_scalars = msg_to_scalars::<E, F, 48>(messages, &api_id);
        let generators = create_generators::<E, H>(messages.len() + 1, &api_id);

        self.core_verify::<F, C, H>(signature, generators.as_slice(), header, &message_scalars, &api_id)
    }
    
    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-coreverify
    pub(crate) fn core_verify<F, C, H>(&self, signature: Signature<E, F>, generators: &[E::G1], header: &[u8], messages: &[F], api_id: &[u8]) -> Result<bool, SignatureError> 
    where 
        F: Field+ FromOkm<48, F>,
        C: for<'a> Constants<'a, E>,
        H: HashToG1<E>,
        E::G2: Mul<F, Output = E::G2>,
        E::G1: Mul<F, Output = E::G1>,
    {
        
        if messages.len() + 1 != generators.len() {
            return Err(SignatureError::InvalidMessageAndGeneratorsLength);
        }

        let domain = calculate_domain::<E, F, 48>(self, generators[0], &generators[1..], header, api_id);

        let mut b: E::G1 = C::BP1();
        b = b + generators[0] * domain;

        for i in 1..generators.len() {
            b = b + generators[i] * messages[i - 1];
        }
        
        Ok(E::pairing(signature.a, self.pk + C::BP2() * signature.e).0 * E::pairing(b, -C::BP2()).0 == E::TargetField::ONE)
    }
}
