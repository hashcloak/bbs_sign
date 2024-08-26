use ark_ec::pairing::Pairing;
use ark_ff::fields::Field;

use crate::key_gen::PublicKey;
use crate::sign::{SignatureError, Signature};
use crate::utils::core_utilities::calculate_domain;
use crate::constants::{Constants, CIPHERSUITE_ID};
use crate::utils::interface_utilities::{msg_to_scalars, HashToG1};
use crate::utils::interface_utilities::create_generators;
use crate::utils::utilities_helper;
use elliptic_curve::ops::Mul;

impl <E: Pairing>PublicKey<E> {

    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-signature-verification-veri
    pub fn verify<F: Field+ utilities_helper::FromOkm<48, F>, H: HashToG1<E>, C: Constants<E>,>(&self, signature: Signature<E, F>, header: &[u8], messages: &[&[u8]]) -> Result<bool, SignatureError> 
    
    where 
    E: Pairing,
    E::G2: Mul<F, Output = E::G2>,
    E::G1: Mul<F, Output = E::G1>,
    // E::TargetField: Mul<Fq12, Output = E::TargetField>,

    {
        
        let api_id = [CIPHERSUITE_ID, b"H2G_HM2S_"].concat();
        let message_scalars = msg_to_scalars::<E, F, 48>(messages, &api_id);
        let generators = create_generators::<E, H>(messages.len() + 1, &api_id);

        self.core_verify::<F, C, H>(signature, generators.as_slice(), header, &message_scalars, &api_id)
    }
    
    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-coreverify
    pub(crate) fn core_verify<F: Field+ utilities_helper::FromOkm<48, F>, C: Constants<E>, H: HashToG1<E>>(&self, signature: Signature<E, F>, generators: &[E::G1], header: &[u8], messages: &[F], api_id: &[u8]) -> Result<bool, SignatureError> 
    
    where 
    E: Pairing,
    E::G2: Mul<F, Output = E::G2>,
    E::G1: Mul<F, Output = E::G1>,
    {
        
        if messages.len() + 1 != generators.len() {
            return Err(SignatureError::InvalidMessageAndGeneratorsLength);
        }

        let domain = calculate_domain::<E, F, 48>(self, generators[0], &generators[1..], header, api_id);

        let mut b: E::G1 = C::bp1();
        b = b + generators[0] * domain;

        for i in 1..generators.len() {
            b = b + generators[i] * messages[i - 1];
        }
        
        Ok(E::pairing(signature.a, self.pk + C::bp2() * signature.e).0 * E::pairing(b, -C::bp2()).0 == E::TargetField::ONE)
    }
}
