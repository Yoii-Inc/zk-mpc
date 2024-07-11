use crate::encryption::constraints::AsymmetricEncryptionGadget;

use ark_crypto_primitives::encryption::elgamal::{
    constraints::{
        ConstraintF, ElGamalEncGadget, OutputVar, ParametersVar, PlaintextVar, PublicKeyVar,
        RandomnessVar,
    },
    ElGamal,
};
use ark_ec::ProjectiveCurve;
use ark_ff::PrimeField;

use ark_r1cs_std::groups::{CurveVar, GroupOpsBounds};
use ark_relations::r1cs::SynthesisError;

impl<C, GG> AsymmetricEncryptionGadget<ElGamal<C>, ConstraintF<C>> for ElGamalEncGadget<C, GG>
where
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
    ConstraintF<C>: PrimeField,
{
    type OutputVar = OutputVar<C, GG>;
    type ParametersVar = ParametersVar<C, GG>;
    type PlaintextVar = PlaintextVar<C, GG>;
    type PublicKeyVar = PublicKeyVar<C, GG>;
    type RandomnessVar = RandomnessVar<ConstraintF<C>>;

    fn encrypt(
        parameters: &Self::ParametersVar,
        message: &Self::PlaintextVar,
        randomness: &Self::RandomnessVar,
        public_key: &Self::PublicKeyVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        <Self as AsymmetricEncryptionGadget<ElGamal<C>, ConstraintF<C>>>::encrypt(
            parameters, message, randomness, public_key,
        )
    }
}
