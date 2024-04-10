use crate::{commitment::CommitmentScheme, FieldShare};
use ark_ff::PrimeField;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;
use core::fmt::Debug;

pub trait CommitmentGadget<C: CommitmentScheme, ConstraintF: PrimeField, S: FieldShare<ConstraintF>>
{
    type InputVar;
    type OutputVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + AllocVar<C::Output, ConstraintF>
        + R1CSVar<ConstraintF>
        + Clone
        + Sized
        + Debug;
    type ParametersVar: AllocVar<C::Parameters, ConstraintF> + Clone;
    type RandomnessVar: AllocVar<C::Randomness, ConstraintF> + Clone;

    fn commit(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
        r: &Self::RandomnessVar,
    ) -> Result<Self::OutputVar, SynthesisError>;
}
