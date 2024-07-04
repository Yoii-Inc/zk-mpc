use crate::commitment::CommitmentScheme;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, R1CSVar, ToBytesGadget};
use ark_relations::r1cs::SynthesisError;
use core::fmt::Debug;

pub trait CommitmentGadget<C: CommitmentScheme, ConstraintF: PrimeField> {
    type OutputVar: ToBytesGadget<ConstraintF>
        + AllocVar<C::Output, ConstraintF>
        + R1CSVar<ConstraintF>
        + Clone
        + Sized
        + Debug;
    type ParametersVar: AllocVar<C::Parameters, ConstraintF> + Clone;
    type RandomnessVar: AllocVar<C::Randomness, ConstraintF> + Clone;
    type InputVar: AllocVar<C::Input, ConstraintF> + Clone;

    fn commit(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
        r: &Self::RandomnessVar,
    ) -> Result<Self::OutputVar, SynthesisError>;
}
