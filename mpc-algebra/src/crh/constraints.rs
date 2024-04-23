use ark_ff::{Field, PrimeField};
use core::fmt::Debug;

use crate::{
    crh::{TwoToOneCRH, CRH},
    FieldShare, MpcCondSelectGadget, MpcEqGadget, MpcUInt8,
};
use ark_relations::r1cs::SynthesisError;

use ark_r1cs_std::prelude::*;

pub trait CRHGadget<H: CRH, ConstraintF: PrimeField, S: FieldShare<ConstraintF>>: Sized {
    type OutputVar: MpcEqGadget<ConstraintF, S>
        + ToBytesGadget<ConstraintF>
        + MpcCondSelectGadget<ConstraintF, S>
        + AllocVar<H::Output, ConstraintF>
        + R1CSVar<ConstraintF>
        + Debug
        + Clone
        + Sized;

    type ParametersVar: AllocVar<H::Parameters, ConstraintF> + Clone;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &[MpcUInt8<ConstraintF, S>],
    ) -> Result<Self::OutputVar, SynthesisError>;
}

pub trait TwoToOneCRHGadget<H: TwoToOneCRH, ConstraintF: PrimeField, S: FieldShare<ConstraintF>>:
    Sized
{
    type OutputVar: MpcEqGadget<ConstraintF, S>
        + ToBytesGadget<ConstraintF>
        + MpcCondSelectGadget<ConstraintF, S>
        + AllocVar<H::Output, ConstraintF>
        + R1CSVar<ConstraintF>
        + Debug
        + Clone
        + Sized;

    type ParametersVar: AllocVar<H::Parameters, ConstraintF> + Clone;

    fn evaluate(
        parameters: &Self::ParametersVar,
        left_input: &[MpcUInt8<ConstraintF, S>],
        right_input: &[MpcUInt8<ConstraintF, S>],
    ) -> Result<Self::OutputVar, SynthesisError>;
}
