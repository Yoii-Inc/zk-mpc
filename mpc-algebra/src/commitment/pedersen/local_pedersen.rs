use std::borrow::Borrow;

use ark_crypto_primitives::{
    commitment::pedersen::{
        constraints::{CommGadget, ParametersVar, RandomnessVar},
        Commitment, Parameters, Randomness,
    },
    crh::pedersen::Window,
};
use ark_ec::ProjectiveCurve;
use ark_ff::{to_bytes, Field, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    groups::{CurveVar, GroupOpsBounds},
    uint8::UInt8,
};
use ark_relations::r1cs::{Namespace, SynthesisError};

use crate::{constraints::CommitmentGadget, CommitmentScheme};

impl<C: ProjectiveCurve, W: Window> CommitmentScheme for Commitment<C, W> {
    type Input = Vec<u8>;
    type Parameters = Parameters<C>;
    type Randomness = Randomness<C>;
    type Output = C::Affine;

    fn setup<R: rand::prelude::Rng>(
        r: &mut R,
    ) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
        <Self as ark_crypto_primitives::CommitmentScheme>::setup(r)
    }

    fn commit(
        parameters: &Self::Parameters,
        input: &Self::Input,
        r: &Self::Randomness,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        <Self as ark_crypto_primitives::CommitmentScheme>::commit(parameters, input, r)
    }
}

// constraint
type ConstraintF<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

#[derive(Clone, Debug)]
pub struct InputVar<F: PrimeField>(Vec<UInt8<F>>);

impl<C, GG, W> CommitmentGadget<Commitment<C, W>, ConstraintF<C>> for CommGadget<C, GG, W>
where
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintF<C>>,
    W: Window,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type OutputVar = GG;
    type ParametersVar = ParametersVar<C, GG>;
    type RandomnessVar = RandomnessVar<ConstraintF<C>>;
    type InputVar = InputVar<ConstraintF<C>>;

    fn commit(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
        r: &Self::RandomnessVar,
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        <Self as ark_crypto_primitives::CommitmentGadget<Commitment<C, W>, ConstraintF<C>>>::commit(
            parameters,
            input.0.as_slice(),
            r,
        )
    }
}

impl<F> AllocVar<Vec<u8>, F> for InputVar<F>
where
    F: PrimeField,
{
    fn new_variable<T: Borrow<Vec<u8>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let obj = f()?;
        let x = obj.borrow();

        match mode {
            AllocationMode::Constant => Ok(Self(UInt8::constant_vec(x))),
            AllocationMode::Input => UInt8::new_input_vec(cs, x).map(Self),
            AllocationMode::Witness => UInt8::new_witness_vec(cs, x).map(Self),
        }
    }
}
