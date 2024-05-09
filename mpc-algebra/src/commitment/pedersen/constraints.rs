use crate::{
    commitment::{
        constraints::CommitmentGadget,
        pedersen::{Commitment, Parameters, Randomness},
    },
    mpc_primitives, reveal, MpcUInt8, Reveal,
};

use crate::crh::pedersen::Window;

// use ark_crypto_primitives::{
//     commitment::pedersen::{Commitment, Parameters, Randomness},
//     crh::pedersen::Window,
// };
use ark_ec::ProjectiveCurve;
use ark_ff::{
    fields::{Field, PrimeField},
    to_bytes, SquareRootField, Zero,
};
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_relations::r1cs::{Namespace, SynthesisError};

// use ark_r1cs_std::prelude::*;
use crate::groups::GroupOpsBounds;

use crate::r1cs_helper::groups::MpcCurveVar;

use core::{borrow::Borrow, marker::PhantomData};
use derivative::Derivative;

use crate::{FieldShare, MpcBoolean, MpcToBitsGadget};

type ConstraintF<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

#[derive(Derivative)]
#[derivative(Clone(bound = "C: ProjectiveCurve, GG: MpcCurveVar<C, ConstraintF<C>>"))]
pub struct ParametersVar<C: ProjectiveCurve, GG: MpcCurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
    ConstraintF<C>: PrimeField + SquareRootField,
{
    pub params: Parameters<C>,
    #[doc(hidden)]
    _group_var: PhantomData<GG>,
}

#[derive(Clone, Debug)]
// pub struct RandomnessVar<F: Field>(Vec<UInt8<F>>);
pub struct RandomnessVar<F: PrimeField>(Vec<MpcBoolean<F>>);

pub struct CommGadget<C: ProjectiveCurve, GG: MpcCurveVar<C, ConstraintF<C>>, W: Window>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
    ConstraintF<C>: PrimeField + SquareRootField,
{
    #[doc(hidden)]
    _curve: PhantomData<*const C>,
    #[doc(hidden)]
    _group_var: PhantomData<*const GG>,
    #[doc(hidden)]
    _window: PhantomData<*const W>,
}

impl<C, GG, W> CommitmentGadget<Commitment<C, W>, ConstraintF<C>> for CommGadget<C, GG, W>
where
    C: ProjectiveCurve,
    GG: MpcCurveVar<C, ConstraintF<C>>,
    W: Window,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
    ConstraintF<C>: PrimeField + SquareRootField,
    // <C as ProjectiveCurve>::ScalarField: Reveal,
    <C as ProjectiveCurve>::ScalarField:
        mpc_primitives::BitDecomposition<Output = Vec<<C as ProjectiveCurve>::ScalarField>>,
    // <C as reveal::Reveal>::Base: ProjectiveCurve,
    // <<C as ProjectiveCurve>::ScalarField as reveal::Reveal>::Base: ark_ff::PrimeField,
{
    type InputVar = Vec<MpcBoolean<ConstraintF<C>>>;
    type OutputVar = GG;
    type ParametersVar = ParametersVar<C, GG>;
    type RandomnessVar = RandomnessVar<ConstraintF<C>>;

    #[tracing::instrument(target = "r1cs", skip(parameters, r))]
    fn commit(
        parameters: &Self::ParametersVar,
        //input: &[UInt8<ConstraintF<C>>],
        input: &Self::InputVar,
        r: &Self::RandomnessVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        assert!((input.len() * 8) <= (W::WINDOW_SIZE * W::NUM_WINDOWS));

        let mut padded_input = input.to_vec();
        // Pad if input length is less than `W::WINDOW_SIZE * W::NUM_WINDOWS`.
        if (input.len()) < W::WINDOW_SIZE * W::NUM_WINDOWS {
            let current_length = input.len();
            for _ in current_length..(W::WINDOW_SIZE * W::NUM_WINDOWS) {
                padded_input.push(MpcBoolean::constant(false));
            }
        }

        assert_eq!(padded_input.len(), W::WINDOW_SIZE * W::NUM_WINDOWS);
        assert_eq!(parameters.params.generators.len(), W::NUM_WINDOWS);

        // Allocate new variable for commitment output.

        let input_in_bits = padded_input.chunks(W::WINDOW_SIZE);
        let mut result =
            GG::precomputed_base_multiscalar_mul_le(&parameters.params.generators, input_in_bits)?;

        // Compute h^r
        // let rand_bits: Vec<_> =
        //     r.0.iter()
        //         .flat_map(|byte| byte.to_bits_le().unwrap())
        //         .collect();

        let rand_bits: Vec<_> = r.0.clone();
        result.precomputed_base_scalar_mul_le(
            rand_bits
                .iter()
                .zip(&parameters.params.randomness_generator),
        )?;

        Ok(result)
    }
}

impl<C, GG> AllocVar<Parameters<C>, ConstraintF<C>> for ParametersVar<C, GG>
where
    C: ProjectiveCurve,
    GG: MpcCurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
    ConstraintF<C>: PrimeField + SquareRootField,
{
    fn new_variable<T: Borrow<Parameters<C>>>(
        _cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let params = f()?.borrow().clone();
        Ok(ParametersVar {
            params,
            _group_var: PhantomData,
        })
    }
}

impl<C, F> AllocVar<Randomness<C>, F> for RandomnessVar<F>
where
    C: ProjectiveCurve,
    F: PrimeField,
{
    fn new_variable<T: Borrow<Randomness<C>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let r = to_bytes![&f().map(|b| b.borrow().0).unwrap_or(C::ScalarField::zero())].unwrap();
        match mode {
            // AllocationMode::Constant => Ok(Self(UInt8::constant_vec(&r))),
            // AllocationMode::Input => UInt8::new_input_vec(cs, &r).map(Self),
            // AllocationMode::Witness => UInt8::new_witness_vec(cs, &r).map(Self),
            AllocationMode::Constant => todo!(),
            AllocationMode::Input => todo!(),
            AllocationMode::Witness => todo!(),
        }
    }
}
