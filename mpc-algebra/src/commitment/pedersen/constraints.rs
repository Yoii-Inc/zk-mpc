use crate::mpc_primitives::ModulusConversion;
use crate::{
    commitment::{
        constraints::CommitmentGadget,
        pedersen::{Commitment, Input, Parameters, Randomness},
    },
    mpc_primitives,
};

use crate::crh::pedersen::Window;

// use ark_crypto_primitives::{
//     commitment::pedersen::{Commitment, Parameters, Randomness},
//     crh::pedersen::Window,
// };
use ark_ec::ProjectiveCurve;
use ark_ff::BigInteger;
use ark_ff::{
    fields::{Field, PrimeField},
    SquareRootField, Zero,
};
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_relations::r1cs::{Namespace, SynthesisError};
use mpc_trait::MpcWire;

use tokio::task::block_in_place;

// use ark_r1cs_std::prelude::*;
use crate::groups::GroupOpsBounds;

use crate::mpc_primitives::BitDecomposition;
use crate::r1cs_helper::groups::MpcCurveVar;
use crate::r1cs_helper::mpc_bits::MpcToBitsGadget;
use crate::wire::boolean_field::BooleanWire;
use crate::MpcBoolean;

use core::{borrow::Borrow, marker::PhantomData};
use derivative::Derivative;

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

#[derive(Clone, Debug)]
pub struct InputVar<F: PrimeField>(Vec<MpcBoolean<F>>);

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
    <C as ProjectiveCurve>::ScalarField:
        mpc_primitives::BitDecomposition + mpc_primitives::ModulusConversion<ConstraintF<C>>,
{
    type OutputVar = GG;
    type ParametersVar = ParametersVar<C, GG>;
    type RandomnessVar = RandomnessVar<ConstraintF<C>>;
    type InputVar = InputVar<ConstraintF<C>>;

    #[tracing::instrument(target = "r1cs", skip(parameters, r))]
    fn commit(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
        r: &Self::RandomnessVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        assert!((input.0.len()) <= (W::WINDOW_SIZE * W::NUM_WINDOWS));

        let mut padded_input: Vec<MpcBoolean<ConstraintF<C>>> = input.0.clone();
        // Pad if input length is less than `W::WINDOW_SIZE * W::NUM_WINDOWS`.
        if (input.0.len()) < W::WINDOW_SIZE * W::NUM_WINDOWS {
            let current_length = input.0.len();
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
    <C as ark_ec::ProjectiveCurve>::ScalarField:
        mpc_primitives::BitDecomposition + ModulusConversion<F>,
{
    fn new_variable<T: Borrow<Randomness<C>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let r = f().map(|r| r.borrow().0).unwrap_or(C::ScalarField::zero());

        let bits_r = if r.is_shared() {
            // shared
            let bits = r
                .sync_bit_decomposition()
                .iter()
                .map(|b| b.field().sync_modulus_conversion())
                .collect::<Vec<_>>();
            bits
        } else {
            // public
            r.into_repr()
                .to_bits_le()
                .iter()
                .map(|b| F::from(*b))
                .collect::<Vec<_>>()
        };

        // padding
        let mut bits_r = bits_r;
        for _ in bits_r.len()..F::BigInt::NUM_LIMBS * 64 {
            bits_r.push(F::zero());
        }

        match mode {
            AllocationMode::Constant => unimplemented!(),
            AllocationMode::Input => MpcBoolean::new_input_vec(cs, &bits_r).map(Self),
            AllocationMode::Witness => MpcBoolean::new_witness_vec(cs, &bits_r).map(Self),
        }
    }
}

impl<C, F> AllocVar<Input<C>, F> for InputVar<F>
where
    C: ProjectiveCurve,
    F: PrimeField,
    <C as ark_ec::ProjectiveCurve>::ScalarField:
        mpc_primitives::BitDecomposition + ModulusConversion<F>,
{
    fn new_variable<T: Borrow<Input<C>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let x = f().map(|x| x.borrow().0).unwrap_or(C::ScalarField::zero());

        let bits_x = block_in_place(|| {
            let decomposed = tokio::runtime::Handle::current().block_on(x.bit_decomposition());
            decomposed
                .iter()
                .map(|b| tokio::runtime::Handle::current().block_on(b.field().modulus_conversion()))
                .collect::<Vec<_>>()
        });

        let bits_x = x
            .sync_bit_decomposition()
            .iter()
            .map(|b| b.field().sync_modulus_conversion())
            .collect::<Vec<_>>();

        // padding
        let mut bits_x = bits_x;
        for _ in bits_x.len()..F::BigInt::NUM_LIMBS * 64 {
            bits_x.push(F::zero());
        }

        match mode {
            AllocationMode::Constant => unimplemented!(),
            AllocationMode::Input => MpcBoolean::new_input_vec(cs, &bits_x).map(Self),
            AllocationMode::Witness => MpcBoolean::new_witness_vec(cs, &bits_x).map(Self),
        }
    }
}
