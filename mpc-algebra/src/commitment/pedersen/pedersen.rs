use ark_crypto_primitives::Error;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{bytes::ToBytes, BitIteratorLE, Field, FpParameters, PrimeField, ToConstraintField};
use ark_std::io::{Result as IoResult, Write};
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;
use ark_std::{end_timer, start_timer, One, Zero};
use ark_std::{PubUniformRand, UniformRand};
use derivative::Derivative;
use mpc_trait::MpcWire;

use crate::crh::{pedersen, pedersen::Window, CRH};
use crate::{BitDecomposition, CommitmentScheme, FieldShare, MpcField, Reveal};

// pub use ark_crypto_primitives::crh::pedersen::Window;
// use ark_crypto_primitives::crh::{pedersen, CRH};

#[derive(Clone, Debug)]
pub struct Parameters<C: ProjectiveCurve> {
    pub randomness_generator: Vec<C>,
    pub generators: Vec<Vec<C>>,
}

pub struct Commitment<C: ProjectiveCurve, W: Window> {
    group: PhantomData<C>,
    window: PhantomData<W>,
}

#[derive(Derivative)]
#[derivative(Clone, PartialEq, Debug, Eq, Default)]
pub struct Randomness<C: ProjectiveCurve>(pub C::ScalarField);

impl<C: ProjectiveCurve> UniformRand for Randomness<C> {
    #[inline]
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Randomness(UniformRand::rand(rng))
    }
}

impl<C: ProjectiveCurve> MpcWire for Randomness<C> {}

impl<C: ProjectiveCurve> PubUniformRand for Randomness<C> {
    #[inline]
    fn pub_rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Randomness(PubUniformRand::pub_rand(rng))
    }
}

impl<C: ProjectiveCurve> ToBytes for Randomness<C> {
    fn write<W: Write>(&self, writer: W) -> IoResult<()> {
        self.0.write(writer)
    }
}

impl<C: ProjectiveCurve, W: Window> CommitmentScheme for Commitment<C, W>
where
    <C as ProjectiveCurve>::ScalarField: Reveal + BitDecomposition<Output = Vec<C::ScalarField>>,
    C: Reveal,
    <C as Reveal>::Base: ProjectiveCurve,
    <C::ScalarField as Reveal>::Base: PrimeField,
{
    // Input is expected to be a vector of field elements. Each field element represents bool.
    type Input = Vec<C::ScalarField>;
    type Parameters = Parameters<C>;
    type Randomness = Randomness<C>;
    type Output = C::Affine;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        // let time = start_timer!(|| format!(
        //     "PedersenCOMM::Setup: {} {}-bit windows; {{0,1}}^{{{}}} -> C",
        //     W::NUM_WINDOWS,
        //     W::WINDOW_SIZE,
        //     W::NUM_WINDOWS * W::WINDOW_SIZE
        // ));
        let num_powers = <C::ScalarField as PrimeField>::Params::MODULUS_BITS as usize;
        let randomness_generator = pedersen::CRH::<C, W>::generator_powers(num_powers, rng);
        let generators = pedersen::CRH::<C, W>::create_generators(rng);
        // end_timer!(time);

        Ok(Self::Parameters {
            randomness_generator,
            generators,
        })
    }

    fn commit(
        parameters: &Self::Parameters,
        input: &Self::Input,
        randomness: &Self::Randomness,
    ) -> Result<Self::Output, Error> {
        let commit_time = start_timer!(|| "PedersenCOMM::Commit");
        // If the input is too long, return an error.
        if input.len() / 8 > W::WINDOW_SIZE * W::NUM_WINDOWS {
            panic!("incorrect input length: {:?}", input.len());
        }

        // check each element of input is bool if debug
        #[cfg(debug_assertions)]
        for i in input.iter() {
            let mut j = i.clone();
            j.publicize();
            assert!(j.is_zero() || j.is_one());
        }

        // Pad the input to the necessary length.
        let mut padded_input = Vec::with_capacity(input.len());
        let mut input = input;

        let padded_input_vec;
        if input.len() < W::WINDOW_SIZE * W::NUM_WINDOWS {
            padded_input.extend_from_slice(input);
            let padded_length = W::WINDOW_SIZE * W::NUM_WINDOWS;
            padded_input.resize(padded_length, <C as ProjectiveCurve>::ScalarField::zero());
            padded_input_vec = padded_input.as_slice().to_vec();
            input = &padded_input_vec;
        }
        assert_eq!(parameters.generators.len(), W::NUM_WINDOWS);

        // Invoke Pedersen CRH here, to prevent code duplication.

        let crh_parameters = pedersen::Parameters {
            generators: parameters.generators.clone(),
        };

        let mut result: C = pedersen::CRH::<C, W>::evaluate(&crh_parameters, input)?.into();
        let randomize_time = start_timer!(|| "Randomize");

        // Compute h^r.K
        let iter_bases = parameters
            .randomness_generator
            .iter()
            .map(|x| x.into_affine())
            .collect::<Vec<_>>();
        let bits = randomness.0.bit_decomposition();

        result += C::Affine::multi_scalar_mul(&iter_bases[..], &bits);

        end_timer!(randomize_time);
        end_timer!(commit_time);

        Ok(result.into())
    }
}

impl<ConstraintF: Field, C: ProjectiveCurve + ToConstraintField<ConstraintF>>
    ToConstraintField<ConstraintF> for Parameters<C>
{
    #[inline]
    fn to_field_elements(&self) -> Option<Vec<ConstraintF>> {
        Some(Vec::new())
    }
}
