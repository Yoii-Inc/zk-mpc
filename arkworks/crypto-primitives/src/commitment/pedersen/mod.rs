use crate::{Error, Vec};
use ark_ec::ProjectiveCurve;
use ark_ff::{bytes::ToBytes, BitIteratorLE, Field, FpParameters, PrimeField, ToConstraintField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::io::Result as IoResult;
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;
use ark_std::{PubUniformRand, UniformRand};
use mpc_trait::MpcWire;
use serde::{Deserialize, Serialize};

use super::CommitmentScheme;

pub use crate::crh::pedersen::Window;
use crate::crh::{pedersen, CRH};

#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize)]
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
#[derive(CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize)]
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

impl<C: ProjectiveCurve, W: Window> CommitmentScheme for Commitment<C, W> {
    type Parameters = Parameters<C>;
    type Randomness = Randomness<C>;
    type Output = C::Affine;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        let time = start_timer!(|| format!(
            "PedersenCOMM::Setup: {} {}-bit windows; {{0,1}}^{{{}}} -> C",
            W::NUM_WINDOWS,
            W::WINDOW_SIZE,
            W::NUM_WINDOWS * W::WINDOW_SIZE
        ));
        let num_powers = <C::ScalarField as PrimeField>::Params::MODULUS_BITS as usize;
        let randomness_generator = pedersen::CRH::<C, W>::generator_powers(num_powers, rng);
        let generators = pedersen::CRH::<C, W>::create_generators(rng);
        end_timer!(time);

        Ok(Self::Parameters {
            randomness_generator,
            generators,
        })
    }

    fn commit(
        parameters: &Self::Parameters,
        input: &[u8],
        randomness: &Self::Randomness,
    ) -> Result<Self::Output, Error> {
        let commit_time = start_timer!(|| "PedersenCOMM::Commit");
        // If the input is too long, return an error.
        if input.len() > W::WINDOW_SIZE * W::NUM_WINDOWS {
            panic!("incorrect input length: {:?}", input.len());
        }
        // Pad the input to the necessary length.
        let mut padded_input = Vec::with_capacity(input.len());
        let mut input = input;
        if (input.len() * 8) < W::WINDOW_SIZE * W::NUM_WINDOWS {
            padded_input.extend_from_slice(input);
            let padded_length = (W::WINDOW_SIZE * W::NUM_WINDOWS) / 8;
            padded_input.resize(padded_length, 0u8);
            input = padded_input.as_slice();
        }
        assert_eq!(parameters.generators.len(), W::NUM_WINDOWS);

        // Invoke Pedersen CRH here, to prevent code duplication.

        let crh_parameters = pedersen::Parameters {
            generators: parameters.generators.clone(),
        };
        let mut result: C = pedersen::CRH::<C, W>::evaluate(&crh_parameters, &input)?.into();
        let randomize_time = start_timer!(|| "Randomize");

        // Compute h^r.
        for (bit, power) in BitIteratorLE::new(randomness.0.into_repr())
            .into_iter()
            .zip(&parameters.randomness_generator)
        {
            if bit {
                result += power
            }
        }
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
