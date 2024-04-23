use ark_ff::bytes::ToBytes;
use ark_std::hash::Hash;
use ark_std::rand::Rng;

pub mod pedersen;

use ark_crypto_primitives::Error;

pub mod constraints;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
pub use constraints::*;

pub trait CRH {
    const INPUT_SIZE_BITS: usize;

    type Output: ToBytes
        + Clone
        + Eq
        + core::fmt::Debug
        + Hash
        + Default
        + CanonicalSerialize
        + CanonicalDeserialize;
    type Parameters: Clone + Default;
    type Input;

    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error>;
    fn evaluate(parameters: &Self::Parameters, input: &Self::Input) -> Result<Self::Output, Error>;
}

pub trait TwoToOneCRH {
    /// The bit size of the left input.
    const LEFT_INPUT_SIZE_BITS: usize;
    /// The bit size of the right input.
    const RIGHT_INPUT_SIZE_BITS: usize;

    type Output: ToBytes
        + Clone
        + Eq
        + core::fmt::Debug
        + Hash
        + Default
        + CanonicalSerialize
        + CanonicalDeserialize;
    type Parameters: Clone + Default;
    type Input;

    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error>;
    /// Evaluates this CRH on the left and right inputs.
    ///
    /// # Panics
    ///
    /// If `left_input.len() != Self::LEFT_INPUT_SIZE_BITS`, or if
    /// `right_input.len() != Self::RIGHT_INPUT_SIZE_BITS`, then this method panics.
    fn evaluate(
        parameters: &Self::Parameters,
        left_input: &Self::Input,
        right_input: &Self::Input,
    ) -> Result<Self::Output, Error>;
}
