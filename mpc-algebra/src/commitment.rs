use ark_ff::UniformRand;
use ark_std::rand::Rng;
use ark_std::{fmt::Debug, hash::Hash};

use ark_ff::bytes::ToBytes;

pub mod constraints;
pub mod pedersen;

use ark_crypto_primitives::Error;

pub trait CommitmentScheme {
    type Input;
    type Output: ToBytes + Clone + Default + Eq + Hash + Debug;
    type Parameters: Clone;
    type Randomness: Clone + ToBytes + Default + Eq + UniformRand + Debug;

    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error>;

    fn commit(
        parameters: &Self::Parameters,
        input: &Self::Input,
        r: &Self::Randomness,
    ) -> Result<Self::Output, Error>;
}
