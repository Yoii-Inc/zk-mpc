use ark_ff::{PrimeField, SquareRootField};
use ark_relations::r1cs::SynthesisError;

use crate::{MpcBoolean, MpcUInt8};

/// Specifies constraints for conversion to a little-endian bit representation
/// of `self`.
pub trait MpcToBitsGadget<F: PrimeField + SquareRootField> {
    /// Outputs the canonical little-endian bit-wise representation of `self`.
    ///
    /// This is the correct default for 99% of use cases.
    fn to_bits_le(&self) -> Result<Vec<MpcBoolean<F>>, SynthesisError>;

    /// Outputs a possibly non-unique little-endian bit-wise representation of
    /// `self`.
    ///
    /// If you're not absolutely certain that your usecase can get away with a
    /// non-canonical representation, please use `self.to_bits()` instead.
    fn to_non_unique_bits_le(&self) -> Result<Vec<MpcBoolean<F>>, SynthesisError> {
        self.to_bits_le()
    }

    /// Outputs the canonical big-endian bit-wise representation of `self`.
    fn to_bits_be(&self) -> Result<Vec<MpcBoolean<F>>, SynthesisError> {
        let mut res = self.to_bits_le()?;
        res.reverse();
        Ok(res)
    }

    /// Outputs a possibly non-unique big-endian bit-wise representation of
    /// `self`.
    fn to_non_unique_bits_be(&self) -> Result<Vec<MpcBoolean<F>>, SynthesisError> {
        let mut res = self.to_non_unique_bits_le()?;
        res.reverse();
        Ok(res)
    }
}

impl<F: PrimeField + SquareRootField> MpcToBitsGadget<F> for [MpcBoolean<F>] {
    /// Outputs `self`.
    fn to_bits_le(&self) -> Result<Vec<MpcBoolean<F>>, SynthesisError> {
        Ok(self.to_vec())
    }
}

impl<F: PrimeField + SquareRootField> MpcToBitsGadget<F> for MpcUInt8<F> {
    fn to_bits_le(&self) -> Result<Vec<MpcBoolean<F>>, SynthesisError> {
        Ok(self.bits.to_vec())
    }
}

impl<F: PrimeField + SquareRootField> MpcToBitsGadget<F> for [MpcUInt8<F>] {
    /// Interprets `self` as an integer, and outputs the little-endian
    /// bit-wise decomposition of that integer.
    fn to_bits_le(&self) -> Result<Vec<MpcBoolean<F>>, SynthesisError> {
        let bits = self.iter().flat_map(|b| &b.bits).cloned().collect();
        Ok(bits)
    }
}
