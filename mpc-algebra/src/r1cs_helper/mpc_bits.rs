use ark_ff::{PrimeField, SquareRootField};
use ark_relations::r1cs::SynthesisError;

use crate::{FieldShare, MpcBoolean};

/// Specifies constraints for conversion to a little-endian bit representation
/// of `self`.
pub trait MpcToBitsGadget<F: PrimeField + SquareRootField, S: FieldShare<F>> {
    /// Outputs the canonical little-endian bit-wise representation of `self`.
    ///
    /// This is the correct default for 99% of use cases.
    fn to_bits_le(&self) -> Result<Vec<MpcBoolean<F, S>>, SynthesisError>;

    /// Outputs a possibly non-unique little-endian bit-wise representation of
    /// `self`.
    ///
    /// If you're not absolutely certain that your usecase can get away with a
    /// non-canonical representation, please use `self.to_bits()` instead.
    fn to_non_unique_bits_le(&self) -> Result<Vec<MpcBoolean<F, S>>, SynthesisError> {
        self.to_bits_le()
    }

    /// Outputs the canonical big-endian bit-wise representation of `self`.
    fn to_bits_be(&self) -> Result<Vec<MpcBoolean<F, S>>, SynthesisError> {
        let mut res = self.to_bits_le()?;
        res.reverse();
        Ok(res)
    }

    /// Outputs a possibly non-unique big-endian bit-wise representation of
    /// `self`.
    fn to_non_unique_bits_be(&self) -> Result<Vec<MpcBoolean<F, S>>, SynthesisError> {
        let mut res = self.to_non_unique_bits_le()?;
        res.reverse();
        Ok(res)
    }
}
