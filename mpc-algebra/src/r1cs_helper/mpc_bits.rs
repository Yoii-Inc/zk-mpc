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

/// Specifies constraints for conversion to a little-endian byte representation
/// of `self`.
pub trait MpcToBytesGadget<F: PrimeField + SquareRootField> {
    /// Outputs a canonical, little-endian, byte decomposition of `self`.
    ///
    /// This is the correct default for 99% of use cases.
    fn to_bytes(&self) -> Result<Vec<MpcUInt8<F>>, SynthesisError>;

    /// Outputs a possibly non-unique byte decomposition of `self`.
    ///
    /// If you're not absolutely certain that your usecase can get away with a
    /// non-canonical representation, please use `self.to_bytes(cs)` instead.
    fn to_non_unique_bytes(&self) -> Result<Vec<MpcUInt8<F>>, SynthesisError> {
        self.to_bytes()
    }
}

impl<F: PrimeField + SquareRootField> MpcToBytesGadget<F> for [MpcUInt8<F>] {
    fn to_bytes(&self) -> Result<Vec<MpcUInt8<F>>, SynthesisError> {
        Ok(self.to_vec())
    }
}

impl<'a, F: PrimeField + SquareRootField, T: 'a + MpcToBytesGadget<F>> MpcToBytesGadget<F>
    for &'a T
{
    fn to_bytes(&self) -> Result<Vec<MpcUInt8<F>>, SynthesisError> {
        (*self).to_bytes()
    }
}

impl<'a, F: PrimeField + SquareRootField> MpcToBytesGadget<F> for &'a [MpcUInt8<F>] {
    fn to_bytes(&self) -> Result<Vec<MpcUInt8<F>>, SynthesisError> {
        Ok(self.to_vec())
    }
}
