use ark_ff::{BitIteratorBE, Field, PrimeField, SquareRootField};
use ark_r1cs_std::{alloc::AllocVar, R1CSVar};
use ark_relations::r1cs::SynthesisError;
use sha2::digest::generic_array::typenum::SquareRoot;

use core::{
    fmt::Debug,
    ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign},
};

use crate::{FieldShare, MpcBoolean, MpcCondSelectGadget, MpcEqGadget, MpcToBitsGadget};

pub trait FieldOpsBounds<'a, F, T: 'a>:
    Sized
    + Add<&'a T, Output = T>
    + Sub<&'a T, Output = T>
    + Mul<&'a T, Output = T>
    + Add<T, Output = T>
    + Sub<T, Output = T>
    + Mul<T, Output = T>
    + Add<F, Output = T>
    + Sub<F, Output = T>
    + Mul<F, Output = T>
{
}

/// A variable representing a field. Corresponds to the native type `F`.
pub trait FieldVar<F: Field, ConstraintF: PrimeField + SquareRootField, S: FieldShare<ConstraintF>>:
    'static
    + Clone
    + From<MpcBoolean<ConstraintF, S>>
    + R1CSVar<ConstraintF, Value = F>
    + MpcEqGadget<ConstraintF, S>
    + MpcToBitsGadget<ConstraintF, S>
    + AllocVar<F, ConstraintF>
    // + ToBytesGadget<ConstraintF>
    + MpcCondSelectGadget<ConstraintF, S>
    + for<'a> FieldOpsBounds<'a, F, Self>
    + for<'a> AddAssign<&'a Self>
    + for<'a> SubAssign<&'a Self>
    + for<'a> MulAssign<&'a Self>
    + AddAssign<Self>
    + SubAssign<Self>
    + MulAssign<Self>
    + AddAssign<F>
    + SubAssign<F>
    + MulAssign<F>
    + Debug
{
    /// Returns the constant `F::zero()`.
    fn zero() -> Self;

    /// Returns a `Boolean` representing whether `self == Self::zero()`.
    fn is_zero(&self) -> Result<MpcBoolean<ConstraintF, S>, SynthesisError> {
        self.is_eq(&Self::zero())
    }

    /// Returns the constant `F::one()`.
    fn one() -> Self;

    /// Returns a `Boolean` representing whether `self == Self::one()`.
    fn is_one(&self) -> Result<MpcBoolean<ConstraintF, S>, SynthesisError> {
        self.is_eq(&Self::one())
    }

    /// Returns a constant with value `v`.
    ///
    /// This *should not* allocate any variables.
    fn constant(v: F) -> Self;

    /// Computes `self + self`.
    fn double(&self) -> Result<Self, SynthesisError> {
        Ok(self.clone() + self)
    }

    /// Sets `self = self + self`.
    fn double_in_place(&mut self) -> Result<&mut Self, SynthesisError> {
        *self += self.double()?;
        Ok(self)
    }

    /// Coputes `-self`.
    fn negate(&self) -> Result<Self, SynthesisError>;

    /// Sets `self = -self`.
    #[inline]
    fn negate_in_place(&mut self) -> Result<&mut Self, SynthesisError> {
        *self = self.negate()?;
        Ok(self)
    }

    /// Computes `self * self`.
    ///
    /// A default implementation is provided which just invokes the underlying
    /// multiplication routine. However, this method should be specialized
    /// for extension fields, where faster algorithms exist for squaring.
    fn square(&self) -> Result<Self, SynthesisError> {
        Ok(self.clone() * self)
    }

    /// Sets `self = self.square()`.
    fn square_in_place(&mut self) -> Result<&mut Self, SynthesisError> {
        *self = self.square()?;
        Ok(self)
    }

    /// Enforces that `self * other == result`.
    fn mul_equals(&self, other: &Self, result: &Self) -> Result<(), SynthesisError> {
        let actual_result = self.clone() * other;
        result.enforce_equal(&actual_result)
    }

    /// Enforces that `self * self == result`.
    fn square_equals(&self, result: &Self) -> Result<(), SynthesisError> {
        let actual_result = self.square()?;
        result.enforce_equal(&actual_result)
    }

    /// Computes `result` such that `self * result == Self::one()`.
    fn inverse(&self) -> Result<Self, SynthesisError>;

    /// Returns `(self / d)`. but requires fewer constraints than `self * d.inverse()`.
    /// It is up to the caller to ensure that `d` is non-zero,
    /// since in that case the result is unconstrained.
    fn mul_by_inverse(&self, d: &Self) -> Result<Self, SynthesisError> {
        let d_inv = if self.is_constant() || d.is_constant() {
            d.inverse()?
        } else {
            Self::new_witness(self.cs(), || Ok(d.value()?.inverse().unwrap_or(F::zero())))?
        };
        Ok(d_inv * self)
    }

    /// Computes the frobenius map over `self`.
    fn frobenius_map(&self, power: usize) -> Result<Self, SynthesisError>;

    /// Sets `self = self.frobenius_map()`.
    fn frobenius_map_in_place(&mut self, power: usize) -> Result<&mut Self, SynthesisError> {
        *self = self.frobenius_map(power)?;
        Ok(self)
    }

    /// Comptues `self^bits`, where `bits` is a *little-endian* bit-wise
    /// decomposition of the exponent.
    fn pow_le(&self, bits: &[MpcBoolean<ConstraintF, S>]) -> Result<Self, SynthesisError> {
        let mut res = Self::one();
        let mut power = self.clone();
        for bit in bits {
            let tmp = res.clone() * &power;
            res = bit.select(&tmp, &res)?;
            power.square_in_place()?;
        }
        Ok(res)
    }

    /// Computes `self^S`, where S is interpreted as an little-endian
    /// u64-decomposition of an integer.
    fn pow_by_constant<SS: AsRef<[u64]>>(&self, exp: SS) -> Result<Self, SynthesisError> {
        let mut res = Self::one();
        for i in BitIteratorBE::without_leading_zeros(exp) {
            res.square_in_place()?;
            if i {
                res *= self;
            }
        }
        Ok(res)
    }
}
