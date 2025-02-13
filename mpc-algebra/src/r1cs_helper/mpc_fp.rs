use std::borrow::Borrow;

use ark_ff::{BigInteger, PrimeField, SquareRootField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    impl_ops, R1CSVar,
};
use ark_r1cs_std::{impl_bounded_ops, Assignment};
use ark_relations::{
    lc,
    r1cs::{ConstraintSystemRef, LinearCombination, Namespace, SynthesisError, Variable},
};
use ark_std::{One, Zero};

use ark_ff::FpParameters;

use crate::{
    boolean_field::BooleanWire,
    mpc_eq::MpcEqGadget,
    mpc_fields::{FieldOpsBounds, MpcFieldVar},
    mpc_select::{MpcCondSelectGadget, MpcTwoBitLookupGadget},
    BitDecomposition, EqualityZero, MpcBoolean, MpcToBitsGadget, MpcToBytesGadget, MpcUInt8,
    Reveal,
};

use tokio::runtime::Runtime;

/// Represents a variable in the constraint system whose
/// value can be an arbitrary field element.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct MpcAllocatedFp<F: PrimeField> {
    pub(crate) value: Option<F>,
    /// The allocated variable corresponding to `self` in `self.cs`.
    pub variable: Variable,
    /// The constraint system that `self` was allocated in.
    pub cs: ConstraintSystemRef<F>,
}

impl<F: PrimeField> MpcAllocatedFp<F> {
    /// Constructs a new `AllocatedFp` from a (optional) value, a low-level
    /// Variable, and a `ConstraintSystemRef`.
    pub fn new(value: Option<F>, variable: Variable, cs: ConstraintSystemRef<F>) -> Self {
        Self {
            value,
            variable,
            cs,
        }
    }
}

/// Represent variables corresponding to a field element in `F`.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub enum MpcFpVar<F: PrimeField> {
    /// Represents a constant in the constraint system, which means that
    /// it does not have a corresponding variable.
    Constant(F),
    /// Represents an allocated variable constant in the constraint system.
    Var(MpcAllocatedFp<F>),
}

impl<F: PrimeField> R1CSVar<F> for MpcFpVar<F> {
    type Value = F;

    fn cs(&self) -> ConstraintSystemRef<F> {
        match self {
            Self::Constant(_) => ConstraintSystemRef::None,
            Self::Var(a) => a.cs.clone(),
        }
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        match self {
            Self::Constant(v) => Ok(*v),
            Self::Var(v) => v.value(),
        }
    }
}

// impl<F: PrimeField> From<Boolean<F>> for FpVar<F> {
//     fn from(other: Boolean<F>) -> Self {
//         if let Boolean::Constant(b) = other {
//             Self::Constant(F::from(b as u8))
//         } else {
//             // `other` is a variable
//             let cs = other.cs();
//             let variable = cs.new_lc(other.lc()).unwrap();
//             Self::Var(AllocatedFp::new(
//                 other.value().ok().map(|b| F::from(b as u8)),
//                 variable,
//                 cs,
//             ))
//         }
//     }
// }

impl<F: PrimeField> From<MpcBoolean<F>> for MpcFpVar<F> {
    fn from(other: MpcBoolean<F>) -> Self {
        if let MpcBoolean::<F>::Constant(b) = other {
            Self::Constant(F::from(b as u8))
        } else {
            // `other` is a variable
            let cs = other.cs();
            let variable = cs.new_lc(other.lc()).unwrap();
            Self::Var(MpcAllocatedFp::new(
                other.value().ok().map(|b| F::from(b as u8)),
                variable,
                cs,
            ))
        }
    }
}

impl<F: PrimeField> From<MpcAllocatedFp<F>> for MpcFpVar<F> {
    fn from(other: MpcAllocatedFp<F>) -> Self {
        Self::Var(other)
    }
}

impl<'a, F: PrimeField> FieldOpsBounds<'a, F, Self> for MpcFpVar<F> {}
impl<'a, F: PrimeField> FieldOpsBounds<'a, F, MpcFpVar<F>> for &'a MpcFpVar<F> {}

impl<F: PrimeField> MpcAllocatedFp<F> {
    /// Constructs `Self` from a `Boolean`: if `other` is false, this outputs
    /// `zero`, else it outputs `one`.
    pub fn from(other: MpcBoolean<F>) -> Self {
        let cs = other.cs();
        let variable = cs.new_lc(other.lc()).unwrap();
        Self::new(other.value_field().ok(), variable, cs)
    }

    /// Returns the value assigned to `self` in the underlying constraint system
    /// (if a value was assigned).
    pub fn value(&self) -> Result<F, SynthesisError> {
        self.cs.assigned_value(self.variable).get()
    }

    /// Outputs `self + other`.
    ///
    /// This does not create any constraints.
    #[tracing::instrument(target = "r1cs")]
    pub fn add(&self, other: &Self) -> Self {
        let value = match (self.value, other.value) {
            (Some(val1), Some(val2)) => Some(val1 + val2),
            (..) => None,
        };

        let variable = self
            .cs
            .new_lc(lc!() + self.variable + other.variable)
            .unwrap();
        MpcAllocatedFp::new(value, variable, self.cs.clone())
    }

    /// Outputs `self - other`.
    ///
    /// This does not create any constraints.
    #[tracing::instrument(target = "r1cs")]
    pub fn sub(&self, other: &Self) -> Self {
        let value = match (self.value, other.value) {
            (Some(val1), Some(val2)) => Some(val1 - val2),
            (..) => None,
        };

        let variable = self
            .cs
            .new_lc(lc!() + self.variable - other.variable)
            .unwrap();
        MpcAllocatedFp::new(value, variable, self.cs.clone())
    }

    /// Outputs `self * other`.
    ///
    /// This requires *one* constraint.
    #[tracing::instrument(target = "r1cs")]
    pub fn mul(&self, other: &Self) -> Self {
        let product = MpcAllocatedFp::new_witness(self.cs.clone(), || {
            Ok(self.value.get()? * other.value.get()?)
        })
        .unwrap();
        self.cs
            .enforce_constraint(
                lc!() + self.variable,
                lc!() + other.variable,
                lc!() + product.variable,
            )
            .unwrap();
        product
    }

    /// Output `self + other`
    ///
    /// This does not create any constraints.
    #[tracing::instrument(target = "r1cs")]
    pub fn add_constant(&self, other: F) -> Self {
        if other.is_zero() {
            self.clone()
        } else {
            let value = self.value.map(|val| val + other);
            let variable = self
                .cs
                .new_lc(lc!() + self.variable + (other, Variable::One))
                .unwrap();
            MpcAllocatedFp::new(value, variable, self.cs.clone())
        }
    }

    /// Output `self - other`
    ///
    /// This does not create any constraints.
    #[tracing::instrument(target = "r1cs")]
    pub fn sub_constant(&self, other: F) -> Self {
        self.add_constant(-other)
    }

    /// Output `self * other`
    ///
    /// This does not create any constraints.
    #[tracing::instrument(target = "r1cs")]
    pub fn mul_constant(&self, other: F) -> Self {
        if other.is_one() {
            self.clone()
        } else {
            let value = self.value.map(|val| val * other);
            let variable = self.cs.new_lc(lc!() + (other, self.variable)).unwrap();
            MpcAllocatedFp::new(value, variable, self.cs.clone())
        }
    }

    /// Output `self + self`
    ///
    /// This does not create any constraints.
    #[tracing::instrument(target = "r1cs")]
    pub fn double(&self) -> Result<Self, SynthesisError> {
        let value = self.value.map(|val| val.double());
        let variable = self.cs.new_lc(lc!() + self.variable + self.variable)?;
        Ok(Self::new(value, variable, self.cs.clone()))
    }

    /// Output `-self`
    ///
    /// This does not create any constraints.
    #[tracing::instrument(target = "r1cs")]
    pub fn negate(&self) -> Self {
        let mut result = self.clone();
        result.negate_in_place();
        result
    }

    /// Sets `self = -self`
    ///
    /// This does not create any constraints.
    #[tracing::instrument(target = "r1cs")]
    pub fn negate_in_place(&mut self) -> &mut Self {
        if let Some(val) = self.value.as_mut() {
            *val = -(*val);
        }
        self.variable = self.cs.new_lc(lc!() - self.variable).unwrap();
        self
    }

    /// Outputs `self * self`
    ///
    /// This requires *one* constraint.
    #[tracing::instrument(target = "r1cs")]
    pub fn square(&self) -> Result<Self, SynthesisError> {
        Ok(self.mul(self))
    }

    /// Outputs `result` such that `result * self = 1`.
    ///
    /// This requires *one* constraint.
    #[tracing::instrument(target = "r1cs")]
    pub fn inverse(&self) -> Result<Self, SynthesisError> {
        let inverse = Self::new_witness(self.cs.clone(), || {
            Ok(self.value.get()?.inverse().unwrap_or_else(F::zero))
        })?;

        self.cs.enforce_constraint(
            lc!() + self.variable,
            lc!() + inverse.variable,
            lc!() + Variable::One,
        )?;
        Ok(inverse)
    }

    /// This is a no-op for prime fields.
    #[tracing::instrument(target = "r1cs")]
    pub fn frobenius_map(&self, _: usize) -> Result<Self, SynthesisError> {
        Ok(self.clone())
    }

    /// Enforces that `self * other = result`.
    ///
    /// This requires *one* constraint.
    #[tracing::instrument(target = "r1cs")]
    pub fn mul_equals(&self, other: &Self, result: &Self) -> Result<(), SynthesisError> {
        self.cs.enforce_constraint(
            lc!() + self.variable,
            lc!() + other.variable,
            lc!() + result.variable,
        )
    }

    /// Enforces that `self * self = result`.
    ///
    /// This requires *one* constraint.
    #[tracing::instrument(target = "r1cs")]
    pub fn square_equals(&self, result: &Self) -> Result<(), SynthesisError> {
        self.cs.enforce_constraint(
            lc!() + self.variable,
            lc!() + self.variable,
            lc!() + result.variable,
        )
    }

    /// Outputs the bit `self == other`.
    ///
    /// This requires three constraints.
    #[tracing::instrument(target = "r1cs")]
    pub fn is_eq(&self, other: &Self) -> Result<MpcBoolean<F>, SynthesisError> {
        Ok(self.is_neq(other)?.not())
    }

    /// Outputs the bit `self != other`.
    ///
    /// This requires three constraints.
    #[tracing::instrument(target = "r1cs")]
    pub fn is_neq(&self, other: &Self) -> Result<MpcBoolean<F>, SynthesisError> {
        unimplemented!();
        // let is_not_equal = MpcBoolean::new_witness(self.cs.clone(), || {
        //     Ok(self.value.get()? != other.value.get()?)
        // })?;
        // let multiplier = self.cs.new_witness_variable(|| {
        //     if is_not_equal.value()? {
        //         (self.value.get()? - other.value.get()?).inverse().get()
        //     } else {
        //         Ok(MpcField::<F, S>::one())
        //     }
        // })?;

        // // Completeness:
        // // Case 1: self != other:
        // // ----------------------
        // //   constraint 1:
        // //   (self - other) * multiplier = is_not_equal
        // //   => (non_zero) * multiplier = 1 (satisfied, because multiplier = 1/(self -
        // // other)
        // //
        // //   constraint 2:
        // //   (self - other) * not(is_not_equal) = 0
        // //   => (non_zero) * not(1) = 0
        // //   => (non_zero) * 0 = 0
        // //
        // // Case 2: self == other:
        // // ----------------------
        // //   constraint 1:
        // //   (self - other) * multiplier = is_not_equal
        // //   => 0 * multiplier = 0 (satisfied, because multiplier = 1
        // //
        // //   constraint 2:
        // //   (self - other) * not(is_not_equal) = 0
        // //   => 0 * not(0) = 0
        // //   => 0 * 1 = 0
        // //
        // // --------------------------------------------------------------------
        // //
        // // Soundness:
        // // Case 1: self != other, but is_not_equal = 0.
        // // --------------------------------------------
        // //   constraint 1:
        // //   (self - other) * multiplier = is_not_equal
        // //   => non_zero * multiplier = 0 (only satisfiable if multiplier == 0)
        // //
        // //   constraint 2:
        // //   (self - other) * not(is_not_equal) = 0
        // //   => (non_zero) * 1 = 0 (impossible)
        // //
        // // Case 2: self == other, but is_not_equal = 1.
        // // --------------------------------------------
        // //   constraint 1:
        // //   (self - other) * multiplier = is_not_equal
        // //   0 * multiplier = 1 (unsatisfiable)
        // self.cs.enforce_constraint(
        //     lc!() + self.variable - other.variable,
        //     lc!() + multiplier,
        //     is_not_equal.lc(),
        // )?;
        // self.cs.enforce_constraint(
        //     lc!() + self.variable - other.variable,
        //     is_not_equal.not().lc(),
        //     lc!(),
        // )?;
        // Ok(is_not_equal)
    }

    /// Enforces that self == other if `should_enforce.is_eq(&Boolean::TRUE)`.
    ///
    /// This requires one constraint.
    #[tracing::instrument(target = "r1cs")]
    pub fn conditional_enforce_equal(
        &self,
        other: &Self,
        should_enforce: &MpcBoolean<F>,
    ) -> Result<(), SynthesisError> {
        self.cs.enforce_constraint(
            lc!() + self.variable - other.variable,
            lc!() + should_enforce.lc(),
            lc!(),
        )
    }

    /// Enforces that self != other if `should_enforce.is_eq(&Boolean::TRUE)`.
    ///
    /// This requires one constraint.
    #[tracing::instrument(target = "r1cs")]
    pub fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        should_enforce: &MpcBoolean<F>,
    ) -> Result<(), SynthesisError> {
        let multiplier = Self::new_witness(self.cs.clone(), || {
            if should_enforce.value()? {
                (self.value.get()? - other.value.get()?).inverse().get()
            } else {
                Ok(F::zero())
            }
        })?;

        self.cs.enforce_constraint(
            lc!() + self.variable - other.variable,
            lc!() + multiplier.variable,
            should_enforce.lc(),
        )?;
        Ok(())
    }
}

impl<F: PrimeField + SquareRootField + EqualityZero> MpcAllocatedFp<F> {
    pub fn is_zero(&self) -> Result<MpcBoolean<F>, SynthesisError> {
        let zero = MpcAllocatedFp::new_constant(self.cs.clone(), F::zero())?;

        let diff = zero.value.get()? - self.value.get()?;

        if diff.is_shared() {
            let rt = Runtime::new().unwrap();
            let is_zero_value = rt.block_on(diff.is_zero_shared());

            let is_not_zero =
                MpcBoolean::new_witness(self.cs.clone(), || Ok((!is_zero_value).field()))?;

            let multiplier = self
                .cs
                .new_witness_variable(|| (diff + is_zero_value.field()).inverse().get())?;

            self.cs.enforce_constraint(
                lc!() + zero.variable - self.variable,
                lc!() + multiplier,
                is_not_zero.lc(),
            )?;
            self.cs.enforce_constraint(
                lc!() + zero.variable - self.variable,
                is_not_zero.not().lc(),
                lc!(),
            )?;
            Ok(is_not_zero.not())
        } else {
            let is_zero_value = F::from(diff.is_zero());

            let is_not_zero =
                MpcBoolean::new_witness(self.cs.clone(), || Ok(F::one() - is_zero_value))?;

            let multiplier = self
                .cs
                .new_witness_variable(|| (diff + is_zero_value).inverse().get())?;

            self.cs.enforce_constraint(
                lc!() + zero.variable - self.variable,
                lc!() + multiplier,
                is_not_zero.lc(),
            )?;
            self.cs.enforce_constraint(
                lc!() + zero.variable - self.variable,
                is_not_zero.not().lc(),
                lc!(),
            )?;
            Ok(is_not_zero.not())
        }
    }
}

impl<F: PrimeField + SquareRootField + BitDecomposition> MpcToBitsGadget<F> for MpcAllocatedFp<F> {
    /// Outputs the unique bit-wise decomposition of `self` in *little-endian*
    /// form.
    ///
    /// This method enforces that the output is in the field, i.e.
    /// it invokes `Boolean::enforce_in_field_le` on the bit decomposition.
    #[tracing::instrument(target = "r1cs")]
    fn to_bits_le(&self) -> Result<Vec<MpcBoolean<F>>, SynthesisError> {
        let bits = self.to_non_unique_bits_le()?;
        MpcBoolean::enforce_in_field_le(&bits)?;
        Ok(bits)
    }

    #[tracing::instrument(target = "r1cs")]
    fn to_non_unique_bits_le(&self) -> Result<Vec<MpcBoolean<F>>, SynthesisError> {
        let cs = self.cs.clone();
        let bits = if let Some(value) = self.value {
            // let field_char = BitIteratorBE::new(F::characteristic());
            // let bits: Vec<_> = BitIteratorBE::new(value.into_repr())
            //     .zip(field_char)
            //     .skip_while(|(_, c)| !c)
            //     .map(|(b, _)| Some(b))
            //     .collect();
            let rt = Runtime::new().unwrap();
            let bits = rt.block_on(value.bit_decomposition());
            assert_eq!(bits.len(), F::Params::MODULUS_BITS as usize);
            bits.iter().map(|b| Some(*b)).collect()
        } else {
            vec![None; F::Params::MODULUS_BITS as usize]
        };

        // Convert to little-endian
        // bits.reverse();

        let bits: Vec<_> = bits
            .into_iter()
            .map(|b| MpcBoolean::new_witness(cs.clone(), || b.get().map(|b| b.field())))
            .collect::<Result<_, _>>()?;

        let mut lc = LinearCombination::zero();
        let mut coeff = F::one();

        for bit in bits.iter() {
            lc = &lc + bit.lc() * coeff;

            coeff.double_in_place();
        }

        lc = lc - self.variable;

        cs.enforce_constraint(lc!(), lc!(), lc)?;

        Ok(bits)
    }
}

impl<F: PrimeField + SquareRootField + BitDecomposition> MpcToBytesGadget<F> for MpcAllocatedFp<F> {
    /// Outputs the unique byte decomposition of `self` in *little-endian*
    /// form.
    ///
    /// This method enforces that the decomposition represents
    /// an integer that is less than `F::MODULUS`.
    #[tracing::instrument(target = "r1cs")]
    fn to_bytes(&self) -> Result<Vec<MpcUInt8<F>>, SynthesisError> {
        let num_bits = F::BigInt::NUM_LIMBS * 64;
        let mut bits = self.to_bits_le()?;
        let remainder = core::iter::repeat(MpcBoolean::constant(false)).take(num_bits - bits.len());
        bits.extend(remainder);
        let bytes = bits
            .chunks(8)
            .map(|chunk| MpcUInt8::from_bits_le(chunk))
            .collect();
        Ok(bytes)
    }

    #[tracing::instrument(target = "r1cs")]
    fn to_non_unique_bytes(&self) -> Result<Vec<MpcUInt8<F>>, SynthesisError> {
        let num_bits = F::BigInt::NUM_LIMBS * 64;
        let mut bits = self.to_non_unique_bits_le()?;
        let remainder = core::iter::repeat(MpcBoolean::constant(false)).take(num_bits - bits.len());
        bits.extend(remainder);
        let bytes = bits
            .chunks(8)
            .map(|chunk| MpcUInt8::from_bits_le(chunk))
            .collect();
        Ok(bytes)
    }
}

/// Specifies how to convert a variable of type `Self` to variables of
/// type `FpVar<ConstraintF>`
pub trait MpcToConstraintFieldGadget<ConstraintF: PrimeField> {
    /// Converts `self` to `FpVar<ConstraintF>` variables.
    fn to_constraint_field(
        &self,
    ) -> Result<Vec<MpcFpVar<ConstraintF>>, ark_relations::r1cs::SynthesisError>;
}

impl<F: PrimeField> MpcToConstraintFieldGadget<F> for MpcAllocatedFp<F> {
    #[tracing::instrument(target = "r1cs")]
    fn to_constraint_field(&self) -> Result<Vec<MpcFpVar<F>>, SynthesisError> {
        Ok(vec![self.clone().into()])
    }
}

impl<F: PrimeField> MpcCondSelectGadget<F> for MpcAllocatedFp<F> {
    #[inline]
    #[tracing::instrument(target = "r1cs")]
    fn conditionally_select(
        cond: &MpcBoolean<F>,
        true_val: &Self,
        false_val: &Self,
    ) -> Result<Self, SynthesisError> {
        match cond {
            MpcBoolean::Constant(true) => Ok(true_val.clone()),
            MpcBoolean::Constant(false) => Ok(false_val.clone()),
            _ => {
                let cs = cond.cs();
                let result = Self::new_witness(cs.clone(), || {
                    Ok(cond.value_field()? * true_val.value()?
                        + (F::one() - cond.value_field()?) * false_val.value()?)
                })?;
                // a = self; b = other; c = cond;
                //
                // r = c * a + (1  - c) * b
                // r = b + c * (a - b)
                // c * (a - b) = r - b
                cs.enforce_constraint(
                    cond.lc(),
                    lc!() + true_val.variable - false_val.variable,
                    lc!() + result.variable - false_val.variable,
                )?;

                Ok(result)
            }
        }
    }
}

/// Uses two bits to perform a lookup into a table
/// `b` is little-endian: `b[0]` is LSB.
impl<F: PrimeField> MpcTwoBitLookupGadget<F> for MpcAllocatedFp<F> {
    type TableConstant = F;
    #[tracing::instrument(target = "r1cs")]
    fn two_bit_lookup(
        b: &[MpcBoolean<F>],
        c: &[Self::TableConstant],
    ) -> Result<Self, SynthesisError> {
        debug_assert_eq!(b.len(), 2);
        debug_assert_eq!(c.len(), 4);
        let result = Self::new_witness(b.cs(), || {
            let res = (c[0] + (c[1] - c[0]) * b[0].value_field().unwrap())
                * (F::one() - b[1].value_field().unwrap())
                + (c[2] + (c[3] - c[2]) * b[0].value_field().unwrap())
                    * b[1].value_field().unwrap();
            Ok(res)
        })?;
        let one = Variable::One;
        b.cs().enforce_constraint(
            lc!() + b[1].lc() * (c[3] - c[2] - c[1] + c[0]) + (c[1] - c[0], one),
            lc!() + b[0].lc(),
            lc!() + result.variable - (c[0], one) + b[1].lc() * (c[0] - c[2]),
        )?;

        Ok(result)
    }
}

// impl<F: PrimeField> ThreeBitCondNegLookupGadget<F> for AllocatedFp<F> {
//     type TableConstant = F;

//     #[tracing::instrument(target = "r1cs")]
//     fn three_bit_cond_neg_lookup(
//         b: &[Boolean<F>],
//         b0b1: &Boolean<F>,
//         c: &[Self::TableConstant],
//     ) -> Result<Self, SynthesisError> {
//         debug_assert_eq!(b.len(), 3);
//         debug_assert_eq!(c.len(), 4);
//         let result = Self::new_witness(b.cs(), || {
//             let lsb = usize::from(b[0].value()?);
//             let msb = usize::from(b[1].value()?);
//             let index = lsb + (msb << 1);
//             let intermediate = c[index];

//             let is_negative = b[2].value()?;
//             let y = if is_negative {
//                 -intermediate
//             } else {
//                 intermediate
//             };
//             Ok(y)
//         })?;

//         let y_lc = b0b1.lc() * (c[3] - &c[2] - &c[1] + &c[0])
//             + b[0].lc() * (c[1] - &c[0])
//             + b[1].lc() * (c[2] - &c[0])
//             + (c[0], Variable::One);
//         // enforce y * (1 - 2 * b_2) == res
//         b.cs().enforce_constraint(
//             y_lc.clone(),
//             b[2].lc() * F::from(2u64).neg() + (F::one(), Variable::One),
//             lc!() + result.variable,
//         )?;

//         Ok(result)
//     }
// }

impl<F: PrimeField> AllocVar<F, F> for MpcAllocatedFp<F> {
    fn new_variable<T: Borrow<F>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        if mode == AllocationMode::Constant {
            let v = *f()?.borrow();
            let lc = cs.new_lc(lc!() + (v, Variable::One))?;
            Ok(Self::new(Some(v), lc, cs))
        } else {
            let mut value = None;
            let value_generator = || {
                value = Some(*f()?.borrow());
                value.ok_or(SynthesisError::AssignmentMissing)
            };
            let variable = if mode == AllocationMode::Input {
                cs.new_input_variable(value_generator)?
            } else {
                cs.new_witness_variable(value_generator)?
            };
            Ok(Self::new(value, variable, cs))
        }
    }
}

// TODO: Consider security of this implementation
impl<F: PrimeField + Reveal> Zero for MpcFpVar<F>
where
    <F as Reveal>::Base: Zero,
{
    fn zero() -> Self {
        Self::Constant(F::zero())
    }

    fn is_zero(&self) -> bool {
        match self {
            Self::Constant(c) => {
                let rt = Runtime::new().unwrap();
                rt.block_on(c.reveal()).is_zero()
            }
            Self::Var(v) => {
                let rt = Runtime::new().unwrap();
                rt.block_on(v.value.expect("value is None").reveal())
                    .is_zero()
            }
        }
    }
}

impl<F: PrimeField> One for MpcFpVar<F> {
    fn one() -> Self {
        Self::Constant(F::one())
    }
}

impl<F: PrimeField + SquareRootField + EqualityZero + BitDecomposition> MpcFieldVar<F, F>
    for MpcFpVar<F>
{
    fn constant(f: F) -> Self {
        Self::Constant(f)
    }

    fn zero() -> Self {
        Self::Constant(F::zero())
    }

    fn is_zero(&self) -> Result<MpcBoolean<F>, SynthesisError> {
        self.is_zero()
    }

    fn one() -> Self {
        Self::Constant(F::one())
    }

    #[tracing::instrument(target = "r1cs")]
    fn double(&self) -> Result<Self, SynthesisError> {
        match self {
            Self::Constant(c) => Ok(Self::Constant(c.double())),
            Self::Var(v) => Ok(Self::Var(v.double()?)),
        }
    }

    #[tracing::instrument(target = "r1cs")]
    fn negate(&self) -> Result<Self, SynthesisError> {
        match self {
            Self::Constant(c) => Ok(Self::Constant(-*c)),
            Self::Var(v) => Ok(Self::Var(v.negate())),
        }
    }

    #[tracing::instrument(target = "r1cs")]
    fn square(&self) -> Result<Self, SynthesisError> {
        match self {
            Self::Constant(c) => Ok(Self::Constant(c.square())),
            Self::Var(v) => Ok(Self::Var(v.square()?)),
        }
    }

    /// Enforce that `self * other == result`.
    #[tracing::instrument(target = "r1cs")]
    fn mul_equals(&self, other: &Self, result: &Self) -> Result<(), SynthesisError> {
        use MpcFpVar::*;
        match (self, other, result) {
            (Constant(_), Constant(_), Constant(_)) => Ok(()),
            (Constant(_), Constant(_), _) | (Constant(_), Var(_), _) | (Var(_), Constant(_), _) => {
                result.enforce_equal(&(self * other))
            } // this multiplication should be free
            (Var(v1), Var(v2), Var(v3)) => v1.mul_equals(v2, v3),
            (Var(v1), Var(v2), Constant(f)) => {
                let cs = v1.cs.clone();
                let v3 = MpcAllocatedFp::new_constant(cs, f).unwrap();
                v1.mul_equals(v2, &v3)
            }
        }
    }

    /// Enforce that `self * self == result`.
    #[tracing::instrument(target = "r1cs")]
    fn square_equals(&self, result: &Self) -> Result<(), SynthesisError> {
        use MpcFpVar::*;
        match (self, result) {
            (Constant(_), Constant(_)) => Ok(()),
            (Constant(f), Var(r)) => {
                let cs = r.cs.clone();
                let v = MpcAllocatedFp::new_witness(cs, || Ok(f))?;
                v.square_equals(&r)
            }
            (Var(v), Constant(f)) => {
                let cs = v.cs.clone();
                let r = MpcAllocatedFp::new_witness(cs, || Ok(f))?;
                v.square_equals(&r)
            }
            (Var(v1), Var(v2)) => v1.square_equals(v2),
        }
    }

    #[tracing::instrument(target = "r1cs")]
    fn inverse(&self) -> Result<Self, SynthesisError> {
        match self {
            MpcFpVar::Var(v) => v.inverse().map(MpcFpVar::Var),
            MpcFpVar::Constant(f) => f.inverse().get().map(MpcFpVar::Constant),
        }
    }

    #[tracing::instrument(target = "r1cs")]
    fn frobenius_map(&self, power: usize) -> Result<Self, SynthesisError> {
        match self {
            MpcFpVar::Var(v) => v.frobenius_map(power).map(MpcFpVar::Var),
            MpcFpVar::Constant(f) => {
                let mut f = *f;
                f.frobenius_map(power);
                Ok(MpcFpVar::Constant(f))
            }
        }
    }

    #[tracing::instrument(target = "r1cs")]
    fn frobenius_map_in_place(&mut self, power: usize) -> Result<&mut Self, SynthesisError> {
        *self = self.frobenius_map(power)?;
        Ok(self)
    }
}

impl_ops!(
    MpcFpVar<F>,
    F,
    Add,
    add,
    AddAssign,
    add_assign,
    |this: &'a MpcFpVar<F>, other: &'a MpcFpVar<F>| {
        use MpcFpVar::*;
        match (this, other) {
            (Constant(c1), Constant(c2)) => Constant(*c1 + *c2),
            (Constant(c), Var(v)) | (Var(v), Constant(c)) => Var(v.add_constant(*c)),
            (Var(v1), Var(v2)) => Var(v1.add(v2)),
        }
    },
    |this: &'a MpcFpVar<F>, other: F| { this + &MpcFpVar::Constant(other) },
    F: PrimeField
);

impl_ops!(
    MpcFpVar<F>,
    F,
    Sub,
    sub,
    SubAssign,
    sub_assign,
    |this: &'a MpcFpVar<F>, other: &'a MpcFpVar<F>| {
        use MpcFpVar::*;
        match (this, other) {
            (Constant(c1), Constant(c2)) => Constant(*c1 - *c2),
            (Var(v), Constant(c)) => Var(v.sub_constant(*c)),
            (Constant(c), Var(v)) => Var(v.sub_constant(*c).negate()),
            (Var(v1), Var(v2)) => Var(v1.sub(v2)),
        }
    },
    |this: &'a MpcFpVar<F>, other: F| { this - &MpcFpVar::Constant(other) },
    F: PrimeField
);

impl_ops!(
    MpcFpVar<F>,
    F,
    Mul,
    mul,
    MulAssign,
    mul_assign,
    |this: &'a MpcFpVar<F>, other: &'a MpcFpVar<F>| {
        use MpcFpVar::*;

        match (this, other) {
            (Constant(c1), Constant(c2)) => Constant(*c1 * *c2),
            (Constant(c), Var(v)) | (Var(v), Constant(c)) => Var(v.mul_constant(*c)),
            (Var(v1), Var(v2)) => Var(v1.mul(v2)),
        }
    },
    |this: &'a MpcFpVar<F>, other: F| {
        if other.is_zero() {
            // rewrite
            MpcFpVar::Constant(F::zero())
        } else {
            this * &MpcFpVar::Constant(other)
        }
    },
    F: PrimeField
);

/// *************************************************************************
/// *************************************************************************

impl<F: PrimeField> MpcEqGadget<F> for MpcFpVar<F> {
    #[tracing::instrument(target = "r1cs")]
    fn is_eq(&self, other: &Self) -> Result<MpcBoolean<F>, SynthesisError> {
        match (self, other) {
            (Self::Constant(c1), Self::Constant(c2)) => Ok(MpcBoolean::Constant(c1 == c2)),
            (Self::Constant(c), Self::Var(v)) | (Self::Var(v), Self::Constant(c)) => {
                let cs = v.cs.clone();
                let c = MpcAllocatedFp::new_constant(cs, c)?;
                c.is_eq(v)
            }
            (Self::Var(v1), Self::Var(v2)) => v1.is_eq(v2),
        }
    }

    #[tracing::instrument(target = "r1cs")]
    fn conditional_enforce_equal(
        &self,
        other: &Self,
        should_enforce: &MpcBoolean<F>,
    ) -> Result<(), SynthesisError> {
        match (self, other) {
            (Self::Constant(_), Self::Constant(_)) => Ok(()),
            (Self::Constant(c), Self::Var(v)) | (Self::Var(v), Self::Constant(c)) => {
                let cs = v.cs.clone();
                let c = MpcAllocatedFp::new_constant(cs, c)?;
                c.conditional_enforce_equal(v, should_enforce)
            }
            (Self::Var(v1), Self::Var(v2)) => v1.conditional_enforce_equal(v2, should_enforce),
        }
    }

    #[tracing::instrument(target = "r1cs")]
    fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        should_enforce: &MpcBoolean<F>,
    ) -> Result<(), SynthesisError> {
        match (self, other) {
            (Self::Constant(_), Self::Constant(_)) => Ok(()),
            (Self::Constant(c), Self::Var(v)) | (Self::Var(v), Self::Constant(c)) => {
                let cs = v.cs.clone();
                let c = MpcAllocatedFp::new_constant(cs, c)?;
                c.conditional_enforce_not_equal(v, should_enforce)
            }
            (Self::Var(v1), Self::Var(v2)) => v1.conditional_enforce_not_equal(v2, should_enforce),
        }
    }
}

impl<F: PrimeField + SquareRootField + EqualityZero> MpcFpVar<F> {
    pub fn is_zero(&self) -> Result<MpcBoolean<F>, SynthesisError> {
        match self {
            Self::Constant(c1) => Ok(MpcBoolean::Constant(c1.is_zero())),
            Self::Var(v1) => v1.is_zero(),
        }
    }
}

impl<F: PrimeField + SquareRootField + BitDecomposition> MpcToBitsGadget<F> for MpcFpVar<F> {
    fn to_bits_le(&self) -> Result<Vec<MpcBoolean<F>>, SynthesisError> {
        match self {
            Self::Constant(_) => self.to_non_unique_bits_le(),
            Self::Var(v) => v.to_bits_le(),
        }
    }

    fn to_non_unique_bits_le(&self) -> Result<Vec<MpcBoolean<F>>, SynthesisError> {
        use ark_ff::BitIteratorLE;
        match self {
            Self::Constant(c) => Ok(BitIteratorLE::new(&c.into_repr())
                .take((F::Params::MODULUS_BITS) as usize)
                .map(MpcBoolean::constant)
                .collect::<Vec<_>>()),
            Self::Var(v) => v.to_non_unique_bits_le(),
        }
    }
}

impl<F: PrimeField + SquareRootField + BitDecomposition> MpcToBytesGadget<F> for MpcFpVar<F> {
    /// Outputs the unique byte decomposition of `self` in *little-endian*
    /// form.
    #[tracing::instrument(target = "r1cs")]
    fn to_bytes(&self) -> Result<Vec<MpcUInt8<F>>, SynthesisError> {
        match self {
            Self::Constant(c) => Ok(MpcUInt8::constant_vec(&ark_ff::to_bytes![c].unwrap())),
            Self::Var(v) => v.to_bytes(),
        }
    }

    #[tracing::instrument(target = "r1cs")]
    fn to_non_unique_bytes(&self) -> Result<Vec<MpcUInt8<F>>, SynthesisError> {
        match self {
            Self::Constant(c) => Ok(MpcUInt8::constant_vec(&ark_ff::to_bytes![c].unwrap())),
            Self::Var(v) => v.to_non_unique_bytes(),
        }
    }
}

// impl<F: PrimeField, S: FieldShare<F>> ToConstraintFieldGadget<MpcField<F, S>> for MpcFpVar<F, S> {
//     #[tracing::instrument(target = "r1cs")]
//     fn to_constraint_field(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
//         Ok(vec![self.clone()])
//     }
// }

impl<F: PrimeField> MpcCondSelectGadget<F> for MpcFpVar<F> {
    #[tracing::instrument(target = "r1cs")]
    fn conditionally_select(
        cond: &MpcBoolean<F>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        match cond {
            MpcBoolean::Constant(true) => Ok(true_value.clone()),
            MpcBoolean::Constant(false) => Ok(false_value.clone()),
            _ => {
                match (true_value, false_value) {
                    (Self::Constant(t), Self::Constant(f)) => {
                        let is = MpcAllocatedFp::from(cond.clone());
                        let not = MpcAllocatedFp::from(cond.not());
                        // cond * t + (1 - cond) * f
                        Ok(is.mul_constant(*t).add(&not.mul_constant(*f)).into())
                    }
                    (..) => {
                        let cs = cond.cs();
                        let true_value = match true_value {
                            Self::Constant(f) => MpcAllocatedFp::new_constant(cs.clone(), f)?,
                            Self::Var(v) => v.clone(),
                        };
                        let false_value = match false_value {
                            Self::Constant(f) => MpcAllocatedFp::new_constant(cs, f)?,
                            Self::Var(v) => v.clone(),
                        };
                        cond.select(&true_value, &false_value).map(Self::Var)
                    }
                }
            }
        }
    }
}

/// Uses two bits to perform a lookup into a table
/// `b` is little-endian: `b[0]` is LSB.
impl<F: PrimeField> MpcTwoBitLookupGadget<F> for MpcFpVar<F> {
    type TableConstant = F;

    #[tracing::instrument(target = "r1cs")]
    fn two_bit_lookup(
        b: &[MpcBoolean<F>],
        c: &[Self::TableConstant],
    ) -> Result<Self, SynthesisError> {
        debug_assert_eq!(b.len(), 2);
        debug_assert_eq!(c.len(), 4);
        if b.is_constant() {
            let lsb = usize::from(b[0].value()?);
            let msb = usize::from(b[1].value()?);
            let index = lsb + (msb << 1);
            Ok(Self::Constant(c[index]))
        } else {
            MpcAllocatedFp::two_bit_lookup(b, c).map(Self::Var)
        }
    }
}

// impl<F: PrimeField> ThreeBitCondNegLookupGadget<F> for FpVar<F> {
//     type TableConstant = F;

//     #[tracing::instrument(target = "r1cs")]
//     fn three_bit_cond_neg_lookup(
//         b: &[Boolean<F>],
//         b0b1: &Boolean<F>,
//         c: &[Self::TableConstant],
//     ) -> Result<Self, SynthesisError> {
//         debug_assert_eq!(b.len(), 3);
//         debug_assert_eq!(c.len(), 4);

//         if b.cs().or(b0b1.cs()).is_none() {
//             // We only have constants

//             let lsb = usize::from(b[0].value()?);
//             let msb = usize::from(b[1].value()?);
//             let index = lsb + (msb << 1);
//             let intermediate = c[index];

//             let is_negative = b[2].value()?;
//             let y = if is_negative {
//                 -intermediate
//             } else {
//                 intermediate
//             };
//             Ok(Self::Constant(y))
//         } else {
//             AllocatedFp::three_bit_cond_neg_lookup(b, b0b1, c).map(Self::Var)
//         }
//     }
// }

impl<F: PrimeField> AllocVar<F, F> for MpcFpVar<F> {
    fn new_variable<T: Borrow<F>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        if mode == AllocationMode::Constant {
            Ok(Self::Constant(*f()?.borrow()))
        } else {
            MpcAllocatedFp::new_variable(cs, f, mode).map(Self::Var)
        }
    }
}
