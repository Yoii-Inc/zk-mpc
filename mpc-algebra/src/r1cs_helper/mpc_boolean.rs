use ark_ff::{BitIteratorBE, Field, FpParameters, PrimeField};
use ark_r1cs_std::{
    fields::fp::{AllocatedFp, FpVar},
    prelude::*,
    Assignment, ToConstraintFieldGadget,
};
use ark_relations::{
    lc,
    r1cs::{ConstraintSystemRef, LinearCombination, Namespace, SynthesisError, Variable},
};
use ark_std::{One, Zero};
use core::borrow::Borrow;

use crate::{
    mpc_eq::MpcEqGadget, mpc_fp::MpcFpVar, mpc_select::MpcCondSelectGadget, FieldShare, MpcField,
};

use crate::reveal::Reveal;

/// Represents a variable in the constraint system which is guaranteed
/// to be either zero or one.
///
/// In general, one should prefer using `Boolean` instead of `MpcAllocatedBool`,
/// as `Boolean` offers better support for constant values, and implements
/// more traits.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use]
pub struct MpcAllocatedBool<F: PrimeField, S: FieldShare<F>> {
    pub variable: Variable,
    pub cs: ConstraintSystemRef<MpcField<F, S>>,
}

pub(crate) fn bool_to_field<F: PrimeField>(val: impl Borrow<bool>) -> F {
    // TODO: MPC Fieldの元として返す
    if *val.borrow() {
        F::one()
    } else {
        F::zero()
    }
}

impl<F: PrimeField, S: FieldShare<F>> MpcAllocatedBool<F, S> {
    /// Get the assigned value for `self`.
    pub fn value(&self) -> Result<bool, SynthesisError> {
        let value = self.cs.assigned_value(self.variable).get()?;
        // reveal is not recommended. It is better to avoid revealing.
        if value.reveal().is_zero() {
            println!("ZEROZEROZERO.");
            Ok(false)
        } else if value.reveal().is_one() {
            println!("ONEONEONE");
            Ok(true)
        } else {
            unreachable!("Incorrect value assigned: {:?}", value);
        }
    }

    /// Get the R1CS variable for `self`.
    pub fn variable(&self) -> Variable {
        self.variable
    }

    /// Allocate a witness variable without a booleanity check.
    fn new_witness_without_booleanity_check<T: Borrow<bool>>(
        cs: ConstraintSystemRef<MpcField<F, S>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
    ) -> Result<Self, SynthesisError> {
        let variable = cs.new_witness_variable(|| f().map(bool_to_field))?;
        Ok(Self { variable, cs })
    }

    /// Performs an XOR operation over the two operands, returning
    /// an `MpcAllocatedBool`.
    #[tracing::instrument(target = "r1cs")]
    pub fn xor(&self, b: &Self) -> Result<Self, SynthesisError> {
        let result = Self::new_witness_without_booleanity_check(self.cs.clone(), || {
            Ok(self.value()? ^ b.value()?)
        })?;

        // Constrain (a + a) * (b) = (a + b - c)
        // Given that a and b are boolean constrained, if they
        // are equal, the only solution for c is 0, and if they
        // are different, the only solution for c is 1.
        //
        // ¬(a ∧ b) ∧ ¬(¬a ∧ ¬b) = c
        // (1 - (a * b)) * (1 - ((1 - a) * (1 - b))) = c
        // (1 - ab) * (1 - (1 - a - b + ab)) = c
        // (1 - ab) * (a + b - ab) = c
        // a + b - ab - (a^2)b - (b^2)a + (a^2)(b^2) = c
        // a + b - ab - ab - ab + ab = c
        // a + b - 2ab = c
        // -2a * b = c - a - b
        // 2a * b = a + b - c
        // (a + a) * b = a + b - c
        self.cs.enforce_constraint(
            lc!() + self.variable + self.variable,
            lc!() + b.variable,
            lc!() + self.variable + b.variable - result.variable,
        )?;

        Ok(result)
    }

    /// Performs an AND operation over the two operands, returning
    /// an `MpcAllocatedBool`.
    #[tracing::instrument(target = "r1cs")]
    pub fn and(&self, b: &Self) -> Result<Self, SynthesisError> {
        let result = Self::new_witness_without_booleanity_check(self.cs.clone(), || {
            Ok(self.value()? & b.value()?)
        })?;

        // Constrain (a) * (b) = (c), ensuring c is 1 iff
        // a AND b are both 1.
        self.cs.enforce_constraint(
            lc!() + self.variable,
            lc!() + b.variable,
            lc!() + result.variable,
        )?;

        Ok(result)
    }

    /// Performs an OR operation over the two operands, returning
    /// an `MpcAllocatedBool`.
    #[tracing::instrument(target = "r1cs")]
    pub fn or(&self, b: &Self) -> Result<Self, SynthesisError> {
        let result = Self::new_witness_without_booleanity_check(self.cs.clone(), || {
            Ok(self.value()? | b.value()?)
        })?;

        // Constrain (1 - a) * (1 - b) = (c), ensuring c is 1 iff
        // a and b are both false, and otherwise c is 0.
        self.cs.enforce_constraint(
            lc!() + Variable::One - self.variable,
            lc!() + Variable::One - b.variable,
            lc!() + Variable::One - result.variable,
        )?;

        Ok(result)
    }

    /// Calculates `a AND (NOT b)`.
    #[tracing::instrument(target = "r1cs")]
    pub fn and_not(&self, b: &Self) -> Result<Self, SynthesisError> {
        let result = Self::new_witness_without_booleanity_check(self.cs.clone(), || {
            Ok(self.value()? & !b.value()?)
        })?;

        // Constrain (a) * (1 - b) = (c), ensuring c is 1 iff
        // a is true and b is false, and otherwise c is 0.
        self.cs.enforce_constraint(
            lc!() + self.variable,
            lc!() + Variable::One - b.variable,
            lc!() + result.variable,
        )?;

        Ok(result)
    }

    /// Calculates `(NOT a) AND (NOT b)`.
    #[tracing::instrument(target = "r1cs")]
    pub fn nor(&self, b: &Self) -> Result<Self, SynthesisError> {
        let result = Self::new_witness_without_booleanity_check(self.cs.clone(), || {
            Ok(!(self.value()? | b.value()?))
        })?;

        // Constrain (1 - a) * (1 - b) = (c), ensuring c is 1 iff
        // a and b are both false, and otherwise c is 0.
        self.cs.enforce_constraint(
            lc!() + Variable::One - self.variable,
            lc!() + Variable::One - b.variable,
            lc!() + result.variable,
        )?;

        Ok(result)
    }
}

impl<F: PrimeField, S: FieldShare<F>> AllocVar<MpcField<F, S>, MpcField<F, S>>
    for MpcAllocatedBool<F, S>
{
    /// Produces a new variable of the appropriate kind
    /// (instance or witness), with a booleanity check.
    ///
    /// N.B.: we could omit the booleanity check when allocating `self`
    /// as a new public input, but that places an additional burden on
    /// protocol designers. Better safe than sorry!
    fn new_variable<T: Borrow<MpcField<F, S>>>(
        cs: impl Into<Namespace<MpcField<F, S>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        if mode == AllocationMode::Constant {
            // let variable = if *f()?.borrow() {
            //     Variable::One
            // } else {
            //     Variable::Zero
            // };
            // Ok(Self { variable, cs })
            unimplemented!()
            // Ok(Self::Constant(*f()?.borrow()))
        } else {
            let variable = if mode == AllocationMode::Input {
                cs.new_input_variable(|| Ok(*f()?.borrow()))?
            } else {
                cs.new_witness_variable(|| Ok(*f()?.borrow()))?
            };

            // Constrain: (1 - a) * a = 0
            // This constrains a to be either 0 or 1.

            cs.enforce_constraint(lc!() + Variable::One - variable, lc!() + variable, lc!())?;

            Ok(Self { variable, cs })
        }
    }
}

impl<F: PrimeField, S: FieldShare<F>> MpcCondSelectGadget<F, S> for MpcAllocatedBool<F, S> {
    #[tracing::instrument(target = "r1cs")]
    fn conditionally_select(
        cond: &MpcBoolean<F, S>,
        true_val: &Self,
        false_val: &Self,
    ) -> Result<Self, SynthesisError> {
        let res = MpcBoolean::conditionally_select(
            cond,
            &true_val.clone().into(),
            &false_val.clone().into(),
        )?;
        match res {
            MpcBoolean::Is(a) => Ok(a),
            _ => unreachable!("Impossible"),
        }
    }
}

/// Represents a boolean value in the constraint system which is guaranteed
/// to be either zero or one.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use]
pub enum MpcBoolean<F: PrimeField, S: FieldShare<F>> {
    /// Existential view of the boolean variable.
    Is(MpcAllocatedBool<F, S>),
    /// Negated view of the boolean variable.
    Not(MpcAllocatedBool<F, S>),
    /// Constant (not an allocated variable).
    Constant(bool),
}

impl<F: PrimeField, S: FieldShare<F>> R1CSVar<MpcField<F, S>> for MpcBoolean<F, S> {
    type Value = bool;

    fn cs(&self) -> ConstraintSystemRef<MpcField<F, S>> {
        match self {
            Self::Is(a) | Self::Not(a) => a.cs.clone(),
            _ => ConstraintSystemRef::None,
        }
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        match self {
            MpcBoolean::Constant(c) => Ok(*c),
            MpcBoolean::Is(ref v) => v.value(),
            MpcBoolean::Not(ref v) => v.value().map(|b| !b),
        }
    }
}

impl<F: PrimeField, S: FieldShare<F>> MpcBoolean<F, S> {
    /// The constant `true`.
    pub const TRUE: Self = MpcBoolean::Constant(true);

    /// The constant `false`.
    pub const FALSE: Self = MpcBoolean::Constant(false);

    /// Constructs a `LinearCombination` from `Self`'s variables according
    /// to the following map.
    ///
    /// * `Boolean::Constant(true) => lc!() + Variable::One`
    /// * `Boolean::Constant(false) => lc!()`
    /// * `Boolean::Is(v) => lc!() + v.variable()`
    /// * `Boolean::Not(v) => lc!() + Variable::One - v.variable()`
    pub fn lc(&self) -> LinearCombination<MpcField<F, S>> {
        match self {
            MpcBoolean::Constant(false) => lc!(),
            MpcBoolean::Constant(true) => lc!() + Variable::One,
            MpcBoolean::Is(v) => v.variable().into(),
            MpcBoolean::Not(v) => lc!() + Variable::One - v.variable(),
        }
    }

    /// Constructs a `Boolean` vector from a slice of constant `u8`.
    /// The `u8`s are decomposed in little-endian manner.
    ///
    /// This *does not* create any new variables or constraints.
    ///
    /// ```
    /// # fn main() -> Result<(), ark_relations::r1cs::SynthesisError> {
    /// // We'll use the BLS12-381 scalar field for our constraints.
    /// use ark_test_curves::bls12_381::Fr;
    /// use ark_relations::r1cs::*;
    /// use ark_r1cs_std::prelude::*;
    ///
    /// let cs = ConstraintSystem::<Fr>::new_ref();
    /// let t = Boolean::<Fr>::TRUE;
    /// let f = Boolean::<Fr>::FALSE;
    ///
    /// let bits = vec![f, t];
    /// let generated_bits = Boolean::constant_vec_from_bytes(&[2]);
    /// bits[..2].enforce_equal(&generated_bits[..2])?;
    /// assert!(cs.is_satisfied().unwrap());
    /// # Ok(())
    /// # }
    /// ```
    pub fn constant_vec_from_bytes(values: &[u8]) -> Vec<Self> {
        let mut bits = vec![];
        for byte in values {
            for i in 0..8 {
                bits.push(Self::Constant(((byte >> i) & 1u8) == 1u8));
            }
        }
        bits
    }

    /// Constructs a constant `Boolean` with value `b`.
    ///
    /// This *does not* create any new variables or constraints.
    /// ```
    /// # fn main() -> Result<(), ark_relations::r1cs::SynthesisError> {
    /// // We'll use the BLS12-381 scalar field for our constraints.
    /// use ark_test_curves::bls12_381::Fr;
    /// use ark_r1cs_std::prelude::*;
    ///
    /// let true_var = Boolean::<Fr>::TRUE;
    /// let false_var = Boolean::<Fr>::FALSE;
    ///
    /// true_var.enforce_equal(&Boolean::constant(true))?;
    /// false_var.enforce_equal(&Boolean::constant(false))?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn constant(b: bool) -> Self {
        MpcBoolean::Constant(b)
    }

    /// Negates `self`.
    ///
    /// This *does not* create any new variables or constraints.
    /// ```
    /// # fn main() -> Result<(), ark_relations::r1cs::SynthesisError> {
    /// // We'll use the BLS12-381 scalar field for our constraints.
    /// use ark_test_curves::bls12_381::Fr;
    /// use ark_relations::r1cs::*;
    /// use ark_r1cs_std::prelude::*;
    ///
    /// let cs = ConstraintSystem::<Fr>::new_ref();
    ///
    /// let a = Boolean::new_witness(cs.clone(), || Ok(true))?;
    /// let b = Boolean::new_witness(cs.clone(), || Ok(false))?;
    ///
    /// a.not().enforce_equal(&b)?;
    /// b.not().enforce_equal(&a)?;
    ///
    /// a.not().enforce_equal(&Boolean::FALSE)?;
    /// b.not().enforce_equal(&Boolean::TRUE)?;
    ///
    /// assert!(cs.is_satisfied().unwrap());
    /// # Ok(())
    /// # }
    /// ```
    pub fn not(&self) -> Self {
        match *self {
            MpcBoolean::Constant(c) => MpcBoolean::Constant(!c),
            MpcBoolean::Is(ref v) => MpcBoolean::Not(v.clone()),
            MpcBoolean::Not(ref v) => MpcBoolean::Is(v.clone()),
        }
    }

    /// Outputs `self ^ other`.
    ///
    /// If at least one of `self` and `other` are constants, then this method
    /// *does not* create any constraints or variables.
    ///
    /// ```
    /// # fn main() -> Result<(), ark_relations::r1cs::SynthesisError> {
    /// // We'll use the BLS12-381 scalar field for our constraints.
    /// use ark_test_curves::bls12_381::Fr;
    /// use ark_relations::r1cs::*;
    /// use ark_r1cs_std::prelude::*;
    ///
    /// let cs = ConstraintSystem::<Fr>::new_ref();
    ///
    /// let a = Boolean::new_witness(cs.clone(), || Ok(true))?;
    /// let b = Boolean::new_witness(cs.clone(), || Ok(false))?;
    ///
    /// a.xor(&b)?.enforce_equal(&Boolean::TRUE)?;
    /// b.xor(&a)?.enforce_equal(&Boolean::TRUE)?;
    ///
    /// a.xor(&a)?.enforce_equal(&Boolean::FALSE)?;
    /// b.xor(&b)?.enforce_equal(&Boolean::FALSE)?;
    ///
    /// assert!(cs.is_satisfied().unwrap());
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(target = "r1cs")]
    pub fn xor<'a>(&'a self, other: &'a Self) -> Result<Self, SynthesisError> {
        use MpcBoolean::*;
        match (self, other) {
            (&Constant(false), x) | (x, &Constant(false)) => Ok(x.clone()),
            (&Constant(true), x) | (x, &Constant(true)) => Ok(x.not()),
            // a XOR (NOT b) = NOT(a XOR b)
            (is @ &Is(_), not @ &Not(_)) | (not @ &Not(_), is @ &Is(_)) => {
                Ok(is.xor(&not.not())?.not())
            }
            // a XOR b = (NOT a) XOR (NOT b)
            (&Is(ref a), &Is(ref b)) | (&Not(ref a), &Not(ref b)) => Ok(Is(a.xor(b)?)),
        }
    }

    /// Outputs `self | other`.
    ///
    /// If at least one of `self` and `other` are constants, then this method
    /// *does not* create any constraints or variables.
    ///
    /// ```
    /// # fn main() -> Result<(), ark_relations::r1cs::SynthesisError> {
    /// // We'll use the BLS12-381 scalar field for our constraints.
    /// use ark_test_curves::bls12_381::Fr;
    /// use ark_relations::r1cs::*;
    /// use ark_r1cs_std::prelude::*;
    ///
    /// let cs = ConstraintSystem::<Fr>::new_ref();
    ///
    /// let a = Boolean::new_witness(cs.clone(), || Ok(true))?;
    /// let b = Boolean::new_witness(cs.clone(), || Ok(false))?;
    ///
    /// a.or(&b)?.enforce_equal(&Boolean::TRUE)?;
    /// b.or(&a)?.enforce_equal(&Boolean::TRUE)?;
    ///
    /// a.or(&a)?.enforce_equal(&Boolean::TRUE)?;
    /// b.or(&b)?.enforce_equal(&Boolean::FALSE)?;
    ///
    /// assert!(cs.is_satisfied().unwrap());
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(target = "r1cs")]
    pub fn or<'a>(&'a self, other: &'a Self) -> Result<Self, SynthesisError> {
        use MpcBoolean::*;
        match (self, other) {
            (&Constant(false), x) | (x, &Constant(false)) => Ok(x.clone()),
            (&Constant(true), _) | (_, &Constant(true)) => Ok(Constant(true)),
            // a OR b = NOT ((NOT a) AND (NOT b))
            (a @ &Is(_), b @ &Not(_)) | (b @ &Not(_), a @ &Is(_)) | (b @ &Not(_), a @ &Not(_)) => {
                Ok(a.not().and(&b.not())?.not())
            }
            (&Is(ref a), &Is(ref b)) => a.or(b).map(From::from),
        }
    }

    /// Outputs `self & other`.
    ///
    /// If at least one of `self` and `other` are constants, then this method
    /// *does not* create any constraints or variables.
    ///
    /// ```
    /// # fn main() -> Result<(), ark_relations::r1cs::SynthesisError> {
    /// // We'll use the BLS12-381 scalar field for our constraints.
    /// use ark_test_curves::bls12_381::Fr;
    /// use ark_relations::r1cs::*;
    /// use ark_r1cs_std::prelude::*;
    ///
    /// let cs = ConstraintSystem::<Fr>::new_ref();
    ///
    /// let a = Boolean::new_witness(cs.clone(), || Ok(true))?;
    /// let b = Boolean::new_witness(cs.clone(), || Ok(false))?;
    ///
    /// a.and(&a)?.enforce_equal(&Boolean::TRUE)?;
    ///
    /// a.and(&b)?.enforce_equal(&Boolean::FALSE)?;
    /// b.and(&a)?.enforce_equal(&Boolean::FALSE)?;
    /// b.and(&b)?.enforce_equal(&Boolean::FALSE)?;
    ///
    /// assert!(cs.is_satisfied().unwrap());
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(target = "r1cs")]
    pub fn and<'a>(&'a self, other: &'a Self) -> Result<Self, SynthesisError> {
        use MpcBoolean::*;
        match (self, other) {
            // false AND x is always false
            (&Constant(false), _) | (_, &Constant(false)) => Ok(Constant(false)),
            // true AND x is always x
            (&Constant(true), x) | (x, &Constant(true)) => Ok(x.clone()),
            // a AND (NOT b)
            (&Is(ref is), &Not(ref not)) | (&Not(ref not), &Is(ref is)) => Ok(Is(is.and_not(not)?)),
            // (NOT a) AND (NOT b) = a NOR b
            (&Not(ref a), &Not(ref b)) => Ok(Is(a.nor(b)?)),
            // a AND b
            (&Is(ref a), &Is(ref b)) => Ok(Is(a.and(b)?)),
        }
    }

    /// Outputs `bits[0] & bits[1] & ... & bits.last().unwrap()`.
    ///
    /// ```
    /// # fn main() -> Result<(), ark_relations::r1cs::SynthesisError> {
    /// // We'll use the BLS12-381 scalar field for our constraints.
    /// use ark_test_curves::bls12_381::Fr;
    /// use ark_relations::r1cs::*;
    /// use ark_r1cs_std::prelude::*;
    ///
    /// let cs = ConstraintSystem::<Fr>::new_ref();
    ///
    /// let a = Boolean::new_witness(cs.clone(), || Ok(true))?;
    /// let b = Boolean::new_witness(cs.clone(), || Ok(false))?;
    /// let c = Boolean::new_witness(cs.clone(), || Ok(true))?;
    ///
    /// Boolean::kary_and(&[a.clone(), b.clone(), c.clone()])?.enforce_equal(&Boolean::FALSE)?;
    /// Boolean::kary_and(&[a.clone(), c.clone()])?.enforce_equal(&Boolean::TRUE)?;
    ///
    /// assert!(cs.is_satisfied().unwrap());
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(target = "r1cs")]
    pub fn kary_and(bits: &[Self]) -> Result<Self, SynthesisError> {
        assert!(!bits.is_empty());
        let mut cur: Option<Self> = None;
        for next in bits {
            cur = if let Some(b) = cur {
                Some(b.and(next)?)
            } else {
                Some(next.clone())
            };
        }

        Ok(cur.expect("should not be 0"))
    }

    /// Outputs `bits[0] | bits[1] | ... | bits.last().unwrap()`.
    ///
    /// ```
    /// # fn main() -> Result<(), ark_relations::r1cs::SynthesisError> {
    /// // We'll use the BLS12-381 scalar field for our constraints.
    /// use ark_test_curves::bls12_381::Fr;
    /// use ark_relations::r1cs::*;
    /// use ark_r1cs_std::prelude::*;
    ///
    /// let cs = ConstraintSystem::<Fr>::new_ref();
    ///
    /// let a = Boolean::new_witness(cs.clone(), || Ok(true))?;
    /// let b = Boolean::new_witness(cs.clone(), || Ok(false))?;
    /// let c = Boolean::new_witness(cs.clone(), || Ok(false))?;
    ///
    /// Boolean::kary_or(&[a.clone(), b.clone(), c.clone()])?.enforce_equal(&Boolean::TRUE)?;
    /// Boolean::kary_or(&[a.clone(), c.clone()])?.enforce_equal(&Boolean::TRUE)?;
    /// Boolean::kary_or(&[b.clone(), c.clone()])?.enforce_equal(&Boolean::FALSE)?;
    ///
    /// assert!(cs.is_satisfied().unwrap());
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(target = "r1cs")]
    pub fn kary_or(bits: &[Self]) -> Result<Self, SynthesisError> {
        assert!(!bits.is_empty());
        let mut cur: Option<Self> = None;
        for next in bits {
            cur = if let Some(b) = cur {
                Some(b.or(next)?)
            } else {
                Some(next.clone())
            };
        }

        Ok(cur.expect("should not be 0"))
    }

    /// Outputs `(bits[0] & bits[1] & ... & bits.last().unwrap()).not()`.
    ///
    /// ```
    /// # fn main() -> Result<(), ark_relations::r1cs::SynthesisError> {
    /// // We'll use the BLS12-381 scalar field for our constraints.
    /// use ark_test_curves::bls12_381::Fr;
    /// use ark_relations::r1cs::*;
    /// use ark_r1cs_std::prelude::*;
    ///
    /// let cs = ConstraintSystem::<Fr>::new_ref();
    ///
    /// let a = Boolean::new_witness(cs.clone(), || Ok(true))?;
    /// let b = Boolean::new_witness(cs.clone(), || Ok(false))?;
    /// let c = Boolean::new_witness(cs.clone(), || Ok(true))?;
    ///
    /// Boolean::kary_nand(&[a.clone(), b.clone(), c.clone()])?.enforce_equal(&Boolean::TRUE)?;
    /// Boolean::kary_nand(&[a.clone(), c.clone()])?.enforce_equal(&Boolean::FALSE)?;
    /// Boolean::kary_nand(&[b.clone(), c.clone()])?.enforce_equal(&Boolean::TRUE)?;
    ///
    /// assert!(cs.is_satisfied().unwrap());
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(target = "r1cs")]
    pub fn kary_nand(bits: &[Self]) -> Result<Self, SynthesisError> {
        Ok(Self::kary_and(bits)?.not())
    }

    /// Enforces that `Self::kary_nand(bits).is_eq(&Boolean::TRUE)`.
    ///
    /// Informally, this means that at least one element in `bits` must be
    /// `false`.
    #[tracing::instrument(target = "r1cs")]
    fn enforce_kary_nand(bits: &[Self]) -> Result<(), SynthesisError> {
        use MpcBoolean::*;
        let r = Self::kary_nand(bits)?;
        match r {
            Constant(true) => Ok(()),
            Constant(false) => Err(SynthesisError::AssignmentMissing),
            Is(_) | Not(_) => {
                r.cs()
                    .enforce_constraint(r.lc(), lc!() + Variable::One, lc!() + Variable::One)
            }
        }
    }

    /// Convert a little-endian bitwise representation of a field element to `FpVar<F>`
    #[tracing::instrument(target = "r1cs", skip(bits))]
    pub fn le_bits_to_fp_var(bits: &[Self]) -> Result<FpVar<MpcField<F, S>>, SynthesisError>
    where
        F: PrimeField,
    {
        // Compute the value of the `FpVar` variable via double-and-add.
        let mut value = None;
        let cs = bits.cs();
        // Assign a value only when `cs` is in setup mode, or if we are constructing
        // a constant.
        let should_construct_value = (!cs.is_in_setup_mode()) || bits.is_constant();
        if should_construct_value {
            let bits = bits.iter().map(|b| b.value().unwrap()).collect::<Vec<_>>();
            let bytes = bits
                .chunks(8)
                .map(|c| {
                    let mut value = 0u8;
                    for (i, &bit) in c.iter().enumerate() {
                        value += (bit as u8) << i;
                    }
                    value
                })
                .collect::<Vec<_>>();
            value = Some(MpcField::<F, S>::from_le_bytes_mod_order(&bytes));
        }

        if bits.is_constant() {
            Ok(FpVar::constant(value.unwrap()))
        } else {
            let mut power = MpcField::<F, S>::one();
            // Compute a linear combination for the new field variable, again
            // via double and add.
            let mut combined_lc = LinearCombination::zero();
            bits.iter().for_each(|b| {
                combined_lc = &combined_lc + (power, b.lc());
                power.double_in_place();
            });
            // Allocate the new variable as a SymbolicLc
            let variable = cs.new_lc(combined_lc)?;
            // If the number of bits is less than the size of the field,
            // then we do not need to enforce that the element is less than
            // the modulus.
            if bits.len() >= <MpcField<F, S> as PrimeField>::Params::MODULUS_BITS as usize {
                Self::enforce_in_field_le(bits)?;
            }
            Ok(AllocatedFp::new(value, variable, cs.clone()).into())
        }
    }

    /// Enforces that `bits`, when interpreted as a integer, is less than
    /// `F::characteristic()`, That is, interpret bits as a little-endian
    /// integer, and enforce that this integer is "in the field Z_p", where
    /// `p = F::characteristic()` .
    #[tracing::instrument(target = "r1cs")]
    pub fn enforce_in_field_le(bits: &[Self]) -> Result<(), SynthesisError> {
        // `bits` < F::characteristic() <==> `bits` <= F::characteristic() -1
        let mut b = F::characteristic().to_vec();
        assert_eq!(b[0] % 2, 1);
        b[0] -= 1; // This works, because the LSB is one, so there's no borrows.
        let run = Self::enforce_smaller_or_equal_than_le(bits, b)?;

        // We should always end in a "run" of zeros, because
        // the characteristic is an odd prime. So, this should
        // be empty.
        assert!(run.is_empty());

        Ok(())
    }

    /// Enforces that `bits` is less than or equal to `element`,
    /// when both are interpreted as (little-endian) integers.
    #[tracing::instrument(target = "r1cs", skip(element))]
    pub fn enforce_smaller_or_equal_than_le<'a>(
        bits: &[Self],
        element: impl AsRef<[u64]>,
    ) -> Result<Vec<Self>, SynthesisError> {
        let b: &[u64] = element.as_ref();

        let mut bits_iter = bits.iter().rev(); // Iterate in big-endian

        // Runs of ones in r
        let mut last_run = MpcBoolean::constant(true);
        let mut current_run = vec![];

        let mut element_num_bits = 0;
        for _ in BitIteratorBE::without_leading_zeros(b) {
            element_num_bits += 1;
        }

        if bits.len() > element_num_bits {
            let mut or_result = MpcBoolean::constant(false);
            for should_be_zero in &bits[element_num_bits..] {
                or_result = or_result.or(should_be_zero)?;
                let _ = bits_iter.next().unwrap();
            }
            or_result.enforce_equal(&MpcBoolean::constant(false))?;
        }

        for (b, a) in BitIteratorBE::without_leading_zeros(b).zip(bits_iter.by_ref()) {
            if b {
                // This is part of a run of ones.
                current_run.push(a.clone());
            } else {
                if !current_run.is_empty() {
                    // This is the start of a run of zeros, but we need
                    // to k-ary AND against `last_run` first.

                    current_run.push(last_run.clone());
                    last_run = Self::kary_and(&current_run)?;
                    current_run.truncate(0);
                }

                // If `last_run` is true, `a` must be false, or it would
                // not be in the field.
                //
                // If `last_run` is false, `a` can be true or false.
                //
                // Ergo, at least one of `last_run` and `a` must be false.
                Self::enforce_kary_nand(&[last_run.clone(), a.clone()])?;
            }
        }
        assert!(bits_iter.next().is_none());

        Ok(current_run)
    }

    /// Conditionally selects one of `first` and `second` based on the value of
    /// `self`:
    ///
    /// If `self.is_eq(&Boolean::TRUE)`, this outputs `first`; else, it outputs
    /// `second`.
    /// ```
    /// # fn main() -> Result<(), ark_relations::r1cs::SynthesisError> {
    /// // We'll use the BLS12-381 scalar field for our constraints.
    /// use ark_test_curves::bls12_381::Fr;
    /// use ark_relations::r1cs::*;
    /// use ark_r1cs_std::prelude::*;
    ///
    /// let cs = ConstraintSystem::<Fr>::new_ref();
    ///
    /// let a = Boolean::new_witness(cs.clone(), || Ok(true))?;
    /// let b = Boolean::new_witness(cs.clone(), || Ok(false))?;
    ///
    /// let cond = Boolean::new_witness(cs.clone(), || Ok(true))?;
    ///
    /// cond.select(&a, &b)?.enforce_equal(&Boolean::TRUE)?;
    /// cond.select(&b, &a)?.enforce_equal(&Boolean::FALSE)?;
    ///
    /// assert!(cs.is_satisfied().unwrap());
    /// # Ok(())
    /// # }
    /// ```
    ///
    #[tracing::instrument(target = "r1cs", skip(first, second))]
    pub fn select<T: MpcCondSelectGadget<F, S>>(
        &self,
        first: &T,
        second: &T,
    ) -> Result<T, SynthesisError> {
        T::conditionally_select(&self, first, second)
    }
}

impl<F: PrimeField, S: FieldShare<F>> From<MpcAllocatedBool<F, S>> for MpcBoolean<F, S> {
    fn from(b: MpcAllocatedBool<F, S>) -> Self {
        MpcBoolean::Is(b)
    }
}

impl<F: PrimeField, S: FieldShare<F>> AllocVar<MpcField<F, S>, MpcField<F, S>>
    for MpcBoolean<F, S>
{
    fn new_variable<T: Borrow<MpcField<F, S>>>(
        cs: impl Into<Namespace<MpcField<F, S>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        if mode == AllocationMode::Constant {
            // Ok(MpcBoolean::Constant(*f()?.borrow()))
            unimplemented!()
        } else {
            MpcAllocatedBool::new_variable(cs, f, mode).map(MpcBoolean::from)
        }
    }
}

impl<F: PrimeField, S: FieldShare<F>> MpcEqGadget<F, S> for MpcBoolean<F, S> {
    #[tracing::instrument(target = "r1cs")]
    fn is_eq(&self, other: &Self) -> Result<MpcBoolean<F, S>, SynthesisError> {
        // self | other | XNOR(self, other) | self == other
        // -----|-------|-------------------|--------------
        //   0  |   0   |         1         |      1
        //   0  |   1   |         0         |      0
        //   1  |   0   |         0         |      0
        //   1  |   1   |         1         |      1
        Ok(self.xor(other)?.not())
    }

    #[tracing::instrument(target = "r1cs")]
    fn conditional_enforce_equal(
        &self,
        other: &Self,
        condition: &MpcBoolean<F, S>,
    ) -> Result<(), SynthesisError> {
        use MpcBoolean::*;
        let one = Variable::One;
        let difference = match (self, other) {
            // 1 == 1; 0 == 0
            (Constant(true), Constant(true)) | (Constant(false), Constant(false)) => return Ok(()),
            // false != true
            (Constant(_), Constant(_)) => return Err(SynthesisError::AssignmentMissing),
            // 1 - a
            (Constant(true), Is(a)) | (Is(a), Constant(true)) => lc!() + one - a.variable(),
            // a - 0 = a
            (Constant(false), Is(a)) | (Is(a), Constant(false)) => lc!() + a.variable(),
            // 1 - !a = 1 - (1 - a) = a
            (Constant(true), Not(a)) | (Not(a), Constant(true)) => lc!() + a.variable(),
            // !a - 0 = !a = 1 - a
            (Constant(false), Not(a)) | (Not(a), Constant(false)) => lc!() + one - a.variable(),
            // b - a,
            (Is(a), Is(b)) => lc!() + b.variable() - a.variable(),
            // !b - a = (1 - b) - a
            (Is(a), Not(b)) | (Not(b), Is(a)) => lc!() + one - b.variable() - a.variable(),
            // !b - !a = (1 - b) - (1 - a) = a - b,
            (Not(a), Not(b)) => lc!() + a.variable() - b.variable(),
        };

        if condition != &Constant(false) {
            let cs = self.cs().or(other.cs()).or(condition.cs());
            cs.enforce_constraint(lc!() + difference, condition.lc(), lc!())?;
        }
        Ok(())
    }

    #[tracing::instrument(target = "r1cs")]
    fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        should_enforce: &MpcBoolean<F, S>,
    ) -> Result<(), SynthesisError> {
        use MpcBoolean::*;
        let one = Variable::One;
        let difference = match (self, other) {
            // 1 != 0; 0 != 1
            (Constant(true), Constant(false)) | (Constant(false), Constant(true)) => return Ok(()),
            // false == false and true == true
            (Constant(_), Constant(_)) => return Err(SynthesisError::AssignmentMissing),
            // 1 - a
            (Constant(true), Is(a)) | (Is(a), Constant(true)) => lc!() + one - a.variable(),
            // a - 0 = a
            (Constant(false), Is(a)) | (Is(a), Constant(false)) => lc!() + a.variable(),
            // 1 - !a = 1 - (1 - a) = a
            (Constant(true), Not(a)) | (Not(a), Constant(true)) => lc!() + a.variable(),
            // !a - 0 = !a = 1 - a
            (Constant(false), Not(a)) | (Not(a), Constant(false)) => lc!() + one - a.variable(),
            // b - a,
            (Is(a), Is(b)) => lc!() + b.variable() - a.variable(),
            // !b - a = (1 - b) - a
            (Is(a), Not(b)) | (Not(b), Is(a)) => lc!() + one - b.variable() - a.variable(),
            // !b - !a = (1 - b) - (1 - a) = a - b,
            (Not(a), Not(b)) => lc!() + a.variable() - b.variable(),
        };

        if should_enforce != &Constant(false) {
            let cs = self.cs().or(other.cs()).or(should_enforce.cs());
            cs.enforce_constraint(difference, should_enforce.lc(), should_enforce.lc())?;
        }
        Ok(())
    }
}

// impl<F: PrimeField, S: FieldShare<F>> ToBytesGadget<MpcField<F, S>> for MpcBoolean<F, S> {
//     /// Outputs `1u8` if `self` is true, and `0u8` otherwise.
//     #[tracing::instrument(target = "r1cs")]
//     fn to_bytes(&self) -> Result<Vec<UInt8<MpcField<F, S>>>, SynthesisError> {
//         let value = self.value().map(u8::from).ok();
//         let mut bits = [MpcBoolean::FALSE; 8];
//         bits[0] = self.clone();
//         Ok(vec![UInt8 { bits, value }])
//     }
// }

// impl<F: PrimeField, S: FieldShare<F>> ToConstraintFieldGadget<MpcField<F, S>> for MpcBoolean<F, S> {
//     #[tracing::instrument(target = "r1cs")]
//     fn to_constraint_field(&self) -> Result<Vec<MpcFpVar<MpcField<F, S>>>, SynthesisError> {
//         let var = From::from(self.clone());
//         Ok(vec![var])
//     }
// }

impl<F: PrimeField, S: FieldShare<F>> MpcCondSelectGadget<F, S> for MpcBoolean<F, S> {
    #[tracing::instrument(target = "r1cs")]
    fn conditionally_select(
        cond: &MpcBoolean<F, S>,
        true_val: &Self,
        false_val: &Self,
    ) -> Result<Self, SynthesisError> {
        use MpcBoolean::*;
        match cond {
            Constant(true) => Ok(true_val.clone()),
            Constant(false) => Ok(false_val.clone()),
            cond @ Not(_) => Self::conditionally_select(&cond.not(), false_val, true_val),
            cond @ Is(_) => match (true_val, false_val) {
                (x, &Constant(false)) => cond.and(x),
                (&Constant(false), x) => cond.not().and(x),
                (&Constant(true), x) => cond.or(x),
                (x, &Constant(true)) => cond.not().or(x),
                (a, b) => {
                    let cs = cond.cs();
                    let result: MpcBoolean<F, S> =
                        MpcAllocatedBool::new_witness_without_booleanity_check(cs.clone(), || {
                            let cond = cond.value()?;
                            Ok(if cond { a.value()? } else { b.value()? })
                        })?
                        .into();
                    // a = self; b = other; c = cond;
                    //
                    // r = c * a + (1  - c) * b
                    // r = b + c * (a - b)
                    // c * (a - b) = r - b
                    //
                    // If a, b, cond are all boolean, so is r.
                    //
                    // self | other | cond | result
                    // -----|-------|----------------
                    //   0  |   0   |   1  |    0
                    //   0  |   1   |   1  |    0
                    //   1  |   0   |   1  |    1
                    //   1  |   1   |   1  |    1
                    //   0  |   0   |   0  |    0
                    //   0  |   1   |   0  |    1
                    //   1  |   0   |   0  |    0
                    //   1  |   1   |   0  |    1
                    cs.enforce_constraint(
                        cond.lc(),
                        lc!() + a.lc() - b.lc(),
                        lc!() + result.lc() - b.lc(),
                    )?;

                    Ok(result)
                }
            },
        }
    }
}
