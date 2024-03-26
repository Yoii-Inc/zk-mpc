// use crate::{prelude::*, Vec};
use crate::{FieldShare, MpcBoolean};
use ark_ff::PrimeField;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::SynthesisError;

/// Specifies how to generate constraints that check for equality for two
/// variables of type `Self`.
pub trait MpcEqGadget<F: PrimeField, S: FieldShare<F>> {
    /// Output a `Boolean` value representing whether `self.value() ==
    /// other.value()`.
    fn is_eq(&self, other: &Self) -> Result<MpcBoolean<F, S>, SynthesisError>;

    /// Output a `Boolean` value representing whether `self.value() !=
    /// other.value()`.
    ///
    /// By default, this is defined as `self.is_eq(other)?.not()`.
    fn is_neq(&self, other: &Self) -> Result<MpcBoolean<F, S>, SynthesisError> {
        Ok(self.is_eq(other)?.not())
    }

    /// If `should_enforce == true`, enforce that `self` and `other` are equal;
    /// else, enforce a vacuously true statement.
    ///
    /// A safe default implementation is provided that generates the following
    /// constraints: `self.is_eq(other)?.conditional_enforce_equal(&Boolean:
    /// :TRUE, should_enforce)`.
    ///
    /// More efficient specialized implementation may be possible; implementors
    /// are encouraged to carefully analyze the efficiency and safety of these.
    #[tracing::instrument(target = "r1cs", skip(self, other))]
    fn conditional_enforce_equal(
        &self,
        other: &Self,
        should_enforce: &MpcBoolean<F, S>,
    ) -> Result<(), SynthesisError> {
        self.is_eq(&other)?
            .conditional_enforce_equal(&MpcBoolean::constant(true), should_enforce)
    }

    /// Enforce that `self` and `other` are equal.
    ///
    /// A safe default implementation is provided that generates the following
    /// constraints: `self.conditional_enforce_equal(other,
    /// &Boolean::TRUE)`.
    ///
    /// More efficient specialized implementation may be possible; implementors
    /// are encouraged to carefully analyze the efficiency and safety of these.
    #[tracing::instrument(target = "r1cs", skip(self, other))]
    fn enforce_equal(&self, other: &Self) -> Result<(), SynthesisError> {
        self.conditional_enforce_equal(other, &MpcBoolean::constant(true))
    }

    /// If `should_enforce == true`, enforce that `self` and `other` are *not*
    /// equal; else, enforce a vacuously true statement.
    ///
    /// A safe default implementation is provided that generates the following
    /// constraints: `self.is_neq(other)?.conditional_enforce_equal(&
    /// Boolean::TRUE, should_enforce)`.
    ///
    /// More efficient specialized implementation may be possible; implementors
    /// are encouraged to carefully analyze the efficiency and safety of these.
    #[tracing::instrument(target = "r1cs", skip(self, other))]
    fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        should_enforce: &MpcBoolean<F, S>,
    ) -> Result<(), SynthesisError> {
        self.is_neq(&other)?
            .conditional_enforce_equal(&MpcBoolean::constant(true), should_enforce)
    }

    /// Enforce that `self` and `other` are *not* equal.
    ///
    /// A safe default implementation is provided that generates the following
    /// constraints: `self.conditional_enforce_not_equal(other,
    /// &Boolean::TRUE)`.
    ///
    /// More efficient specialized implementation may be possible; implementors
    /// are encouraged to carefully analyze the efficiency and safety of these.
    #[tracing::instrument(target = "r1cs", skip(self, other))]
    fn enforce_not_equal(&self, other: &Self) -> Result<(), SynthesisError> {
        self.conditional_enforce_not_equal(other, &MpcBoolean::constant(true))
    }
}

impl<T: MpcEqGadget<F, S> + R1CSVar<F>, F: PrimeField, S: FieldShare<F>> MpcEqGadget<F, S>
    for [T]
{
    #[tracing::instrument(target = "r1cs", skip(self, other))]
    fn is_eq(&self, other: &Self) -> Result<MpcBoolean<F, S>, SynthesisError> {
        assert_eq!(self.len(), other.len());
        assert!(!self.is_empty());
        let mut results = Vec::with_capacity(self.len());
        for (a, b) in self.iter().zip(other) {
            results.push(a.is_eq(b)?);
        }
        MpcBoolean::kary_and(&results)
    }

    #[tracing::instrument(target = "r1cs", skip(self, other))]
    fn conditional_enforce_equal(
        &self,
        other: &Self,
        condition: &MpcBoolean<F, S>,
    ) -> Result<(), SynthesisError> {
        assert_eq!(self.len(), other.len());
        for (a, b) in self.iter().zip(other) {
            a.conditional_enforce_equal(b, condition)?;
        }
        Ok(())
    }

    #[tracing::instrument(target = "r1cs", skip(self, other))]
    fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        should_enforce: &MpcBoolean<F, S>,
    ) -> Result<(), SynthesisError> {
        assert_eq!(self.len(), other.len());
        let some_are_different = self.is_neq(other)?;
        if [&some_are_different, should_enforce].is_constant() {
            assert!(some_are_different.value().unwrap());
            Ok(())
        } else {
            let cs = [&some_are_different, should_enforce].cs();
            cs.enforce_constraint(
                some_are_different.lc(),
                should_enforce.lc(),
                should_enforce.lc(),
            )
        }
    }
}
