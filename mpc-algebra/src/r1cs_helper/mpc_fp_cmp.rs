use crate::{
    mpc_fields::MpcFieldVar, BitDecomposition, EqualityZero, MpcBoolean, MpcFpVar, MpcToBitsGadget,
};
use ark_ff::{PrimeField, SquareRootField};
use ark_r1cs_std::R1CSVar;
use ark_relations::{
    lc,
    r1cs::{SynthesisError, Variable},
};
use core::cmp::Ordering;

impl<F: PrimeField + SquareRootField + EqualityZero + BitDecomposition> MpcFpVar<F> {
    /// This function enforces the ordering between `self` and `other`. The
    /// constraint system will not be satisfied otherwise. If `self` should
    /// also be checked for equality, e.g. `self <= other` instead of `self <
    /// other`, set `should_also_check_quality` to `true`. This variant
    /// verifies `self` and `other` are `<= (p-1)/2`.
    #[tracing::instrument(target = "r1cs")]
    pub fn enforce_cmp(
        &self,
        other: &MpcFpVar<F>,
        ordering: Ordering,
        should_also_check_equality: bool,
    ) -> Result<(), SynthesisError> {
        let (left, right) = self.process_cmp_inputs(other, ordering, should_also_check_equality)?;
        left.enforce_smaller_than(&right)
    }

    /// This function enforces the ordering between `self` and `other`. The
    /// constraint system will not be satisfied otherwise. If `self` should
    /// also be checked for equality, e.g. `self <= other` instead of `self <
    /// other`, set `should_also_check_quality` to `true`. This variant
    /// assumes `self` and `other` are `<= (p-1)/2` and does not generate
    /// constraints to verify that.
    #[tracing::instrument(target = "r1cs")]
    pub fn enforce_cmp_unchecked(
        &self,
        other: &MpcFpVar<F>,
        ordering: Ordering,
        should_also_check_equality: bool,
    ) -> Result<(), SynthesisError> {
        let (left, right) = self.process_cmp_inputs(other, ordering, should_also_check_equality)?;
        left.enforce_smaller_than_unchecked(&right)
    }

    /// This function checks the ordering between `self` and `other`. It outputs
    /// self `Boolean` that contains the result - `1` if true, `0`
    /// otherwise. The constraint system will be satisfied in any case. If
    /// `self` should also be checked for equality, e.g. `self <= other`
    /// instead of `self < other`, set `should_also_check_quality` to
    /// `true`. This variant verifies `self` and `other` are `<= (p-1)/2`.
    #[tracing::instrument(target = "r1cs")]
    pub fn is_cmp(
        &self,
        other: &MpcFpVar<F>,
        ordering: Ordering,
        should_also_check_equality: bool,
    ) -> Result<MpcBoolean<F>, SynthesisError> {
        let (left, right) = self.process_cmp_inputs(other, ordering, should_also_check_equality)?;
        left.is_smaller_than(&right)
    }

    /// This function checks the ordering between `self` and `other`. It outputs
    /// a `Boolean` that contains the result - `1` if true, `0` otherwise.
    /// The constraint system will be satisfied in any case. If `self`
    /// should also be checked for equality, e.g. `self <= other` instead of
    /// `self < other`, set `should_also_check_quality` to `true`. This
    /// variant assumes `self` and `other` are `<= (p-1)/2` and does not
    /// generate constraints to verify that.
    #[tracing::instrument(target = "r1cs")]
    pub fn is_cmp_unchecked(
        &self,
        other: &MpcFpVar<F>,
        ordering: Ordering,
        should_also_check_equality: bool,
    ) -> Result<MpcBoolean<F>, SynthesisError> {
        let (left, right) = self.process_cmp_inputs(other, ordering, should_also_check_equality)?;
        left.is_smaller_than_unchecked(&right)
    }

    fn process_cmp_inputs(
        &self,
        other: &Self,
        ordering: Ordering,
        should_also_check_equality: bool,
    ) -> Result<(Self, Self), SynthesisError> {
        let (left, right) = match ordering {
            Ordering::Less => (self, other),
            Ordering::Greater => (other, self),
            Ordering::Equal => return Err(SynthesisError::Unsatisfiable),
        };
        let right_for_check = if should_also_check_equality {
            right + F::one()
        } else {
            right.clone()
        };

        Ok((left.clone(), right_for_check))
    }

    /// Helper function to enforce that `self <= (p-1)/2`.
    #[tracing::instrument(target = "r1cs")]
    pub fn enforce_smaller_or_equal_than_mod_minus_one_div_two(
        &self,
    ) -> Result<(), SynthesisError> {
        // It's okay to use `to_non_unique_bits` bits here because we're enforcing
        // self <= (p-1)/2, which implies self < p.
        let _ = MpcBoolean::enforce_smaller_or_equal_than_le(
            &self.to_non_unique_bits_le()?,
            F::modulus_minus_one_div_two(),
        )?;
        Ok(())
    }

    /// Helper function to check `self < other` and output a result bit. This
    /// function verifies `self` and `other` are `<= (p-1)/2`.
    fn is_smaller_than(&self, other: &MpcFpVar<F>) -> Result<MpcBoolean<F>, SynthesisError> {
        self.enforce_smaller_or_equal_than_mod_minus_one_div_two()?;
        other.enforce_smaller_or_equal_than_mod_minus_one_div_two()?;
        self.is_smaller_than_unchecked(other)
    }

    /// Helper function to check `self < other` and output a result bit. This
    /// function assumes `self` and `other` are `<= (p-1)/2` and does not
    /// generate constraints to verify that.
    fn is_smaller_than_unchecked(
        &self,
        other: &MpcFpVar<F>,
    ) -> Result<MpcBoolean<F>, SynthesisError> {
        Ok((self - other)
            .double()?
            .to_bits_le()?
            .first()
            .unwrap()
            .clone())
    }

    /// Helper function to enforce `self < other`. This function verifies `self`
    /// and `other` are `<= (p-1)/2`.
    fn enforce_smaller_than(&self, other: &MpcFpVar<F>) -> Result<(), SynthesisError> {
        self.enforce_smaller_or_equal_than_mod_minus_one_div_two()?;
        other.enforce_smaller_or_equal_than_mod_minus_one_div_two()?;
        self.enforce_smaller_than_unchecked(other)
    }

    /// Helper function to enforce `self < other`. This function assumes `self`
    /// and `other` are `<= (p-1)/2` and does not generate constraints to
    /// verify that.
    fn enforce_smaller_than_unchecked(&self, other: &MpcFpVar<F>) -> Result<(), SynthesisError> {
        let is_smaller_than = self.is_smaller_than_unchecked(other)?;
        let lc_one = lc!() + Variable::One;
        [self, other]
            .cs()
            .enforce_constraint(is_smaller_than.lc(), lc_one.clone(), lc_one)
    }
}
