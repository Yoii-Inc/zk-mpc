use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use mpc_algebra::{malicious_majority::MpcField, MpcBoolean, MpcEqGadget, MpcFpVar};
use mpc_algebra::{BooleanWire, EqualityZero};

type Fr = ark_bls12_377::Fr;
type MFr = MpcField<Fr>;

pub struct EqualityZeroCircuit<F: PrimeField> {
    pub a: F,
}

impl ConstraintSynthesizer<MFr> for EqualityZeroCircuit<MFr> {
    fn generate_constraints(self, cs: ConstraintSystemRef<MFr>) -> Result<(), SynthesisError> {
        let a_var = MpcFpVar::new_witness(cs.clone(), || Ok(self.a))?;

        a_var.is_zero()?.enforce_equal(&MpcBoolean::TRUE)?;

        Ok(())
    }
}

impl ConstraintSynthesizer<Fr> for EqualityZeroCircuit<Fr> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a_var = FpVar::new_witness(cs.clone(), || Ok(self.a))?;

        a_var.is_zero()?.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}

#[derive(Clone)]
pub struct NotEqualityZeroCircuit<F: PrimeField> {
    pub a: F,
}

impl ConstraintSynthesizer<MFr> for NotEqualityZeroCircuit<MFr> {
    fn generate_constraints(self, cs: ConstraintSystemRef<MFr>) -> Result<(), SynthesisError> {
        let a_var = MpcFpVar::new_witness(cs.clone(), || Ok(self.a))?;

        let is_zero_var =
            MpcBoolean::new_input(cs.clone(), || Ok(self.a.is_zero_shared().field()))?;

        a_var.is_zero()?.enforce_equal(&is_zero_var)?;

        Ok(())
    }
}

impl ConstraintSynthesizer<Fr> for NotEqualityZeroCircuit<Fr> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a_var = FpVar::new_witness(cs.clone(), || Ok(self.a))?;

        let is_zero_var = Boolean::new_input(cs.clone(), || Ok(ark_ff::Zero::is_zero(&self.a)))?;

        a_var.is_zero()?.enforce_equal(&is_zero_var)?;

        Ok(())
    }
}
