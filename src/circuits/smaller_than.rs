use std::cmp::Ordering;

use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use mpc_algebra::malicious_majority::MpcField;
use mpc_algebra::MpcFpVar;

type Fr = ark_bls12_377::Fr;
type MFr = MpcField<Fr>;

pub struct LessThanCircuit<F: PrimeField> {
    pub a: F,
    pub b: F,
    pub cmp: Ordering,
    pub check_eq: bool,
}

impl ConstraintSynthesizer<MFr> for LessThanCircuit<MFr> {
    fn generate_constraints(self, cs: ConstraintSystemRef<MFr>) -> Result<(), SynthesisError> {
        let a_var = MpcFpVar::new_witness(cs.clone(), || Ok(self.a))?;
        let b_var = MpcFpVar::new_witness(cs, || Ok(self.b))?;

        let _res = MpcFpVar::is_cmp(&a_var, &b_var, self.cmp, self.check_eq).unwrap();

        Ok(())
    }
}

impl ConstraintSynthesizer<Fr> for LessThanCircuit<Fr> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a_var = FpVar::new_witness(cs.clone(), || Ok(self.a))?;
        let b_var = FpVar::new_witness(cs, || Ok(self.b))?;

        let _res = FpVar::is_cmp(&a_var, &b_var, self.cmp, self.check_eq).unwrap();

        Ok(())
    }
}
