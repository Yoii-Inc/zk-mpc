use std::cmp::Ordering;

use ark_ff::One;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use mpc_algebra::malicious_majority::MpcField;
use mpc_algebra::{MpcBoolean, MpcEqGadget, MpcFpVar};

type Fr = ark_bls12_377::Fr;
type MFr = MpcField<Fr>;

/// This circuit checks if a value is smaller than another value.
pub struct SmallerThanCircuit<F: PrimeField> {
    pub a: F,
    pub b: F,
    pub res: F,
    pub cmp: Ordering,
    pub check_eq: bool,
}

impl ConstraintSynthesizer<MFr> for SmallerThanCircuit<MFr> {
    fn generate_constraints(self, cs: ConstraintSystemRef<MFr>) -> Result<(), SynthesisError> {
        let a_var = MpcFpVar::new_witness(cs.clone(), || Ok(self.a))?;
        let b_var = MpcFpVar::new_witness(cs.clone(), || Ok(self.b))?;
        let res_var = MpcBoolean::new_witness(cs.clone(), || Ok(self.res))?;
        let res2 = MpcFpVar::is_cmp(&a_var, &b_var, self.cmp, self.check_eq).unwrap();

        res_var.enforce_equal(&res2);

        Ok(())
    }
}

impl ConstraintSynthesizer<Fr> for SmallerThanCircuit<Fr> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a_var = FpVar::new_witness(cs.clone(), || Ok(self.a))?;
        let b_var = FpVar::new_witness(cs.clone(), || Ok(self.b))?;
        let res_var = Boolean::new_witness(cs.clone(), || Ok(self.res.is_one()))?;
        let res2 = FpVar::is_cmp(&a_var, &b_var, self.cmp, self.check_eq).unwrap();

        res_var.enforce_equal(&res2);

        Ok(())
    }
}
