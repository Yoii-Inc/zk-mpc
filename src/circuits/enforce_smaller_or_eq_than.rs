use ark_ff::One;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::field::*;
use mpc_algebra::MpcBoolean;

type Fr = ark_bls12_377::Fr;
type MFr = MpcField<Fr>;

pub struct SmallerEqThanCircuit<F: PrimeField> {
    pub a: Vec<F>,
    // instance
    pub b: Fr,
}

impl ConstraintSynthesizer<MFr> for SmallerEqThanCircuit<MFr> {
    fn generate_constraints(self, cs: ConstraintSystemRef<MFr>) -> Result<(), SynthesisError> {
        // let a_var = MpcFpVar::new_witness(cs.clone(), || Ok(self.a))?;
        let a_var = self
            .a
            .iter()
            .map(|x| MpcBoolean::new_witness(cs.clone(), || Ok(x)).unwrap())
            .collect::<Vec<_>>();

        let _ = MpcBoolean::enforce_smaller_or_equal_than_le(&a_var, self.b.into_repr()).unwrap();
        Ok(())
    }
}

impl ConstraintSynthesizer<Fr> for SmallerEqThanCircuit<Fr> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a_var = self
            .a
            .iter()
            .map(|x| Boolean::new_witness(cs.clone(), || Ok(x.is_one())).unwrap())
            .collect::<Vec<_>>();

        let _ = Boolean::enforce_smaller_or_equal_than_le(&a_var, self.b.into_repr()).unwrap();
        Ok(())
    }
}
