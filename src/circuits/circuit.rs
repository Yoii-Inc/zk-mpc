use ark_ff::PrimeField;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

use super::{LocalOrMPC, PedersenComCircuit};

#[derive(Clone)]
pub struct MyCircuit<F: PrimeField + LocalOrMPC<F>> {
    pub a: Option<F>,
    pub b: Option<F>,

    pub params: Option<F::PedersenParam>,
    pub vec_x: Option<Vec<F>>,
    pub randomness: Option<Vec<F::PedersenRandomness>>,

    pub vec_h_x: Option<Vec<F::PedersenCommitment>>,
}

impl<F: PrimeField + LocalOrMPC<F>> MyCircuit<F> {
    fn verify_commitments(&self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        for i in 0..self.vec_x.as_ref().unwrap().len() {
            let x = self.vec_x.clone().unwrap()[i];
            let h_x = &self.vec_h_x.clone().unwrap()[i];
            let randomness = &self.randomness.clone().unwrap()[i];

            let x_com_circuit = PedersenComCircuit {
                param: self.params.clone(),
                input: Some(x),
                open: Some(randomness.clone()),
                commit: Some(h_x.clone()),
            };

            x_com_circuit.generate_constraints(cs.clone())?;
        }

        Ok(())
    }
}

impl<ConstraintF: PrimeField + LocalOrMPC<ConstraintF>> ConstraintSynthesizer<ConstraintF>
    for MyCircuit<ConstraintF>
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            a.mul_assign(&b);
            Ok(a)
        })?;

        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;

        self.verify_commitments(cs.clone())?;

        println!("total number of constraints: {}", cs.num_constraints());

        Ok(())
    }
}
