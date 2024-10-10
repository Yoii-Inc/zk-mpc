use ark_ff::PrimeField;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

use crate::input::SampleMpcInput;

use super::{LocalOrMPC, PedersenComCircuit};

#[derive(Clone)]
pub struct MyCircuit<F: PrimeField + LocalOrMPC<F>> {
    pub mpc_input: SampleMpcInput<F>,
}

impl<F: PrimeField + LocalOrMPC<F>> MyCircuit<F> {
    fn verify_commitments(&self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a_com_circuit = PedersenComCircuit {
            param: Some(self.clone().mpc_input.common.unwrap().pedersen_param),
            input: self.clone().mpc_input.peculiar.unwrap().a.input,
            open: self.clone().mpc_input.peculiar.unwrap().a.randomness,
            commit: self.clone().mpc_input.peculiar.unwrap().a.commitment,
        };

        a_com_circuit.generate_constraints(cs.clone())?;

        let b_com_circuit = PedersenComCircuit {
            param: Some(self.clone().mpc_input.common.unwrap().pedersen_param),
            input: self.clone().mpc_input.peculiar.unwrap().b.input,
            open: self.clone().mpc_input.peculiar.unwrap().b.randomness,
            commit: self.clone().mpc_input.peculiar.unwrap().b.commitment,
        };

        b_com_circuit.generate_constraints(cs.clone())?;

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
        let peculiar_input = self
            .mpc_input
            .peculiar
            .clone()
            .ok_or(SynthesisError::AssignmentMissing)?;

        let a = cs.new_witness_variable(|| Ok(peculiar_input.a.input))?;
        let b = cs.new_witness_variable(|| Ok(peculiar_input.b.input))?;
        let c = cs.new_input_variable(|| {
            let mut a = peculiar_input.a.input;
            let b = peculiar_input.b.input;

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

#[derive(Clone)]
pub struct MySimpleCircuit<F: PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
}

impl<ConstraintF: PrimeField> ConstraintSynthesizer<ConstraintF> for MySimpleCircuit<ConstraintF> {
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

        println!("total number of constraints: {}", cs.num_constraints());

        Ok(())
    }
}
