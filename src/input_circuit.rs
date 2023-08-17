use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};

use ark_bls12_377::Fr;

use std::cmp::Ordering;

use ark_crypto_primitives::{
    commitment::{
        pedersen::{constraints::CommGadget, Commitment, Randomness},
        CommitmentGadget,
    },
    crh::pedersen,
    CommitmentScheme,
};

use ark_ed_on_bls12_377::{constraints::EdwardsVar, EdwardsParameters};

pub type JubJub = ark_ed_on_bls12_377::EdwardsProjective;

pub const PERDERSON_WINDOW_SIZE: usize = 100;
pub const PERDERSON_WINDOW_NUM: usize = 256;

#[derive(Clone)]
pub struct Window;
impl pedersen::Window for Window {
    const WINDOW_SIZE: usize = PERDERSON_WINDOW_SIZE;
    const NUM_WINDOWS: usize = PERDERSON_WINDOW_NUM;
}

pub type PedersenComScheme = Commitment<JubJub, Window>;
pub type PedersenCommitment = <PedersenComScheme as CommitmentScheme>::Output;
pub type PedersenParam = <PedersenComScheme as CommitmentScheme>::Parameters;
pub type PedersenRandomness = Randomness<JubJub>;

pub type PedersenComSchemeVar = CommGadget<JubJub, EdwardsVar, Window>;
pub type PedersenParamVar =
    <PedersenComSchemeVar as CommitmentGadget<PedersenComScheme, Fr>>::ParametersVar;
pub type PedersenRandomnessVar =
    <PedersenComSchemeVar as CommitmentGadget<PedersenComScheme, Fr>>::RandomnessVar;
pub type PedersenCommitmentVar = AffineVar<EdwardsParameters, FpVar<Fr>>;

#[derive(Clone)]
pub struct PedersenComCircuit {
    pub param: PedersenParam,
    pub input: Fr,
    pub open: PedersenRandomness,
    pub commit: PedersenCommitment,
}

impl ConstraintSynthesizer<Fr> for PedersenComCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        #[cfg(debug_assertions)]
        println!("is setup mode?: {}", cs.is_in_setup_mode());
        let _cs_no = cs.num_constraints();

        // step 1. Allocate Parameters for perdersen commitment
        let param_var =
            PedersenParamVar::new_input(ark_relations::ns!(cs, "gadget_parameters"), || {
                Ok(&self.param)
            })
            .unwrap();
        let _cs_no = cs.num_constraints() - _cs_no;
        #[cfg(debug_assertions)]
        println!("cs for parameters: {}", _cs_no);
        let _cs_no = cs.num_constraints();

        // step 2. Allocate inputs
        let input_var = FpVar::new_witness(cs.clone(), || Ok(self.input))?;
        let input_var_byte = input_var.to_bytes()?;

        let _cs_no = cs.num_constraints() - _cs_no;
        #[cfg(debug_assertions)]
        println!("cs for account: {}", _cs_no);
        let _cs_no = cs.num_constraints();

        // step 3. Allocate the opening
        let open_var =
            PedersenRandomnessVar::new_witness(ark_relations::ns!(cs, "gadget_randomness"), || {
                Ok(&self.open)
            })
            .unwrap();

        let _cs_no = cs.num_constraints() - _cs_no;
        #[cfg(debug_assertions)]
        println!("cs for opening: {}", _cs_no);
        let _cs_no = cs.num_constraints();

        // step 4. Allocate the output
        let result_var =
            PedersenComSchemeVar::commit(&param_var, &input_var_byte, &open_var).unwrap();

        let _cs_no = cs.num_constraints() - _cs_no;
        #[cfg(debug_assertions)]
        println!("cs for commitment: {}", _cs_no);
        let _cs_no = cs.num_constraints();

        // circuit to compare the commited value with supplied value
        let commitment_var2 =
            PedersenCommitmentVar::new_input(ark_relations::ns!(cs, "gadget_commitment"), || {
                Ok(self.commit)
            })
            .unwrap();
        result_var.enforce_equal(&commitment_var2).unwrap();

        let _cs_no = cs.num_constraints() - _cs_no;
        #[cfg(debug_assertions)]
        println!("cs for comparison: {}", _cs_no);

        #[cfg(debug_assertions)]
        println!("total cs for Commitment: {}", cs.num_constraints());
        Ok(())
    }
}

#[derive(Clone)]
pub struct MySecretInputCircuit {
    // private witness to the circuit
    x: Option<Fr>,
    randomness: Option<PedersenRandomness>,
    params: Option<PedersenParam>,

    // public instance to the circuit
    h_x: Option<PedersenCommitment>,
    lower_bound: Option<Fr>,
    upper_bound: Option<Fr>,
}

impl MySecretInputCircuit {
    fn verify_constraints(&self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x = FpVar::new_witness(cs.clone(), || {
            self.x.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let lower_bound = FpVar::new_input(cs.clone(), || {
            self.lower_bound.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let upper_bound = FpVar::new_input(cs.clone(), || {
            self.upper_bound.ok_or(SynthesisError::AssignmentMissing)
        })?;

        x.enforce_cmp(&lower_bound, Ordering::Greater, true)?;
        x.enforce_cmp(&upper_bound, Ordering::Less, false)?;

        Ok(())
    }

    fn verify_commitment(&self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x_com_circuit = PedersenComCircuit {
            param: self.params.clone().unwrap(),
            input: self.x.clone().unwrap(),
            open: self.randomness.clone().unwrap(),
            commit: self.h_x.unwrap(),
        };

        x_com_circuit.generate_constraints(cs.clone())?;

        Ok(())
    }
}

impl ConstraintSynthesizer<Fr> for MySecretInputCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        self.verify_constraints(cs.clone())?;

        self.verify_commitment(cs.clone())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_377::Bls12_377;
    use ark_ff::{BigInteger, PrimeField};
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    use ark_std::UniformRand;

    use super::*;

    #[test]
    fn test_no_circom() {
        let mut rng = rand::thread_rng();

        // generate the setup parameters
        let x = Fr::from(4);

        let lower_bound = Fr::from(3);
        let upper_bound = Fr::from(7);

        // Pedersen commitment
        let params = PedersenComScheme::setup(&mut rng).unwrap();
        let randomness = PedersenRandomness::rand(&mut rng);
        let x_bytes = x.into_repr().to_bytes_le();
        let h_x = PedersenComScheme::commit(&params, &x_bytes, &randomness).unwrap();

        let circuit = MySecretInputCircuit {
            x: Some(x),
            h_x: Some(h_x),
            lower_bound: Some(lower_bound),
            upper_bound: Some(upper_bound),
            randomness: Some(randomness),
            params: Some(params),
        };

        let (circuit_pk, circuit_vk) =
            Groth16::<Bls12_377>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();

        // calculate the proof by passing witness variable value
        let proof = Groth16::<Bls12_377>::prove(&circuit_pk, circuit.clone(), &mut rng).unwrap();

        // // validate the proof
        assert!(Groth16::<Bls12_377>::verify(
            &circuit_vk,
            &[lower_bound, upper_bound, h_x.x, h_x.y],
            &proof
        )
        .unwrap());
    }
}
