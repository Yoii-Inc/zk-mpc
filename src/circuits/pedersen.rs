use ark_bls12_377::Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};

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
pub type PedersenParamVar<ConstraintF> =
    <PedersenComSchemeVar as CommitmentGadget<PedersenComScheme, ConstraintF>>::ParametersVar;
pub type PedersenRandomnessVar<ConstraintF> =
    <PedersenComSchemeVar as CommitmentGadget<PedersenComScheme, ConstraintF>>::RandomnessVar;
pub type PedersenCommitmentVar<ConstraintF> = AffineVar<EdwardsParameters, FpVar<ConstraintF>>;

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
pub struct PedersenComsCircuit {
    pub param: PedersenParam,
    pub inputs: Vec<Fr>,
    pub opens: Vec<PedersenRandomness>,
    pub commits: Vec<PedersenCommitment>,
}

impl ConstraintSynthesizer<Fr> for PedersenComsCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        for ((input, open), commit) in self
            .inputs
            .iter()
            .zip(self.opens.iter())
            .zip(self.commits.iter())
        {
            let circuit = PedersenComCircuit {
                param: self.param.clone(),
                input: *input,
                open: open.clone(),
                commit: *commit,
            };

            circuit.generate_constraints(cs.clone())?;
        }
        Ok(())
    }
}
