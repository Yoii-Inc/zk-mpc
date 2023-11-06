use ark_bls12_377::Fr;
use ark_ec::ProjectiveCurve;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use ark_ff::PrimeField;
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
use mpc_algebra::{
    AdditiveFieldShare, MpcEdwardsParameters, MpcEdwardsProjective, MpcEdwardsVar, MpcField,
};

use ark_ff::bytes::ToBytes;
use ark_std::{fmt::Debug, hash::Hash};

type MFr = MpcField<Fr, AdditiveFieldShare<Fr>>;

pub trait LocalOrMPC<ConstraintF: PrimeField> {
    type JubJub: ProjectiveCurve;
    type PedersenComScheme: CommitmentScheme<
        Output = Self::PedersenCommitment,
        Parameters = Self::PedersenParam,
        Randomness = Self::PedersenRandomness,
    >;
    type PedersenCommitment: ToBytes + Clone + Default + Eq + Hash + Debug;
    type PedersenParam: Clone;
    type PedersenRandomness: Clone + PartialEq + Debug + Eq + Default;

    type PedersenComSchemeVar: CommitmentGadget<
        Self::PedersenComScheme,
        ConstraintF,
        OutputVar = Self::PedersenCommitmentVar,
        ParametersVar = Self::PedersenParamVar,
        RandomnessVar = Self::PedersenRandomnessVar,
    >;
    type PedersenParamVar: AllocVar<Self::PedersenParam, ConstraintF> + Clone;
    type PedersenRandomnessVar: AllocVar<<Self::PedersenComScheme as CommitmentScheme>::Randomness, ConstraintF>
        + Clone;
    type PedersenCommitmentVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + AllocVar<<Self::PedersenComScheme as CommitmentScheme>::Output, ConstraintF>
        + R1CSVar<ConstraintF>
        + Clone
        + Sized
        + Debug;
}

impl LocalOrMPC<Fr> for Fr {
    type JubJub = ark_ed_on_bls12_377::EdwardsProjective;

    type PedersenComScheme = Commitment<Self::JubJub, Window>;
    type PedersenCommitment = <Self::PedersenComScheme as CommitmentScheme>::Output;
    type PedersenParam = <Self::PedersenComScheme as CommitmentScheme>::Parameters;
    type PedersenRandomness = Randomness<Self::JubJub>;

    type PedersenComSchemeVar = CommGadget<Self::JubJub, EdwardsVar, Window>;
    type PedersenParamVar = <Self::PedersenComSchemeVar as CommitmentGadget<
        Self::PedersenComScheme,
        Fr,
    >>::ParametersVar;
    type PedersenRandomnessVar = <Self::PedersenComSchemeVar as CommitmentGadget<
        Self::PedersenComScheme,
        Fr,
    >>::RandomnessVar;
    type PedersenCommitmentVar = AffineVar<EdwardsParameters, FpVar<Fr>>;
}

impl LocalOrMPC<MFr> for MFr {
    type JubJub = MpcEdwardsProjective;

    type PedersenComScheme = Commitment<Self::JubJub, Window>;
    type PedersenCommitment = <Self::PedersenComScheme as CommitmentScheme>::Output;
    type PedersenParam = <Self::PedersenComScheme as CommitmentScheme>::Parameters;
    type PedersenRandomness = Randomness<Self::JubJub>;

    type PedersenComSchemeVar = CommGadget<Self::JubJub, MpcEdwardsVar, Window>;
    type PedersenParamVar = <Self::PedersenComSchemeVar as CommitmentGadget<
        Self::PedersenComScheme,
        MFr,
    >>::ParametersVar;
    type PedersenRandomnessVar = <Self::PedersenComSchemeVar as CommitmentGadget<
        Self::PedersenComScheme,
        MFr,
    >>::RandomnessVar;
    type PedersenCommitmentVar = AffineVar<MpcEdwardsParameters, FpVar<MFr>>;
}

pub const PERDERSON_WINDOW_SIZE: usize = 256;
pub const PERDERSON_WINDOW_NUM: usize = 1;

#[derive(Clone)]
pub struct Window;
impl pedersen::Window for Window {
    const WINDOW_SIZE: usize = PERDERSON_WINDOW_SIZE;
    const NUM_WINDOWS: usize = PERDERSON_WINDOW_NUM;
}

#[derive(Clone)]
pub struct PedersenComCircuit<F: PrimeField + LocalOrMPC<F>> {
    pub param: Option<F::PedersenParam>,
    pub input: Option<F>,
    pub open: Option<F::PedersenRandomness>,
    pub commit: Option<F::PedersenCommitment>,
}

impl<F: PrimeField + LocalOrMPC<F>> ConstraintSynthesizer<F> for PedersenComCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        #[cfg(debug_assertions)]
        println!("is setup mode?: {}", cs.is_in_setup_mode());
        let _cs_no = cs.num_constraints();

        // step 1. Allocate Parameters for perdersen commitment
        let param_var =
            F::PedersenParamVar::new_input(ark_relations::ns!(cs, "gadget_parameters"), || {
                self.param.ok_or(SynthesisError::AssignmentMissing)
            })?;
        let _cs_no = cs.num_constraints() - _cs_no;
        #[cfg(debug_assertions)]
        println!("cs for parameters: {}", _cs_no);
        let _cs_no = cs.num_constraints();

        // step 2. Allocate inputs
        let input_var = FpVar::new_witness(cs.clone(), || {
            self.input.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let input_var_byte = input_var.to_bytes()?;

        let _cs_no = cs.num_constraints() - _cs_no;
        #[cfg(debug_assertions)]
        println!("cs for account: {}", _cs_no);
        let _cs_no = cs.num_constraints();

        // step 3. Allocate the opening
        let open_var = F::PedersenRandomnessVar::new_witness(
            ark_relations::ns!(cs, "gadget_randomness"),
            || self.open.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let _cs_no = cs.num_constraints() - _cs_no;
        #[cfg(debug_assertions)]
        println!("cs for opening: {}", _cs_no);
        let _cs_no = cs.num_constraints();

        // step 4. Allocate the output
        let result_var = F::PedersenComSchemeVar::commit(&param_var, &input_var_byte, &open_var)?;

        let _cs_no = cs.num_constraints() - _cs_no;
        #[cfg(debug_assertions)]
        println!("cs for commitment: {}", _cs_no);
        let _cs_no = cs.num_constraints();

        // circuit to compare the commited value with supplied value
        let commitment_var2 = F::PedersenCommitmentVar::new_input(
            ark_relations::ns!(cs, "gadget_commitment"),
            || self.commit.ok_or(SynthesisError::AssignmentMissing),
        )?;
        result_var.enforce_equal(&commitment_var2)?;

        let _cs_no = cs.num_constraints() - _cs_no;
        #[cfg(debug_assertions)]
        println!("cs for comparison: {}", _cs_no);

        #[cfg(debug_assertions)]
        println!("total cs for Commitment: {}", cs.num_constraints());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_ff::BigInteger;
    use ark_std::{test_rng, UniformRand};

    type MFr = mpc_algebra::MpcField<Fr, mpc_algebra::AdditiveFieldShare<Fr>>;

    #[test]
    fn additivity_test_local() {
        let rng = &mut test_rng();

        let a = Fr::from(3);

        let params = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::setup(rng).unwrap();

        let randomness_a = <Fr as LocalOrMPC<Fr>>::PedersenRandomness::rand(rng);

        let a_bytes = a.into_repr().to_bytes_le();

        let h_a =
            <Fr as LocalOrMPC<Fr>>::PedersenComScheme::commit(&params, &a_bytes, &randomness_a)
                .unwrap();

        let b = Fr::from(4);

        let randomness_b = <Fr as LocalOrMPC<Fr>>::PedersenRandomness::rand(rng);

        let b_bytes = b.into_repr().to_bytes_le();

        let h_b =
            <Fr as LocalOrMPC<Fr>>::PedersenComScheme::commit(&params, &b_bytes, &randomness_b)
                .unwrap();

        // Note: Do not exceed the modulus. break additivity
        let sum = a + b;

        let randomness = Randomness(randomness_a.0 + randomness_b.0);

        let bytes = sum.into_repr().to_bytes_le();

        let h_sum = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::commit(&params, &bytes, &randomness)
            .unwrap();

        assert_eq!(h_a + h_b, h_sum)
    }

    #[test]
    fn additivity_test_mpc() {
        let rng = &mut test_rng();

        let a = MFr::Public(Fr::from(3));

        let params = <MFr as LocalOrMPC<MFr>>::PedersenComScheme::setup(rng).unwrap();

        let randomness_a = <MFr as LocalOrMPC<MFr>>::PedersenRandomness::rand(rng);

        let a_bytes = a.into_repr().to_bytes_le();

        let h_a =
            <MFr as LocalOrMPC<MFr>>::PedersenComScheme::commit(&params, &a_bytes, &randomness_a)
                .unwrap();

        let b = MFr::Public(Fr::from(4));

        let randomness_b = <MFr as LocalOrMPC<MFr>>::PedersenRandomness::rand(rng);

        let b_bytes = b.into_repr().to_bytes_le();

        let h_b =
            <MFr as LocalOrMPC<MFr>>::PedersenComScheme::commit(&params, &b_bytes, &randomness_b)
                .unwrap();

        let sum = a + b;

        let randomness = Randomness(randomness_a.0 + randomness_b.0);

        let bytes = sum.into_repr().to_bytes_le();

        let h_sum =
            <MFr as LocalOrMPC<MFr>>::PedersenComScheme::commit(&params, &bytes, &randomness)
                .unwrap();

        assert_eq!(h_a + h_b, h_sum)
    }
}
