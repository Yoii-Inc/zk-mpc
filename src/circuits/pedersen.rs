use ark_bls12_377::Fr;
use ark_crypto_primitives::{
    commitment::{
        pedersen::{constraints::CommGadget, Commitment, Parameters, Randomness},
        CommitmentGadget,
    },
    crh::pedersen,
    CommitmentScheme,
};
use ark_ec::ProjectiveCurve;
use ark_ed_on_bls12_377::{constraints::EdwardsVar, EdwardsParameters};
use ark_ff::bytes::ToBytes;
use ark_ff::PrimeField;
use ark_r1cs_std::boolean::AllocatedBool;
use ark_r1cs_std::fields::fp::FpVar::Var;
use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};
use ark_std::{fmt::Debug, hash::Hash};

use mpc_algebra::honest_but_curious as hbc;
use mpc_algebra::malicious_majority as mm;

use num_traits::One;

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
    type PedersenParamVar: AllocVar<Self::PedersenParam, ConstraintF>
        + Clone
        + GetParam<Self::JubJub>;
    type PedersenRandomnessVar: AllocVar<<Self::PedersenComScheme as CommitmentScheme>::Randomness, ConstraintF>
        + Clone;
    type PedersenCommitmentVar: CurveVar<Self::JubJub, ConstraintF>
        + AllocVar<<Self::PedersenComScheme as CommitmentScheme>::Output, ConstraintF>;
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

impl LocalOrMPC<hbc::MpcField<Fr>> for hbc::MpcField<Fr> {
    type JubJub = hbc::MpcEdwardsProjective;

    type PedersenComScheme = Commitment<Self::JubJub, Window>;
    type PedersenCommitment = <Self::PedersenComScheme as CommitmentScheme>::Output;
    type PedersenParam = <Self::PedersenComScheme as CommitmentScheme>::Parameters;
    type PedersenRandomness = Randomness<Self::JubJub>;

    type PedersenComSchemeVar = CommGadget<Self::JubJub, hbc::MpcEdwardsVar, Window>;
    type PedersenParamVar = <Self::PedersenComSchemeVar as CommitmentGadget<
        Self::PedersenComScheme,
        hbc::MpcField<Fr>,
    >>::ParametersVar;
    type PedersenRandomnessVar = <Self::PedersenComSchemeVar as CommitmentGadget<
        Self::PedersenComScheme,
        hbc::MpcField<Fr>,
    >>::RandomnessVar;
    type PedersenCommitmentVar = AffineVar<hbc::MpcEdwardsParameters, FpVar<hbc::MpcField<Fr>>>;
}

impl LocalOrMPC<mm::MpcField<Fr>> for mm::MpcField<Fr> {
    type JubJub = mm::MpcEdwardsProjective;

    type PedersenComScheme = Commitment<Self::JubJub, Window>;
    type PedersenCommitment = <Self::PedersenComScheme as CommitmentScheme>::Output;
    type PedersenParam = <Self::PedersenComScheme as CommitmentScheme>::Parameters;
    type PedersenRandomness = Randomness<Self::JubJub>;

    type PedersenComSchemeVar = CommGadget<Self::JubJub, mm::MpcEdwardsVar, Window>;
    type PedersenParamVar = <Self::PedersenComSchemeVar as CommitmentGadget<
        Self::PedersenComScheme,
        mm::MpcField<Fr>,
    >>::ParametersVar;
    type PedersenRandomnessVar = <Self::PedersenComSchemeVar as CommitmentGadget<
        Self::PedersenComScheme,
        mm::MpcField<Fr>,
    >>::RandomnessVar;
    type PedersenCommitmentVar = AffineVar<mm::MpcEdwardsParameters, FpVar<mm::MpcField<Fr>>>;
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
    pub input: F,
    pub input_bit: Vec<F>,
    pub open_bit: Vec<F>,
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
        let input_var = FpVar::new_witness(cs.clone(), || Ok(self.input))?;
        // let input_var_byte = input_var.to_bytes()?;
        let input_bit_var = self
            .input_bit
            .iter()
            .map(|b| {
                let alloc_bool = {
                    let variable = cs.new_witness_variable(|| Ok(*b))?;

                    // Constrain: (1 - a) * a = 0
                    // This constrains a to be either 0 or 1.

                    cs.enforce_constraint(
                        lc!() + Variable::One - variable,
                        lc!() + variable,
                        lc!(),
                    )?;

                    AllocatedBool {
                        variable,
                        cs: cs.clone(),
                    }
                };
                Ok(Boolean::Is(alloc_bool))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // step 2.5. check input consistency

        let mut lc = lc!();
        let mut coeff = F::one();

        for bit in input_bit_var.iter() {
            lc = &lc + bit.lc() * coeff;

            coeff.double_in_place();
        }

        if let Var(v) = input_var {
            lc = lc - v.variable;
        }

        // lc = lc - &input_var.variable;

        cs.enforce_constraint(lc!(), lc!(), lc)?;

        let _cs_no = cs.num_constraints() - _cs_no;
        #[cfg(debug_assertions)]
        println!("cs for account: {}", _cs_no);
        let _cs_no = cs.num_constraints();

        // step 3. Allocate the opening

        let open_bit_var = self
            .open_bit
            .iter()
            .map(|b| {
                let alloc_bool = {
                    let variable = cs.new_witness_variable(|| Ok(*b))?;

                    // Constrain: (1 - a) * a = 0
                    // This constrains a to be either 0 or 1.

                    cs.enforce_constraint(
                        lc!() + Variable::One - variable,
                        lc!() + variable,
                        lc!(),
                    )?;

                    AllocatedBool {
                        variable,
                        cs: cs.clone(),
                    }
                };
                Ok(Boolean::Is(alloc_bool))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let _cs_no = cs.num_constraints() - _cs_no;
        #[cfg(debug_assertions)]
        println!("cs for opening: {}", _cs_no);
        let _cs_no = cs.num_constraints();

        // step 4. Allocate the output

        let result_var = {
            assert!((input_bit_var.len()) <= (PERDERSON_WINDOW_SIZE * PERDERSON_WINDOW_NUM));

            let mut padded_input = input_bit_var.to_vec();
            // Pad if input length is less than `W::WINDOW_SIZE * W::NUM_WINDOWS`.
            if (input_bit_var.len()) < PERDERSON_WINDOW_SIZE * PERDERSON_WINDOW_NUM {
                let current_length = input_bit_var.len();
                for _ in current_length..(PERDERSON_WINDOW_SIZE * PERDERSON_WINDOW_NUM) {
                    padded_input.push(Boolean::constant(false));
                }
            }

            assert_eq!(
                padded_input.len(),
                PERDERSON_WINDOW_SIZE * PERDERSON_WINDOW_NUM
            );
            assert_eq!(param_var.params().generators.len(), PERDERSON_WINDOW_NUM);

            // Allocate new variable for commitment output.

            let input_in_bits = padded_input.chunks(PERDERSON_WINDOW_SIZE);
            let mut result = F::PedersenCommitmentVar::precomputed_base_multiscalar_mul_le(
                &param_var.params().generators,
                input_in_bits,
            )?;

            // Compute h^r
            result.precomputed_base_scalar_mul_le(
                open_bit_var
                    .iter()
                    .zip(&param_var.params().randomness_generator),
            )?;

            Ok(result)
        }?;

        let _cs_no = cs.num_constraints() - _cs_no;
        #[cfg(debug_assertions)]
        println!("cs for commitment: {}", _cs_no);
        let _cs_no = cs.num_constraints();

        // circuit to compare the commited value with supplied value
        let commitment_var = F::PedersenCommitmentVar::new_input(
            ark_relations::ns!(cs, "gadget_commitment"),
            || self.commit.ok_or(SynthesisError::AssignmentMissing),
        )?;

        result_var.enforce_equal(&commitment_var)?;

        let _cs_no = cs.num_constraints() - _cs_no;
        #[cfg(debug_assertions)]
        println!("cs for comparison: {}", _cs_no);

        #[cfg(debug_assertions)]
        println!("total cs for Commitment: {}", cs.num_constraints());
        Ok(())
    }
}

pub trait GetParam<C: ProjectiveCurve> {
    fn params(&self) -> Parameters<C>;
}

impl GetParam<<Fr as LocalOrMPC<Fr>>::JubJub> for <Fr as LocalOrMPC<Fr>>::PedersenParamVar {
    fn params(&self) -> Parameters<<Fr as LocalOrMPC<Fr>>::JubJub> {
        self.params.clone()
    }
}

impl GetParam<<hbc::MpcField<Fr> as LocalOrMPC<hbc::MpcField<Fr>>>::JubJub>
    for <hbc::MpcField<Fr> as LocalOrMPC<hbc::MpcField<Fr>>>::PedersenParamVar
{
    fn params(&self) -> Parameters<<hbc::MpcField<Fr> as LocalOrMPC<hbc::MpcField<Fr>>>::JubJub> {
        self.params.clone()
    }
}

impl GetParam<<mm::MpcField<Fr> as LocalOrMPC<mm::MpcField<Fr>>>::JubJub>
    for <mm::MpcField<Fr> as LocalOrMPC<mm::MpcField<Fr>>>::PedersenParamVar
{
    fn params(&self) -> Parameters<<mm::MpcField<Fr> as LocalOrMPC<mm::MpcField<Fr>>>::JubJub> {
        self.params.clone()
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
