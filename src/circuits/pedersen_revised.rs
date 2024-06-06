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
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget};
use ark_r1cs_std::{boolean::AllocatedBool, fields::fp::FpVar};
use ark_r1cs_std::{fields::fp::FpVar::Var, ToBitsGadget};
use ark_r1cs_std::{groups::curves::twisted_edwards::AffineVar, uint8::UInt8};

use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};
use ark_std::{fmt::Debug, hash::Hash};

use mpc_algebra::{
    groups::curves::twisted_edwards::MpcAffineVar, honest_but_curious as hbc, MpcBoolean,
    MpcEqGadget, MpcToBitsGadget, MpcUInt8,
};
use mpc_algebra::{malicious_majority as mm, MpcFpVar};

use mpc_algebra::{AdditiveFieldShare, FieldShare};

use mpc_algebra::{
    commitment::constraints::CommitmentGadget as MpcCommitmentGadget,
    commitment::pedersen::{
        CommGadget as MpcCommGadget, Commitment as MpcCommitment, Parameters as MpcParameters,
        Randomness as MpcRandomness,
    },
    CommitmentScheme as MpcCommitmentScheme,
};

use num_traits::One;

// pub trait LocalOrMPC2<ConstraintF: PrimeField> {
//     type JubJub: ProjectiveCurve;
//     type PedersenComScheme: CommitmentScheme<
//         Output = Self::PedersenCommitment,
//         Parameters = Self::PedersenParam,
//         Randomness = Self::PedersenRandomness,
//     >;
//     type PedersenCommitment: ToBytes + Clone + Default + Eq + Hash + Debug;
//     type PedersenParam: Clone;
//     type PedersenRandomness: Clone + PartialEq + Debug + Eq + Default + GetRandomness<Self::JubJub>;

//     type PedersenComSchemeVar: CommitmentGadget<
//         Self::PedersenComScheme,
//         ConstraintF,
//         OutputVar = Self::PedersenCommitmentVar,
//         ParametersVar = Self::PedersenParamVar,
//         RandomnessVar = Self::PedersenRandomnessVar,
//     >;
//     type PedersenParamVar: AllocVar<Self::PedersenParam, ConstraintF>
//         + Clone
//         + GetParam<Self::JubJub>;
//     type PedersenRandomnessVar: AllocVar<<Self::PedersenComScheme as CommitmentScheme>::Randomness, ConstraintF>
//         + Clone;
//     type PedersenCommitmentVar: CurveVar<Self::JubJub, ConstraintF>
//         + AllocVar<<Self::PedersenComScheme as CommitmentScheme>::Output, ConstraintF>;
// }

// impl LocalOrMPC2<Fr> for Fr {
//     type JubJub = ark_ed_on_bls12_377::EdwardsProjective;

//     type PedersenComScheme = Commitment<Self::JubJub, Window>;
//     type PedersenCommitment = <Self::PedersenComScheme as CommitmentScheme>::Output;
//     type PedersenParam = <Self::PedersenComScheme as CommitmentScheme>::Parameters;
//     type PedersenRandomness = Randomness<Self::JubJub>;

//     type PedersenComSchemeVar = CommGadget<Self::JubJub, EdwardsVar, Window>;
//     type PedersenParamVar = <Self::PedersenComSchemeVar as CommitmentGadget<
//         Self::PedersenComScheme,
//         Fr,
//     >>::ParametersVar;
//     type PedersenRandomnessVar = <Self::PedersenComSchemeVar as CommitmentGadget<
//         Self::PedersenComScheme,
//         Fr,
//     >>::RandomnessVar;
//     type PedersenCommitmentVar = AffineVar<EdwardsParameters, FpVar<Fr>>;
// }

// Local
type JubJub = ark_ed_on_bls12_377::EdwardsProjective;

pub type PedersenComScheme = Commitment<JubJub, Window>;
type PedersenCommitment = <PedersenComScheme as CommitmentScheme>::Output;
type PedersenParam = <PedersenComScheme as CommitmentScheme>::Parameters;
pub type PedersenRandomness = Randomness<JubJub>;

type PedersenComSchemeVar = CommGadget<JubJub, EdwardsVar, Window>;
type PedersenParamVar =
    <PedersenComSchemeVar as CommitmentGadget<PedersenComScheme, Fr>>::ParametersVar;
type PedersenRandomnessVar =
    <PedersenComSchemeVar as CommitmentGadget<PedersenComScheme, Fr>>::RandomnessVar;
type PedersenCommitmentVar = EdwardsVar;

// MPC:hbc
type JubJub_hbc = mpc_algebra::edwards2::MpcEdwardsProjective;

pub type PedersenComScheme_hbc = MpcCommitment<JubJub_hbc, Window>;
type PedersenCommitment_hbc = <PedersenComScheme_hbc as MpcCommitmentScheme>::Output;
type PedersenParam_hbc = <PedersenComScheme_hbc as MpcCommitmentScheme>::Parameters;
type PedersenRandomness_hbc = MpcRandomness<JubJub_hbc>;

type PedersenComSchemeVar_hbc =
    MpcCommGadget<JubJub_hbc, mpc_algebra::AdditiveMpcEdwardsVar, Window>;
type PedersenParamVar_hbc = <PedersenComSchemeVar_hbc as MpcCommitmentGadget<
    PedersenComScheme_hbc,
    hbc::MpcField<Fr>,
>>::ParametersVar;
type PedersenRandomnessVar_hbc = <PedersenComSchemeVar_hbc as MpcCommitmentGadget<
    PedersenComScheme_hbc,
    hbc::MpcField<Fr>,
>>::RandomnessVar;
type PedersenCommitmentVar_hbc = mpc_algebra::AdditiveMpcEdwardsVar;

// impl LocalOrMPC2<hbc::MpcField<Fr>> for hbc::MpcField<Fr> {
//     // type JubJub = mpc_algebra::edwards2::MpcEdwardsProjective;

//     // type PedersenComScheme = Commitment<Self::JubJub, Window>;
//     // type PedersenCommitment = <Self::PedersenComScheme as CommitmentScheme>::Output;
//     // type PedersenParam = <Self::PedersenComScheme as CommitmentScheme>::Parameters;
//     // type PedersenRandomness = Randomness<Self::JubJub>;

//     type PedersenComSchemeVar = MpcCommGadget<
//         Self::JubJub,
//         mpc_algebra::AdditiveMpcEdwardsVar,
//         Window,
//         mpc_algebra::AdditiveFieldShare<Fr>,
//     >;
//     // type PedersenParamVar = <Self::PedersenComSchemeVar as CommitmentGadget<
//     //     Self::PedersenComScheme,
//     //     hbc::MpcField<Fr>,
//     // >>::ParametersVar;
//     // type PedersenRandomnessVar = <Self::PedersenComSchemeVar as CommitmentGadget<
//     //     Self::PedersenComScheme,
//     //     hbc::MpcField<Fr>,
//     // >>::RandomnessVar;
//     // type PedersenCommitmentVar = AffineVar<hbc::MpcEdwardsParameters, FpVar<hbc::MpcField<Fr>>>;
// }

// impl LocalOrMPC2<mm::MpcField<Fr>> for mm::MpcField<Fr> {
//     type JubJub = mm::MpcEdwardsProjective;

//     type PedersenComScheme = Commitment<Self::JubJub, Window>;
//     type PedersenCommitment = <Self::PedersenComScheme as CommitmentScheme>::Output;
//     type PedersenParam = <Self::PedersenComScheme as CommitmentScheme>::Parameters;
//     type PedersenRandomness = Randomness<Self::JubJub>;

//     type PedersenComSchemeVar =
//         MpcCommGadget<Self::JubJub, mm::MpcEdwardsVar, Window, mpc_algebra::SpdzFieldShare<Fr>>;
//     type PedersenParamVar = <Self::PedersenComSchemeVar as CommitmentGadget<
//         Self::PedersenComScheme,
//         mm::MpcField<Fr>,
//     >>::ParametersVar;
//     type PedersenRandomnessVar = <Self::PedersenComSchemeVar as CommitmentGadget<
//         Self::PedersenComScheme,
//         mm::MpcField<Fr>,
//     >>::RandomnessVar;
//     type PedersenCommitmentVar = AffineVar<mm::MpcEdwardsParameters, FpVar<mm::MpcField<Fr>>>;
// }

pub const PERDERSON_WINDOW_SIZE: usize = 256;
pub const PERDERSON_WINDOW_NUM: usize = 1;

#[derive(Clone)]
pub struct Window;
impl pedersen::Window for Window {
    const WINDOW_SIZE: usize = PERDERSON_WINDOW_SIZE;
    const NUM_WINDOWS: usize = PERDERSON_WINDOW_NUM;
}
impl mpc_algebra::crh::pedersen::Window for Window {
    const WINDOW_SIZE: usize = PERDERSON_WINDOW_SIZE;
    const NUM_WINDOWS: usize = PERDERSON_WINDOW_NUM;
}

// #[derive(Clone)]
// pub struct RevisedPedersenComCircuit<F: PrimeField + LocalOrMPC2<F>> {
//     pub param: Option<F::PedersenParam>,
//     pub input: F,
//     // pub input_bit: Vec<F>,
//     // pub open_bit: Vec<F>,
//     pub open: Option<F::PedersenRandomness>,
//     pub commit: Option<F::PedersenCommitment>,
// }

#[derive(Clone)]
pub struct LocalPedersenComCircuit {
    pub param: Option<PedersenParam>,
    pub input: Fr,
    pub open: PedersenRandomness,
    pub commit: PedersenCommitment,
}

impl ConstraintSynthesizer<Fr> for LocalPedersenComCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        #[cfg(debug_assertions)]
        println!("is setup mode?: {}", cs.is_in_setup_mode());
        let _cs_no = cs.num_constraints();

        // step 1. Allocate Parameters for perdersen commitment
        let param_var =
            PedersenParamVar::new_input(ark_relations::ns!(cs, "gadget_parameters"), || {
                self.param.ok_or(SynthesisError::AssignmentMissing)
            })?;
        let _cs_no = cs.num_constraints() - _cs_no;
        #[cfg(debug_assertions)]
        println!("cs for parameters: {}", _cs_no);
        let _cs_no = cs.num_constraints();

        // step 2. Allocate inputs
        // for input_bit in self.input.iter() {
        //     input_var.push(MpcBoolean::new_witness(cs.clone(), || Ok(*input_bit)).unwrap());
        // }
        // let input_var = FpVar::new_witness(cs.clone(), || Ok(self.input)).unwrap();

        // let input_bit_var = input_var.to_bits_le()?;

        let mut input_var = vec![];
        for input_byte in self.input.0.to_bytes_le().iter() {
            input_var.push(UInt8::new_witness(cs.clone(), || Ok(*input_byte)).unwrap());
        }

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
        let result_var = PedersenComSchemeVar::commit(&param_var, &input_var, &open_var).unwrap();

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
pub struct MpcPedersenComCircuit {
    pub param: Option<PedersenParam_hbc>,
    pub input: Vec<hbc::MpcU8Field<Fr>>,
    pub open: PedersenRandomness_hbc,
    pub commit: PedersenCommitment_hbc,
}

impl ConstraintSynthesizer<hbc::MpcField<Fr>> for MpcPedersenComCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<hbc::MpcField<Fr>>,
    ) -> Result<(), SynthesisError> {
        #[cfg(debug_assertions)]
        println!("is setup mode?: {}", cs.is_in_setup_mode());
        let _cs_no = cs.num_constraints();

        // step 1. Allocate Parameters for perdersen commitment
        let param_var =
            PedersenParamVar_hbc::new_input(ark_relations::ns!(cs, "gadget_parameters"), || {
                self.param.ok_or(SynthesisError::AssignmentMissing)
            })?;
        let _cs_no = cs.num_constraints() - _cs_no;
        #[cfg(debug_assertions)]
        println!("cs for parameters: {}", _cs_no);
        let _cs_no = cs.num_constraints();

        // step 2. Allocate inputs
        // let mut input_var = vec![];
        // for input_bit in self.input.iter() {
        //     input_var.push(MpcBoolean::new_witness(cs.clone(), || Ok(*input_bit)).unwrap());
        // }
        // let input_var = MpcFpVar::new_witness(cs.clone(), || Ok(self.input)).unwrap();

        // let input_bit_var = input_var.to_bits_le()?;

        let mut input_var = vec![];

        // vec<scalarfield>で入ってくるので，Vec<MpcUInt8>に変換する
        assert_eq!(self.input.len() % 8, 0);

        for input_byte in self.input.iter() {
            input_var.push(MpcUInt8::new_witness(cs.clone(), || Ok(*input_byte)).unwrap());
        }
        // for input_byte in self.input.iter() {
        //     input_var.push(MpcUInt8::new_witness(cs.clone(), || Ok(*input_byte)).unwrap());
        // }
        // let input_byte_var  =

        let _cs_no = cs.num_constraints() - _cs_no;
        #[cfg(debug_assertions)]
        println!("cs for account: {}", _cs_no);
        let _cs_no = cs.num_constraints();

        // step 3. Allocate the opening
        let open_var = PedersenRandomnessVar_hbc::new_witness(
            ark_relations::ns!(cs, "gadget_randomness"),
            || Ok(&self.open),
        )
        .unwrap();

        let _cs_no = cs.num_constraints() - _cs_no;
        #[cfg(debug_assertions)]
        println!("cs for opening: {}", _cs_no);
        let _cs_no = cs.num_constraints();

        // step 4. Allocate the output
        let result_var =
            PedersenComSchemeVar_hbc::commit(&param_var, &input_var, &open_var).unwrap();

        let _cs_no = cs.num_constraints() - _cs_no;
        #[cfg(debug_assertions)]
        println!("cs for commitment: {}", _cs_no);
        let _cs_no = cs.num_constraints();

        // circuit to compare the commited value with supplied value
        let commitment_var2 = PedersenCommitmentVar_hbc::new_input(
            ark_relations::ns!(cs, "gadget_commitment"),
            || Ok(self.commit),
        )
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

// impl<F: PrimeField + LocalOrMPC2<F>> ConstraintSynthesizer<F> for RevisedPedersenComCircuit<F> {
//     fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
//         #[cfg(debug_assertions)]
//         println!("is setup mode?: {}", cs.is_in_setup_mode());
//         let _cs_no = cs.num_constraints();

//         // step 1. Allocate Parameters for perdersen commitment
//         let param_var =
//             F::PedersenParamVar::new_input(ark_relations::ns!(cs, "gadget_parameters"), || {
//                 self.param.ok_or(SynthesisError::AssignmentMissing)
//             })?;
//         let _cs_no = cs.num_constraints() - _cs_no;
//         #[cfg(debug_assertions)]
//         println!("cs for parameters: {}", _cs_no);
//         let _cs_no = cs.num_constraints();

//         // step 2. Allocate inputs
//         let input_var = FpVar::new_witness(cs.clone(), || Ok(self.input))?;
//         // let input_var_byte = input_var.to_bytes()?;
//         // let input_bit_var = self
//         //     .input_bit
//         //     .iter()
//         //     .map(|b| {
//         //         let alloc_bool = {
//         //             let variable = cs.new_witness_variable(|| Ok(*b))?;

//         //             // Constrain: (1 - a) * a = 0
//         //             // This constrains a to be either 0 or 1.

//         //             cs.enforce_constraint(
//         //                 lc!() + Variable::One - variable,
//         //                 lc!() + variable,
//         //                 lc!(),
//         //             )?;

//         //             AllocatedBool {
//         //                 variable,
//         //                 cs: cs.clone(),
//         //             }
//         //         };
//         //         Ok(Boolean::Is(alloc_bool))
//         //     })
//         //     .collect::<Result<Vec<_>, _>>()?;
//         let input_bit_var = input_var.to_bits_le()?;

//         // // step 2.5. check input consistency

//         // let mut lc = lc!();
//         // let mut coeff = F::one();

//         // for bit in input_bit_var.iter() {
//         //     lc = &lc + bit.lc() * coeff;

//         //     coeff.double_in_place();
//         // }

//         // if let Var(v) = input_var {
//         //     lc = lc - v.variable;
//         // }

//         // // lc = lc - &input_var.variable;

//         // cs.enforce_constraint(lc!(), lc!(), lc)?;

//         let _cs_no = cs.num_constraints() - _cs_no;
//         #[cfg(debug_assertions)]
//         println!("cs for account: {}", _cs_no);
//         let _cs_no = cs.num_constraints();

//         // step 3. Allocate the opening

//         // let open_bit_var = self
//         //     .open_bit
//         //     .iter()
//         //     .map(|b| {
//         //         let alloc_bool = {
//         //             let variable = cs.new_witness_variable(|| Ok(*b))?;

//         //             // Constrain: (1 - a) * a = 0
//         //             // This constrains a to be either 0 or 1.

//         //             cs.enforce_constraint(
//         //                 lc!() + Variable::One - variable,
//         //                 lc!() + variable,
//         //                 lc!(),
//         //             )?;

//         //             AllocatedBool {
//         //                 variable,
//         //                 cs: cs.clone(),
//         //             }
//         //         };
//         //         Ok(Boolean::Is(alloc_bool))
//         //     })
//         //     .collect::<Result<Vec<_>, _>>()?;
//         // let open_bit_var = self
//         //     .open
//         //     .ok_or(SynthesisError::AssignmentMissing)?
//         //     .0
//         //     .into_repr()
//         //     .to_bits_le();

//         let open_var = F::PedersenRandomnessVar::new_witness(
//             ark_relations::ns!(cs, "gadgets_randomness"),
//             || self.open.ok_or(SynthesisError::AssignmentMissing),
//         )?;

//         let _cs_no = cs.num_constraints() - _cs_no;
//         #[cfg(debug_assertions)]
//         println!("cs for opening: {}", _cs_no);
//         let _cs_no = cs.num_constraints();

//         // step 4. Allocate the output

//         // let result_var = {
//         //     assert!((input_bit_var.len()) <= (PERDERSON_WINDOW_SIZE * PERDERSON_WINDOW_NUM));

//         //     let mut padded_input = input_bit_var.to_vec();
//         //     // Pad if input length is less than `W::WINDOW_SIZE * W::NUM_WINDOWS`.
//         //     if (input_bit_var.len()) < PERDERSON_WINDOW_SIZE * PERDERSON_WINDOW_NUM {
//         //         let current_length = input_bit_var.len();
//         //         for _ in current_length..(PERDERSON_WINDOW_SIZE * PERDERSON_WINDOW_NUM) {
//         //             padded_input.push(Boolean::constant(false));
//         //         }
//         //     }

//         //     assert_eq!(
//         //         padded_input.len(),
//         //         PERDERSON_WINDOW_SIZE * PERDERSON_WINDOW_NUM
//         //     );
//         //     assert_eq!(param_var.params().generators.len(), PERDERSON_WINDOW_NUM);

//         //     // Allocate new variable for commitment output.

//         //     let input_in_bits = padded_input.chunks(PERDERSON_WINDOW_SIZE);
//         //     let mut result = F::PedersenCommitmentVar::precomputed_base_multiscalar_mul_le(
//         //         &param_var.params().generators,
//         //         input_in_bits,
//         //     )?;

//         //     // Compute h^r
//         //     result.precomputed_base_scalar_mul_le(
//         //         open_bit_var
//         //             .iter()
//         //             .zip(&param_var.params().randomness_generator),
//         //     )?;

//         //     Ok(result)
//         // }?;

//         let result_var = F::PedersenComSchemeVar::commit(&param_var, &input_var, &open_var)?;

//         let _cs_no = cs.num_constraints() - _cs_no;
//         #[cfg(debug_assertions)]
//         println!("cs for commitment: {}", _cs_no);
//         let _cs_no = cs.num_constraints();

//         // circuit to compare the commited value with supplied value
//         let commitment_var = F::PedersenCommitmentVar::new_input(
//             ark_relations::ns!(cs, "gadget_commitment"),
//             || self.commit.ok_or(SynthesisError::AssignmentMissing),
//         )?;

//         result_var.enforce_equal(&commitment_var)?;

//         let _cs_no = cs.num_constraints() - _cs_no;
//         #[cfg(debug_assertions)]
//         println!("cs for comparison: {}", _cs_no);

//         #[cfg(debug_assertions)]
//         println!("total cs for Commitment: {}", cs.num_constraints());
//         Ok(())
//     }
// }

// pub trait GetParam<C: ProjectiveCurve> {
//     fn params(&self) -> Parameters<C>;
// }

// impl GetParam<<Fr as LocalOrMPC2<Fr>>::JubJub> for <Fr as LocalOrMPC2<Fr>>::PedersenParamVar {
//     fn params(&self) -> Parameters<<Fr as LocalOrMPC2<Fr>>::JubJub> {
//         self.params.clone()
//     }
// }

// impl GetParam<<hbc::MpcField<Fr> as LocalOrMPC2<hbc::MpcField<Fr>>>::JubJub>
//     for <hbc::MpcField<Fr> as LocalOrMPC2<hbc::MpcField<Fr>>>::PedersenParamVar
// {
//     fn params(&self) -> Parameters<<hbc::MpcField<Fr> as LocalOrMPC2<hbc::MpcField<Fr>>>::JubJub> {
//         self.params.clone()
//     }
// }

// impl GetParam<<mm::MpcField<Fr> as LocalOrMPC2<mm::MpcField<Fr>>>::JubJub>
//     for <mm::MpcField<Fr> as LocalOrMPC2<mm::MpcField<Fr>>>::PedersenParamVar
// {
//     fn params(&self) -> Parameters<<mm::MpcField<Fr> as LocalOrMPC2<mm::MpcField<Fr>>>::JubJub> {
//         self.params.clone()
//     }
// }

// pub trait GetRandomness<C: ProjectiveCurve> {
//     fn randomness(&self) -> C::ScalarField;
// }

// impl GetRandomness<<Fr as LocalOrMPC2<Fr>>::JubJub>
//     for <Fr as LocalOrMPC2<Fr>>::PedersenRandomness
// {
//     fn randomness(&self) -> <<Fr as LocalOrMPC2<Fr>>::JubJub as ProjectiveCurve>::ScalarField {
//         self.0
//     }
// }

// impl GetRandomness<<hbc::MpcField<Fr> as LocalOrMPC2<hbc::MpcField<Fr>>>::JubJub>
//     for <hbc::MpcField<Fr> as LocalOrMPC2<hbc::MpcField<Fr>>>::PedersenRandomness
// {
//     fn randomness(
//         &self,
//     ) -> <<hbc::MpcField<Fr> as LocalOrMPC2<hbc::MpcField<Fr>>>::JubJub as ProjectiveCurve>::ScalarField{
//         self.0
//     }
// }

// impl GetRandomness<<mm::MpcField<Fr> as LocalOrMPC2<mm::MpcField<Fr>>>::JubJub>
//     for <mm::MpcField<Fr> as LocalOrMPC2<mm::MpcField<Fr>>>::PedersenRandomness
// {
//     fn randomness(
//         &self,
//     ) -> <<mm::MpcField<Fr> as LocalOrMPC2<mm::MpcField<Fr>>>::JubJub as ProjectiveCurve>::ScalarField
//     {
//         self.0
//     }
// }

// #[cfg(test)]
// mod tests {
//     use super::*;

//     use ark_ff::BigInteger;
//     use ark_std::{test_rng, UniformRand};

//     type MFr = mpc_algebra::MpcField<Fr, mpc_algebra::AdditiveFieldShare<Fr>>;

//     #[test]
//     fn additivity_test_local() {
//         let rng = &mut test_rng();

//         let a = Fr::from(3);

//         let params = <Fr as LocalOrMPC2<Fr>>::PedersenComScheme::setup(rng).unwrap();

//         let randomness_a = <Fr as LocalOrMPC2<Fr>>::PedersenRandomness::rand(rng);

//         let a_bytes = a.into_repr().to_bytes_le();

//         let h_a =
//             <Fr as LocalOrMPC2<Fr>>::PedersenComScheme::commit(&params, &a_bytes, &randomness_a)
//                 .unwrap();

//         let b = Fr::from(4);

//         let randomness_b = <Fr as LocalOrMPC2<Fr>>::PedersenRandomness::rand(rng);

//         let b_bytes = b.into_repr().to_bytes_le();

//         let h_b =
//             <Fr as LocalOrMPC2<Fr>>::PedersenComScheme::commit(&params, &b_bytes, &randomness_b)
//                 .unwrap();

//         // Note: Do not exceed the modulus. break additivity
//         let sum = a + b;

//         let randomness = Randomness(randomness_a.0 + randomness_b.0);

//         let bytes = sum.into_repr().to_bytes_le();

//         let h_sum =
//             <Fr as LocalOrMPC2<Fr>>::PedersenComScheme::commit(&params, &bytes, &randomness)
//                 .unwrap();

//         assert_eq!(h_a + h_b, h_sum)
//     }

//     #[test]
//     fn additivity_test_mpc() {
//         let rng = &mut test_rng();

//         let a = MFr::Public(Fr::from(3));

//         let params = <MFr as LocalOrMPC2<MFr>>::PedersenComScheme::setup(rng).unwrap();

//         let randomness_a = <MFr as LocalOrMPC2<MFr>>::PedersenRandomness::rand(rng);

//         let a_bytes = a.into_repr().to_bytes_le();

//         let h_a =
//             <MFr as LocalOrMPC2<MFr>>::PedersenComScheme::commit(&params, &a_bytes, &randomness_a)
//                 .unwrap();

//         let b = MFr::Public(Fr::from(4));

//         let randomness_b = <MFr as LocalOrMPC2<MFr>>::PedersenRandomness::rand(rng);

//         let b_bytes = b.into_repr().to_bytes_le();

//         let h_b =
//             <MFr as LocalOrMPC2<MFr>>::PedersenComScheme::commit(&params, &b_bytes, &randomness_b)
//                 .unwrap();

//         let sum = a + b;

//         let randomness = Randomness(randomness_a.0 + randomness_b.0);

//         let bytes = sum.into_repr().to_bytes_le();

//         let h_sum =
//             <MFr as LocalOrMPC2<MFr>>::PedersenComScheme::commit(&params, &bytes, &randomness)
//                 .unwrap();

//         assert_eq!(h_a + h_b, h_sum)
//     }
// }
