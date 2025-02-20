use ark_bls12_377::Fr;
use ark_crypto_primitives::{
    commitment::{
        pedersen::{constraints::CommGadget, Commitment, Randomness},
        CommitmentGadget,
    },
    crh::pedersen,
    CommitmentScheme,
};
use ark_ec::ProjectiveCurve;
use ark_ed_on_bls12_377::constraints::EdwardsVar;
use ark_ff::bytes::ToBytes;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget};

use mpc_algebra::Reveal;

use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{fmt::Debug, hash::Hash};

use mpc_algebra::{
    honest_but_curious as hbc, malicious_majority as mm, pedersen::Input, FieldShare, MpcEqGadget,
};

use mpc_algebra::{
    commitment::constraints::CommitmentGadget as MpcCommitmentGadget,
    // commitment::pedersen::local_pedersen::Commitment,
    commitment::pedersen::{
        CommGadget as MpcCommGadget, Commitment as MpcCommitment, Randomness as MpcRandomness,
    },
    CommitmentScheme as MpcCommitmentScheme,
};
use mpc_trait::MpcWire;

pub trait LocalOrMPC<ConstraintF: PrimeField> {
    type JubJub: ProjectiveCurve;
    type PedersenComScheme: MpcCommitmentScheme<
        Output = Self::PedersenCommitment,
        Parameters = Self::PedersenParam,
        Input = Self::PedersenInput,
        Randomness = Self::PedersenRandomness,
    >;
    type PedersenCommitment: ToBytes + Clone + Default + Eq + Hash + Debug;
    type PedersenParam: Clone;
    type PedersenInput;
    type PedersenRandomness: Clone + PartialEq + Debug + Eq + Default;

    type PedersenComSchemeVar: MpcCommitmentGadget<
        Self::PedersenComScheme,
        ConstraintF,
        OutputVar = Self::PedersenCommitmentVar,
        ParametersVar = Self::PedersenParamVar,
        InputVar = Self::PedersenInputVar,
        RandomnessVar = Self::PedersenRandomnessVar,
    >;
    type PedersenParamVar: AllocVar<Self::PedersenParam, ConstraintF> + Clone;
    type PedersenRandomnessVar: AllocVar<<Self::PedersenComScheme as MpcCommitmentScheme>::Randomness, ConstraintF>
        + Clone;
    type PedersenInputVar: AllocVar<<Self::PedersenComScheme as MpcCommitmentScheme>::Input, ConstraintF>
        + Clone;
    type PedersenCommitmentVar: AllocVar<
        <Self::PedersenComScheme as MpcCommitmentScheme>::Output,
        ConstraintF,
    >;

    fn convert_input(&self) -> Self::PedersenInput;

    fn enforce_equal_output(
        a: &Self::PedersenCommitmentVar,
        b: &Self::PedersenCommitmentVar,
    ) -> Result<(), SynthesisError>;
}

impl LocalOrMPC<Fr> for Fr {
    type JubJub = ark_ed_on_bls12_377::EdwardsProjective;

    type PedersenComScheme = Commitment<Self::JubJub, Window>;
    type PedersenCommitment = <Self::PedersenComScheme as MpcCommitmentScheme>::Output;
    type PedersenParam = <Self::PedersenComScheme as MpcCommitmentScheme>::Parameters;
    type PedersenInput = <Self::PedersenComScheme as MpcCommitmentScheme>::Input;
    type PedersenRandomness = Randomness<Self::JubJub>;

    type PedersenComSchemeVar = CommGadget<Self::JubJub, EdwardsVar, Window>;
    type PedersenParamVar = <Self::PedersenComSchemeVar as MpcCommitmentGadget<
        Self::PedersenComScheme,
        Fr,
    >>::ParametersVar;
    type PedersenRandomnessVar = <Self::PedersenComSchemeVar as MpcCommitmentGadget<
        Self::PedersenComScheme,
        Fr,
    >>::RandomnessVar;
    type PedersenInputVar =
        <Self::PedersenComSchemeVar as MpcCommitmentGadget<Self::PedersenComScheme, Fr>>::InputVar;
    type PedersenCommitmentVar = EdwardsVar;

    fn convert_input(&self) -> Self::PedersenInput {
        self.into_repr().to_bytes_le()
    }

    fn enforce_equal_output(
        a: &Self::PedersenCommitmentVar,
        b: &Self::PedersenCommitmentVar,
    ) -> Result<(), SynthesisError> {
        a.enforce_equal(b)
    }
}

impl LocalOrMPC<hbc::MpcField<Fr>> for hbc::MpcField<Fr> {
    type JubJub = mpc_algebra::edwards2::AdditiveMpcEdwardsProjective;

    type PedersenComScheme = MpcCommitment<Self::JubJub, Window>;
    type PedersenCommitment = <Self::PedersenComScheme as MpcCommitmentScheme>::Output;
    type PedersenParam = <Self::PedersenComScheme as MpcCommitmentScheme>::Parameters;
    type PedersenInput = Input<Self::JubJub>;
    type PedersenRandomness = MpcRandomness<Self::JubJub>;

    type PedersenComSchemeVar =
        MpcCommGadget<Self::JubJub, mpc_algebra::AdditiveMpcEdwardsVar, Window>;
    type PedersenParamVar = <Self::PedersenComSchemeVar as MpcCommitmentGadget<
        Self::PedersenComScheme,
        hbc::MpcField<Fr>,
    >>::ParametersVar;
    type PedersenInputVar = <Self::PedersenComSchemeVar as MpcCommitmentGadget<
        Self::PedersenComScheme,
        hbc::MpcField<Fr>,
    >>::InputVar;
    type PedersenRandomnessVar = <Self::PedersenComSchemeVar as MpcCommitmentGadget<
        Self::PedersenComScheme,
        hbc::MpcField<Fr>,
    >>::RandomnessVar;
    type PedersenCommitmentVar = mpc_algebra::AdditiveMpcEdwardsVar;

    fn convert_input(&self) -> Self::PedersenInput {
        if self.is_shared() {
            Self::PedersenInput::new(
                <Self::JubJub as ProjectiveCurve>::ScalarField::from_add_shared(
                    ark_ed_on_bls12_377::Fr::from_le_bytes_mod_order(
                        &self.unwrap_as_public().into_repr().to_bytes_le(),
                    ),
                ),
            )
        } else {
            Self::PedersenInput::new(<Self::JubJub as ProjectiveCurve>::ScalarField::from_public(
                ark_ed_on_bls12_377::Fr::from_le_bytes_mod_order(
                    &self.unwrap_as_public().into_repr().to_bytes_le(),
                ),
            ))
        }
    }

    fn enforce_equal_output(
        a: &Self::PedersenCommitmentVar,
        b: &Self::PedersenCommitmentVar,
    ) -> Result<(), SynthesisError> {
        a.enforce_equal(b)
    }
}

// impl LocalOrMPC<mm::MpcField<Fr>> for mm::MpcField<Fr> {
//     type JubJub = mpc_algebra::edwards2::SpdzMpcEdwardsProjective;

//     type PedersenComScheme = MpcCommitment<Self::JubJub, Window>;
//     type PedersenCommitment = <Self::PedersenComScheme as MpcCommitmentScheme>::Output;
//     type PedersenParam = <Self::PedersenComScheme as MpcCommitmentScheme>::Parameters;
//     type PedersenInput = Input<Self::JubJub>;
//     type PedersenRandomness = MpcRandomness<Self::JubJub>;

//     type PedersenComSchemeVar = MpcCommGadget<Self::JubJub, mpc_algebra::SpdzMpcEdwardsVar, Window>;
//     type PedersenParamVar = <Self::PedersenComSchemeVar as MpcCommitmentGadget<
//         Self::PedersenComScheme,
//         mm::MpcField<Fr>,
//     >>::ParametersVar;
//     type PedersenInputVar = <Self::PedersenComSchemeVar as MpcCommitmentGadget<
//         Self::PedersenComScheme,
//         mm::MpcField<Fr>,
//     >>::InputVar;
//     type PedersenRandomnessVar = <Self::PedersenComSchemeVar as MpcCommitmentGadget<
//         Self::PedersenComScheme,
//         mm::MpcField<Fr>,
//     >>::RandomnessVar;
//     type PedersenCommitmentVar = mpc_algebra::SpdzMpcEdwardsVar;

//     fn convert_input(&self) -> Self::PedersenInput {
//         if self.is_shared() {
//             Self::PedersenInput::new(
//                 <Self::JubJub as ProjectiveCurve>::ScalarField::from_add_shared(
//                     ark_ed_on_bls12_377::Fr::from_le_bytes_mod_order(
//                         &self.unwrap_as_public().into_repr().to_bytes_le(),
//                     ),
//                 ),
//             )
//         } else {
//             Self::PedersenInput::new(<Self::JubJub as ProjectiveCurve>::ScalarField::from_public(
//                 ark_ed_on_bls12_377::Fr::from_le_bytes_mod_order(
//                     &self.unwrap_as_public().into_repr().to_bytes_le(),
//                 ),
//             ))
//         }
//     }

//     fn enforce_equal_output(
//         a: &Self::PedersenCommitmentVar,
//         b: &Self::PedersenCommitmentVar,
//     ) -> Result<(), SynthesisError> {
//         a.enforce_equal(b)
//     }
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

#[derive(Clone)]
pub struct PedersenComCircuit<F: PrimeField + LocalOrMPC<F>> {
    pub param: Option<F::PedersenParam>,
    pub input: F,
    pub open: F::PedersenRandomness,
    pub commit: F::PedersenCommitment,
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
        // let mut input_var = vec![];
        // let input_bytes = self.input.into_repr().to_bytes_le();
        // let input_bytes = self.input.to_bytes();
        // assert_eq!(input_bytes.len() % 8, 0);

        // for input_byte in input_bytes.iter() {
        //     input_var.push(F::UInt8::new_witness(cs.clone(), || Ok(input_byte)).unwrap());
        // }

        let input_var =
            F::PedersenInputVar::new_witness(ark_relations::ns!(cs, "gadget_input"), || {
                Ok(self.input.convert_input())
            })
            .unwrap();

        let _cs_no = cs.num_constraints() - _cs_no;
        #[cfg(debug_assertions)]
        println!("cs for account: {}", _cs_no);
        let _cs_no = cs.num_constraints();

        // step 3. Allocate the opening
        let open_var = F::PedersenRandomnessVar::new_witness(
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
            F::PedersenComSchemeVar::commit(&param_var, &input_var, &open_var).unwrap();

        let _cs_no = cs.num_constraints() - _cs_no;
        #[cfg(debug_assertions)]
        println!("cs for commitment: {}", _cs_no);
        let _cs_no = cs.num_constraints();

        // circuit to compare the commited value with supplied value
        let commitment_var2 = F::PedersenCommitmentVar::new_input(
            ark_relations::ns!(cs, "gadget_commitment"),
            || Ok(self.commit),
        )
        .unwrap();
        F::enforce_equal_output(&result_var, &commitment_var2).unwrap();

        let _cs_no = cs.num_constraints() - _cs_no;
        #[cfg(debug_assertions)]
        println!("cs for comparison: {}", _cs_no);

        #[cfg(debug_assertions)]
        println!("total cs for Commitment: {}", cs.num_constraints());
        Ok(())
    }
}

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
