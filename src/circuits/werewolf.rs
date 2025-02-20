use ark_bls12_377::Fr;
use ark_crypto_primitives::encryption::elgamal::{constraints::ElGamalEncGadget, ElGamal};
use ark_crypto_primitives::encryption::*;
use ark_ec::AffineCurve;
use ark_ec::ProjectiveCurve;
use ark_ed_on_bls12_377::constraints::EdwardsVar;
use ark_ff::{PrimeField, SquareRootField};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_r1cs_std::{R1CSVar, ToBitsGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{test_rng, One, Zero};
use mpc_algebra::groups::MpcCurveVar;
use mpc_algebra::mpc_fields::MpcFieldVar;
use mpc_algebra::{
    BitDecomposition, EqualityZero, MpcBoolean, MpcCondSelectGadget, MpcEqGadget, MpcFpVar,
    MpcToBitsGadget, Reveal,
};

use nalgebra as na;

use mpc_algebra::honest_but_curious as hbc;
use mpc_algebra::malicious_majority as mm;

use mpc_algebra::encryption::constraints::AsymmetricEncryptionGadget;
use mpc_algebra::encryption::elgamal::{
    constraints::ElGamalEncGadget as MpcElGamalEncGadget, elgamal::ElGamal as MpcElGamal,
};

use super::{circuit, LocalOrMPC, PedersenComCircuit};
use crate::input::{InputWithCommit, WerewolfKeyInput, WerewolfMpcInput};

#[derive(Clone)]
pub struct KeyPublicizeCircuit<F: PrimeField + LocalOrMPC<F>> {
    pub mpc_input: WerewolfKeyInput<F>,
}

impl<F: PrimeField + LocalOrMPC<F>> KeyPublicizeCircuit<F> {
    fn verify_commitments(&self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let pedersen_param = self.clone().mpc_input.common.unwrap().pedersen_param;

        let pub_key_or_dummy_x_vec = self.clone().mpc_input.peculiar.unwrap().pub_key_or_dummy_x;

        for pub_key_or_dummy_x in pub_key_or_dummy_x_vec.iter() {
            let pub_key_or_dummy_x_com_circuit = PedersenComCircuit {
                param: Some(pedersen_param.clone()),
                input: pub_key_or_dummy_x.input,
                open: pub_key_or_dummy_x.randomness.clone(),
                commit: pub_key_or_dummy_x.commitment.clone(),
            };

            pub_key_or_dummy_x_com_circuit.generate_constraints(cs.clone())?;
        }

        let pub_key_or_dummy_y_vec = self.clone().mpc_input.peculiar.unwrap().pub_key_or_dummy_y;

        for pub_key_or_dummy_y in pub_key_or_dummy_y_vec.iter() {
            let pub_key_or_dummy_y_com_circuit = PedersenComCircuit {
                param: Some(pedersen_param.clone()),
                input: pub_key_or_dummy_y.input,
                open: pub_key_or_dummy_y.randomness.clone(),
                commit: pub_key_or_dummy_y.commitment.clone(),
            };

            pub_key_or_dummy_y_com_circuit.generate_constraints(cs.clone())?;
        }

        Ok(())
    }
}

impl<F: PrimeField + LocalOrMPC<F>> ConstraintSynthesizer<F> for KeyPublicizeCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let pk_x = self.clone().mpc_input.peculiar.unwrap().pub_key_or_dummy_x;
        let pk_y = self.clone().mpc_input.peculiar.unwrap().pub_key_or_dummy_y;

        let is_fortune_teller = self.clone().mpc_input.peculiar.unwrap().is_fortune_teller;

        let x_var = pk_x
            .iter()
            .map(|x| {
                FpVar::<F>::new_witness(ark_relations::ns!(cs, "gadget_randomness"), || Ok(x.input))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let y_var = pk_y
            .iter()
            .map(|y| {
                FpVar::<F>::new_witness(ark_relations::ns!(cs, "gadget_randomness"), || Ok(y.input))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let is_ft_var = is_fortune_teller
            .iter()
            .map(|b| {
                FpVar::<F>::new_witness(ark_relations::ns!(cs, "gadget_randomness"), || Ok(b.input))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // is_fortune_teller = 0 or 1
        for b in is_ft_var.iter() {
            let is_zero = ark_r1cs_std::prelude::FieldVar::<F, F>::is_zero(b)?;
            let is_one = ark_r1cs_std::prelude::FieldVar::<F, F>::is_one(b)?;
            let is_bool = is_zero.or(&is_one)?;
            is_bool.enforce_equal(&Boolean::constant(true))?;
        }

        let _sum_x_var =
            x_var
                .iter()
                .enumerate()
                .fold(<FpVar<F> as Zero>::zero(), |mut acc, (i, x)| {
                    acc = acc + x * &is_ft_var[i];
                    acc
                });

        let _sum_y_var =
            y_var
                .iter()
                .enumerate()
                .fold(<FpVar<F> as Zero>::zero(), |mut acc, (i, y)| {
                    acc = acc + y * &is_ft_var[i];
                    acc
                });

        // self.verify_commitments(cs.clone())?;

        println!("total number of constraints: {}", cs.num_constraints());

        Ok(())
    }
}

#[derive(Clone)]
pub struct DivinationCircuit<F: PrimeField + ElGamalLocalOrMPC<F> + LocalOrMPC<F>> {
    pub mpc_input: WerewolfMpcInput<F>,
}

impl<F: PrimeField + LocalOrMPC<F> + ElGamalLocalOrMPC<F>> DivinationCircuit<F> {
    fn verify_commitments(&self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let pedersen_param = self.clone().mpc_input.common.unwrap().pedersen_param;

        let is_werewolf_vec = self.clone().mpc_input.peculiar.unwrap().is_werewolf;

        for is_werewolf in is_werewolf_vec.iter() {
            let is_werewolf_com_circuit = PedersenComCircuit {
                param: Some(pedersen_param.clone()),
                input: is_werewolf.input,
                open: is_werewolf.randomness.clone(),
                commit: is_werewolf.commitment.clone(),
            };

            is_werewolf_com_circuit.generate_constraints(cs.clone())?;
        }

        let is_target_vec = self.clone().mpc_input.peculiar.unwrap().is_target;

        for is_target in is_target_vec.iter() {
            let is_target_com_circuit = PedersenComCircuit {
                param: Some(pedersen_param.clone()),
                input: is_target.input,
                open: is_target.randomness.clone(),
                commit: is_target.commitment.clone(),
            };

            is_target_com_circuit.generate_constraints(cs.clone())?;
        }

        Ok(())
    }
}

// Constraint Implementation for Local Field
impl ConstraintSynthesizer<Fr> for DivinationCircuit<Fr> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let common_input = self.clone().mpc_input.common.unwrap();
        let peculiar_input = self.clone().mpc_input.peculiar.unwrap();

        let is_werewolf_bit = peculiar_input
            .is_werewolf
            .clone()
            .iter()
            .map(|b| Boolean::new_witness(cs.clone(), || Ok(b.input.is_one())))
            .collect::<Result<Vec<_>, _>>()?;

        let is_target_bit = peculiar_input
            .is_target
            .clone()
            .iter()
            .map(|b| Boolean::new_witness(cs.clone(), || Ok(b.input.is_one())))
            .collect::<Result<Vec<_>, _>>()?;

        let is_wt = is_werewolf_bit
            .iter()
            .zip(is_target_bit.iter())
            .map(|(x, y)| x.and(y))
            .collect::<Result<Vec<_>, _>>()?;

        let is_target_werewolf_bit = Boolean::kary_or(is_wt.as_slice())?;

        let one_point = <Fr as ElGamalLocalOrMPC<Fr>>::EdwardsVar::new_witness(
            ark_relations::ns!(cs, "gadget_randomness"),
            || Ok(<Fr as ElGamalLocalOrMPC<Fr>>::ElGamalPlaintext::prime_subgroup_generator()),
        )?;

        let zero_point = <Fr as ElGamalLocalOrMPC<Fr>>::EdwardsVar::new_witness(
            ark_relations::ns!(cs, "gadget_randomness"),
            || Ok(<Fr as ElGamalLocalOrMPC<Fr>>::ElGamalPlaintext::default()),
        )?;

        let is_target_werewolf = is_target_werewolf_bit.select(&one_point, &zero_point)?;

        // elgamal encryption

        let param_var = <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalParamVar::new_input(
            ark_relations::ns!(cs, "gadget_parameters"),
            || Ok(common_input.elgamal_param.clone()),
        )?;

        let randomness_bits_var = peculiar_input
            .randomness_bit
            .clone()
            .iter()
            .map(|b| Boolean::new_witness(cs.clone(), || Ok(b.is_one())))
            .collect::<Result<Vec<_>, _>>()?;

        // allocate public key
        let pub_key_var = <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalPublicKeyVar::new_input(
            ark_relations::ns!(cs, "gadget_public_key"),
            || Ok(common_input.pub_key),
        )?;

        // allocate the output
        let enc_result_var = {
            // flatten randomness to little-endian bit vector
            let randomness = randomness_bits_var;

            // compute s = randomness*pk
            let s = Fr::get_public_key(&pub_key_var)
                .clone()
                .scalar_mul_le(randomness.iter())?;

            // compute c1 = randomness*generator
            let c1 = Fr::get_generator(&param_var)
                .clone()
                .scalar_mul_le(randomness.iter())?;

            // compute c2 = m + s
            let c2 = is_target_werewolf.clone() + s;

            <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalCiphertextVar::new(c1, c2)
        };

        // compare
        let enc_result_var2 = <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalCiphertextVar::new_input(
            ark_relations::ns!(cs, "gadget_commitment"),
            || {
                let is_werewolf: Fr = peculiar_input
                    .is_werewolf
                    .iter()
                    .zip(peculiar_input.is_target.iter())
                    .map(|(x, y)| x.input * y.input)
                    .sum();

                let message = match is_werewolf.is_one() {
                    true => {
                        <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalPlaintext::prime_subgroup_generator()
                    }
                    false => <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalPlaintext::default(),
                };
                let enc_result = <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalScheme::encrypt(
                    &common_input.elgamal_param,
                    &common_input.pub_key,
                    &message,
                    &peculiar_input.randomness,
                )
                .unwrap();
                Ok(enc_result)
            },
        )?;

        enc_result_var.enforce_equal(&enc_result_var2)?;

        // self.verify_commitments(cs.clone())?;

        println!("total number of constraints: {}", cs.num_constraints());

        Ok(())
    }
}

// Constraint Implementation for hbc MpcField
impl ConstraintSynthesizer<hbc::MpcField<Fr>> for DivinationCircuit<hbc::MpcField<Fr>> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<hbc::MpcField<Fr>>,
    ) -> Result<(), SynthesisError> {
        let common_input = self.clone().mpc_input.common.unwrap();
        let peculiar_input = self.clone().mpc_input.peculiar.unwrap();

        let is_werewolf_bit = MpcBoolean::new_witness_vec(
            cs.clone(),
            &peculiar_input
                .is_werewolf
                .clone()
                .iter()
                .map(|b| b.input)
                .collect::<Vec<_>>(),
        )?;

        let is_target_bit = MpcBoolean::new_witness_vec(
            cs.clone(),
            &peculiar_input
                .is_target
                .clone()
                .iter()
                .map(|b| b.input)
                .collect::<Vec<_>>(),
        )?;

        let is_wt = is_werewolf_bit
            .iter()
            .zip(is_target_bit.iter())
            .map(|(x, y)| x.and(y))
            .collect::<Result<Vec<_>, _>>()?;

        let is_target_werewolf_bit = MpcBoolean::kary_or(is_wt.as_slice())?;

        let one_point =
            <hbc::MpcField<Fr> as ElGamalLocalOrMPC<hbc::MpcField<Fr>>>::EdwardsVar::new_witness(
                ark_relations::ns!(cs, "gadget_randomness"),
                || {
                    Ok(<hbc::MpcField<Fr> as ElGamalLocalOrMPC<
                        hbc::MpcField<Fr>,
                    >>::ElGamalPlaintext::prime_subgroup_generator(
                    ))
                },
            )?;

        let zero_point =
            <hbc::MpcField<Fr> as ElGamalLocalOrMPC<hbc::MpcField<Fr>>>::EdwardsVar::new_witness(
                ark_relations::ns!(cs, "gadget_randomness"),
                || {
                    Ok(<hbc::MpcField<Fr> as ElGamalLocalOrMPC<
                        hbc::MpcField<Fr>,
                    >>::ElGamalPlaintext::default())
                },
            )?;

        let is_target_werewolf =
            hbc::MpcField::<Fr>::select(&is_target_werewolf_bit, &one_point, &zero_point)?;

        // elgamal encryption

        let param_var =
            <hbc::MpcField<Fr> as ElGamalLocalOrMPC<hbc::MpcField<Fr>>>::ElGamalParamVar::new_input(
                ark_relations::ns!(cs, "gadget_parameters"),
                || Ok(common_input.elgamal_param.clone()),
            )?;

        let randomness_bits_var =
            MpcBoolean::new_witness_vec(cs.clone(), &peculiar_input.randomness_bit)?;

        // allocate public key
        let pub_key_var = <hbc::MpcField<Fr>as ElGamalLocalOrMPC<hbc::MpcField<Fr>>>::ElGamalPublicKeyVar::new_input(
            ark_relations::ns!(cs, "gadget_public_key"),
            || Ok(common_input.pub_key),
        )?;

        // allocate the output
        let enc_result_var = {
            // flatten randomness to little-endian bit vector
            let randomness = randomness_bits_var;

            // compute s = randomness*pk
            let s = hbc::MpcField::<Fr>::get_public_key(&pub_key_var)
                .clone()
                .scalar_mul_le(randomness.iter())?;

            // compute c1 = randomness*generator
            let c1 = hbc::MpcField::<Fr>::get_generator(&param_var)
                .clone()
                .scalar_mul_le(randomness.iter())?;

            // compute c2 = m + s
            let c2 = is_target_werewolf.clone() + s;

            <hbc::MpcField<Fr> as ElGamalLocalOrMPC<hbc::MpcField<Fr>>>::ElGamalCiphertextVar::new(
                c1, c2,
            )
        };

        // compare
        let enc_result_var2 = <hbc::MpcField<Fr> as ElGamalLocalOrMPC<hbc::MpcField<Fr>>>::ElGamalCiphertextVar::new_input(
            ark_relations::ns!(cs, "gadget_commitment"),
            || {
                let is_werewolf: hbc::MpcField<Fr> = peculiar_input
                    .is_werewolf
                    .iter()
                    .zip(peculiar_input.is_target.iter())
                    .map(|(x, y)| x.input * y.input)
                    .sum();

                let message = match is_werewolf.clone().reveal().is_one() {
                    true => {
                        <hbc::MpcField<Fr> as ElGamalLocalOrMPC<hbc::MpcField<Fr>>>::ElGamalPlaintext::prime_subgroup_generator(
                        )
                    }
                    false => <hbc::MpcField<Fr> as ElGamalLocalOrMPC<hbc::MpcField<Fr>>>::ElGamalPlaintext::default(),
                };
                let enc_result = <hbc::MpcField<Fr> as ElGamalLocalOrMPC<hbc::MpcField<Fr>>>::ElGamalScheme::encrypt(
                    &common_input.elgamal_param,
                    &common_input.pub_key,
                    &message,
                    &peculiar_input.randomness,
                )
                .unwrap();
                Ok(enc_result)
            },
        )?;

        enc_result_var.enforce_equal(&enc_result_var2)?;

        // self.verify_commitments(cs.clone())?;

        println!("total number of constraints: {}", cs.num_constraints());

        Ok(())
    }
}

// impl ConstraintSynthesizer<mm::MpcField<Fr>> for DivinationCircuit<mm::MpcField<Fr>> {
//     fn generate_constraints(
//         self,
//         cs: ConstraintSystemRef<mm::MpcField<Fr>>,
//     ) -> Result<(), SynthesisError> {
//         let common_input = self.clone().mpc_input.common.unwrap();
//         let peculiar_input = self.clone().mpc_input.peculiar.unwrap();

//         let is_werewolf_bit = MpcBoolean::new_witness_vec(
//             cs.clone(),
//             &peculiar_input
//                 .is_werewolf
//                 .clone()
//                 .iter()
//                 .map(|b| b.input)
//                 .collect::<Vec<_>>(),
//         )?;

//         let is_target_bit = MpcBoolean::new_witness_vec(
//             cs.clone(),
//             &peculiar_input
//                 .is_target
//                 .clone()
//                 .iter()
//                 .map(|b| b.input)
//                 .collect::<Vec<_>>(),
//         )?;

//         let is_wt = is_werewolf_bit
//             .iter()
//             .zip(is_target_bit.iter())
//             .map(|(x, y)| x.and(y))
//             .collect::<Result<Vec<_>, _>>()?;

//         let is_target_werewolf_bit = MpcBoolean::kary_or(is_wt.as_slice())?;

//         let one_point =
//             <mm::MpcField<Fr> as ElGamalLocalOrMPC<mm::MpcField<Fr>>>::EdwardsVar::new_witness(
//                 ark_relations::ns!(cs, "gadget_randomness"),
//                 || {
//                     Ok(<mm::MpcField<Fr> as ElGamalLocalOrMPC<
//                         mm::MpcField<Fr>,
//                     >>::ElGamalPlaintext::prime_subgroup_generator(
//                     ))
//                 },
//             )?;

//         let zero_point =
//             <mm::MpcField<Fr> as ElGamalLocalOrMPC<mm::MpcField<Fr>>>::EdwardsVar::new_witness(
//                 ark_relations::ns!(cs, "gadget_randomness"),
//                 || {
//                     Ok(<mm::MpcField<Fr> as ElGamalLocalOrMPC<
//                         mm::MpcField<Fr>,
//                     >>::ElGamalPlaintext::default())
//                 },
//             )?;

//         let is_target_werewolf =
//             mm::MpcField::<Fr>::select(&is_target_werewolf_bit, &one_point, &zero_point)?;

//         // elgamal encryption

//         let param_var =
//             <mm::MpcField<Fr> as ElGamalLocalOrMPC<mm::MpcField<Fr>>>::ElGamalParamVar::new_input(
//                 ark_relations::ns!(cs, "gadget_parameters"),
//                 || Ok(common_input.elgamal_param.clone()),
//             )?;

//         let randomness_bits_var =
//             MpcBoolean::new_witness_vec(cs.clone(), &peculiar_input.randomness_bit)?;

//         // allocate public key
//         let pub_key_var = <mm::MpcField<Fr>as ElGamalLocalOrMPC<mm::MpcField<Fr>>>::ElGamalPublicKeyVar::new_input(
//             ark_relations::ns!(cs, "gadget_public_key"),
//             || Ok(common_input.pub_key),
//         )?;

//         // allocate the output
//         let enc_result_var = {
//             // flatten randomness to little-endian bit vector
//             let randomness = randomness_bits_var;

//             // compute s = randomness*pk
//             let s = mm::MpcField::<Fr>::get_public_key(&pub_key_var)
//                 .clone()
//                 .scalar_mul_le(randomness.iter())?;

//             // compute c1 = randomness*generator
//             let c1 = mm::MpcField::<Fr>::get_generator(&param_var)
//                 .clone()
//                 .scalar_mul_le(randomness.iter())?;

//             // compute c2 = m + s
//             let c2 = is_target_werewolf.clone() + s;

//             <mm::MpcField<Fr> as ElGamalLocalOrMPC<mm::MpcField<Fr>>>::ElGamalCiphertextVar::new(
//                 c1, c2,
//             )
//         };

//         // compare
//         let enc_result_var2 = <mm::MpcField<Fr> as ElGamalLocalOrMPC<mm::MpcField<Fr>>>::ElGamalCiphertextVar::new_input(
//             ark_relations::ns!(cs, "gadget_commitment"),
//             || {
//                 let is_werewolf: mm::MpcField<Fr> = peculiar_input
//                     .is_werewolf
//                     .iter()
//                     .zip(peculiar_input.is_target.iter())
//                     .map(|(x, y)| x.input * y.input)
//                     .sum();

//                 let message = match is_werewolf.clone().reveal().is_one() {
//                     true => {
//                         <mm::MpcField<Fr> as ElGamalLocalOrMPC<mm::MpcField<Fr>>>::ElGamalPlaintext::prime_subgroup_generator(
//                         )
//                     }
//                     false => <mm::MpcField<Fr> as ElGamalLocalOrMPC<mm::MpcField<Fr>>>::ElGamalPlaintext::default(),
//                 };
//                 let enc_result = <mm::MpcField<Fr> as ElGamalLocalOrMPC<mm::MpcField<Fr>>>::ElGamalScheme::encrypt(
//                     &common_input.elgamal_param,
//                     &common_input.pub_key,
//                     &message,
//                     &peculiar_input.randomness,
//                 )
//                 .unwrap();
//                 Ok(enc_result)
//             },
//         )?;

//         enc_result_var.enforce_equal(&enc_result_var2)?;

//         // self.verify_commitments(cs.clone())?;

//         println!("total number of constraints: {}", cs.num_constraints());

//         Ok(())
//     }
// }

#[derive(Clone)]
pub struct AnonymousVotingCircuit<F: PrimeField + LocalOrMPC<F>> {
    pub is_target_id: Vec<Vec<F>>,
    pub is_most_voted_id: F,

    pub pedersen_param: F::PedersenParam,
    pub player_randomness: Vec<F>,
    pub player_commitment: Vec<F::PedersenCommitment>,
}

impl ConstraintSynthesizer<Fr> for AnonymousVotingCircuit<Fr> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> ark_relations::r1cs::Result<()> {
        // initialize
        let player_num = self.player_randomness.len();
        let alive_player_num = self.is_target_id.len();

        // check player commitment
        for i in 0..player_num {
            let pedersen_circuit = PedersenComCircuit {
                param: Some(self.pedersen_param.clone()),
                input: self.player_randomness[i],
                open: <Fr as LocalOrMPC<Fr>>::PedersenRandomness::default(),
                commit: self.player_commitment[i],
            };
            pedersen_circuit.generate_constraints(cs.clone())?;
        }

        let is_target_id_var = self
            .is_target_id
            .iter()
            .map(|id| {
                id.iter()
                    .map(|b| FpVar::new_witness(cs.clone(), || Ok(b)))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;

        let is_most_voted_id_var = FpVar::new_input(cs.clone(), || Ok(self.is_most_voted_id))?;

        // calculate
        let mut num_voted_var = Vec::new();

        for i in 0..player_num {
            let mut each_num_voted = <FpVar<Fr> as Zero>::zero();

            for j in 0..alive_player_num {
                each_num_voted += is_target_id_var[j][i].clone();
            }

            num_voted_var.push(each_num_voted);
        }

        let constant = (0..4)
            .map(|i| FpVar::Constant(Fr::from(i as i32)))
            .collect::<Vec<_>>();

        let mut calced_is_most_voted_id = FpVar::new_witness(cs.clone(), || Ok(Fr::zero()))?;

        for i in 0..player_num {
            let a_now = FpVar::conditionally_select_power_of_two_vector(
                &calced_is_most_voted_id.to_bits_le().unwrap()[..2],
                &constant,
            )?;

            let res = FpVar::is_cmp(
                //&num_voted_var[calced_is_most_voted_id],
                &a_now,
                &num_voted_var[i],
                std::cmp::Ordering::Greater,
                true,
            )?;

            let false_value = FpVar::new_witness(cs.clone(), || Ok(Fr::from(i as i32)))?;

            calced_is_most_voted_id =
                FpVar::conditionally_select(&res, &calced_is_most_voted_id, &false_value)?;
        }

        // enforce equal
        is_most_voted_id_var.enforce_equal(&calced_is_most_voted_id);

        println!("total number of constraints: {}", cs.num_constraints());

        Ok(())
    }
}

impl ConstraintSynthesizer<mm::MpcField<Fr>> for AnonymousVotingCircuit<mm::MpcField<Fr>> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<mm::MpcField<Fr>>,
    ) -> ark_relations::r1cs::Result<()> {
        // initialize
        let player_num = self.player_randomness.len();
        let alive_player_num = self.is_target_id.len();

        // check player commitment
        for i in 0..player_num {
            let pedersen_circuit = PedersenComCircuit {
                param: Some(self.pedersen_param.clone()),
                input: self.player_randomness[i],
                open:
                    <mm::MpcField<Fr> as LocalOrMPC<mm::MpcField<Fr>>>::PedersenRandomness::default(
                    ),
                commit: self.player_commitment[i],
            };
            pedersen_circuit.generate_constraints(cs.clone())?;
        }

        let is_target_id_var = self
            .is_target_id
            .iter()
            .map(|id| {
                id.iter()
                    .map(|b| MpcFpVar::new_witness(cs.clone(), || Ok(b)))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;

        let is_most_voted_id_var = MpcFpVar::new_input(cs.clone(), || Ok(self.is_most_voted_id))?;

        // calculate
        let mut num_voted_var = Vec::new();

        for i in 0..player_num {
            let mut each_num_voted = <MpcFpVar<mm::MpcField<Fr>> as MpcFieldVar<
                mm::MpcField<Fr>,
                mm::MpcField<Fr>,
            >>::zero();

            for j in 0..alive_player_num {
                each_num_voted += is_target_id_var[j][i].clone();
            }

            num_voted_var.push(each_num_voted);
        }

        let constant = (0..4)
            .map(|i| {
                MpcFpVar::Constant(mm::MpcField::<Fr>::king_share(
                    Fr::from(i as i32),
                    &mut test_rng(),
                ))
            })
            .collect::<Vec<_>>();

        let mut calced_is_most_voted_id = MpcFpVar::new_witness(cs.clone(), || {
            Ok(mm::MpcField::<Fr>::king_share(Fr::zero(), &mut test_rng()))
        })?;

        for i in 0..player_num {
            let a_now = MpcFpVar::conditionally_select_power_of_two_vector(
                &calced_is_most_voted_id.to_bits_le().unwrap()[..2],
                &constant,
            )?;

            let res = MpcFpVar::is_cmp(
                //&num_voted_var[calced_is_most_voted_id],
                &a_now,
                &num_voted_var[i],
                std::cmp::Ordering::Greater,
                true,
            )?;

            let false_value = MpcFpVar::new_witness(cs.clone(), || {
                Ok(mm::MpcField::<Fr>::king_share(
                    Fr::from(i as i32),
                    &mut test_rng(),
                ))
            })?;

            calced_is_most_voted_id =
                MpcFpVar::conditionally_select(&res, &calced_is_most_voted_id, &false_value)?;
        }

        // enforce equal
        is_most_voted_id_var.enforce_equal(&calced_is_most_voted_id);

        println!("total number of constraints: {}", cs.num_constraints());

        Ok(())
    }
}

#[derive(Clone)]
pub struct WinningJudgeCircuit<F: PrimeField + LocalOrMPC<F>> {
    pub num_alive: F,
    //pubam_werewolf:Vec<F>,
    //pubrole_commitment:Vec<F>,
    pub pedersen_param: F::PedersenParam,
    pub am_werewolf: Vec<InputWithCommit<F>>,
    pub game_state: F,

    pub player_randomness: Vec<F>,
    pub player_commitment: Vec<F::PedersenCommitment>,
}

impl ConstraintSynthesizer<Fr> for WinningJudgeCircuit<Fr> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> ark_relations::r1cs::Result<()> {
        // check player commitment
        let player_num = self.player_randomness.len();
        for i in 0..player_num {
            let pedersen_circuit = PedersenComCircuit {
                param: Some(self.pedersen_param.clone()),
                input: self.player_randomness[i],
                open: <Fr as LocalOrMPC<Fr>>::PedersenRandomness::default(),
                commit: self.player_commitment[i],
            };
            pedersen_circuit.generate_constraints(cs.clone())?;
        }

        // initialize
        let num_alive_var = FpVar::new_input(cs.clone(), || Ok(self.num_alive))?;

        let am_werewolf_var = self
            .am_werewolf
            .iter()
            .map(|b| FpVar::new_witness(cs.clone(), || Ok(b.input)))
            .collect::<Result<Vec<_>, _>>()?;

        let game_state_var = FpVar::new_input(cs.clone(), || Ok(self.game_state))?;

        // calculate
        let num_werewolf_var =
            am_werewolf_var
                .iter()
                .fold(<FpVar<Fr> as Zero>::zero(), |mut acc, x| {
                    acc += x;
                    acc
                });

        let num_citizen_var = num_alive_var - &num_werewolf_var;

        let calced_game_state_var = FpVar::conditionally_select(
            &FieldVar::is_zero(&num_werewolf_var)?,
            &FpVar::constant(Fr::from(2)), // villager win
            &FpVar::conditionally_select(
                &num_werewolf_var.is_cmp(&num_citizen_var, std::cmp::Ordering::Less, false)?,
                &FpVar::constant(Fr::from(3)), // game continues
                &FpVar::constant(Fr::from(1)), // werewolf win
            )?,
        )?;

        // check commitment
        for am_werewolf_with_commit in self.am_werewolf.iter() {
            let am_werewolf_com_circuit = PedersenComCircuit {
                param: Some(self.pedersen_param.clone()),
                input: am_werewolf_with_commit.input,
                open: am_werewolf_with_commit.randomness.clone(),
                commit: am_werewolf_with_commit.commitment.clone(),
            };

            am_werewolf_com_circuit.generate_constraints(cs.clone())?;
        }

        // enforce equal
        game_state_var.enforce_equal(&calced_game_state_var)?;

        println!("total number of constraints: {}", cs.num_constraints());

        Ok(())
    }
}

impl ConstraintSynthesizer<mm::MpcField<Fr>> for WinningJudgeCircuit<mm::MpcField<Fr>> {
    fn generate_constraints(
        self,

        cs: ConstraintSystemRef<mm::MpcField<Fr>>,
    ) -> ark_relations::r1cs::Result<()> {
        // check player commitment
        let player_num = self.player_randomness.len();
        for i in 0..player_num {
            let pedersen_circuit = PedersenComCircuit {
                param: Some(self.pedersen_param.clone()),
                input: self.player_randomness[i],
                open:
                    <mm::MpcField<Fr> as LocalOrMPC<mm::MpcField<Fr>>>::PedersenRandomness::default(
                    ),
                commit: self.player_commitment[i],
            };
            pedersen_circuit.generate_constraints(cs.clone())?;
        }

        //initialize
        let num_alive_var = MpcFpVar::new_input(cs.clone(), || Ok(self.num_alive))?;

        let am_werewolf_var = self
            .am_werewolf
            .iter()
            .map(|b| MpcFpVar::new_witness(cs.clone(), || Ok(b.input)))
            .collect::<Result<Vec<_>, _>>()?;

        let game_state_var = MpcFpVar::new_input(cs.clone(), || Ok(self.game_state))?;

        // calculate
        let num_werewolf_var = am_werewolf_var.iter().fold(
            <MpcFpVar<mm::MpcField<Fr>> as Zero>::zero(),
            |mut acc, x| {
                acc += x;
                acc
            },
        );

        let num_citizen_var = num_alive_var - &num_werewolf_var;

        let calced_game_state_var = MpcFpVar::conditionally_select(
            &num_werewolf_var.is_zero()?,
            &MpcFpVar::constant(mm::MpcField::<Fr>::from(2_u32)), // villager win
            &MpcFpVar::conditionally_select(
                &num_werewolf_var.is_cmp(&num_citizen_var, std::cmp::Ordering::Less, false)?,
                &MpcFpVar::constant(mm::MpcField::<Fr>::from(3_u32)), // game continues
                &MpcFpVar::constant(mm::MpcField::<Fr>::from(1_u32)), //werewol fwin
            )?,
        )?;

        // check commitment
        for am_werewolf_with_commit in self.am_werewolf.iter() {
            let am_werewolf_com_circuit = PedersenComCircuit {
                param: Some(self.pedersen_param.clone()),
                input: am_werewolf_with_commit.input,
                open: am_werewolf_with_commit.randomness.clone(),
                commit: am_werewolf_with_commit.commitment.clone(),
            };

            am_werewolf_com_circuit.generate_constraints(cs.clone())?;
        }

        // enforce equal
        game_state_var.enforce_equal(&calced_game_state_var)?;

        println!("total number of constraints: {}", cs.num_constraints());

        Ok(())
    }
}

#[derive(Clone)]
pub struct RoleAssignmentCircuit<F: PrimeField + LocalOrMPC<F>> {
    // parameter
    pub num_players: usize,
    pub max_group_size: usize,
    pub pedersen_param: F::PedersenParam,

    // instance
    pub tau_matrix: na::DMatrix<F>,
    pub role_commitment: Vec<F::PedersenCommitment>,
    pub player_commitment: Vec<F::PedersenCommitment>,

    // witness
    pub shuffle_matrices: Vec<na::DMatrix<F>>,
    pub randomness: Vec<F::PedersenRandomness>,
    pub player_randomness: Vec<F>,
}

impl ConstraintSynthesizer<Fr> for RoleAssignmentCircuit<Fr> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> ark_relations::r1cs::Result<()> {
        // check player commitment
        assert_eq!(self.num_players, self.player_randomness.len());
        assert_eq!(self.num_players, self.player_commitment.len());
        for i in 0..self.num_players {
            let pedersen_circuit = PedersenComCircuit {
                param: Some(self.pedersen_param.clone()),
                input: self.player_randomness[i],
                open: <Fr as LocalOrMPC<Fr>>::PedersenRandomness::default(),
                commit: self.player_commitment[i],
            };
            pedersen_circuit.generate_constraints(cs.clone())?;
        }

        // initialize
        let tau_matrix_var = na::DMatrix::from_iterator(
            self.tau_matrix.nrows(),
            self.tau_matrix.ncols(),
            self.tau_matrix.iter().map(|b| {
                FpVar::new_witness(cs.clone(), || Ok(b))
                    .expect("tau matrix var is not allocated correctly")
            }),
        );

        let shuffle_matrix_var = self
            .shuffle_matrices
            .iter()
            .map(|mat| {
                na::DMatrix::from_iterator(
                    mat.nrows(),
                    mat.ncols(),
                    mat.iter().map(|b| {
                        FpVar::new_witness(cs.clone(), || Ok(b))
                            .expect("shuffle matrix var is not allocated correctly")
                    }),
                )
            })
            .collect::<Vec<_>>();

        let inverse_shuffle_matrix_var = self
            .shuffle_matrices
            .iter()
            .map(|mat| {
                na::DMatrix::from_iterator(
                    mat.nrows(),
                    mat.ncols(),
                    mat.transpose().iter().map(|b| {
                        FpVar::new_witness(cs.clone(), || Ok(b))
                            .expect("shuffle matrix var is not allocated correctly")
                    }),
                )
            })
            .collect::<Vec<_>>();

        // each shuffle matrix is a permutation matrix and sub matrix is a identity matrix
        shuffle_matrix_var
            .iter()
            .for_each(|matrix| enforce_permutation_matrix(matrix, self.num_players).unwrap());

        // calculate
        // M = Product of shuffle_matrix
        let matrix_M_var = shuffle_matrix_var
            .clone()
            .iter()
            .skip(1)
            .fold(shuffle_matrix_var[1].clone(), |acc, x| acc * x);

        let inverse_matrix_M_var = inverse_shuffle_matrix_var
            .clone()
            .iter()
            .skip(1)
            .fold(inverse_shuffle_matrix_var[1].clone(), |acc, x| acc * x);

        // rho = M^-1 * tau * M
        let rho_var = inverse_matrix_M_var * &tau_matrix_var * &matrix_M_var;

        let mut rho_sequence_var = Vec::with_capacity(self.num_players);
        let mut current_rho = rho_var.clone();
        for _ in 0..self.num_players {
            rho_sequence_var.push(current_rho.clone());
            current_rho *= rho_var.clone(); // rho^(i+1) = rho^i * rho
        }

        // input_result is consistent with the calculated result
        let length = self.tau_matrix.nrows();

        // 1. gen one-hot vector
        let unit_vecs = (0..self.num_players)
            .map(|i| test_one_hot_vector(length, i, cs.clone()))
            .collect::<Vec<_>>();

        // 2. calculate rho^i * unit_vec_j to value
        let calced_vec = unit_vecs
            .iter()
            .map(|unit_vec_j| {
                rho_sequence_var
                    .iter()
                    .map(|rho| {
                        let res_index = rho * unit_vec_j.clone();
                        test_index_to_value(res_index, true).unwrap()
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let calced_role = calced_vec
            .iter()
            .map(|val| test_max(val, self.max_group_size + 1, true).unwrap())
            .collect::<Vec<_>>();

        // commitment
        for i in 0..self.num_players {
            let pedersen_circuit = PedersenComCircuit {
                param: Some(self.pedersen_param.clone()),
                input: calced_role[i].value().unwrap_or_default(),
                open: self.randomness[i].clone(),
                commit: self.role_commitment[i],
            };
            pedersen_circuit.generate_constraints(cs.clone())?;
        }

        Ok(())
    }
}

impl ConstraintSynthesizer<mm::MpcField<Fr>> for RoleAssignmentCircuit<mm::MpcField<Fr>> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<mm::MpcField<Fr>>,
    ) -> ark_relations::r1cs::Result<()> {
        // check player commitment
        assert_eq!(self.num_players, self.player_randomness.len());
        assert_eq!(self.num_players, self.player_commitment.len());
        for i in 0..self.num_players {
            let pedersen_circuit = PedersenComCircuit {
                param: Some(self.pedersen_param.clone()),
                input: self.player_randomness[i],
                open:
                    <mm::MpcField<Fr> as LocalOrMPC<mm::MpcField<Fr>>>::PedersenRandomness::default(
                    ),
                commit: self.player_commitment[i],
            };
            pedersen_circuit.generate_constraints(cs.clone())?;
        }

        // initialize
        let tau_matrix_var = na::DMatrix::from_iterator(
            self.tau_matrix.nrows(),
            self.tau_matrix.ncols(),
            self.tau_matrix.iter().map(|b| {
                MpcFpVar::new_witness(cs.clone(), || Ok(b))
                    .expect("tau matrix var is not allocated correctly")
            }),
        );

        let shuffle_matrix_var = self
            .shuffle_matrices
            .iter()
            .map(|mat| {
                na::DMatrix::from_iterator(
                    mat.nrows(),
                    mat.ncols(),
                    mat.iter().map(|b| {
                        MpcFpVar::new_witness(cs.clone(), || Ok(b))
                            .expect("shuffle matrix var is not allocated correctly")
                    }),
                )
            })
            .collect::<Vec<_>>();

        let inverse_shuffle_matrix_var = self
            .shuffle_matrices
            .iter()
            .map(|mat| {
                na::DMatrix::from_iterator(
                    mat.nrows(),
                    mat.ncols(),
                    mat.transpose().iter().map(|b| {
                        MpcFpVar::new_witness(cs.clone(), || Ok(b))
                            .expect("shuffle matrix var is not allocated correctly")
                    }),
                )
            })
            .collect::<Vec<_>>();

        // each shuffle matrix is a permutation matrix and sub matrix is a identity matrix
        shuffle_matrix_var
            .iter()
            .for_each(|matrix| enforce_permutation_matrix_mpc(matrix, self.num_players).unwrap());

        // calculate
        // M = Product of shuffle_matrix
        let matrix_M_var = shuffle_matrix_var
            .clone()
            .iter()
            .skip(1)
            .fold(shuffle_matrix_var[1].clone(), |acc, x| acc * x);

        let inverse_matrix_M_var = inverse_shuffle_matrix_var
            .clone()
            .iter()
            .skip(1)
            .fold(inverse_shuffle_matrix_var[1].clone(), |acc, x| acc * x);

        //  rho = M^-1 * tau * M
        let rho_var = inverse_matrix_M_var * &tau_matrix_var * &matrix_M_var;

        let mut rho_sequence_var = Vec::with_capacity(self.num_players);
        let mut current_rho = rho_var.clone();
        for _ in 0..self.num_players {
            rho_sequence_var.push(current_rho.clone());
            current_rho *= rho_var.clone(); // rho^(i+1) = rho^i * rho
        }

        // input_result is consistent with the calculated result
        let length = self.tau_matrix.nrows();

        // 1. gen one-hot vector
        let unit_vecs = (0..self.num_players)
            .map(|i| test_one_hot_vector_mpc(length, i, cs.clone()))
            .collect::<Vec<_>>();

        // 2. calculate rho^i * unit_vec_j to value
        let calced_vec = unit_vecs
            .iter()
            .map(|unit_vec_j| {
                rho_sequence_var
                    .iter()
                    .map(|rho| {
                        let res_index = rho * unit_vec_j.clone();
                        test_index_to_value_mpc(res_index, true).unwrap()
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let calced_role = calced_vec
            .iter()
            .map(|val| test_max_mpc(val, self.max_group_size + 1, true).unwrap())
            .collect::<Vec<_>>();

        // commitment
        for i in 0..self.num_players {
            let pedersen_circuit = PedersenComCircuit {
                param: Some(self.pedersen_param.clone()),
                input: calced_role[i].value().unwrap(),
                open: self.randomness[i],
                commit: self.role_commitment[i],
            };
            pedersen_circuit.generate_constraints(cs.clone())?;
        }

        println!("total number of constraints: {}", cs.num_constraints());

        Ok(())
    }
}

pub trait ElGamalLocalOrMPC<ConstraintF: PrimeField> {
    type JubJub: ProjectiveCurve;

    type ElGamalScheme: AsymmetricEncryptionScheme<
        Parameters = Self::ElGamalParam,
        PublicKey = Self::ElGamalPubKey,
        SecretKey = Self::ElGamalSecretKey,
        Randomness = Self::ElGamalRandomness,
        Plaintext = Self::ElGamalPlaintext,
        Ciphertext = Self::ElGamalCiphertext,
    >;
    type ElGamalParam: Clone;
    type ElGamalPubKey: Clone;
    type ElGamalSecretKey;
    type ElGamalRandomness: Clone;
    type ElGamalPlaintext: Clone;
    type ElGamalCiphertext: Clone;

    type BooleanVar;
    type EdwardsVar: AllocVar<Self::JubJub, ConstraintF> + Clone;

    type ElGamalGadget: AsymmetricEncryptionGadget<
        Self::ElGamalScheme,
        ConstraintF,
        OutputVar = Self::ElGamalCiphertextVar,
        ParametersVar = Self::ElGamalParamVar,
        PublicKeyVar = Self::ElGamalPublicKeyVar,
        RandomnessVar = Self::ElGamalRandomnessVar,
    >;
    type ElGamalParamVar: AllocVar<Self::ElGamalParam, ConstraintF> + Clone;
    type ElGamalPublicKeyVar: AllocVar<Self::ElGamalPubKey, ConstraintF> + Clone;
    type ElGamalRandomnessVar: AllocVar<Self::ElGamalRandomness, ConstraintF> + Clone;
    type ElGamalPlaintextVar: AllocVar<Self::ElGamalPlaintext, ConstraintF> + Clone;
    type ElGamalCiphertextVar: AllocVar<Self::ElGamalCiphertext, ConstraintF> + Clone;

    fn get_generator(a: &Self::ElGamalParamVar) -> Self::EdwardsVar;

    fn get_public_key(a: &Self::ElGamalPublicKeyVar) -> Self::EdwardsVar;

    fn select(
        boolean: &Self::BooleanVar,
        frist: &Self::EdwardsVar,
        second: &Self::EdwardsVar,
    ) -> Result<Self::EdwardsVar, SynthesisError>;

    fn enforce_equal_output(
        a: &Self::ElGamalCiphertextVar,
        b: &Self::ElGamalCiphertextVar,
    ) -> Result<(), SynthesisError>;
}

impl ElGamalLocalOrMPC<Fr> for Fr {
    type JubJub = ark_ed_on_bls12_377::EdwardsProjective;

    type ElGamalScheme = ElGamal<ark_ed_on_bls12_377::EdwardsProjective>;
    type ElGamalParam = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::Parameters;
    type ElGamalPubKey = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::PublicKey;
    type ElGamalSecretKey = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::SecretKey;
    type ElGamalRandomness = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::Randomness;
    type ElGamalPlaintext = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::Plaintext;
    type ElGamalCiphertext = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::Ciphertext;

    type EdwardsVar = EdwardsVar;
    type BooleanVar = Boolean<Fr>;

    type ElGamalGadget = ElGamalEncGadget<ark_ed_on_bls12_377::EdwardsProjective, EdwardsVar>;
    type ElGamalParamVar = <Self::ElGamalGadget as AsymmetricEncryptionGadget<
        Self::ElGamalScheme,
        ark_bls12_377::Fr,
    >>::ParametersVar;
    type ElGamalRandomnessVar = <Self::ElGamalGadget as AsymmetricEncryptionGadget<
        Self::ElGamalScheme,
        ark_bls12_377::Fr,
    >>::RandomnessVar;
    type ElGamalPublicKeyVar = <Self::ElGamalGadget as AsymmetricEncryptionGadget<
        Self::ElGamalScheme,
        ark_bls12_377::Fr,
    >>::PublicKeyVar;
    type ElGamalPlaintextVar = <Self::ElGamalGadget as AsymmetricEncryptionGadget<
        Self::ElGamalScheme,
        ark_bls12_377::Fr,
    >>::PlaintextVar;
    type ElGamalCiphertextVar = <Self::ElGamalGadget as AsymmetricEncryptionGadget<
        Self::ElGamalScheme,
        ark_bls12_377::Fr,
    >>::OutputVar;

    fn get_generator(a: &Self::ElGamalParamVar) -> Self::EdwardsVar {
        a.generator.clone()
    }

    fn get_public_key(a: &Self::ElGamalPublicKeyVar) -> Self::EdwardsVar {
        a.pk.clone()
    }

    fn select(
        boolean: &Self::BooleanVar,
        frist: &Self::EdwardsVar,
        second: &Self::EdwardsVar,
    ) -> Result<Self::EdwardsVar, SynthesisError> {
        boolean.select(frist, second)
    }

    fn enforce_equal_output(
        a: &Self::ElGamalCiphertextVar,
        b: &Self::ElGamalCiphertextVar,
    ) -> Result<(), SynthesisError> {
        a.enforce_equal(b)
    }
}

impl ElGamalLocalOrMPC<hbc::MpcField<Fr>> for hbc::MpcField<Fr> {
    type JubJub = hbc::MpcEdwardsProjective;

    type ElGamalScheme = MpcElGamal<hbc::MpcEdwardsProjective>;
    type ElGamalParam = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::Parameters;
    type ElGamalPubKey = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::PublicKey;
    type ElGamalSecretKey = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::SecretKey;
    type ElGamalRandomness = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::Randomness;
    type ElGamalPlaintext = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::Plaintext;
    type ElGamalCiphertext = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::Ciphertext;

    type EdwardsVar = hbc::MpcEdwardsVar;
    type BooleanVar = MpcBoolean<hbc::MpcField<Fr>>;

    type ElGamalGadget = MpcElGamalEncGadget<hbc::MpcEdwardsProjective, hbc::MpcEdwardsVar>;
    type ElGamalParamVar = <Self::ElGamalGadget as AsymmetricEncryptionGadget<
        Self::ElGamalScheme,
        hbc::MpcField<Fr>,
    >>::ParametersVar;
    type ElGamalRandomnessVar = <Self::ElGamalGadget as AsymmetricEncryptionGadget<
        Self::ElGamalScheme,
        hbc::MpcField<Fr>,
    >>::RandomnessVar;
    type ElGamalPublicKeyVar = <Self::ElGamalGadget as AsymmetricEncryptionGadget<
        Self::ElGamalScheme,
        hbc::MpcField<Fr>,
    >>::PublicKeyVar;
    type ElGamalPlaintextVar = <Self::ElGamalGadget as AsymmetricEncryptionGadget<
        Self::ElGamalScheme,
        hbc::MpcField<Fr>,
    >>::PlaintextVar;
    type ElGamalCiphertextVar = <Self::ElGamalGadget as AsymmetricEncryptionGadget<
        Self::ElGamalScheme,
        hbc::MpcField<Fr>,
    >>::OutputVar;

    fn get_generator(a: &Self::ElGamalParamVar) -> Self::EdwardsVar {
        a.generator.clone()
    }

    fn get_public_key(a: &Self::ElGamalPublicKeyVar) -> Self::EdwardsVar {
        a.pk.clone()
    }

    fn select(
        boolean: &Self::BooleanVar,
        frist: &Self::EdwardsVar,
        second: &Self::EdwardsVar,
    ) -> Result<Self::EdwardsVar, SynthesisError> {
        boolean.select(frist, second)
    }

    fn enforce_equal_output(
        a: &Self::ElGamalCiphertextVar,
        b: &Self::ElGamalCiphertextVar,
    ) -> Result<(), SynthesisError> {
        a.enforce_equal(b)
    }
}

impl ElGamalLocalOrMPC<mm::MpcField<Fr>> for mm::MpcField<Fr> {
    type JubJub = mm::MpcEdwardsProjective;

    type ElGamalScheme = MpcElGamal<mm::MpcEdwardsProjective>;
    type ElGamalParam = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::Parameters;
    type ElGamalPubKey = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::PublicKey;
    type ElGamalSecretKey = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::SecretKey;
    type ElGamalRandomness = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::Randomness;
    type ElGamalPlaintext = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::Plaintext;
    type ElGamalCiphertext = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::Ciphertext;

    type EdwardsVar = mm::MpcEdwardsVar;
    type BooleanVar = MpcBoolean<mm::MpcField<Fr>>;

    type ElGamalGadget = MpcElGamalEncGadget<mm::MpcEdwardsProjective, mm::MpcEdwardsVar>;
    type ElGamalParamVar = <Self::ElGamalGadget as AsymmetricEncryptionGadget<
        Self::ElGamalScheme,
        mm::MpcField<Fr>,
    >>::ParametersVar;
    type ElGamalRandomnessVar = <Self::ElGamalGadget as AsymmetricEncryptionGadget<
        Self::ElGamalScheme,
        mm::MpcField<Fr>,
    >>::RandomnessVar;
    type ElGamalPublicKeyVar = <Self::ElGamalGadget as AsymmetricEncryptionGadget<
        Self::ElGamalScheme,
        mm::MpcField<Fr>,
    >>::PublicKeyVar;
    type ElGamalPlaintextVar = <Self::ElGamalGadget as AsymmetricEncryptionGadget<
        Self::ElGamalScheme,
        mm::MpcField<Fr>,
    >>::PlaintextVar;
    type ElGamalCiphertextVar = <Self::ElGamalGadget as AsymmetricEncryptionGadget<
        Self::ElGamalScheme,
        mm::MpcField<Fr>,
    >>::OutputVar;

    fn get_generator(a: &Self::ElGamalParamVar) -> Self::EdwardsVar {
        a.generator.clone()
    }

    fn get_public_key(a: &Self::ElGamalPublicKeyVar) -> Self::EdwardsVar {
        a.pk.clone()
    }

    fn select(
        boolean: &Self::BooleanVar,
        frist: &Self::EdwardsVar,
        second: &Self::EdwardsVar,
    ) -> Result<Self::EdwardsVar, SynthesisError> {
        boolean.select(frist, second)
    }

    fn enforce_equal_output(
        a: &Self::ElGamalCiphertextVar,
        b: &Self::ElGamalCiphertextVar,
    ) -> Result<(), SynthesisError> {
        a.enforce_equal(b)
    }
}

// return maximum value in the vector a, index runs from 0 to use_index_len
fn test_max<F: PrimeField>(
    a: &[FpVar<F>],
    use_index_len: usize,
    should_enforce: bool,
) -> Result<FpVar<F>, SynthesisError> {
    let cs = a[0].cs().clone();
    let max_var = FpVar::new_witness(cs, || {
        let max = a.iter().map(|x| x.value().unwrap()).max().unwrap();
        Ok(max)
    })?;

    if should_enforce {
        // each element must be less than half of the modulus
        for i in 0..use_index_len {
            a[i].enforce_cmp(&max_var, core::cmp::Ordering::Less, true)?;
        }
    }

    Ok(max_var)
}

fn test_max_mpc<F: PrimeField + SquareRootField + BitDecomposition + EqualityZero>(
    a: &[MpcFpVar<F>],
    use_index_len: usize,
    should_enforce: bool,
) -> Result<MpcFpVar<F>, SynthesisError> {
    let cs = a[0].cs().clone();
    let max_var = MpcFpVar::new_witness(cs, || {
        let max = a.iter().map(|x| x.value().unwrap()).max().unwrap();
        Ok(max)
    })?;

    if should_enforce {
        for i in 0..use_index_len {
            a[i].enforce_cmp(&max_var, core::cmp::Ordering::Less, true)?;
        }
    }

    Ok(max_var)
}

fn test_index_to_value<F: PrimeField>(
    a: na::DVector<FpVar<F>>,
    should_enforce: bool,
) -> Result<FpVar<F>, SynthesisError> {
    let cs = a[0].cs().clone();
    let value_var = FpVar::new_witness(cs.clone(), || {
        let res = a
            .iter()
            .position(|x| x.value().unwrap().is_one())
            .expect("This index vector is not a one-hot vector");
        Ok(F::from(res as u64))
    })?;

    if should_enforce {
        let stair_vector = na::DVector::from(
            (0..a.len())
                .map(|i| FpVar::new_constant(cs.clone(), F::from(i as u64)).unwrap())
                .collect::<Vec<_>>(),
        );
        let ip = a.dot(&stair_vector);

        ip.enforce_equal(&value_var)?;
    }
    Ok(value_var)
}

fn test_index_to_value_mpc<F: PrimeField + Reveal>(
    a: na::DVector<MpcFpVar<F>>,
    should_enforce: bool,
) -> Result<MpcFpVar<F>, SynthesisError>
where
    <F as Reveal>::Base: Zero,
{
    let cs = a[0].cs().clone();
    let value_var = MpcFpVar::new_witness(cs.clone(), || {
        let res = a
            .iter()
            .position(|x| x.value().unwrap().is_one())
            .expect("This index vector is not a one-hot vector");
        Ok(F::from(res as u64))
    })?;

    if should_enforce {
        let stair_vector = na::DVector::from(
            (0..a.len())
                .map(|i| MpcFpVar::new_constant(cs.clone(), F::from(i as u64)).unwrap())
                .collect::<Vec<_>>(),
        );
        let ip = a.dot(&stair_vector);

        ip.enforce_equal(&value_var)?;
    }
    Ok(value_var)
}

fn test_one_hot_vector<F: PrimeField>(
    length: usize,
    index: usize,
    cs: ConstraintSystemRef<F>,
) -> na::DVector<FpVar<F>> {
    assert!(index < length);
    let mut res = na::DVector::<FpVar<F>>::zeros(length);
    for i in 0..length {
        if i == index {
            res[i] = FpVar::new_constant(cs.clone(), F::one()).unwrap();
        } else {
            res[i] = FpVar::new_constant(cs.clone(), F::zero()).unwrap();
        }
    }
    res
}

fn test_one_hot_vector_mpc<F: PrimeField + Reveal>(
    length: usize,
    index: usize,
    cs: ConstraintSystemRef<F>,
) -> na::DVector<MpcFpVar<F>>
where
    <F as Reveal>::Base: Zero,
{
    assert!(index < length);
    let mut res = na::DVector::<MpcFpVar<F>>::zeros(length);
    for i in 0..length {
        if i == index {
            res[i] = MpcFpVar::new_constant(cs.clone(), F::one()).unwrap();
        } else {
            res[i] = MpcFpVar::new_constant(cs.clone(), F::zero()).unwrap();
        }
    }
    res
}

fn enforce_permutation_matrix<F: PrimeField>(
    matrix: &na::DMatrix<FpVar<F>>,
    n: usize,
) -> Result<(), SynthesisError> {
    let size = matrix.nrows();
    // (0,0) ~ (n-1,n-1) is arbitrary permutation matrix

    for i in 0..n {
        let mut i_th_row_sum = <FpVar<F> as Zero>::zero();
        let mut i_th_column_sum = <FpVar<F> as Zero>::zero();

        for j in 0..n {
            // all check 0 or 1 -> row sum and column sum is 1
            let val = &matrix[(i, j)];

            val.is_eq(&<FpVar<F> as Zero>::zero())
                .unwrap()
                .or(&val.is_eq(&<FpVar<F> as One>::one()).unwrap())
                .unwrap()
                .enforce_equal(&Boolean::TRUE)?;

            // row column is ambiguos
            i_th_row_sum += val;
            i_th_column_sum += &matrix[(j, i)];
        }

        i_th_row_sum.enforce_equal(&<FpVar<F> as One>::one())?;
        i_th_column_sum.enforce_equal(&<FpVar<F> as One>::one())?;
    }

    for i in 0..size {
        for j in 0..size {
            if i >= n || j >= n {
                // (n~n+m-1, n~n+m-1) is identity matrix
                if i == j {
                    let val = &matrix[(i, j)];
                    val.enforce_equal(&<FpVar<F> as One>::one())?;
                } else {
                    // other is 0
                    let val = &matrix[(i, j)];
                    val.enforce_equal(&<FpVar<F> as Zero>::zero())?;
                }
            }
        }
    }

    Ok(())
}

fn enforce_permutation_matrix_mpc<
    F: PrimeField + Reveal + ark_ff::SquareRootField + mpc_algebra::EqualityZero,
>(
    matrix: &na::DMatrix<MpcFpVar<F>>,
    n: usize,
) -> Result<(), SynthesisError>
where
    <F as Reveal>::Base: Zero,
{
    let size = matrix.nrows();
    // (0,0) ~ (n-1,n-1) is arbitrary permutation matrix

    for i in 0..n {
        let mut i_th_row_sum = <MpcFpVar<F> as Zero>::zero();
        let mut i_th_column_sum = <MpcFpVar<F> as Zero>::zero();

        for j in 0..n {
            // all check 0 or 1 -> row sum and column sum is 1
            let val = &matrix[(i, j)];

            val.is_zero()
                .unwrap()
                .or(&(val - <MpcFpVar<F> as One>::one()).is_zero().unwrap())
                .unwrap()
                .enforce_equal(&MpcBoolean::TRUE)?;

            // row column is ambiguos
            i_th_row_sum += val;
            i_th_column_sum += &matrix[(j, i)];
        }

        i_th_row_sum.enforce_equal(&<MpcFpVar<F> as One>::one())?;
        i_th_column_sum.enforce_equal(&<MpcFpVar<F> as One>::one())?;
    }

    for i in 0..size {
        for j in 0..size {
            if i >= n || j >= n {
                // (n~n+m-1, n~n+m-1) is identity matrix
                if i == j {
                    let val = &matrix[(i, j)];
                    val.enforce_equal(&<MpcFpVar<F> as One>::one())?;
                } else {
                    // other is 0
                    let val = &matrix[(i, j)];
                    val.enforce_equal(&<MpcFpVar<F> as Zero>::zero())?;
                }
            }
        }
    }

    Ok(())
}
