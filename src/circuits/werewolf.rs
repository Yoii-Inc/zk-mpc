use ark_bls12_377::Fr;
use ark_crypto_primitives::encryption::elgamal::{constraints::ElGamalEncGadget, ElGamal};
use ark_crypto_primitives::encryption::*;
use ark_ec::AffineCurve;
use ark_ec::ProjectiveCurve;
use ark_ed_on_bls12_377::constraints::EdwardsVar;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_r1cs_std::ToBitsGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{test_rng, One, Zero};
use mpc_algebra::groups::MpcCurveVar;
use mpc_algebra::mpc_fields::MpcFieldVar;
use mpc_algebra::{
    MpcBoolean, MpcCondSelectGadget, MpcEqGadget, MpcFpVar, MpcToBitsGadget, Reveal,
};

use mpc_algebra::honest_but_curious as hbc;
use mpc_algebra::malicious_majority as mm;

use mpc_algebra::encryption::constraints::AsymmetricEncryptionGadget;
use mpc_algebra::encryption::elgamal::{
    constraints::ElGamalEncGadget as MpcElGamalEncGadget, elgamal::ElGamal as MpcElGamal,
};

use super::{LocalOrMPC, PedersenComCircuit};
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
            let is_zero = FieldVar::<F, F>::is_zero(b)?;
            let is_one = FieldVar::<F, F>::is_one(b)?;
            let is_bool = is_zero.or(&is_one)?;
            is_bool.enforce_equal(&Boolean::constant(true))?;
        }

        let _sum_x_var = x_var
            .iter()
            .enumerate()
            .fold(FpVar::<F>::zero(), |mut acc, (i, x)| {
                acc = acc + x * &is_ft_var[i];
                acc
            });

        let _sum_y_var = y_var
            .iter()
            .enumerate()
            .fold(FpVar::<F>::zero(), |mut acc, (i, y)| {
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
// impl ConstraintSynthesizer<hbc::MpcField<Fr>> for DivinationCircuit<hbc::MpcField<Fr>> {
//     fn generate_constraints(
//         self,
//         cs: ConstraintSystemRef<hbc::MpcField<Fr>>,
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
//             <hbc::MpcField<Fr> as ElGamalLocalOrMPC<hbc::MpcField<Fr>>>::EdwardsVar::new_witness(
//                 ark_relations::ns!(cs, "gadget_randomness"),
//                 || {
//                     Ok(<hbc::MpcField<Fr> as ElGamalLocalOrMPC<
//                         hbc::MpcField<Fr>,
//                     >>::ElGamalPlaintext::prime_subgroup_generator(
//                     ))
//                 },
//             )?;

//         let zero_point =
//             <hbc::MpcField<Fr> as ElGamalLocalOrMPC<hbc::MpcField<Fr>>>::EdwardsVar::new_witness(
//                 ark_relations::ns!(cs, "gadget_randomness"),
//                 || {
//                     Ok(<hbc::MpcField<Fr> as ElGamalLocalOrMPC<
//                         hbc::MpcField<Fr>,
//                     >>::ElGamalPlaintext::default())
//                 },
//             )?;

//         let is_target_werewolf =
//             hbc::MpcField::<Fr>::select(&is_target_werewolf_bit, &one_point, &zero_point)?;

//         // elgamal encryption

//         let param_var =
//             <hbc::MpcField<Fr> as ElGamalLocalOrMPC<hbc::MpcField<Fr>>>::ElGamalParamVar::new_input(
//                 ark_relations::ns!(cs, "gadget_parameters"),
//                 || Ok(common_input.elgamal_param.clone()),
//             )?;

//         let randomness_bits_var =
//             MpcBoolean::new_witness_vec(cs.clone(), &peculiar_input.randomness_bit)?;

//         // allocate public key
//         let pub_key_var = <hbc::MpcField<Fr>as ElGamalLocalOrMPC<hbc::MpcField<Fr>>>::ElGamalPublicKeyVar::new_input(
//             ark_relations::ns!(cs, "gadget_public_key"),
//             || Ok(common_input.pub_key),
//         )?;

//         // allocate the output
//         let enc_result_var = {
//             // flatten randomness to little-endian bit vector
//             let randomness = randomness_bits_var;

//             // compute s = randomness*pk
//             let s = hbc::MpcField::<Fr>::get_public_key(&pub_key_var)
//                 .clone()
//                 .scalar_mul_le(randomness.iter())?;

//             // compute c1 = randomness*generator
//             let c1 = hbc::MpcField::<Fr>::get_generator(&param_var)
//                 .clone()
//                 .scalar_mul_le(randomness.iter())?;

//             // compute c2 = m + s
//             let c2 = is_target_werewolf.clone() + s;

//             <hbc::MpcField<Fr> as ElGamalLocalOrMPC<hbc::MpcField<Fr>>>::ElGamalCiphertextVar::new(
//                 c1, c2,
//             )
//         };

//         // compare
//         let enc_result_var2 = <hbc::MpcField<Fr> as ElGamalLocalOrMPC<hbc::MpcField<Fr>>>::ElGamalCiphertextVar::new_input(
//             ark_relations::ns!(cs, "gadget_commitment"),
//             || {
//                 let is_werewolf: hbc::MpcField<Fr> = peculiar_input
//                     .is_werewolf
//                     .iter()
//                     .zip(peculiar_input.is_target.iter())
//                     .map(|(x, y)| x.input * y.input)
//                     .sum();

//                 let message = match is_werewolf.clone().reveal().is_one() {
//                     true => {
//                         <hbc::MpcField<Fr> as ElGamalLocalOrMPC<hbc::MpcField<Fr>>>::ElGamalPlaintext::prime_subgroup_generator(
//                         )
//                     }
//                     false => <hbc::MpcField<Fr> as ElGamalLocalOrMPC<hbc::MpcField<Fr>>>::ElGamalPlaintext::default(),
//                 };
//                 let enc_result = <hbc::MpcField<Fr> as ElGamalLocalOrMPC<hbc::MpcField<Fr>>>::ElGamalScheme::encrypt(
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

impl ConstraintSynthesizer<mm::MpcField<Fr>> for DivinationCircuit<mm::MpcField<Fr>> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<mm::MpcField<Fr>>,
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
            <mm::MpcField<Fr> as ElGamalLocalOrMPC<mm::MpcField<Fr>>>::EdwardsVar::new_witness(
                ark_relations::ns!(cs, "gadget_randomness"),
                || {
                    Ok(<mm::MpcField<Fr> as ElGamalLocalOrMPC<
                        mm::MpcField<Fr>,
                    >>::ElGamalPlaintext::prime_subgroup_generator(
                    ))
                },
            )?;

        let zero_point =
            <mm::MpcField<Fr> as ElGamalLocalOrMPC<mm::MpcField<Fr>>>::EdwardsVar::new_witness(
                ark_relations::ns!(cs, "gadget_randomness"),
                || {
                    Ok(<mm::MpcField<Fr> as ElGamalLocalOrMPC<
                        mm::MpcField<Fr>,
                    >>::ElGamalPlaintext::default())
                },
            )?;

        let is_target_werewolf =
            mm::MpcField::<Fr>::select(&is_target_werewolf_bit, &one_point, &zero_point)?;

        // elgamal encryption

        let param_var =
            <mm::MpcField<Fr> as ElGamalLocalOrMPC<mm::MpcField<Fr>>>::ElGamalParamVar::new_input(
                ark_relations::ns!(cs, "gadget_parameters"),
                || Ok(common_input.elgamal_param.clone()),
            )?;

        let randomness_bits_var =
            MpcBoolean::new_witness_vec(cs.clone(), &peculiar_input.randomness_bit)?;

        // allocate public key
        let pub_key_var = <mm::MpcField<Fr>as ElGamalLocalOrMPC<mm::MpcField<Fr>>>::ElGamalPublicKeyVar::new_input(
            ark_relations::ns!(cs, "gadget_public_key"),
            || Ok(common_input.pub_key),
        )?;

        // allocate the output
        let enc_result_var = {
            // flatten randomness to little-endian bit vector
            let randomness = randomness_bits_var;

            // compute s = randomness*pk
            let s = mm::MpcField::<Fr>::get_public_key(&pub_key_var)
                .clone()
                .scalar_mul_le(randomness.iter())?;

            // compute c1 = randomness*generator
            let c1 = mm::MpcField::<Fr>::get_generator(&param_var)
                .clone()
                .scalar_mul_le(randomness.iter())?;

            // compute c2 = m + s
            let c2 = is_target_werewolf.clone() + s;

            <mm::MpcField<Fr> as ElGamalLocalOrMPC<mm::MpcField<Fr>>>::ElGamalCiphertextVar::new(
                c1, c2,
            )
        };

        // compare
        let enc_result_var2 = <mm::MpcField<Fr> as ElGamalLocalOrMPC<mm::MpcField<Fr>>>::ElGamalCiphertextVar::new_input(
            ark_relations::ns!(cs, "gadget_commitment"),
            || {
                let is_werewolf: mm::MpcField<Fr> = peculiar_input
                    .is_werewolf
                    .iter()
                    .zip(peculiar_input.is_target.iter())
                    .map(|(x, y)| x.input * y.input)
                    .sum();

                let message = match is_werewolf.clone().reveal().is_one() {
                    true => {
                        <mm::MpcField<Fr> as ElGamalLocalOrMPC<mm::MpcField<Fr>>>::ElGamalPlaintext::prime_subgroup_generator(
                        )
                    }
                    false => <mm::MpcField<Fr> as ElGamalLocalOrMPC<mm::MpcField<Fr>>>::ElGamalPlaintext::default(),
                };
                let enc_result = <mm::MpcField<Fr> as ElGamalLocalOrMPC<mm::MpcField<Fr>>>::ElGamalScheme::encrypt(
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

#[derive(Clone)]
pub struct AnonymousVotingCircuit<F: PrimeField + LocalOrMPC<F>> {
    pub is_target_id: Vec<Vec<F>>,
    pub is_most_voted_id: F,
}

impl ConstraintSynthesizer<Fr> for AnonymousVotingCircuit<Fr> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> ark_relations::r1cs::Result<()> {
        // initialize
        let player_num = self.is_target_id.len();

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
            let mut each_num_voted = FpVar::zero();

            for j in 0..player_num {
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
        let player_num = self.is_target_id.len();

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
            let mut each_num_voted = MpcFpVar::zero();

            for j in 0..player_num {
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
}

impl ConstraintSynthesizer<Fr> for WinningJudgeCircuit<Fr> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> ark_relations::r1cs::Result<()> {
        // initialize
        let num_alive_var = FpVar::new_input(cs.clone(), || Ok(self.num_alive))?;

        let am_werewolf_var = self
            .am_werewolf
            .iter()
            .map(|b| FpVar::new_witness(cs.clone(), || Ok(b.input)))
            .collect::<Result<Vec<_>, _>>()?;

        let game_state_var = FpVar::new_input(cs.clone(), || Ok(self.game_state))?;

        // calculate
        let num_werewolf_var = am_werewolf_var.iter().fold(FpVar::zero(), |mut acc, x| {
            acc += x;
            acc
        });

        let num_citizen_var = num_alive_var - &num_werewolf_var;

        let calced_game_state_var = FpVar::conditionally_select(
            &num_werewolf_var.is_zero()?,
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
        //initialize
        let num_alive_var = MpcFpVar::new_input(cs.clone(), || Ok(self.num_alive))?;

        let am_werewolf_var = self
            .am_werewolf
            .iter()
            .map(|b| MpcFpVar::new_witness(cs.clone(), || Ok(b.input)))
            .collect::<Result<Vec<_>, _>>()?;

        let game_state_var = MpcFpVar::new_input(cs.clone(), || Ok(self.game_state))?;

        // calculate
        let num_werewolf_var = am_werewolf_var.iter().fold(MpcFpVar::zero(), |mut acc, x| {
            acc += x;
            acc
        });

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

// impl ElGamalLocalOrMPC<hbc::MpcField<Fr>> for hbc::MpcField<Fr> {
//     type JubJub = hbc::MpcEdwardsProjective;

//     type ElGamalScheme = MpcElGamal<hbc::MpcEdwardsProjective>;
//     type ElGamalParam = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::Parameters;
//     type ElGamalPubKey = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::PublicKey;
//     type ElGamalSecretKey = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::SecretKey;
//     type ElGamalRandomness = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::Randomness;
//     type ElGamalPlaintext = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::Plaintext;
//     type ElGamalCiphertext = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::Ciphertext;

//     type EdwardsVar = hbc::MpcEdwardsVar;
//     type BooleanVar = MpcBoolean<hbc::MpcField<Fr>>;

//     type ElGamalGadget = MpcElGamalEncGadget<hbc::MpcEdwardsProjective, hbc::MpcEdwardsVar>;
//     type ElGamalParamVar = <Self::ElGamalGadget as AsymmetricEncryptionGadget<
//         Self::ElGamalScheme,
//         hbc::MpcField<Fr>,
//     >>::ParametersVar;
//     type ElGamalRandomnessVar = <Self::ElGamalGadget as AsymmetricEncryptionGadget<
//         Self::ElGamalScheme,
//         hbc::MpcField<Fr>,
//     >>::RandomnessVar;
//     type ElGamalPublicKeyVar = <Self::ElGamalGadget as AsymmetricEncryptionGadget<
//         Self::ElGamalScheme,
//         hbc::MpcField<Fr>,
//     >>::PublicKeyVar;
//     type ElGamalPlaintextVar = <Self::ElGamalGadget as AsymmetricEncryptionGadget<
//         Self::ElGamalScheme,
//         hbc::MpcField<Fr>,
//     >>::PlaintextVar;
//     type ElGamalCiphertextVar = <Self::ElGamalGadget as AsymmetricEncryptionGadget<
//         Self::ElGamalScheme,
//         hbc::MpcField<Fr>,
//     >>::OutputVar;

//     fn get_generator(a: &Self::ElGamalParamVar) -> Self::EdwardsVar {
//         a.generator.clone()
//     }

//     fn get_public_key(a: &Self::ElGamalPublicKeyVar) -> Self::EdwardsVar {
//         a.pk.clone()
//     }

//     fn select(
//         boolean: &Self::BooleanVar,
//         frist: &Self::EdwardsVar,
//         second: &Self::EdwardsVar,
//     ) -> Result<Self::EdwardsVar, SynthesisError> {
//         boolean.select(frist, second)
//     }

//     fn enforce_equal_output(
//         a: &Self::ElGamalCiphertextVar,
//         b: &Self::ElGamalCiphertextVar,
//     ) -> Result<(), SynthesisError> {
//         a.enforce_equal(b)
//     }
// }

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
