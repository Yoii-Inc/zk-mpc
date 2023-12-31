use ark_bls12_377::Fr;
use ark_crypto_primitives::encryption::elgamal::{constraints::ElGamalEncGadget, ElGamal};
use ark_crypto_primitives::encryption::*;
use ark_ec::AffineCurve;
use ark_ec::ProjectiveCurve;
use ark_ed_on_bls12_377::constraints::EdwardsVar;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::{AllocatedBool, Boolean};
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::groups::CurveVar;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};
use ark_std::One;
use ark_std::Zero;
use mpc_algebra::Reveal;

use mpc_algebra::honest_but_curious as hbc;
use mpc_algebra::malicious_majority as mm;

use super::{LocalOrMPC, PedersenComCircuit};
use crate::input::{WerewolfKeyInput, WerewolfMpcInput};

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
                input_bit: pub_key_or_dummy_x.input_bit.clone(),
                open_bit: pub_key_or_dummy_x.randomness_bit.clone(),
                commit: Some(pub_key_or_dummy_x.commitment.clone()),
            };

            pub_key_or_dummy_x_com_circuit.generate_constraints(cs.clone())?;
        }

        let pub_key_or_dummy_y_vec = self.clone().mpc_input.peculiar.unwrap().pub_key_or_dummy_y;

        for pub_key_or_dummy_y in pub_key_or_dummy_y_vec.iter() {
            let pub_key_or_dummy_y_com_circuit = PedersenComCircuit {
                param: Some(pedersen_param.clone()),
                input: pub_key_or_dummy_y.input,
                input_bit: pub_key_or_dummy_y.input_bit.clone(),
                open_bit: pub_key_or_dummy_y.randomness_bit.clone(),
                commit: Some(pub_key_or_dummy_y.commitment.clone()),
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

        let x_var = pk_x
            .iter()
            .map(|x| cs.new_witness_variable(|| Ok(x.input)).unwrap())
            .collect::<Vec<_>>();

        let y_var = pk_y
            .iter()
            .map(|y| cs.new_witness_variable(|| Ok(y.input)).unwrap())
            .collect::<Vec<_>>();

        let input_x_var = cs.new_input_variable(|| {
            let vec = pk_x.clone();
            let pk = vec.iter().map(|x| x.input).sum();
            Ok(pk)
        })?;

        let input_y_var = cs.new_input_variable(|| {
            let vec = pk_y.clone();
            let pk = vec.iter().map(|y| y.input).sum();
            Ok(pk)
        })?;

        let lc_x = x_var.iter().fold(lc!(), |mut acc, x| {
            acc = acc + x;
            acc
        });

        let lc_y = y_var.iter().fold(lc!(), |mut acc, y| {
            acc = acc + y;
            acc
        });

        cs.enforce_constraint(lc!() + Variable::One, lc_x, lc!() + input_x_var)?;
        cs.enforce_constraint(lc!() + Variable::One, lc_y, lc!() + input_y_var)?;

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
                input_bit: is_werewolf.input_bit.clone(),
                open_bit: is_werewolf.randomness_bit.clone(),
                commit: Some(is_werewolf.commitment.clone()),
            };

            is_werewolf_com_circuit.generate_constraints(cs.clone())?;
        }

        let is_target_vec = self.clone().mpc_input.peculiar.unwrap().is_target;

        for is_target in is_target_vec.iter() {
            let is_target_com_circuit = PedersenComCircuit {
                param: Some(pedersen_param.clone()),
                input: is_target.input,
                input_bit: is_target.input_bit.clone(),
                open_bit: is_target.randomness_bit.clone(),
                commit: Some(is_target.commitment.clone()),
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
            .map(|b| {
                let alloc_bool = {
                    let variable = cs.new_witness_variable(|| Ok(b.input))?;

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

        let is_target_bit = peculiar_input
            .is_target
            .clone()
            .iter()
            .map(|b| {
                let alloc_bool = {
                    let variable = cs.new_witness_variable(|| Ok(b.input))?;

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
            let s = pub_key_var.pk().clone().scalar_mul_le(randomness.iter())?;

            // compute c1 = randomness*generator
            let c1 = param_var
                .generator()
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

// Constraint Implementation for Local Field
impl ConstraintSynthesizer<hbc::MpcField<Fr>> for DivinationCircuit<hbc::MpcField<Fr>> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<hbc::MpcField<Fr>>,
    ) -> Result<(), SynthesisError> {
        let common_input = self.clone().mpc_input.common.unwrap();
        let peculiar_input = self.clone().mpc_input.peculiar.unwrap();

        let is_werewolf_bit = peculiar_input
            .is_werewolf
            .clone()
            .iter()
            .map(|b| {
                let alloc_bool = {
                    let variable = cs.new_witness_variable(|| Ok(b.input))?;

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

        let is_target_bit = peculiar_input
            .is_target
            .clone()
            .iter()
            .map(|b| {
                let alloc_bool = {
                    let variable = cs.new_witness_variable(|| Ok(b.input))?;

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

        let is_wt = is_werewolf_bit
            .iter()
            .zip(is_target_bit.iter())
            .map(|(x, y)| x.and(y))
            .collect::<Result<Vec<_>, _>>()?;

        let is_target_werewolf_bit = Boolean::kary_or(is_wt.as_slice())?;

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

        let is_target_werewolf = is_target_werewolf_bit.select(&one_point, &zero_point)?;

        // elgamal encryption

        let param_var = <hbc::MpcField<Fr> as ElGamalLocalOrMPC<hbc::MpcField<Fr>>>::ElGamalParamVar::new_input(
            ark_relations::ns!(cs, "gadget_parameters"),
            || Ok(common_input.elgamal_param.clone()),
        )?;

        let randomness_bits_var = peculiar_input
            .randomness_bit
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
            let s = pub_key_var.pk().clone().scalar_mul_le(randomness.iter())?;

            // compute c1 = randomness*generator
            let c1 = param_var
                .generator()
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

impl ConstraintSynthesizer<mm::MpcField<Fr>> for DivinationCircuit<mm::MpcField<Fr>> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<mm::MpcField<Fr>>,
    ) -> Result<(), SynthesisError> {
        let common_input = self.clone().mpc_input.common.unwrap();
        let peculiar_input = self.clone().mpc_input.peculiar.unwrap();

        let is_werewolf_bit = peculiar_input
            .is_werewolf
            .clone()
            .iter()
            .map(|b| {
                let alloc_bool = {
                    let variable = cs.new_witness_variable(|| Ok(b.input))?;

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

        let is_target_bit = peculiar_input
            .is_target
            .clone()
            .iter()
            .map(|b| {
                let alloc_bool = {
                    let variable = cs.new_witness_variable(|| Ok(b.input))?;

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

        let is_wt = is_werewolf_bit
            .iter()
            .zip(is_target_bit.iter())
            .map(|(x, y)| x.and(y))
            .collect::<Result<Vec<_>, _>>()?;

        let is_target_werewolf_bit = Boolean::kary_or(is_wt.as_slice())?;

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

        let is_target_werewolf = is_target_werewolf_bit.select(&one_point, &zero_point)?;

        // elgamal encryption

        let param_var =
            <mm::MpcField<Fr> as ElGamalLocalOrMPC<mm::MpcField<Fr>>>::ElGamalParamVar::new_input(
                ark_relations::ns!(cs, "gadget_parameters"),
                || Ok(common_input.elgamal_param.clone()),
            )?;

        let randomness_bits_var = peculiar_input
            .randomness_bit
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
            let s = pub_key_var.pk().clone().scalar_mul_le(randomness.iter())?;

            // compute c1 = randomness*generator
            let c1 = param_var
                .generator()
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

    type EdwardsVar: CurveVar<Self::JubJub, ConstraintF>;

    type ElGamalGadget: AsymmetricEncryptionGadget<
        Self::ElGamalScheme,
        ConstraintF,
        OutputVar = Self::ElGamalCiphertextVar,
        ParametersVar = Self::ElGamalParamVar,
        PublicKeyVar = Self::ElGamalPublicKeyVar,
        RandomnessVar = Self::ElGamalRandomnessVar,
    >;
    type ElGamalParamVar: AllocVar<Self::ElGamalParam, ConstraintF>
        + Clone
        + GetElGamalParam<Self::JubJub, Self::EdwardsVar, ConstraintF>;
    type ElGamalPublicKeyVar: AllocVar<Self::ElGamalPubKey, ConstraintF>
        + Clone
        + GetPubKey<Self::JubJub, Self::EdwardsVar, ConstraintF>;
    type ElGamalRandomnessVar: AllocVar<Self::ElGamalRandomness, ConstraintF> + Clone;
    type ElGamalPlaintextVar: AllocVar<Self::ElGamalPlaintext, ConstraintF> + Clone;
    type ElGamalCiphertextVar: AllocVar<Self::ElGamalCiphertext, ConstraintF> + Clone;
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
}

impl ElGamalLocalOrMPC<hbc::MpcField<Fr>> for hbc::MpcField<Fr> {
    type JubJub = hbc::MpcEdwardsProjective;

    type ElGamalScheme = ElGamal<hbc::MpcEdwardsProjective>;
    type ElGamalParam = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::Parameters;
    type ElGamalPubKey = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::PublicKey;
    type ElGamalSecretKey = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::SecretKey;
    type ElGamalRandomness = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::Randomness;
    type ElGamalPlaintext = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::Plaintext;
    type ElGamalCiphertext = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::Ciphertext;

    type EdwardsVar = hbc::MpcEdwardsVar;

    type ElGamalGadget = ElGamalEncGadget<hbc::MpcEdwardsProjective, hbc::MpcEdwardsVar>;
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
}

impl ElGamalLocalOrMPC<mm::MpcField<Fr>> for mm::MpcField<Fr> {
    type JubJub = mm::MpcEdwardsProjective;

    type ElGamalScheme = ElGamal<mm::MpcEdwardsProjective>;
    type ElGamalParam = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::Parameters;
    type ElGamalPubKey = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::PublicKey;
    type ElGamalSecretKey = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::SecretKey;
    type ElGamalRandomness = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::Randomness;
    type ElGamalPlaintext = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::Plaintext;
    type ElGamalCiphertext = <Self::ElGamalScheme as AsymmetricEncryptionScheme>::Ciphertext;

    type EdwardsVar = mm::MpcEdwardsVar;

    type ElGamalGadget = ElGamalEncGadget<mm::MpcEdwardsProjective, mm::MpcEdwardsVar>;
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
}

pub trait GetPubKey<C: ProjectiveCurve, GG: CurveVar<C, ConstraintF>, ConstraintF: Field> {
    fn pk(&self) -> GG;
}

impl GetPubKey<<Fr as LocalOrMPC<Fr>>::JubJub, EdwardsVar, Fr>
    for <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalPublicKeyVar
{
    fn pk(&self) -> EdwardsVar {
        self.pk.clone()
    }
}

impl
    GetPubKey<
        <hbc::MpcField<Fr> as LocalOrMPC<hbc::MpcField<Fr>>>::JubJub,
        hbc::MpcEdwardsVar,
        hbc::MpcField<Fr>,
    > for <hbc::MpcField<Fr> as ElGamalLocalOrMPC<hbc::MpcField<Fr>>>::ElGamalPublicKeyVar
{
    fn pk(&self) -> hbc::MpcEdwardsVar {
        self.pk.clone()
    }
}

impl
    GetPubKey<
        <mm::MpcField<Fr> as LocalOrMPC<mm::MpcField<Fr>>>::JubJub,
        mm::MpcEdwardsVar,
        mm::MpcField<Fr>,
    > for <mm::MpcField<Fr> as ElGamalLocalOrMPC<mm::MpcField<Fr>>>::ElGamalPublicKeyVar
{
    fn pk(&self) -> mm::MpcEdwardsVar {
        self.pk.clone()
    }
}

pub trait GetElGamalParam<C: ProjectiveCurve, GG: CurveVar<C, ConstraintF>, ConstraintF: Field> {
    fn generator(&self) -> GG;
}

impl GetElGamalParam<<Fr as LocalOrMPC<Fr>>::JubJub, EdwardsVar, Fr>
    for <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalParamVar
{
    fn generator(&self) -> EdwardsVar {
        self.generator.clone()
    }
}

impl
    GetElGamalParam<
        <hbc::MpcField<Fr> as LocalOrMPC<hbc::MpcField<Fr>>>::JubJub,
        hbc::MpcEdwardsVar,
        hbc::MpcField<Fr>,
    > for <hbc::MpcField<Fr> as ElGamalLocalOrMPC<hbc::MpcField<Fr>>>::ElGamalParamVar
{
    fn generator(&self) -> hbc::MpcEdwardsVar {
        self.generator.clone()
    }
}

impl
    GetElGamalParam<
        <mm::MpcField<Fr> as LocalOrMPC<mm::MpcField<Fr>>>::JubJub,
        mm::MpcEdwardsVar,
        mm::MpcField<Fr>,
    > for <mm::MpcField<Fr> as ElGamalLocalOrMPC<mm::MpcField<Fr>>>::ElGamalParamVar
{
    fn generator(&self) -> mm::MpcEdwardsVar {
        self.generator.clone()
    }
}
