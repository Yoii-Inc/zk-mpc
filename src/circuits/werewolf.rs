use ark_bls12_377::Fr;
use ark_crypto_primitives::encryption::elgamal::{constraints::ElGamalEncGadget, ElGamal};
use ark_crypto_primitives::encryption::*;
use ark_ec::AffineCurve;
use ark_ec::ProjectiveCurve;
use ark_ed_on_bls12_377::constraints::EdwardsVar;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};
use ark_std::One;

use mpc_algebra::{AdditiveFieldShare, MpcEdwardsProjective, MpcEdwardsVar, MpcField};

type MFr = MpcField<Fr, AdditiveFieldShare<Fr>>;

#[derive(Clone)]
pub struct KeyPublicizeCircuit<F: PrimeField> {
    pub pub_key_or_dummy_x: Vec<F>,
    pub pub_key_or_dummy_y: Vec<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for KeyPublicizeCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let x_var = self
            .pub_key_or_dummy_x
            .iter()
            .map(|x| cs.new_witness_variable(|| Ok(*x)).unwrap())
            .collect::<Vec<_>>();

        let y_var = self
            .pub_key_or_dummy_y
            .iter()
            .map(|y| cs.new_witness_variable(|| Ok(*y)).unwrap())
            .collect::<Vec<_>>();

        let input_x_var = cs.new_input_variable(|| {
            let vec = self.pub_key_or_dummy_x.clone();
            let pk = vec.iter().sum();
            Ok(pk)
        })?;

        let input_y_var = cs.new_input_variable(|| {
            let vec = self.pub_key_or_dummy_y.clone();
            let pk = vec.iter().sum();
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

        println!("total number of constraints: {}", cs.num_constraints());

        Ok(())
    }
}

#[derive(Clone)]
pub struct DivinationCircuit<F: PrimeField> {
    pub is_werewolf: Option<Vec<F>>,
    pub target_player_id: Option<usize>,

    // elgamal encryption data
    pub param: ElGamalParam,
    pub pub_key: ElGamalPubKey,
    pub randomness: ElGamalRandomness,
    pub output: ElGamalCiphertext,
}

// Constraint Implementation for Local Field
impl ConstraintSynthesizer<Fr> for DivinationCircuit<Fr> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let _is_werewolf = self
            .is_werewolf
            .clone()
            .ok_or(SynthesisError::AssignmentMissing)?
            .iter()
            .map(|x| cs.new_witness_variable(|| Ok(*x)))
            .collect::<Result<Vec<_>, _>>()?;

        let _target_player_id =
            cs.new_witness_variable(|| Ok(Fr::from(self.target_player_id.unwrap() as u32)))?;
        let is_target_werewolf =
            ElGamalPlaintextVar::new_witness(ark_relations::ns!(cs, "gadget_randomness"), || {
                let target = self
                    .target_player_id
                    .ok_or(SynthesisError::AssignmentMissing)?;

                let is_werewolf =
                    self.is_werewolf.ok_or(SynthesisError::AssignmentMissing)?[target];

                match is_werewolf.is_one() {
                    true => Ok(ElGamalPlaintext::prime_subgroup_generator()),
                    false => Ok(ElGamalPlaintext::default()),
                }
            })?;

        // elgamal encryption

        let param_var =
            ElGamalParamVar::new_input(ark_relations::ns!(cs, "gadget_parameters"), || {
                Ok(self.param)
            })?;

        // allocate randomness
        let randomness_var =
            ElGamalRandomnessVar::new_witness(ark_relations::ns!(cs, "gadget_randomness"), || {
                Ok(self.randomness)
            })?;

        // allocate public key
        let pub_key_var =
            ElGamalPublicKeyVar::new_input(ark_relations::ns!(cs, "gadget_public_key"), || {
                Ok(self.pub_key)
            })?;

        // allocate the output
        let enc_result_var = ElGamalGadget::encrypt(
            &param_var,
            &is_target_werewolf,
            &randomness_var,
            &pub_key_var,
        )?;

        // compare
        let enc_result_var2 =
            ElGamalOutputVar::new_input(ark_relations::ns!(cs, "gadget_commitment"), || {
                Ok(self.output)
            })?;

        enc_result_var.enforce_equal(&enc_result_var2)?;

        println!("total number of constraints: {}", cs.num_constraints());

        Ok(())
    }
}

pub type ElGamalScheme = ElGamal<ark_ed_on_bls12_377::EdwardsProjective>;

type ElGamalParam = <ElGamalScheme as AsymmetricEncryptionScheme>::Parameters;
pub type ElGamalPubKey = <ElGamalScheme as AsymmetricEncryptionScheme>::PublicKey;
pub type ElGamalRandomness = <ElGamalScheme as AsymmetricEncryptionScheme>::Randomness;
pub type ElGamalPlaintext = <ElGamalScheme as AsymmetricEncryptionScheme>::Plaintext;
type ElGamalCiphertext = <ElGamalScheme as AsymmetricEncryptionScheme>::Ciphertext;

type ElGamalGadget = ElGamalEncGadget<ark_ed_on_bls12_377::EdwardsProjective, EdwardsVar>;
type ElGamalParamVar =
    <ElGamalGadget as AsymmetricEncryptionGadget<ElGamalScheme, ark_bls12_377::Fr>>::ParametersVar;
type ElGamalRandomnessVar =
    <ElGamalGadget as AsymmetricEncryptionGadget<ElGamalScheme, ark_bls12_377::Fr>>::RandomnessVar;
type ElGamalPublicKeyVar =
    <ElGamalGadget as AsymmetricEncryptionGadget<ElGamalScheme, ark_bls12_377::Fr>>::PublicKeyVar;

type ElGamalPlaintextVar =
    <ElGamalGadget as AsymmetricEncryptionGadget<ElGamalScheme, ark_bls12_377::Fr>>::PlaintextVar;
type ElGamalOutputVar =
    <ElGamalGadget as AsymmetricEncryptionGadget<ElGamalScheme, ark_bls12_377::Fr>>::OutputVar;
