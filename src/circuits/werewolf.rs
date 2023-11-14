use ark_bls12_377::Fr;
use ark_crypto_primitives::encryption::elgamal::{constraints::ElGamalEncGadget, ElGamal};
use ark_crypto_primitives::encryption::*;
use ark_ec::AffineCurve;
use ark_ed_on_bls12_377::constraints::EdwardsVar;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::One;

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
        let is_werewolf = self
            .is_werewolf
            .clone()
            .ok_or(SynthesisError::AssignmentMissing)?
            .iter()
            .map(|x| cs.new_witness_variable(|| Ok(*x)))
            .collect::<Result<Vec<_>, _>>()?;

        let target_player_id =
            cs.new_witness_variable(|| Ok(Fr::from(self.target_player_id.unwrap() as u32)))?;
        let is_target_werewolf =
            ElGamalPlaintextVar::new_witness(ark_relations::ns!(cs, "gadget_randomness"), || {
                let generator = ElGamalPlaintext::prime_subgroup_generator();

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
type ElGamalPubKey = <ElGamalScheme as AsymmetricEncryptionScheme>::PublicKey;
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
