use ark_ff::Field;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

use ark_bls12_377::{Bls12_377, Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;

use ark_std::ops::*;
use ark_std::UniformRand;

use crate::she::{Ciphertext, SecretKey};

#[derive(Clone)]
pub struct MySecretInputCircuit<F: Field> {
    // private witness to the circuit
    x: Option<F>,
    r: Option<F>,

    // public instance to the circuit
    e_r: Option<Ciphertext>,
    epsilon: Option<F>,
    // TODO: implement Correct h_x
    h_x: Option<F>,
}

impl<F> MySecretInputCircuit<F>
where
    F: Field,
{
    fn verify_encryption(&self) {}

    fn verify_epsilon(&self) {}

    fn verify_constraints(&self) {}

    fn verify_commitment(&self) {}
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for MySecretInputCircuit<ConstraintF> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // 1st
        self.verify_encryption();

        // 2nd
        self.verify_epsilon();

        // 3rd
        self.verify_constraints();

        // 4th
        self.verify_commitment();

        Ok(())
    }
}

#[test]
fn test_no_circom() {
    let mut rng = rand::thread_rng();

    // generate the setup parameters
    let (circuit_pk, circuit_vk) = Groth16::<Bls12_377>::circuit_specific_setup(
        MySecretInputCircuit::<Fr> {
            x: None,
            r: None,
            e_r: None,
            epsilon: None,
            h_x: None,
        },
        &mut rng,
    )
    .unwrap();

    // setup SHE parameters
    let std_dev = 3.2;
    let p = 41;
    let q: i128 = 7427466391;
    let degree = 10;

    let secret_key = SecretKey::generate(degree, q, std_dev, &mut rng);
    let public_key = secret_key.public_key_gen(degree, p, q, std_dev, &mut rng);

    // generate random inputs
    let a = Fr::rand(&mut rng);
    let b = Fr::rand(&mut rng);
    let mut c = a;
    c.mul_assign(&b);

    let x = Fr::rand(&mut rng);
    let r = Fr::rand(&mut rng);
    let e_r = Ciphertext::rand(&public_key, degree, q, &mut rng);
    let epsilon = Fr::rand(&mut rng);
    // TODO: implement correct h_x
    let h_x = Fr::rand(&mut rng);

    // calculate the proof by passing witness variable value
    let proof = Groth16::<Bls12_377>::prove(
        &circuit_pk,
        MySecretInputCircuit::<Fr> {
            x: Some(x),
            r: Some(r),
            e_r: Some(e_r),
            epsilon: Some(epsilon),
            h_x: Some(h_x),
        },
        &mut rng,
    )
    .unwrap();

    // validate the proof
    assert!(Groth16::<Bls12_377>::verify(&circuit_vk, &[], &proof).unwrap());
}
