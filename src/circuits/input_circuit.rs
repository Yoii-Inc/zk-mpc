use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use std::cmp::Ordering;

use super::{LocalOrMPC, PedersenComCircuit};

#[derive(Clone)]
pub struct MySecretInputCircuit<F: PrimeField + LocalOrMPC<F>> {
    // private witness to the circuit
    x: Option<F>,
    open: Option<F::PedersenRandomness>,
    params: Option<F::PedersenParam>,

    // public instance to the circuit
    h_x: Option<F::PedersenCommitment>,
    lower_bound: Option<F>,
    upper_bound: Option<F>,
}

impl<F: PrimeField + LocalOrMPC<F>> MySecretInputCircuit<F> {
    pub fn new(
        x: F,
        open: F::PedersenRandomness,
        params: F::PedersenParam,
        h_x: F::PedersenCommitment,
        lower_bound: F,
        upper_bound: F,
    ) -> Self {
        Self {
            x: Some(x),
            open: Some(open),
            params: Some(params),
            h_x: Some(h_x),
            lower_bound: Some(lower_bound),
            upper_bound: Some(upper_bound),
        }
    }

    fn verify_constraints(&self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let x = FpVar::new_witness(cs.clone(), || {
            self.x.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let lower_bound = FpVar::new_input(cs.clone(), || {
            self.lower_bound.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let upper_bound = FpVar::new_input(cs.clone(), || {
            self.upper_bound.ok_or(SynthesisError::AssignmentMissing)
        })?;

        x.enforce_cmp(&lower_bound, Ordering::Greater, true)?;
        x.enforce_cmp(&upper_bound, Ordering::Less, false)?;

        Ok(())
    }

    fn verify_commitment(&self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let x_com_circuit = PedersenComCircuit {
            param: self.params.clone(),
            input: self.x.unwrap(),
            open: self.open.clone().unwrap(),
            commit: self.h_x.clone().unwrap(),
        };

        x_com_circuit.generate_constraints(cs.clone())?;

        Ok(())
    }
}

impl<F: PrimeField + LocalOrMPC<F>> ConstraintSynthesizer<F> for MySecretInputCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        self.verify_constraints(cs.clone())?;

        self.verify_commitment(cs.clone())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_377::Bls12_377;
    use ark_crypto_primitives::CommitmentScheme;
    use ark_ff::{BigInteger, PrimeField};
    use ark_groth16::Groth16;
    use ark_marlin::*;
    use ark_poly::univariate::DensePolynomial;
    use ark_poly_commit::marlin_pc::MarlinKZG10;
    use ark_snark::SNARK;
    use ark_std::UniformRand;
    use blake2::Blake2s;

    type PedersenComScheme = <Fr as LocalOrMPC<Fr>>::PedersenComScheme;
    type PedersenRandomness = <Fr as LocalOrMPC<Fr>>::PedersenRandomness;

    use super::*;

    #[test]
    fn test_groth16() {
        let mut rng = rand::thread_rng();

        // generate the setup parameters
        let x = Fr::from(4);

        let lower_bound = Fr::from(3);
        let upper_bound = Fr::from(7);

        // Pedersen commitment
        let params = PedersenComScheme::setup(&mut rng).unwrap();
        let randomness = PedersenRandomness::rand(&mut rng);

        let x_bytes = x.into_repr().to_bytes_le();
        let h_x = PedersenComScheme::commit(&params, &x_bytes, &randomness).unwrap();

        let circuit = MySecretInputCircuit {
            x: Some(x),
            open: Some(randomness),
            h_x: Some(h_x),
            lower_bound: Some(lower_bound),
            upper_bound: Some(upper_bound),
            params: Some(params),
        };

        let (circuit_pk, circuit_vk) =
            Groth16::<Bls12_377>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();

        // calculate the proof by passing witness variable value
        let proof = Groth16::<Bls12_377>::prove(&circuit_pk, circuit.clone(), &mut rng).unwrap();

        // validate the proof
        assert!(Groth16::<Bls12_377>::verify(
            &circuit_vk,
            &[lower_bound, upper_bound, h_x.x, h_x.y],
            &proof
        )
        .unwrap());

        // expected to fail
        assert!(!Groth16::<Bls12_377>::verify(
            &circuit_vk,
            &[lower_bound, upper_bound, h_x.y, h_x.x],
            &proof
        )
        .unwrap());
    }

    type Fr = ark_bls12_377::Fr;
    type E = ark_bls12_377::Bls12_377;

    type MarlinLocal = Marlin<Fr, MarlinKZG10<E, DensePolynomial<Fr>>, Blake2s>;

    #[test]
    fn test_marlin() {
        let mut rng = rand::thread_rng();

        let universal_srs = MarlinLocal::universal_setup(10000, 50, 100, &mut rng).unwrap();

        // generate the setup parameters
        let x = Fr::from(4);

        let lower_bound = Fr::from(3);
        let upper_bound = Fr::from(7);

        // Pedersen commitment
        let params = PedersenComScheme::setup(&mut rng).unwrap();
        let randomness = PedersenRandomness::rand(&mut rng);

        let x_bytes = x.into_repr().to_bytes_le();
        let h_x = PedersenComScheme::commit(&params, &x_bytes, &randomness).unwrap();

        let circuit = MySecretInputCircuit {
            x: Some(x),
            open: Some(randomness),
            h_x: Some(h_x),
            lower_bound: Some(lower_bound),
            upper_bound: Some(upper_bound),
            params: Some(params),
        };

        let (index_pk, index_vk) = MarlinLocal::index(&universal_srs, circuit.clone()).unwrap();
        println!("Called index");

        // calculate the proof by passing witness variable value
        let proof = MarlinLocal::prove(&index_pk, circuit.clone(), &mut rng).unwrap();
        println!("Called prover");

        assert!(MarlinLocal::verify(
            &index_vk,
            &[lower_bound, upper_bound, h_x.x, h_x.y],
            &proof,
            &mut rng
        )
        .unwrap());

        // expected to fail
        assert!(!MarlinLocal::verify(
            &index_vk,
            &[lower_bound, upper_bound, h_x.y, h_x.x],
            &proof,
            &mut rng
        )
        .unwrap());
    }
}
