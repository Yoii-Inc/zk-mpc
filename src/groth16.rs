//! # Groth16: zk-SNARKs
//!
//! This module provides functions for setting up, proving, and verifying MPC (Multi-Party Computation) circuits using the Groth16 zkSNARK.

use std::ops::{AddAssign, Deref};

use ark_ec::ProjectiveCurve;
use ark_ec::{AffineCurve, PairingEngine};
use ark_ff::{One, PrimeField, UniformRand, Zero};
use ark_groth16::{
    generate_random_parameters, prepare_verifying_key, verify_proof, Proof, ProvingKey,
};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal,
    Result as R1CSResult, SynthesisError,
};
use ark_std::{cfg_iter, cfg_iter_mut, end_timer, start_timer, test_rng};
// use log::debug;
use mpc_algebra::{MpcField, MpcPairingEngine, PairingShare, Reveal};
use rand::Rng;

use crate::circuits::circuit::MySimpleCircuit;

/// Create a Groth16 proof that is zero-knowledge.
/// This method samples randomness for zero knowledges via `rng`.
#[inline]
pub fn create_random_proof<E, C, R>(
    circuit: C,
    pk: &ProvingKey<E>,
    rng: &mut R,
) -> R1CSResult<Proof<E>>
where
    E: PairingEngine,
    //E::Fr: BatchProd,
    C: ConstraintSynthesizer<<E as PairingEngine>::Fr>,
    R: Rng,
{
    //use ark_ff::One;
    //let r = <E as PairingEngine>::Fr::one();
    //let s = <E as PairingEngine>::Fr::one();
    let t = start_timer!(|| "zk sampling");
    let r = <E as PairingEngine>::Fr::rand(rng);
    let s = <E as PairingEngine>::Fr::rand(rng);
    end_timer!(t);

    create_proof::<E, C>(circuit, pk, r, s)
}

/// Create a Groth16 proof that is *not* zero-knowledge.
#[inline]
pub fn create_proof_no_zk<E, C>(circuit: C, pk: &ProvingKey<E>) -> R1CSResult<Proof<E>>
where
    E: PairingEngine,
    //E::Fr: BatchProd,
    C: ConstraintSynthesizer<<E as PairingEngine>::Fr>,
{
    create_proof::<E, C>(
        circuit,
        pk,
        <E as PairingEngine>::Fr::zero(),
        <E as PairingEngine>::Fr::zero(),
    )
}

/// Create a Groth16 proof using randomness `r` and `s`.
#[inline]
pub fn create_proof<E, C>(
    circuit: C,
    pk: &ProvingKey<E>,
    r: <E as PairingEngine>::Fr,
    s: <E as PairingEngine>::Fr,
) -> R1CSResult<Proof<E>>
where
    E: PairingEngine,
    //E::Fr: BatchProd,
    C: ConstraintSynthesizer<<E as PairingEngine>::Fr>,
{
    println!("r: {}", r);
    println!("s: {}", s);
    type D<F> = GeneralEvaluationDomain<F>;

    let prover_time = start_timer!(|| "Groth16::Prover");
    let cs = ConstraintSystem::new_ref();

    // Set the optimization goal
    cs.set_optimization_goal(OptimizationGoal::Constraints);

    // Synthesize the circuit.
    let synthesis_time = start_timer!(|| "Constraint synthesis");
    circuit.generate_constraints(cs.clone())?;
    //debug_assert!(cs.is_satisfied().unwrap());
    end_timer!(synthesis_time);

    let lc_time = start_timer!(|| "Inlining LCs");
    cs.finalize();
    end_timer!(lc_time);

    let witness_map_time = start_timer!(|| "R1CS to QAP witness map");
    let h = R1CStoQAP::witness_map::<<E as PairingEngine>::Fr, D<<E as PairingEngine>::Fr>>(
        cs.clone(),
    )?;
    end_timer!(witness_map_time);
    let prover_crypto_time = start_timer!(|| "crypto");
    let c_acc_time = start_timer!(|| "Compute C");
    let h_acc = <<E as PairingEngine>::G1Affine as AffineCurve>::multi_scalar_mul(&pk.h_query, &h);
    println!("h_acc: {}", h_acc);
    // Compute C
    let prover = cs.borrow().unwrap();
    let l_aux_acc = <<E as PairingEngine>::G1Affine as AffineCurve>::multi_scalar_mul(
        &pk.l_query,
        &prover.witness_assignment,
    );

    let r_s_delta_g1 = pk.delta_g1.into_projective().scalar_mul(&r).scalar_mul(&s);
    println!("r_s_delta_g1: {}", r_s_delta_g1);

    end_timer!(c_acc_time);

    let assignment: Vec<<E as PairingEngine>::Fr> = prover.instance_assignment[1..]
        .iter()
        .chain(prover.witness_assignment.iter())
        .cloned()
        .collect();
    drop(prover);
    drop(cs);

    // Compute A
    let a_acc_time = start_timer!(|| "Compute A");
    let r_g1 = pk.delta_g1.scalar_mul(r);
    println!("r_g1: {}", r_g1);
    // debug!("Assignment:");
    // for (i, a) in assignment.iter().enumerate() {
    //     debug!("  a[{}]: {}", i, a);
    // }

    let g_a = calculate_coeff(r_g1, &pk.a_query, pk.vk.alpha_g1, &assignment);
    println!("g_a: {}", g_a);

    let s_g_a = g_a.scalar_mul(&s);
    println!("s_g_a: {}", s_g_a);
    end_timer!(a_acc_time);

    // Compute B in G1 if needed
    //    let g1_b = if !r.is_zero() {
    let b_g1_acc_time = start_timer!(|| "Compute B in G1");
    let s_g1 = pk.delta_g1.scalar_mul(s);
    let g1_b = calculate_coeff(s_g1, &pk.b_g1_query, pk.beta_g1, &assignment);

    end_timer!(b_g1_acc_time);
    //
    //        g1_b
    //    } else {
    //        <E as PairingEngine>::G1Projective::zero()
    //    };

    // Compute B in G2
    let b_g2_acc_time = start_timer!(|| "Compute B in G2");
    let s_g2 = pk.vk.delta_g2.scalar_mul(s);
    let g2_b = calculate_coeff(s_g2, &pk.b_g2_query, pk.vk.beta_g2, &assignment);
    let r_g1_b = g1_b.scalar_mul(&r);
    println!("r_g1_b: {}", r_g1_b);
    drop(assignment);

    end_timer!(b_g2_acc_time);

    let c_time = start_timer!(|| "Finish C");
    let mut g_c = s_g_a;
    g_c += &r_g1_b;
    g_c -= &r_s_delta_g1;
    g_c += &l_aux_acc;
    g_c += &h_acc;
    end_timer!(c_time);
    end_timer!(prover_crypto_time);

    end_timer!(prover_time);

    Ok(Proof {
        a: g_a.into_affine(),
        b: g2_b.into_affine(),
        c: g_c.into_affine(),
    })
}

fn calculate_coeff<G: AffineCurve>(
    initial: G::Projective,
    query: &[G],
    vk_param: G,
    assignment: &[G::ScalarField],
) -> G::Projective where {
    let el = query[0];
    let t = start_timer!(|| format!("MSM size {} {}", query.len() - 1, assignment.len()));
    let acc = G::multi_scalar_mul(&query[1..], assignment);
    end_timer!(t);
    let mut res = initial;
    res.add_assign_mixed(&el);
    res += &acc;
    res.add_assign_mixed(&vk_param);

    res
}

/// r1cs to qap
#[inline]
fn evaluate_constraint<'a, LHS, RHS, R>(terms: &'a [(LHS, usize)], assignment: &'a [RHS]) -> R
where
    LHS: One + Send + Sync + PartialEq,
    RHS: Send + Sync + core::ops::Mul<&'a LHS, Output = RHS> + Copy,
    R: Zero + Send + Sync + AddAssign<RHS> + core::iter::Sum,
{
    // Need to wrap in a closure when using Rayon
    #[cfg(feature = "parallel")]
    let zero = || R::zero();
    #[cfg(not(feature = "parallel"))]
    let zero = R::zero();

    let res = cfg_iter!(terms).fold(zero, |mut sum, (coeff, index)| {
        let val = &assignment[*index];

        if coeff.is_one() {
            sum += *val;
        } else {
            sum += val.mul(coeff);
        }

        sum
    });

    // Need to explicitly call `.sum()` when using Rayon
    #[cfg(feature = "parallel")]
    return res.sum();
    #[cfg(not(feature = "parallel"))]
    return res;
}

pub struct R1CStoQAP;

impl R1CStoQAP {
    #[inline]
    pub fn witness_map<F: PrimeField, D: EvaluationDomain<F>>(
        prover: ConstraintSystemRef<F>,
    ) -> R1CSResult<Vec<F>> {
        let matrices = prover.to_matrices().unwrap();
        let zero = F::zero();
        let num_inputs = prover.num_instance_variables();
        let num_constraints = prover.num_constraints();
        let cs = prover.borrow().unwrap();
        let prover = cs.deref();

        let full_assignment = [
            prover.instance_assignment.as_slice(),
            prover.witness_assignment.as_slice(),
        ]
        .concat();

        let domain =
            D::new(num_constraints + num_inputs).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_size = domain.size();

        let mut a = vec![zero; domain_size];
        let mut b = vec![zero; domain_size];

        cfg_iter_mut!(a[..num_constraints])
            .zip(cfg_iter_mut!(b[..num_constraints]))
            .zip(cfg_iter!(&matrices.a))
            .zip(cfg_iter!(&matrices.b))
            .for_each(|(((a, b), at_i), bt_i)| {
                *a = evaluate_constraint(&at_i, &full_assignment);
                *b = evaluate_constraint(&bt_i, &full_assignment);
            });

        {
            let start = num_constraints;
            let end = start + num_inputs;
            a[start..end].clone_from_slice(&full_assignment[..num_inputs]);
        }

        domain.ifft_in_place(&mut a);
        domain.ifft_in_place(&mut b);

        domain.coset_fft_in_place(&mut a);
        domain.coset_fft_in_place(&mut b);
        let mut ab = a.clone();
        let batch_product_timer = start_timer!(|| "batch product");
        F::batch_product_in_place(&mut ab, &b);
        end_timer!(batch_product_timer);

        let mut c = vec![zero; domain_size];
        cfg_iter_mut!(c[..prover.num_constraints])
            .enumerate()
            .for_each(|(i, c)| {
                *c = evaluate_constraint(&matrices.c[i], &full_assignment);
            });

        domain.ifft_in_place(&mut c);
        domain.coset_fft_in_place(&mut c);

        cfg_iter_mut!(ab)
            .zip(c)
            .for_each(|(ab_i, c_i)| *ab_i -= &c_i);

        domain.divide_by_vanishing_poly_on_coset_in_place(&mut ab);
        domain.coset_ifft_in_place(&mut ab);

        Ok(ab)
    }
}

pub async fn mpc_test_prove_and_verify<E: PairingEngine, S: PairingShare<E>>(n_iters: usize) {
    let rng = &mut test_rng();

    let params =
        generate_random_parameters::<E, _, _>(MySimpleCircuit { a: None, b: None }, rng).unwrap();

    let pvk = prepare_verifying_key::<E>(&params.vk);
    let mpc_params: ProvingKey<MpcPairingEngine<E, S>> = ProvingKey::from_public(params);

    for _ in 0..n_iters {
        let a = MpcField::<E::Fr, S::FrShare>::rand(rng);
        let b = MpcField::<E::Fr, S::FrShare>::rand(rng);

        let mut c = a;
        c *= &b;

        let mpc_circuit = MySimpleCircuit {
            a: Some(a),
            b: Some(b),
        };

        let mpc_proof = create_random_proof(mpc_circuit, &mpc_params, rng).unwrap();

        let proof = mpc_proof.reveal().await;
        let pub_a = a.reveal().await;
        let pub_c = c.reveal().await;

        assert!(verify_proof(&pvk, &proof, &[pub_c]).unwrap());
        assert!(!verify_proof(&pvk, &proof, &[pub_a]).unwrap());
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_377::{Bls12_377, Fr};
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    use ark_std::UniformRand;

    use mpc_net::LocalTestNet;

    use super::super::circuits::circuit::MySimpleCircuit;

    use super::*;

    #[test]
    fn test_single() {
        let mut rng = rand::thread_rng();

        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);

        let mut c = a;
        c *= b;

        let circuit = MySimpleCircuit::<Fr> {
            a: Some(a),
            b: Some(b),
        };

        let (circuit_pk, circuit_vk) =
            Groth16::<Bls12_377>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();

        let proof = Groth16::<Bls12_377>::prove(&circuit_pk, circuit.clone(), &mut rng).unwrap();

        assert!(Groth16::<Bls12_377>::verify(&circuit_vk, &[c], &proof).unwrap());
        assert!(!Groth16::<Bls12_377>::verify(&circuit_vk, &[a], &proof).unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_multi() {
        const N_PARTIES: usize = 3;
        let testnet = LocalTestNet::new_local_testnet(N_PARTIES).await.unwrap();

        testnet
            .simulate_network_round((), |_, _| async move {
                mpc_test_prove_and_verify::<
                    ark_bls12_377::Bls12_377,
                    mpc_algebra::AdditivePairingShare<ark_bls12_377::Bls12_377>,
                >(1)
                .await
            })
            .await;
    }
}
