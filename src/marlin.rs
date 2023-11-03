use ark_crypto_primitives::CommitmentScheme;
use ark_ff::{BigInteger, PrimeField};
use ark_marlin::{ahp::prover::*, *};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_std::{end_timer, start_timer, test_rng, PubUniformRand, UniformRand};
use blake2::Blake2s;
use mpc_algebra::*;

use crate::circuits::{circuit::MyCircuit, LocalOrMPC, PedersenComCircuit};

pub type MpcField<F> = wire::field::MpcField<F, AdditiveFieldShare<F>>;
// pub type MpcGroup<G> = group::MpcGroup<G, AdditiveGroupShare<G, NaiveMsm<G>>>;
// pub type MpcG1Affine<E> = wire::pairing::MpcG1Affine<E, AdditivePairingShare<E>>;
// pub type MpcG2Affine<E> = wire::pairing::MpcG2Affine<E, AdditivePairingShare<E>>;
// pub type MpcG1Projective<E> = wire::pairing::MpcG1Projective<E, AdditivePairingShare<E>>;
// pub type MpcG2Projective<E> = wire::pairing::MpcG2Projective<E, AdditivePairingShare<E>>;
// pub type MpcG1Prep<E> = wire::pairing::MpcG1Prep<E, AdditivePairingShare<E>>;
// pub type MpcG2Prep<E> = wire::pairing::MpcG2Prep<E, AdditivePairingShare<E>>;
pub type MpcPairingEngine<E> = wire::pairing::MpcPairingEngine<E, AdditivePairingShare<E>>;

fn prover_message_publicize(
    p: ProverMsg<MpcField<ark_bls12_377::Fr>>,
) -> ProverMsg<ark_bls12_377::Fr> {
    match p {
        ProverMsg::EmptyMessage => ProverMsg::EmptyMessage,
        ProverMsg::FieldElements(d) => {
            ProverMsg::FieldElements(d.into_iter().map(|e| e.reveal()).collect())
        }
    }
}

fn comm_publicize(
    pf: ark_poly_commit::marlin_pc::Commitment<ME>,
) -> ark_poly_commit::marlin_pc::Commitment<E> {
    ark_poly_commit::marlin_pc::Commitment {
        comm: commit_from_mpc(pf.comm),
        shifted_comm: pf.shifted_comm.map(commit_from_mpc),
    }
}

fn commit_from_mpc<'a>(
    p: ark_poly_commit::kzg10::Commitment<MpcPairingEngine<ark_bls12_377::Bls12_377>>,
) -> ark_poly_commit::kzg10::Commitment<ark_bls12_377::Bls12_377> {
    ark_poly_commit::kzg10::Commitment(p.0.reveal())
}
fn pf_from_mpc<'a>(
    pf: ark_poly_commit::kzg10::Proof<MpcPairingEngine<ark_bls12_377::Bls12_377>>,
) -> ark_poly_commit::kzg10::Proof<ark_bls12_377::Bls12_377> {
    ark_poly_commit::kzg10::Proof {
        w: pf.w.reveal(),
        random_v: pf.random_v.map(MpcField::reveal),
    }
}

fn batch_pf_publicize(
    pf: ark_poly_commit::BatchLCProof<MFr, DensePolynomial<MFr>, MpcMarlinKZG10>,
) -> ark_poly_commit::BatchLCProof<Fr, DensePolynomial<Fr>, LocalMarlinKZG10> {
    ark_poly_commit::BatchLCProof {
        proof: pf.proof.into_iter().map(pf_from_mpc).collect(),
        evals: pf
            .evals
            .map(|e| e.into_iter().map(MpcField::reveal).collect()),
    }
}

pub fn pf_publicize(
    k: Proof<MpcField<ark_bls12_377::Fr>, MpcMarlinKZG10>,
) -> Proof<ark_bls12_377::Fr, LocalMarlinKZG10> {
    let pf_timer = start_timer!(|| "publicize proof");
    let r = Proof::<ark_bls12_377::Fr, LocalMarlinKZG10> {
        commitments: k
            .commitments
            .into_iter()
            .map(|cs| cs.into_iter().map(comm_publicize).collect())
            .collect(),
        evaluations: k.evaluations.into_iter().map(|e| e.reveal()).collect(),
        prover_messages: k
            .prover_messages
            .into_iter()
            .map(prover_message_publicize)
            .collect(),
        pc_proof: batch_pf_publicize(k.pc_proof),
    };
    end_timer!(pf_timer);
    r
}

type Fr = ark_bls12_377::Fr;
type E = ark_bls12_377::Bls12_377;
type ME = MpcPairingEngine<ark_bls12_377::Bls12_377>;
type MFr = MpcField<Fr>;
type MpcMarlinKZG10 = MarlinKZG10<ME, DensePolynomial<MFr>>;
type LocalMarlinKZG10 = MarlinKZG10<E, DensePolynomial<Fr>>;
type LocalMarlin = Marlin<Fr, LocalMarlinKZG10, Blake2s>;
type MpcMarlin = Marlin<MFr, MpcMarlinKZG10, Blake2s>;

pub fn mpc_test_prove_and_verify(n_iters: usize) {
    let n = 2;

    let rng = &mut test_rng();

    let srs = LocalMarlin::universal_setup(10000, 50, 100, rng).unwrap();

    let params = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::setup(rng).unwrap();

    let vec_x = (0..n).map(|_| Fr::from(0)).collect::<Vec<_>>();

    let vec_x_bytes = vec_x
        .iter()
        .map(|x| x.into_repr().to_bytes_le())
        .collect::<Vec<_>>();

    let randomness = (0..n)
        .map(|_| <Fr as LocalOrMPC<Fr>>::PedersenRandomness::rand(rng))
        .collect::<Vec<_>>();

    let h_x_vec = (0..n)
        .map(|i| {
            <Fr as LocalOrMPC<Fr>>::PedersenComScheme::commit(
                &params,
                &vec_x_bytes[i],
                &randomness[i],
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    let empty_circuit: MyCircuit<Fr> = MyCircuit {
        a: None,
        b: None,
        params: Some(params.clone()),
        vec_x: Some(vec_x.clone()),
        randomness: Some(randomness.clone()),
        vec_h_x: Some(h_x_vec.clone()),
    };
    let (index_pk, index_vk) = LocalMarlin::index(&srs, empty_circuit).unwrap();
    let mpc_index_pk = IndexProverKey::from_public(index_pk);

    for _ in 0..n_iters {
        let a = MpcField::<ark_bls12_377::Fr>::from(2u8);
        let b = MpcField::<ark_bls12_377::Fr>::from(2u8);

        // Pedersen commitment
        //// commom parameter
        let mpc_params = params.to_mpc();

        //// input
        let x = (0..n).map(|_| MFr::pub_rand(rng)).collect::<Vec<_>>();
        let x_bytes = x
            .iter()
            .map(|x| x.into_repr().to_bytes_le())
            .collect::<Vec<_>>();

        //// randomness
        let randomness = (0..n)
            .map(|_| <MFr as LocalOrMPC<MFr>>::PedersenRandomness::pub_rand(rng))
            .collect::<Vec<_>>();

        //// commitment
        let h_x = x_bytes
            .iter()
            .zip(randomness.iter())
            .map(|(x_bytes, randomness)| {
                <MFr as LocalOrMPC<MFr>>::PedersenComScheme::commit(
                    &mpc_params,
                    &x_bytes,
                    &randomness,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let circ = MyCircuit {
            a: Some(a),
            b: Some(b),
            params: Some(mpc_params.clone()),
            vec_x: Some(x.clone()),
            randomness: Some(randomness.clone()),
            vec_h_x: Some(h_x.clone()),
        };
        let mut c = a;
        c *= &b;
        let mut inputs = vec![c.reveal()];

        for commitment in h_x {
            inputs.push(commitment.x.reveal());
            inputs.push(commitment.y.reveal());
        }

        // then, inputs is like [c, h_x_1.x, h_x_1.y, h_x_2.x, h_x_2.y, ...]

        println!("{a}\n{b}\n{c}");
        let mpc_proof = MpcMarlin::prove(&mpc_index_pk, circ, rng).unwrap();
        let proof = pf_publicize(mpc_proof);
        let public_a = a.reveal();
        let is_valid = LocalMarlin::verify(&index_vk, &inputs, &proof, rng).unwrap();
        assert!(is_valid);
        let is_valid = LocalMarlin::verify(&index_vk, &[public_a], &proof, rng).unwrap();
        assert!(!is_valid);
    }
}

pub fn mpc_test_prove_and_verify_pedersen(n_iters: usize) {
    // setup
    let rng = &mut test_rng();

    let srs = LocalMarlin::universal_setup(5000, 50, 100, rng).unwrap();

    // Pedersen commitment
    //// commom parameter
    let params = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::setup(rng).unwrap();

    //// input
    let x = Fr::from(4);
    let x_bytes = x.into_repr().to_bytes_le();

    //// randomness
    let randomness = <Fr as LocalOrMPC<Fr>>::PedersenRandomness::pub_rand(rng);

    //// commitment
    let h_x_local =
        <Fr as LocalOrMPC<Fr>>::PedersenComScheme::commit(&params, &x_bytes, &randomness).unwrap();

    let empty_circuit = PedersenComCircuit {
        param: Some(params.clone()),
        input: Some(x),
        open: Some(randomness.clone()),
        commit: Some(h_x_local),
    };

    let (index_pk, index_vk) = LocalMarlin::index(&srs, empty_circuit).unwrap();
    let mpc_index_pk = IndexProverKey::from_public(index_pk);

    for _ in 0..n_iters {
        // Pedersen commitment
        //// commom parameter
        let mpc_params = params.to_mpc();

        //// input
        let x = MFr::pub_rand(rng);
        let x_bytes = x.into_repr().to_bytes_le();

        //// randomness
        let randomness = <MFr as LocalOrMPC<MFr>>::PedersenRandomness::pub_rand(rng);

        //// commitment
        let h_x =
            <MFr as LocalOrMPC<MFr>>::PedersenComScheme::commit(&mpc_params, &x_bytes, &randomness)
                .unwrap();

        let circuit = PedersenComCircuit {
            param: Some(mpc_params.clone()),
            input: Some(x),
            open: Some(randomness.clone()),
            commit: Some(h_x),
        };

        let inputs = vec![h_x.x.reveal(), h_x.y.reveal()];
        let invalid_inputs = vec![h_x.y.reveal(), h_x.x.reveal()];

        // prove
        let mpc_proof = MpcMarlin::prove(&mpc_index_pk, circuit, rng).unwrap();
        let proof = pf_publicize(mpc_proof);

        // verify
        let is_valid = LocalMarlin::verify(&index_vk, &inputs, &proof, rng).unwrap();
        assert!(is_valid);
        let is_valid = LocalMarlin::verify(&index_vk, &invalid_inputs, &proof, rng).unwrap();
        assert!(!is_valid);
    }
}
