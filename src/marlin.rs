use ark_crypto_primitives::CommitmentScheme;
use ark_ec::twisted_edwards_extended::GroupAffine;
use ark_ff::{BigInteger, PrimeField};
use ark_marlin::{ahp::prover::*, *};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_std::{end_timer, start_timer, test_rng, PubUniformRand, UniformRand};

use blake2::Blake2s;
// use mpc_algebra::honest_but_curious::*;
use mpc_algebra::malicious_majority::*;
use mpc_algebra::{FromLocal, Reveal};
use mpc_net::{MpcMultiNet, MpcNet};
use num_traits::One;

use crate::{
    circuits::{circuit::MyCircuit, LocalOrMPC, PedersenComCircuit},
    input::{MpcInputTrait, SampleMpcInput},
};

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
pub type MFr = MpcField<Fr>;

type E = ark_bls12_377::Bls12_377;
type ME = MpcPairingEngine<ark_bls12_377::Bls12_377>;

type LocalMarlinKZG10 = MarlinKZG10<E, DensePolynomial<Fr>>;
type MpcMarlinKZG10 = MarlinKZG10<ME, DensePolynomial<MFr>>;

pub type LocalMarlin = Marlin<Fr, LocalMarlinKZG10, Blake2s>;
pub type MpcMarlin = Marlin<MFr, MpcMarlinKZG10, Blake2s>;

pub fn mpc_test_prove_and_verify(n_iters: usize) {
    let rng = &mut test_rng();

    let srs = LocalMarlin::universal_setup(10000, 50, 100, rng).unwrap();

    let local_input = SampleMpcInput::<Fr>::rand(rng);

    let local_circuit = MyCircuit {
        mpc_input: local_input,
    };

    let (index_pk, index_vk) = LocalMarlin::index(&srs, local_circuit).unwrap();
    let mpc_index_pk = IndexProverKey::from_public(index_pk);

    for _ in 0..n_iters {
        // Pedersen commitment
        //// commom parameter

        let mut mpc_input: SampleMpcInput<MFr> = SampleMpcInput::init();

        mpc_input.set_public_input(rng, None);
        mpc_input.set_private_input(Some((Fr::rand(rng), Fr::rand(rng))));
        mpc_input.generate_input(rng);

        let mpc_circuit = MyCircuit {
            mpc_input: mpc_input.clone(),
        };
        let c = mpc_input.clone().peculiar.unwrap().a.input
            * mpc_input.clone().peculiar.unwrap().b.input;
        let mut inputs = vec![c.reveal()];

        let peculiar_a_commitment: MpcEdwardsAffine =
            mpc_input.peculiar.clone().unwrap().a.commitment;
        let peculiar_b_commitment: MpcEdwardsAffine = mpc_input.peculiar.unwrap().b.commitment;

        inputs.push(peculiar_a_commitment.x.reveal());
        inputs.push(peculiar_a_commitment.y.reveal());
        inputs.push(peculiar_b_commitment.x.reveal());
        inputs.push(peculiar_b_commitment.y.reveal());

        // then, inputs is like [c, h_x_1.x, h_x_1.y, h_x_2.x, h_x_2.y, ...]

        let mpc_proof = MpcMarlin::prove(&mpc_index_pk, mpc_circuit, rng).unwrap();
        let proof = pf_publicize(mpc_proof);
        // let public_a = a.reveal();
        let is_valid = LocalMarlin::verify(&index_vk, &inputs, &proof, rng).unwrap();
        assert!(is_valid);
        let is_valid = LocalMarlin::verify(&index_vk, &[c.reveal()], &proof, rng).unwrap();
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
    let input_bit = x
        .into_repr()
        .to_bits_le()
        .iter()
        .map(|b| Fr::from(*b))
        .collect::<Vec<_>>();
    let x_bytes = x.into_repr().to_bytes_le();

    //// randomness
    let randomness = <Fr as LocalOrMPC<Fr>>::PedersenRandomness::pub_rand(rng);

    let open_bit = randomness
        .0
        .into_repr()
        .to_bits_le()
        .iter()
        .map(|b| Fr::from(*b))
        .collect::<Vec<_>>();

    //// commitment
    let h_x_local =
        <Fr as LocalOrMPC<Fr>>::PedersenComScheme::commit(&params, &x_bytes, &randomness).unwrap();

    let empty_circuit = PedersenComCircuit {
        param: Some(params.clone()),
        input: x,
        input_bit,
        open_bit,
        commit: Some(h_x_local),
    };

    let (index_pk, index_vk) = LocalMarlin::index(&srs, empty_circuit).unwrap();
    let mpc_index_pk = IndexProverKey::from_public(index_pk);

    for _ in 0..n_iters {
        // Pedersen commitment
        //// commom parameter
        let mpc_params = <MFr as LocalOrMPC<MFr>>::PedersenParam::from_local(&params);

        //// input
        let x = MFr::rand(rng);
        let input_bit = match MpcMultiNet::party_id() {
            0 => x
                .clone()
                .reveal()
                .into_repr()
                .to_bits_le()
                .iter()
                .map(|b| MFr::from_add_shared(Fr::from(*b)))
                .collect::<Vec<_>>(),
            _ => x
                .clone()
                .reveal()
                .into_repr()
                .to_bits_le()
                .iter()
                .map(|_b| MFr::from_add_shared(Fr::from(false)))
                .collect::<Vec<_>>(),
        };

        //// randomness
        let randomness = <MFr as LocalOrMPC<MFr>>::PedersenRandomness::pub_rand(rng);

        let open_bit = randomness
            .0
            .into_repr()
            .to_bits_le()
            .iter()
            .map(|b| MFr::from(*b))
            .collect::<Vec<_>>();

        //// commitment
        let h_x = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::commit(
            &params,
            &x.clone().reveal().into_repr().to_bytes_le(),
            &randomness.clone().reveal(),
        )
        .unwrap();

        let h_x_mpc = GroupAffine::<MpcEdwardsParameters>::new(
            MFr::from_public(h_x.x),
            MFr::from_public(h_x.y),
        );

        let circuit = PedersenComCircuit {
            param: Some(mpc_params.clone()),
            input: x,
            input_bit,
            open_bit,
            commit: Some(h_x_mpc),
        };

        // inputs
        let inputs = vec![h_x_mpc.x.reveal(), h_x_mpc.y.reveal()];
        let invalid_inputs = vec![h_x_mpc.y.reveal(), h_x_mpc.x.reveal()];

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
