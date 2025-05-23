//! # Marlin: zk-SNARKs
//!
//! This module provides functions for setting up, proving, and verifying MPC (Multi-Party Computation) circuits using the Marlin zkSNARK.

use ark_ff::{BigInteger, PrimeField};
use ark_marlin::{ahp::prover::*, *};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_serialize::CanonicalSerialize;
use ark_std::{end_timer, start_timer, test_rng, PubUniformRand, UniformRand};
use futures::future::join_all;
use std::cmp::Ordering;
use std::io::Write;

use crate::field::*;
use blake2::Blake2s;
use itertools::Itertools;
use mpc_algebra::{BooleanWire, LessThan, UniformBitRand};
use mpc_algebra::{CommitmentScheme, FromLocal, Reveal};

use ark_std::{One, Zero};

use crate::circuits::enforce_smaller_or_eq_than::SmallerEqThanCircuit;
use crate::circuits::smaller_than::SmallerThanCircuit;
use crate::{
    circuits::{
        bit_decomposition::BitDecompositionCircuit,
        circuit::MyCircuit,
        equality_zero::{EqualityZeroCircuit, NotEqualityZeroCircuit},
        LocalOrMPC, PedersenComCircuit,
    },
    input::{MpcInputTrait, SampleMpcInput},
};

pub fn setup_and_index<C: ConstraintSynthesizer<Fr>>(
    circuit: C,
) -> (
    IndexProverKey<MFr, MpcMarlinKZG10>,
    IndexVerifierKey<Fr, LocalMarlinKZG10>,
) {
    let rng = &mut test_rng();
    let srs = LocalMarlin::universal_setup(30000, 500, 1000, rng).unwrap();
    let (index_pk, index_vk) = LocalMarlin::index(&srs, circuit).unwrap();
    let mpc_index_pk = IndexProverKey::from_public(index_pk);
    (mpc_index_pk, index_vk)
}

pub async fn prove_and_verify<C: ConstraintSynthesizer<MFr>>(
    mpc_index_pk: &IndexProverKey<MFr, MpcMarlinKZG10>,
    index_vk: &IndexVerifierKey<Fr, LocalMarlinKZG10>,
    circuit: C,
    inputs: Vec<Fr>,
) -> bool {
    let rng = &mut test_rng();
    let mpc_proof = MpcMarlin::prove(mpc_index_pk, circuit, rng).unwrap();
    let proof = pf_publicize(mpc_proof).await;

    LocalMarlin::verify(index_vk, &inputs, &proof, rng).unwrap()
}

async fn prover_message_publicize(
    p: ProverMsg<MpcField<ark_bls12_377::Fr>>,
) -> ProverMsg<ark_bls12_377::Fr> {
    match p {
        ProverMsg::EmptyMessage => ProverMsg::EmptyMessage,
        ProverMsg::FieldElements(d) => {
            // ProverMsg::FieldElements(d.into_iter().map(|e| e.reveal()).collect())
            ProverMsg::FieldElements(join_all(d.into_iter().map(MpcField::reveal)).await)
        }
    }
}

async fn comm_publicize(
    pf: ark_poly_commit::marlin_pc::Commitment<ME>,
) -> ark_poly_commit::marlin_pc::Commitment<E> {
    ark_poly_commit::marlin_pc::Commitment {
        comm: commit_from_mpc(pf.comm).await,
        // shifted_comm: pf.shifted_comm.map(commit_from_mpc).await,
        shifted_comm: match pf.shifted_comm {
            Some(v) => Some(commit_from_mpc(v).await),
            None => None,
        },
    }
}

async fn commit_from_mpc<'a>(
    p: ark_poly_commit::kzg10::Commitment<MpcPairingEngine<ark_bls12_377::Bls12_377>>,
) -> ark_poly_commit::kzg10::Commitment<ark_bls12_377::Bls12_377> {
    ark_poly_commit::kzg10::Commitment(p.0.reveal().await)
}

async fn pf_from_mpc<'a>(
    pf: ark_poly_commit::kzg10::Proof<MpcPairingEngine<ark_bls12_377::Bls12_377>>,
) -> ark_poly_commit::kzg10::Proof<ark_bls12_377::Bls12_377> {
    ark_poly_commit::kzg10::Proof {
        w: pf.w.reveal().await,
        // random_v: pf.random_v.map(MpcField::reveal).await,
        random_v: match pf.random_v {
            Some(v) => Some(v.reveal().await),
            None => None,
        },
    }
}

async fn batch_pf_publicize(
    pf: ark_poly_commit::BatchLCProof<MFr, DensePolynomial<MFr>, MpcMarlinKZG10>,
) -> ark_poly_commit::BatchLCProof<Fr, DensePolynomial<Fr>, LocalMarlinKZG10> {
    ark_poly_commit::BatchLCProof {
        // proof: pf.proof.into_iter().map(pf_from_mpc).collect(),
        proof: join_all(pf.proof.into_iter().map(pf_from_mpc)).await,
        // evals: pf
        //     .evals
        //     .map(|e| e.into_iter().map(MpcField::reveal).collect()),
        evals: match pf.evals {
            Some(e) => Some(join_all(e.into_iter().map(MpcField::reveal)).await),
            None => None,
        },
    }
}

pub async fn pf_publicize(
    k: Proof<MpcField<ark_bls12_377::Fr>, MpcMarlinKZG10>,
) -> Proof<ark_bls12_377::Fr, LocalMarlinKZG10> {
    let pf_timer = start_timer!(|| "publicize proof");
    let r = Proof::<ark_bls12_377::Fr, LocalMarlinKZG10> {
        // commitments: k
        //     .commitments
        //     .into_iter()
        //     .map(|cs| cs.into_iter().map(comm_publicize).collect())
        //     .collect(),
        // evaluations: k.evaluations.into_iter().map(|e| e.reveal()).collect(),
        // prover_messages: k
        //     .prover_messages
        //     .into_iter()
        //     .map(prover_message_publicize)
        //     .collect(),
        // pc_proof: batch_pf_publicize(k.pc_proof),
        commitments: join_all(
            k.commitments
                .into_iter()
                .map(|cs| async move { join_all(cs.into_iter().map(comm_publicize)).await }),
        )
        .await,
        evaluations: join_all(k.evaluations.into_iter().map(|e| e.reveal())).await,
        prover_messages: join_all(k.prover_messages.into_iter().map(prover_message_publicize))
            .await,
        pc_proof: batch_pf_publicize(k.pc_proof).await,
    };
    end_timer!(pf_timer);
    r
}

type Fr = ark_bls12_377::Fr;
pub type MFr = MpcField<Fr>;

type E = ark_bls12_377::Bls12_377;
type ME = MpcPairingEngine<ark_bls12_377::Bls12_377>;

pub type LocalMarlinKZG10 = MarlinKZG10<E, DensePolynomial<Fr>>;
pub type MpcMarlinKZG10 = MarlinKZG10<ME, DensePolynomial<MFr>>;

pub type LocalMarlin = Marlin<Fr, LocalMarlinKZG10, Blake2s>;
pub type MpcMarlin = Marlin<MFr, MpcMarlinKZG10, Blake2s>;

pub async fn mpc_test_prove_and_verify(n_iters: usize) {
    let rng = &mut test_rng();
    let local_input = SampleMpcInput::<Fr>::rand(rng);
    let local_circuit = MyCircuit {
        mpc_input: local_input,
    };
    let (mpc_index_pk, index_vk) = setup_and_index(local_circuit);

    for _ in 0..n_iters {
        let mut mpc_input: SampleMpcInput<MFr> = SampleMpcInput::init();
        mpc_input.set_public_input(rng, None);
        mpc_input.set_private_input(Some((Fr::rand(rng), Fr::rand(rng))));
        mpc_input.generate_input(rng);

        let mpc_circuit = MyCircuit {
            mpc_input: mpc_input.clone(),
        };
        let peculiar = mpc_input.peculiar.unwrap();
        let c = peculiar.a.input * peculiar.b.input;
        let inputs = vec![
            c.reveal().await,
            peculiar.a.commitment.reveal().await.x,
            peculiar.a.commitment.reveal().await.y,
            peculiar.b.commitment.reveal().await.x,
            peculiar.b.commitment.reveal().await.y,
        ];
        let invalid_inputs = vec![c.reveal().await];

        assert!(prove_and_verify(&mpc_index_pk, &index_vk, mpc_circuit.clone(), inputs,).await);
        assert!(!prove_and_verify(&mpc_index_pk, &index_vk, mpc_circuit, invalid_inputs,).await);
    }
}

pub async fn mpc_test_prove_and_verify_pedersen(n_iters: usize) {
    let rng = &mut test_rng();
    let params = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::setup(rng).unwrap();
    let x = Fr::from(4);
    let x_bytes = x.into_repr().to_bytes_le();
    let randomness = <Fr as LocalOrMPC<Fr>>::PedersenRandomness::pub_rand(rng);
    let h_x_local =
        <Fr as LocalOrMPC<Fr>>::PedersenComScheme::commit(&params, &x_bytes, &randomness).unwrap();
    let empty_circuit = PedersenComCircuit {
        param: Some(params.clone()),
        input: x,
        open: randomness,
        commit: h_x_local,
    };
    let (mpc_index_pk, index_vk) = setup_and_index(empty_circuit);

    for _ in 0..n_iters {
        let mpc_params = <MFr as LocalOrMPC<MFr>>::PedersenParam::from_local(&params);
        let x = MFr::rand(rng);
        let input = <MFr as LocalOrMPC<MFr>>::convert_input(&x);
        let randomness = <MFr as LocalOrMPC<MFr>>::PedersenRandomness::rand(rng);
        let h_x_mpc =
            <MFr as LocalOrMPC<MFr>>::PedersenComScheme::commit(&mpc_params, &input, &randomness)
                .unwrap();
        let circuit = PedersenComCircuit {
            param: Some(mpc_params.clone()),
            input: x,
            open: randomness,
            commit: h_x_mpc,
        };
        let inputs = vec![h_x_mpc.reveal().await.x, h_x_mpc.reveal().await.y];
        let invalid_inputs = vec![h_x_mpc.reveal().await.y, h_x_mpc.reveal().await.x];

        assert!(prove_and_verify(&mpc_index_pk, &index_vk, circuit.clone(), inputs).await);
        assert!(!prove_and_verify(&mpc_index_pk, &index_vk, circuit, invalid_inputs).await);
    }
}

pub async fn test_equality_zero(n_iters: usize) {
    let local_circuit = EqualityZeroCircuit { a: Fr::zero() };
    let (mpc_index_pk, index_vk) = setup_and_index(local_circuit);

    for _ in 0..n_iters {
        let valid_mpc_circuit = EqualityZeroCircuit {
            a: MFr::from_add_shared(Fr::zero()),
        };
        let invalid_mpc_circuit = EqualityZeroCircuit {
            a: MFr::from_add_shared(Fr::one()),
        };

        assert!(prove_and_verify(&mpc_index_pk, &index_vk, valid_mpc_circuit, vec![]).await);
        assert!(!prove_and_verify(&mpc_index_pk, &index_vk, invalid_mpc_circuit, vec![]).await);
    }
}

pub async fn test_not_equality_zero(n_iters: usize) {
    let local_circuit = NotEqualityZeroCircuit { a: Fr::one() };
    let (mpc_index_pk, index_vk) = setup_and_index(local_circuit);

    let rng = &mut test_rng();

    let is_zero_false_val = Fr::zero();
    let is_zero_true_val = Fr::one();

    for _ in 0..n_iters {
        let mpc_circuit = NotEqualityZeroCircuit { a: MFr::rand(rng) };

        if mpc_circuit.a.reveal().await != Fr::zero() {
            assert!(
                prove_and_verify(
                    &mpc_index_pk,
                    &index_vk,
                    mpc_circuit,
                    vec![is_zero_false_val]
                )
                .await
            );
        } else {
            assert!(
                prove_and_verify(
                    &mpc_index_pk,
                    &index_vk,
                    mpc_circuit,
                    vec![is_zero_true_val]
                )
                .await
            );
        }
    }
}

pub async fn test_bit_decomposition(n_iters: usize) {
    let rng = &mut test_rng();

    let local_circuit = BitDecompositionCircuit { a: Fr::zero() };
    let (mpc_index_pk, index_vk) = setup_and_index(local_circuit);

    for _ in 0..n_iters {
        let mpc_circuit = BitDecompositionCircuit { a: MFr::rand(rng) };
        assert!(prove_and_verify(&mpc_index_pk, &index_vk, mpc_circuit, vec![]).await);
    }
}

pub async fn test_enforce_smaller_eq_than(n_iters: usize) {
    let rng = &mut test_rng();

    for _ in 0..n_iters {
        let (local_a_bit_rand, _) = MpcBooleanField::<Fr>::rand_number_bitwise(rng).await;
        // let local_a_bit_rand = local_a_bit_rand.iter().map(|x| x.reveal()).collect_vec();

        let local_a_bit_rand = join_all(
            local_a_bit_rand
                .iter()
                .map(|x| async move { x.reveal().await }),
        )
        .await
        .into_iter()
        .collect_vec();
        let b = Fr::rand(rng);

        let local_circuit = SmallerEqThanCircuit {
            a: local_a_bit_rand,
            b,
        };
        let (mpc_index_pk, index_vk) = setup_and_index(local_circuit);
        // generate random shared bits
        let (a_bit_rand, a_rand) = MpcBooleanField::<Fr>::rand_number_bitwise(rng).await;
        let a_bit_rand = a_bit_rand.into_iter().map(|x| x.field()).collect_vec();
        let mpc_circuit = SmallerEqThanCircuit { a: a_bit_rand, b };
        let inputs = vec![];
        if a_rand.reveal().await <= b {
            assert!(prove_and_verify(&mpc_index_pk, &index_vk, mpc_circuit, inputs).await);
        } else {
            assert!(!prove_and_verify(&mpc_index_pk, &index_vk, mpc_circuit, inputs).await);
        }
    }
}

pub async fn test_smaller_than(n_iters: usize) {
    let rng = &mut test_rng();
    let (_, local_a_rand) =
        MpcBooleanField::<Fr>::rand_number_bitwise_less_than_half_modulus(rng).await;
    let (_, local_b_rand) =
        MpcBooleanField::<Fr>::rand_number_bitwise_less_than_half_modulus(rng).await;
    let local_res = local_a_rand.is_smaller_than(&local_b_rand).await;

    let local_circuit = SmallerThanCircuit {
        a: local_a_rand.reveal().await,
        b: local_b_rand.reveal().await,
        res: local_res.reveal().await,
        cmp: Ordering::Less,
        check_eq: true,
    };
    let (mpc_index_pk, index_vk) = setup_and_index(local_circuit);
    for _ in 0..n_iters {
        let (_, a_rand) =
            MpcBooleanField::<Fr>::rand_number_bitwise_less_than_half_modulus(rng).await;
        let (_, b_rand) =
            MpcBooleanField::<Fr>::rand_number_bitwise_less_than_half_modulus(rng).await;
        let res = a_rand.is_smaller_than(&b_rand).await;
        let mpc_circuit = SmallerThanCircuit {
            a: a_rand,
            b: b_rand,
            res: res.field(),
            cmp: Ordering::Less,
            check_eq: true,
        };
        let inputs = vec![];
        assert!(prove_and_verify(&mpc_index_pk, &index_vk, mpc_circuit, inputs).await);
    }
}

fn save_srs_to_file(srs: &UniversalSRS<Fr, LocalMarlinKZG10>, filename: &str) {
    let mut file = std::io::BufWriter::new(std::fs::File::create(filename).unwrap());
    let mut serialized_data = Vec::new();
    srs.serialize(&mut serialized_data).unwrap();
    file.write_all(&serialized_data).unwrap();
}

#[cfg(test)]
mod tests {

    // use crate::{AdditiveFieldShare, Reveal};
    // use ark_bls12_377::Fr;
    // use ark_ff::{PrimeField, UniformRand};
    // use mpc_net::{LocalTestNet, MpcMultiNet as Net, MpcNet};
    // use rand::{rngs::StdRng, Rng, SeedableRng};

    // use super::MpcField;

    // type MFr = MpcField<Fr, AdditiveFieldShare<Fr>>;

    use std::io::Read;

    use ark_std::test_rng;
    use mpc_net::LocalTestNet;

    use crate::circuits::circuit::MySimpleCircuit;

    use ark_serialize::CanonicalDeserialize;

    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_add() {
        const N_PARTIES: usize = 4;
        let testnet = LocalTestNet::new_local_testnet(N_PARTIES).await.unwrap();

        testnet
            .simulate_network_round((), |conn, _| async move {
                let rng = &mut test_rng();

                let local_circuit = MySimpleCircuit { a: None, b: None };

                let (mpc_index_pk, index_vk) = setup_and_index(local_circuit);

                let a = MFr::rand(rng);
                let b = MFr::rand(rng);

                let mpc_circuit = MySimpleCircuit {
                    a: Some(a),
                    b: Some(b),
                };
                let c = a * b;
                let inputs = vec![c.reveal().await];

                let invalid_inputs = vec![Fr::rand(rng)];

                assert!(
                    prove_and_verify(&mpc_index_pk, &index_vk, mpc_circuit.clone(), inputs,).await
                );
                assert!(
                    !prove_and_verify(&mpc_index_pk, &index_vk, mpc_circuit, invalid_inputs,).await
                );
            })
            .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_2() {
        // env_logger::builder()
        //     .format_timestamp(None)
        //     .filter_level(log::LevelFilter::Trace)
        //     .init();
        const N_PARTIES: usize = 3;
        let testnet = LocalTestNet::new_local_testnet(N_PARTIES).await.unwrap();

        testnet
            .simulate_network_round(
                (),
                |conn, _| async move { mpc_test_prove_and_verify(1).await },
            )
            .await;
    }

    #[test]
    #[ignore] // this test can't be run in github actions.
    fn test_write_srs() {
        let timer = start_timer!(|| "universal_setup");
        let rng = &mut rand::thread_rng();
        let universal_srs = LocalMarlin::universal_setup(30000, 500, 1000, rng).unwrap();
        end_timer!(timer);
        let timer = start_timer!(|| "save_srs_to_file");
        save_srs_to_file(&universal_srs, "outputs/srs_30k_500_1k.bin");
        end_timer!(timer);
    }

    #[test]
    #[ignore] // this test can't be run in github actions.
    fn test_read_srs() {
        let timer = start_timer!(|| "read_srs_from_file");
        let mut file = std::fs::File::open("outputs/srs.bin").unwrap();
        let mut serialized_data = Vec::new();
        file.read_to_end(&mut serialized_data).unwrap();
        end_timer!(timer);

        let timer = start_timer!(|| "deserialize_srs");
        let srs =
            UniversalSRS::<Fr, LocalMarlinKZG10>::deserialize(&mut &serialized_data[..]).unwrap();
        end_timer!(timer);
    }

    #[test]
    fn test_single() {
        let rng = &mut test_rng();

        let a = Fr::rand(rng);
        let b = Fr::rand(rng);

        let circuit = MySimpleCircuit {
            a: Some(a),
            b: Some(b),
        };

        // let (mpc_index_pk, index_vk) = setup_and_index(local_circuit);

        let srs = LocalMarlin::universal_setup(300, 50, 100, rng).unwrap();
        let (index_pk, index_vk) = LocalMarlin::index(&srs, circuit.clone()).unwrap();

        let c = a * b;
        let inputs = vec![c];

        let invalid_inputs = vec![Fr::rand(rng)];

        let rng = &mut test_rng();
        let proof = LocalMarlin::prove(&index_pk, circuit, rng).unwrap();
        // let proof = pf_publicize(mpc_proof).await;

        assert!(LocalMarlin::verify(&index_vk, &inputs, &proof, rng).unwrap());

        // assert!(prove_and_verify(&mpc_index_pk, &index_vk, mpc_circuit.clone(), inputs,).await);
        // assert!(!prove_and_verify(&mpc_index_pk, &index_vk, mpc_circuit, invalid_inputs,).await);
    }
}
