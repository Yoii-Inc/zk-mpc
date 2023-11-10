use ark_bls12_377::Fr;
use ark_crypto_primitives::CommitmentScheme;
use ark_ff::{BigInteger, FpParameters, PrimeField};
use ark_marlin::IndexProverKey;
use ark_serialize::{CanonicalDeserialize, Read};
use ark_std::test_rng;

use mpc_algebra::Reveal;
use mpc_net::{MpcMultiNet as Net, MpcNet};

use serde::Deserialize;
use std::{fs::File, path::PathBuf, vec};
use structopt::StructOpt;

mod circuits;
use circuits::{circuit::MySimpleCircuit, LocalOrMPC, PedersenComCircuit};
mod marlin;
use marlin::*;

#[derive(Debug, StructOpt)]
#[structopt(name = "example", about = "An example of StructOpt usage.")]
struct Opt {
    zksnark: String,

    // Input value file
    input_file_path: String,

    // Id
    id: usize,

    // Input address file
    #[structopt(parse(from_os_str))]
    input: PathBuf,
}

#[derive(Debug, Deserialize)]
struct ArgInput {
    x: u128,
    y: u128,
    z: u128,
}

#[derive(Debug, Deserialize)]
struct PairPhase {
    r0_angle_mac: String,
    r0_angle_public_modifier: String,
    r0_angle_share: String,
    r0_bracket_mac: String,
    r0_bracket_mac_0: String,
    r0_bracket_mac_1: String,
    r0_bracket_mac_2: String,
    r0_bracket_share: String,
    r1_angle_mac: String,
    r1_angle_public_modifier: String,
    r1_angle_share: String,
    r1_bracket_mac: String,
    r1_bracket_mac_0: String,
    r1_bracket_mac_1: String,
    r1_bracket_mac_2: String,
    r1_bracket_share: String,
    r2_angle_mac: String,
    r2_angle_public_modifier: String,
    r2_angle_share: String,
    r2_bracket_mac: String,
    r2_bracket_mac_0: String,
    r2_bracket_mac_1: String,
    r2_bracket_mac_2: String,
    r2_bracket_share: String,
}

enum ZkSnark {
    Groth16,
    Marlin,
}

fn which_zksnark(zksnark: &str) -> Result<ZkSnark, std::io::Error> {
    match zksnark {
        "groth16" => Ok(ZkSnark::Groth16),
        "marlin" => Ok(ZkSnark::Marlin),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Only groth16 or marlin are supported",
        )),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::from_args();

    let zksnark: ZkSnark = match which_zksnark(&opt.zksnark) {
        Ok(zk) => {
            println!("selected zksnarks is OK");
            zk
        }
        Err(err) => {
            eprintln!("Error: {err}");
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                err,
            )));
        }
    };

    // init
    Net::init_from_file(opt.input.to_str().unwrap(), opt.id);

    let mut file = File::open(opt.input_file_path).expect("Failed to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Failed to read file");

    let data: ArgInput = serde_json::from_str(&contents).unwrap();
    println!("{:?}", data);

    let rng = &mut test_rng();

    // online calculation

    // TODO: Separate the following part in preprocessing.

    // load pair phase data
    // deserialize
    let online_setup_file_path = format!("./outputs/{}/online_setup.json", opt.id);
    let mut online_setup_file = File::open(online_setup_file_path).expect("Failed to open file");

    let mut output_string = String::new();
    online_setup_file
        .read_to_string(&mut output_string)
        .expect("Failed to read file");

    let output_data: PairPhase = serde_json::from_str(&output_string).unwrap();

    let (r0, r1, r2) = {
        let remove_prefix_string =
            if let Some(stripped) = output_data.r0_angle_share.strip_prefix("0x") {
                stripped.to_string()
            } else {
                output_data.r0_angle_share.clone()
            };

        let remove_prefix_string1 =
            if let Some(stripped) = output_data.r0_angle_share.strip_prefix("0x") {
                stripped.to_string()
            } else {
                output_data.r1_angle_share.clone()
            };

        let remove_prefix_string2 =
            if let Some(stripped) = output_data.r0_angle_share.strip_prefix("0x") {
                stripped.to_string()
            } else {
                output_data.r2_angle_share.clone()
            };

        let reader: &[u8] = &hex::decode(remove_prefix_string).unwrap();

        let deserialized_r0_angle_share: Fr = Fr::deserialize(reader).unwrap();

        let reader: &[u8] = &hex::decode(remove_prefix_string1).unwrap();

        let deserialized_r1_angle_share: Fr = Fr::deserialize(reader).unwrap();

        let reader: &[u8] = &hex::decode(remove_prefix_string2).unwrap();

        let deserialized_r2_angle_share: Fr = Fr::deserialize(reader).unwrap();

        (
            deserialized_r0_angle_share,
            deserialized_r1_angle_share,
            deserialized_r2_angle_share,
        )
    };

    let sum_r0 = MFr::from_add_shared(r0).reveal();
    let sum_r1 = MFr::from_add_shared(r1).reveal();
    let sum_r2 = MFr::from_add_shared(r2).reveal();

    let shared_input = match Net::party_id() {
        0 => {
            vec![
                MFr::from_add_shared(
                    Fr::from(data.x) - sum_r0
                        + r0
                        + Fr::from(ark_ed_on_bls12_377::FrParameters::MODULUS),
                ),
                MFr::from_add_shared(r1),
                MFr::from_add_shared(r2),
            ]
        }
        1 => {
            vec![
                MFr::from_add_shared(r0),
                MFr::from_add_shared(
                    Fr::from(data.y) - sum_r1
                        + r1
                        + Fr::from(ark_ed_on_bls12_377::FrParameters::MODULUS),
                ),
                MFr::from_add_shared(r2),
            ]
        }
        2 => {
            vec![
                MFr::from_add_shared(r0),
                MFr::from_add_shared(r1),
                MFr::from_add_shared(
                    Fr::from(data.z) - sum_r2
                        + r2
                        + Fr::from(ark_ed_on_bls12_377::FrParameters::MODULUS),
                ),
            ]
        }
        _ => panic!("invalid party id"),
    };

    match zksnark {
        ZkSnark::Groth16 => {}
        ZkSnark::Marlin => {
            let srs = LocalMarlin::universal_setup(10000, 50, 100, rng).expect("Failed to setup");

            // commitmnet phase
            // Pedersen commitment
            //// commom parameter
            let params = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::setup(rng).unwrap();

            // TODO: Load local_commitment from file

            let mut vec_inputs = Vec::new();
            let mut vec_randomness = Vec::new();
            let mut vec_h_x_local = Vec::new();

            for x in shared_input.clone() {
                //// input(parent)
                let x_parent: Fr = x.clone().reveal();
                vec_inputs.push(x_parent.clone());
                let x_bytes = x_parent.into_repr().to_bytes_le();

                //// randomness(parent)
                let randomness = <Fr as LocalOrMPC<Fr>>::PedersenRandomness::default();

                vec_randomness.push(randomness.clone());

                //// commitment(parent)
                let h_x_local = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::commit(
                    &params,
                    &x_bytes,
                    &randomness,
                )
                .unwrap();

                vec_h_x_local.push(h_x_local);
            }

            let empty_circuit = PedersenComCircuit {
                param: Some(params.clone()),
                input: Some(vec_inputs[0]),
                open: Some(vec_randomness[0].clone()),
                commit: Some(vec_h_x_local[0]),
            };

            let (index_pk, index_vk) = LocalMarlin::index(&srs, empty_circuit).unwrap();

            // Pedersen commitment
            let commitment = shared_input
                .iter()
                .map(|x| {
                    //// input(child)
                    let x = x.unwrap_as_public();
                    let x_bytes = x.into_repr().to_bytes_le();

                    //// randomness
                    let randomness = <Fr as LocalOrMPC<Fr>>::PedersenRandomness::default();

                    //// commitment
                    let h_x = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::commit(
                        &params,
                        &x_bytes,
                        &randomness,
                    )
                    .unwrap();

                    let circuit = PedersenComCircuit {
                        param: Some(params.clone()),
                        input: Some(x),
                        open: Some(randomness.clone()),
                        commit: Some(h_x),
                    };

                    let inputs = vec![h_x.x, h_x.y];
                    let invalid_inputs = vec![h_x.y, h_x.x];

                    // prove
                    let proof = LocalMarlin::prove(&index_pk, circuit, rng).unwrap();

                    // verify
                    let is_valid = LocalMarlin::verify(&index_vk, &inputs, &proof, rng).unwrap();
                    assert!(is_valid);
                    let is_valid =
                        LocalMarlin::verify(&index_vk, &invalid_inputs, &proof, rng).unwrap();
                    assert!(!is_valid);

                    h_x
                })
                .collect::<Vec<_>>();

            vec_h_x_local
                .iter()
                .zip(commitment.iter())
                .for_each(|(&x, y)| {
                    assert_eq!(x, y.reveal());
                });

            // calculation phase
            let empty_circuit: MySimpleCircuit<Fr> = MySimpleCircuit { a: None, b: None };

            let (index_pk, index_vk) = LocalMarlin::index(&srs, empty_circuit.clone()).unwrap();
            let mpc_index_pk = IndexProverKey::from_public(index_pk);
            println!("Called index");

            let circuit = MySimpleCircuit {
                a: Some(shared_input[0].clone()),
                b: Some(shared_input[1].clone()),
            };
            let c = shared_input[0].clone() * shared_input[1].clone();

            // calculate the proof by passing witness variable value
            let mpc_proof = MpcMarlin::prove(&mpc_index_pk, circuit.clone(), rng).unwrap();
            let proof = pf_publicize(mpc_proof);
            println!("Called prover");

            assert!(LocalMarlin::verify(&index_vk, &[c.reveal()], &proof, rng).unwrap());
        }
    }

    Ok(())
}
