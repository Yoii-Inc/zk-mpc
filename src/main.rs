#![allow(dead_code)]

mod algebra;
mod circuits;
// mod groth16;
mod input;
// mod marlin;
mod preprocessing;
mod serialize;
mod she;

pub mod field {
    // pub use mpc_algebra::honest_but_curious::*;
    pub use mpc_algebra::malicious_majority::*;
}

use ark_bls12_377::{Bls12_377, Fr, FrParameters};
use ark_crypto_primitives::CommitmentScheme;
use ark_ff::{BigInteger, FpParameters, PrimeField};
use ark_groth16::Groth16;
use ark_marlin::*;
use ark_mnt4_753::FqParameters;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_serialize::{CanonicalDeserialize, Read};
use ark_snark::SNARK;
use ark_std::UniformRand;
use blake2::Blake2s;
use serde::Deserialize;
use std::fs::File;
use std::io::Write as Otherwrite;

use structopt::StructOpt;

use crate::circuits::*;
use crate::serialize::{write_r, write_to_file};

#[derive(Debug, StructOpt)]
#[structopt(name = "example", about = "An example of StructOpt usage.")]
struct Opt {
    zksnark: String,
    input_file_path: String,
}

#[derive(Debug, Deserialize)]
struct ArgInput {
    x: u128,
}

#[derive(Debug, Deserialize)]
struct Output {
    hex_commitment: String,
}

enum ZkSnark {
    Groth16,
    Marlin,
}

pub type MarlinLocal = Marlin<Fr, MarlinKZG10<Bls12_377, DensePolynomial<Fr>>, Blake2s>;

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

fn create_file() -> Result<File, std::io::Error> {
    let file = File::create("./outputs/outputs.json")?;
    Ok(file)
}

fn write_data(file: &mut File, data: &[u8]) -> Result<(), std::io::Error> {
    file.write_all(data)?;
    Ok(())
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

    let mut file = File::open(opt.input_file_path).expect("Failed to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Failed to read file");

    let data: ArgInput = serde_json::from_str(&contents).unwrap();
    println!("{:?}", data);

    // preprocessing
    let mut rng = rand::thread_rng();
    // // initialize phase
    let zkpopk_parameters = preprocessing::zkpopk::Parameters::new(
        1,
        3,
        std::convert::Into::<num_bigint::BigUint>::into(FrParameters::MODULUS) / 2_u32,
        1,
        9,
        2,
    );

    let she_parameters = she::SHEParameters::new(
        zkpopk_parameters.get_n(),
        zkpopk_parameters.get_n(),
        FrParameters::MODULUS.into(),
        FqParameters::MODULUS.into(),
        3.2,
    );

    let _bracket_diag_alpha = preprocessing::initialize(&zkpopk_parameters, &she_parameters);

    // // pair phase
    let sk = she::SecretKey::generate(&she_parameters, &mut rng);
    let pk = sk.public_key_gen(&she_parameters, &mut rng);

    let e_alpha = she::Ciphertext::rand(&pk, &mut rng, &she_parameters);

    let (r_bracket, r_angle) =
        preprocessing::pair(&e_alpha, &pk, &sk, &zkpopk_parameters, &she_parameters);

    // // triple phase
    let (_a_angle, _b_angle, _c_angle) =
        preprocessing::triple(&e_alpha, &pk, &sk, &zkpopk_parameters, &she_parameters);

    // make share, prove and verify
    // // generate the setup parameters
    let x = Fr::from(data.x);
    let input_bit = x
        .into_repr()
        .to_bits_le()
        .iter()
        .map(|b| Fr::from(*b))
        .collect::<Vec<_>>();

    let lower_bound = Fr::from(3);
    let upper_bound = Fr::from(7);

    // // Pedersen commitment
    let params = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::setup(&mut rng).unwrap();
    let randomness = <Fr as LocalOrMPC<Fr>>::PedersenRandomness::rand(&mut rng);
    let open_bit = randomness
        .0
        .into_repr()
        .to_bits_le()
        .iter()
        .map(|b| Fr::from(*b))
        .collect::<Vec<_>>();
    let x_bytes = x.into_repr().to_bytes_le();
    let h_x =
        <Fr as LocalOrMPC<Fr>>::PedersenComScheme::commit(&params, &x_bytes, &randomness).unwrap();

    let circuit = input_circuit::MySecretInputCircuit::new(
        x,
        randomness,
        params,
        h_x,
        lower_bound,
        upper_bound,
    );
    match zksnark {
        ZkSnark::Groth16 => {
            let (circuit_pk, circuit_vk) =
                Groth16::<Bls12_377>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();

            // // calculate the proof by passing witness variable value
            let proof = Groth16::<Bls12_377>::prove(&circuit_pk, circuit, &mut rng).unwrap();

            // // validate the proof
            assert!(Groth16::<Bls12_377>::verify(
                &circuit_vk,
                &[lower_bound, upper_bound, h_x.x, h_x.y],
                &proof
            )
            .unwrap());
        }
        ZkSnark::Marlin => {
            let universal_srs =
                MarlinLocal::universal_setup(10000, 50, 100, &mut rng).expect("Failed to setup");

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
        }
    }

    let output_file_path = "./outputs/outputs.json";

    write_to_file(vec![("hex_commitment".to_string(), h_x)], output_file_path)?;

    // deserialize
    let mut output_file = File::open(output_file_path).expect("Failed to open file");

    let mut output_string = String::new();
    output_file
        .read_to_string(&mut output_string)
        .expect("Failed to read file");

    let output_data: Output = serde_json::from_str(&output_string).unwrap();

    let remove_prefix_string = if let Some(stripped) = output_data.hex_commitment.strip_prefix("0x")
    {
        stripped.to_string()
    } else {
        output_data.hex_commitment.clone()
    };

    let reader: &[u8] = &hex::decode(remove_prefix_string).unwrap();

    let deserialized_h_x: <Fr as LocalOrMPC<Fr>>::PedersenCommitment =
        CanonicalDeserialize::deserialize(reader).unwrap();

    assert_eq!(h_x, deserialized_h_x);

    // save to file
    // <r>, [r] for input share
    write_r(3, "outputs", r_angle, r_bracket).unwrap();

    Ok(())
}
