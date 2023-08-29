#![allow(dead_code)]

mod circuit;
mod groth16;
mod input_circuit;
mod preprocessing;
mod she;

use ark_bls12_377::{Bls12_377, Fr, FrParameters};
use ark_crypto_primitives::CommitmentScheme;
use ark_ff::{BigInteger, FpParameters, PrimeField};
use ark_groth16::Groth16;
use ark_mnt4_753::FqParameters;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read};
use ark_snark::SNARK;
use ark_std::UniformRand;
use hex::ToHex;
use serde::Deserialize;
use serde_json::json;
use std::fmt::Write;
use std::fs::File;
use std::io::Write as Otherwrite;

use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "example", about = "An example of StructOpt usage.")]
struct Opt {
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

fn main() {
    let opt = Opt::from_args();

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
        2,
        std::convert::Into::<num_bigint::BigUint>::into(FrParameters::MODULUS) / 2_u32,
        1,
        6,
        2,
    );

    let she_parameters = she::SHEParameters::new(
        zkpopk_parameters.get_n(),
        zkpopk_parameters.get_n(),
        FrParameters::MODULUS.into(),
        FqParameters::MODULUS.into(),
        3.2,
    );

    let bracket_diag_alpha = preprocessing::initialize(&zkpopk_parameters, &she_parameters);

    // // pair phase
    let sk = she::SecretKey::generate(&she_parameters, &mut rng);
    let pk = sk.public_key_gen(&she_parameters, &mut rng);

    let e_alpha = she::Ciphertext::rand(&pk, zkpopk_parameters.get_n(), &mut rng, &she_parameters);

    let (r_bracket, r_angle) =
        preprocessing::pair(&e_alpha, &pk, &sk, &zkpopk_parameters, &she_parameters);

    // // triple phase
    let (a_angle, b_angle, c_angle) =
        preprocessing::triple(&e_alpha, &pk, &sk, &zkpopk_parameters, &she_parameters);

    // make share, prove and verify
    // // generate the setup parameters
    let x = Fr::from(data.x);

    let lower_bound = Fr::from(3);
    let upper_bound = Fr::from(7);

    // // Pedersen commitment
    let params = input_circuit::PedersenComScheme::setup(&mut rng).unwrap();
    let randomness = input_circuit::PedersenRandomness::rand(&mut rng);
    let x_bytes = x.into_repr().to_bytes_le();
    let h_x = input_circuit::PedersenComScheme::commit(&params, &x_bytes, &randomness).unwrap();

    let circuit = input_circuit::MySecretInputCircuit::new(
        x,
        randomness,
        params,
        h_x,
        lower_bound,
        upper_bound,
    );

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

    // serialize commitment
    let mut byte = Vec::new();

    h_x.serialize(&mut byte).unwrap();

    // convert from Vec<u8> to HEX string
    let hex_string = byte.encode_hex::<String>();

    let mut prefixed_hex_string = String::new();
    write!(prefixed_hex_string, "0x{}", hex_string).unwrap();

    // create JSON object
    let json_data = json!({ "hex_commitment": prefixed_hex_string });

    let mut file = match File::create("./outputs/outputs.json") {
        Ok(file) => file,
        Err(e) => panic!("couldn't create output.json: {}", e),
    };

    let json_string = serde_json::to_string_pretty(&json_data).unwrap();

    match file.write_all(json_string.as_bytes()) {
        Ok(_) => println!("The data has been successfully written."),
        Err(e) => panic!("couldn't write data: {}", e),
    }

    // deserialize
    let mut output_file = File::open("./outputs/outputs.json").expect("Failed to open file");

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

    let deserialized_h_x: input_circuit::PedersenCommitment =
        ark_ec::models::twisted_edwards_extended::GroupAffine::deserialize(reader).unwrap();

    assert_eq!(h_x, deserialized_h_x);
}
