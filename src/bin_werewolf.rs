use ark_bls12_377::{Fr, FrParameters};
use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
use ark_ec::AffineCurve;
use ark_ff::FpParameters;
use ark_mnt4_753::FqParameters;
use ark_serialize::{CanonicalDeserialize, Read};
use ark_std::test_rng;
use ark_std::One;
use ark_std::UniformRand;

use circuits::{
    DivinationCircuit, ElGamalPlaintext, ElGamalPubKey, ElGamalRandomness, ElGamalScheme,
    KeyPublicizeCircuit,
};
use serde::Deserialize;
use serialize::{write_r, write_to_file};
use std::{fs::File, path::PathBuf};
use structopt::StructOpt;

use mpc_net::{MpcMultiNet as Net, MpcNet};

mod marlin;
use marlin::*;

mod circuits;
mod preprocessing;
mod serialize;
mod she;

#[derive(Debug, StructOpt)]
struct Opt {
    /// Run mode
    mode: String,

    /// Number of players
    #[structopt(long = "num-players", required_if("mode", "init"))]
    num_players: Option<usize>,

    /// Target player id
    #[structopt(long = "target")]
    target: Option<usize>,

    // Player Id
    id: Option<usize>,

    // Input address file
    #[structopt(parse(from_os_str))]
    input: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::from_args();

    println!("opt is {:?}", opt);

    // init mode is executed by one process. other modes are executed by all players.
    match opt.mode.as_str() {
        "init" => {
            println!("Init mode");
            // initialize werewolf game
            initialize_game(&opt)?;

            // preprocessing MPC
            preprocessing_mpc(&opt)?;
        }
        "preprocessing" => {
            println!("Preprocessing mode");
            // preprocessing calculation of werewolf game

            preprocessing_werewolf(&opt)?;
        }
        "night" => {
            println!("Night mode");
            // run the night phase
            night_werewolf(&opt)?;
        }
        _ => {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Error: Invalid mode. Only init or night are supported",
            ))?;
        }
    };

    Ok(())
}

fn initialize_game(opt: &Opt) -> Result<(), std::io::Error> {
    // public.json
    let file_path = "./werewolf/public.json";
    File::create(file_path)?;

    let datas = vec![
        (
            "num_players".to_string(),
            vec![opt.num_players.unwrap().to_string()],
        ),
        (
            "Roles".to_string(),
            vec![
                "Villager".to_string(),
                "FortuneTeller".to_string(),
                "Werewolf".to_string(),
            ],
        ),
    ];

    write_to_file(datas, file_path).unwrap();

    // role.json
    let role = ["FortuneTeller", "Werewolf", "Villager"];
    for i in 0..opt.num_players.unwrap() {
        let file_path = format!("./werewolf/{}/role.json", i);
        File::create(&file_path)?;

        let datas = vec![("role".to_string(), role[i].to_string())];

        write_to_file(datas, &file_path).unwrap();
    }

    Ok(())
}

fn preprocessing_mpc(opt: &Opt) -> Result<(), std::io::Error> {
    // let opt = Opt::from_args();

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

    // save to file
    // <r>, [r] for input share
    write_r(opt.num_players.unwrap(), "werewolf", r_angle, r_bracket).unwrap();

    Ok(())
}

fn preprocessing_werewolf(opt: &Opt) -> Result<(), std::io::Error> {
    // init
    Net::init_from_file(
        opt.input.clone().unwrap().to_str().unwrap(),
        opt.id.unwrap(),
    );

    // dummmy input
    let mut pub_key_or_dummy = vec![
        ElGamalPubKey::default(),
        ElGamalPubKey::default(),
        ElGamalPubKey::default(),
    ];

    // collaborative proof
    let rng = &mut test_rng();

    let srs = LocalMarlin::universal_setup(10000, 50, 100, rng).expect("Failed to setup");

    // input parameters
    let elgamal_params = ElGamalScheme::setup(rng).unwrap();

    let (pk, sk) = ElGamalScheme::keygen(&elgamal_params, rng).unwrap();

    // let fortune_teller_pk = pk;

    pub_key_or_dummy[0] = pk;

    let key_publicize_circuit = KeyPublicizeCircuit::<Fr> {
        pub_key_or_dummy,
        _field: std::marker::PhantomData,
    };

    let (index_pk, index_vk) = LocalMarlin::index(&srs, key_publicize_circuit.clone()).unwrap();

    let inputs = [pk]
        .iter()
        .flat_map(|point| vec![point.x, point.y])
        .collect::<Vec<_>>();

    // prove
    let proof = LocalMarlin::prove(&index_pk, key_publicize_circuit, rng).unwrap();

    // verify
    let is_valid = LocalMarlin::verify(&index_vk, &inputs, &proof, rng).unwrap();
    assert!(is_valid);

    // save to file
    if Net::party_id() == 0 {
        let datas = vec![("public_key".to_string(), pk)];

        write_to_file(datas, "./werewolf/fortune_teller_key.json").unwrap();

        let secret_data = vec![("secret_key".to_string(), sk.0)];

        write_to_file(
            secret_data,
            format!("./werewolf/{}/secret_key.json", Net::party_id()).as_str(),
        )
        .unwrap();
    }

    Ok(())
}

fn night_werewolf(opt: &Opt) -> Result<(), std::io::Error> {
    // init
    Net::init_from_file(
        opt.input.clone().unwrap().to_str().unwrap(),
        opt.id.unwrap(),
    );

    let self_role = get_my_role();

    match self_role {
        Roles::FortuneTeller => {
            divination(&opt);
        }
        _ => {}
    }

    println!("My role is {:?}", self_role);
    Ok(())
}

#[derive(Debug)]
enum Roles {
    FortuneTeller,
    Werewolf,
    Villager,
}

#[derive(Debug, Deserialize)]
struct Role {
    role: String,
}

fn get_my_role() -> Roles {
    let id = Net::party_id();

    println!("id is {:?}", id);

    // read role.json
    let file_path = format!("./werewolf/{}/role.json", id);
    let mut file = File::open(file_path).unwrap();
    let mut output_string = String::new();
    file.read_to_string(&mut output_string)
        .expect("Failed to read file");

    let data: Role = serde_json::from_str(&output_string).unwrap();

    let remove_prefix_string = if let Some(stripped) = data.role.strip_prefix("0x") {
        stripped.to_string()
    } else {
        data.role.clone()
    };

    let reader: &[u8] = &hex::decode(remove_prefix_string).unwrap();

    let deserialized_role = <String as CanonicalDeserialize>::deserialize(reader).unwrap();

    match deserialized_role.as_str() {
        "FortuneTeller" => Roles::FortuneTeller,
        "Werewolf" => Roles::Werewolf,
        "Villager" => Roles::Villager,
        _ => panic!("Invalid role"),
    }
}

fn divination(opt: &Opt) -> Result<(), std::io::Error> {
    let target_id = opt.target.unwrap();

    let is_werewolf_vec = vec![Fr::from(0), Fr::from(1), Fr::from(0)];

    // collaborative proof
    let rng = &mut test_rng();

    let srs = LocalMarlin::universal_setup(10000, 50, 100, rng).expect("Failed to setup");

    // input parameters
    let elgamal_params = ElGamalScheme::setup(rng).unwrap();

    let (pk, sk) = ElGamalScheme::keygen(&elgamal_params, rng).unwrap();

    let message = match is_werewolf_vec[target_id].is_one() {
        true => ElGamalPlaintext::prime_subgroup_generator(),
        false => ElGamalPlaintext::default(),
    };

    let randomness = ElGamalRandomness::rand(rng);

    let output = ElGamalScheme::encrypt(&elgamal_params, &pk, &message, &randomness).unwrap();

    let divination_circuit = DivinationCircuit::<Fr> {
        is_werewolf: Some(is_werewolf_vec),
        target_player_id: Some(target_id),
        param: elgamal_params.clone(),
        pub_key: pk,
        randomness,
        output,
    };

    let (index_pk, index_vk) = LocalMarlin::index(&srs, divination_circuit.clone()).unwrap();

    let inputs = [elgamal_params.generator, pk, output.0, output.1]
        .iter()
        .flat_map(|point| vec![point.x, point.y])
        .collect::<Vec<_>>();

    // prove
    let proof = LocalMarlin::prove(&index_pk, divination_circuit, rng).unwrap();

    // verify
    let is_valid = LocalMarlin::verify(&index_vk, &inputs, &proof, rng).unwrap();
    assert!(is_valid);

    // save to file
    if Net::party_id() == 0 {
        let divination_result = ElGamalScheme::decrypt(&elgamal_params, &sk, &output).unwrap();

        let mut divination_result_bool = false;

        if divination_result == ElGamalPlaintext::prime_subgroup_generator() {
            println!("Player {} is werewolf", target_id);
            divination_result_bool = true;
        } else {
            println!("Player {} is villager", target_id);
        }
        let datas = vec![
            ("player_id".to_string(), target_id),
            ("is_werewolf".to_string(), divination_result_bool as usize),
        ];

        write_to_file(
            datas,
            format!("./werewolf/{}/divination_result.json", Net::party_id()).as_str(),
        )
        .unwrap();
    }

    Ok(())
}
