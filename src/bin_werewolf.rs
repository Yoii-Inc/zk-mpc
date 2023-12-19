use ark_bls12_377::{Fr, FrParameters};
use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
use ark_ec::twisted_edwards_extended::GroupAffine;
use ark_ec::AffineCurve;
use ark_ed_on_bls12_377::EdwardsParameters;
use ark_ff::FpParameters;
use ark_marlin::IndexProverKey;
use ark_mnt4_753::FqParameters;
use ark_serialize::{CanonicalDeserialize, Read};
use ark_std::test_rng;
use ark_std::UniformRand;

use circuits::{DivinationCircuit, ElGamalLocalOrMPC, KeyPublicizeCircuit};
use core::panic;
use mpc_algebra::MpcEdwardsParameters;
use mpc_algebra::MpcEdwardsProjective;
use mpc_algebra::Reveal;
use serde::Deserialize;
use serialize::{write_r, write_to_file};
use std::{fs::File, path::PathBuf};
use structopt::StructOpt;

use mpc_net::{MpcMultiNet as Net, MpcNet};

mod marlin;
use marlin::*;

use crate::input::MpcInputTrait;
use crate::input::WerewolfKeyInput;
use crate::input::WerewolfMpcInput;

mod circuits;
mod input;
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
    // net init
    Net::init_from_file(
        opt.input.clone().unwrap().to_str().unwrap(),
        opt.id.unwrap(),
    );

    let num_players = 3;

    // dummmy input
    let mut pub_key_or_dummy_x = vec![Fr::from(0); num_players];
    let mut pub_key_or_dummy_y = vec![Fr::from(0); num_players];

    // collaborative proof
    let rng = &mut test_rng();

    let srs = LocalMarlin::universal_setup(17000, 50, 100, rng).expect("Failed to setup");

    let elgamal_params = <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalScheme::setup(rng).unwrap();

    let (pk, sk) =
        <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalScheme::keygen(&elgamal_params, rng).unwrap();
    pub_key_or_dummy_x[1] = pk.x;
    pub_key_or_dummy_y[1] = pk.y;

    let mpc_input = WerewolfKeyInput::rand(rng);

    let key_publicize_circuit = KeyPublicizeCircuit { mpc_input };

    let (index_pk, index_vk) = LocalMarlin::index(&srs, key_publicize_circuit.clone()).unwrap();

    let mpc_index_pk = IndexProverKey::from_public(index_pk);

    let mut mpc_input = WerewolfKeyInput::init();
    mpc_input.set_public_input(rng, None);
    mpc_input.set_private_input(Some((pub_key_or_dummy_x, pub_key_or_dummy_y)));
    mpc_input.generate_input(rng);

    let key_publicize_circuit = KeyPublicizeCircuit {
        mpc_input: mpc_input.clone(),
    };

    // prove
    let mpc_proof = MpcMarlin::prove(&mpc_index_pk, key_publicize_circuit, rng).unwrap();

    let proof = mpc_proof.reveal();

    // let pk = GroupAffine::<MpcEdwardsParameters> {
    //     x: mpc_input.pub_key.x.reveal(),
    //     y: mpc_input.pub_key.y.reveal(),
    //     infinity: mpc_input.pub_key.infinity.reveal(),
    // };

    let pk_x: MFr = mpc_input
        .peculiar
        .clone()
        .unwrap()
        .pub_key_or_dummy_x
        .iter()
        .map(|x| x.input)
        .sum();

    let pk_y: MFr = mpc_input
        .peculiar
        .clone()
        .unwrap()
        .pub_key_or_dummy_y
        .iter()
        .map(|x| x.input)
        .sum();

    let inputs = [pk_x.reveal(), pk_y.reveal()];

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

        let elgamal_parameter_data = vec![("elgamal_param".to_string(), elgamal_params.generator)];

        write_to_file(elgamal_parameter_data, "./werewolf/elgamal_param.json").unwrap();
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

    multi_divination(opt);

    println!("My role is {:?}", self_role);
    Ok(())
}

#[derive(Debug, PartialEq)]
enum Roles {
    FortuneTeller,
    Werewolf,
    Villager,
}

#[derive(Debug, Deserialize)]
struct Role {
    role: String,
}

#[derive(Debug, Deserialize)]
struct ArgSecretKey {
    secret_key: String,
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

fn multi_divination(_opt: &Opt) -> Result<(), std::io::Error> {
    let target_id = 1;

    let is_werewolf_vec = vec![Fr::from(0), Fr::from(1), Fr::from(0)];
    let mut is_target_vec = vec![Fr::from(0); 3];
    is_target_vec[target_id] = Fr::from(1);

    // collaborative proof
    let rng = &mut test_rng();

    let srs = LocalMarlin::universal_setup(30000, 50, 100, rng).expect("Failed to setup");

    // input parameters
    let local_input = WerewolfMpcInput::<Fr>::rand(rng);

    let local_divination_circuit = DivinationCircuit {
        mpc_input: local_input,
    };

    let (index_pk, index_vk) = LocalMarlin::index(&srs, local_divination_circuit.clone()).unwrap();

    let mpc_index_pk = IndexProverKey::from_public(index_pk);

    let (elgamal_param, elgamal_pubkey) = get_elgamal_param_pubkey();

    let mut mpc_input = WerewolfMpcInput::init();
    mpc_input.set_public_input(rng, Some((elgamal_param, elgamal_pubkey)));
    mpc_input.set_private_input(Some((is_werewolf_vec.clone(), is_target_vec.clone())));
    mpc_input.generate_input(rng);

    let multi_divination_circuit = DivinationCircuit {
        mpc_input: mpc_input.clone(),
    };

    let peculiar_is_werewolf_commitment: Vec<GroupAffine<MpcEdwardsParameters>> = mpc_input
        .peculiar
        .clone()
        .unwrap()
        .is_werewolf
        .iter()
        .map(|x| x.commitment)
        .collect::<Vec<_>>();

    let peculiar_is_target_commitment: Vec<GroupAffine<MpcEdwardsParameters>> = mpc_input
        .peculiar
        .clone()
        .unwrap()
        .is_target
        .iter()
        .map(|x| x.commitment)
        .collect::<Vec<_>>();

    let elgamal_generator: ark_crypto_primitives::encryption::elgamal::Parameters<
        MpcEdwardsProjective,
    > = mpc_input.clone().common.unwrap().elgamal_param;

    let elgamal_pubkey: GroupAffine<MpcEdwardsParameters> =
        mpc_input.clone().common.unwrap().pub_key;

    let message = <MFr as ElGamalLocalOrMPC<MFr>>::ElGamalPlaintext::prime_subgroup_generator();

    // let bad_message = <MFr as ElGamalLocalOrMPC<MFr>>::ElGamalPlaintext::prime_subgroup_generator();

    let enc_result = <MFr as ElGamalLocalOrMPC<MFr>>::ElGamalScheme::encrypt(
        &elgamal_generator,
        &elgamal_pubkey,
        &message,
        &mpc_input.clone().peculiar.unwrap().randomness,
    )
    .unwrap();

    let mut inputs = Vec::new();

    // elgamal param
    inputs.push(elgamal_generator.generator.x.reveal());
    inputs.push(elgamal_generator.generator.y.reveal());
    // elgamal pubkey
    inputs.push(elgamal_pubkey.x.reveal());
    inputs.push(elgamal_pubkey.y.reveal());

    // elgamal ciphertext
    inputs.push(enc_result.0.x.reveal());
    inputs.push(enc_result.0.y.reveal());
    inputs.push(enc_result.1.x.reveal());
    inputs.push(enc_result.1.y.reveal());

    // input commitment
    // inputs.push(peculiar_is_werewolf_commitment[0].x.reveal());
    // inputs.push(peculiar_is_werewolf_commitment[0].y.reveal());
    // inputs.push(peculiar_is_werewolf_commitment[1].x.reveal());
    // inputs.push(peculiar_is_werewolf_commitment[1].y.reveal());
    // inputs.push(peculiar_is_werewolf_commitment[2].x.reveal());
    // inputs.push(peculiar_is_werewolf_commitment[2].y.reveal());

    // inputs.push(peculiar_is_target_commitment[0].x.reveal());
    // inputs.push(peculiar_is_target_commitment[0].y.reveal());
    // inputs.push(peculiar_is_target_commitment[1].x.reveal());
    // inputs.push(peculiar_is_target_commitment[1].y.reveal());
    // inputs.push(peculiar_is_target_commitment[2].x.reveal());
    // inputs.push(peculiar_is_target_commitment[2].y.reveal());

    // prove
    let mpc_proof = MpcMarlin::prove(&mpc_index_pk, multi_divination_circuit, rng).unwrap();

    let proof = mpc_proof.reveal();

    // verify
    let is_valid = LocalMarlin::verify(&index_vk, &inputs, &proof, rng).unwrap();
    assert!(is_valid);

    // save divination reesult
    let file_path = format!("./werewolf/{}/secret_key.json", 0);
    let mut file = File::open(file_path).unwrap();
    let mut output_string = String::new();
    file.read_to_string(&mut output_string)
        .expect("Failed to read file");

    let data: ArgSecretKey = serde_json::from_str(&output_string).unwrap();

    let remove_prefix_string = if let Some(stripped) = data.secret_key.strip_prefix("0x") {
        stripped.to_string()
    } else {
        data.secret_key.clone()
    };

    let reader: &[u8] = &hex::decode(remove_prefix_string).unwrap();

    let deserialized_sk =
        <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalSecretKey::new(
            <<ark_ec::twisted_edwards_extended::GroupProjective<
                ark_ed_on_bls12_377::EdwardsParameters,
            > as ark_ec::ProjectiveCurve>::ScalarField as CanonicalDeserialize>::deserialize(
                reader,
            )
            .unwrap(),
        );

    println!("player {} is {}", target_id, is_werewolf_vec[target_id]);
    if Net::party_id() == 0 {
        let divination_result = <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalScheme::decrypt(
            &elgamal_generator.reveal(),
            &deserialized_sk,
            &enc_result.reveal(),
        )
        .unwrap();

        let mut divination_result_bool = false;

        if divination_result
            == <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalPlaintext::prime_subgroup_generator()
        {
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

#[derive(Debug, Deserialize)]
struct ElGamalPubKey {
    // public_key: GroupAffine<ark_ed_on_bls12_377::EdwardsParameters>,
    public_key: String,
}

#[derive(Debug, Deserialize)]
struct ElGamalSecKey {
    // secret_key: Fr,
    secret_key: String,
}

#[derive(Debug, Deserialize)]
struct ElGamalParam {
    elgamal_param: String,
}

fn get_elgamal_param_pubkey() -> (
    <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalParam,
    <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalPubKey,
) {
    // loading public key
    let file_path = format!("./werewolf/fortune_teller_key.json");
    let mut file = File::open(file_path).unwrap();
    let mut output_string = String::new();
    file.read_to_string(&mut output_string)
        .expect("Failed to read file");

    let pub_key: ElGamalPubKey = serde_json::from_str(&output_string).unwrap();

    let remove_prefix_string = if let Some(stripped) = pub_key.public_key.strip_prefix("0x") {
        stripped.to_string()
    } else {
        pub_key.public_key.clone()
    };

    let reader: &[u8] = &hex::decode(remove_prefix_string).unwrap();

    let deserialized_pk = <ark_ec::twisted_edwards_extended::GroupAffine<
        ark_ed_on_bls12_377::EdwardsParameters,
    > as CanonicalDeserialize>::deserialize(reader)
    .unwrap();

    // loading secret key
    // let file_path = format!("./werewolf/{}/secret_key.json", opt.target.unwrap());
    let file_path = format!("./werewolf/{}/secret_key.json", 0);

    let mut file = File::open(file_path).unwrap();
    let mut output_string = String::new();
    file.read_to_string(&mut output_string)
        .expect("Failed to read file");

    let sec_key: ElGamalSecKey = serde_json::from_str(&output_string).unwrap();

    let remove_prefix_string = if let Some(stripped) = sec_key.secret_key.strip_prefix("0x") {
        stripped.to_string()
    } else {
        sec_key.secret_key.clone()
    };

    let reader: &[u8] = &hex::decode(remove_prefix_string).unwrap();

    let deserialized_sk =
        <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalSecretKey::new(
            <<ark_ec::twisted_edwards_extended::GroupProjective<
                ark_ed_on_bls12_377::EdwardsParameters,
            > as ark_ec::ProjectiveCurve>::ScalarField as CanonicalDeserialize>::deserialize(
                reader,
            )
            .unwrap(),
        );

    // loading elgamal param
    let file_path = format!("./werewolf/elgamal_param.json");
    let mut file = File::open(file_path).unwrap();
    let mut output_string = String::new();
    file.read_to_string(&mut output_string)
        .expect("Failed to read file");

    let data: ElGamalParam = serde_json::from_str(&output_string).unwrap();

    let remove_prefix_string = if let Some(stripped) = data.elgamal_param.strip_prefix("0x") {
        stripped.to_string()
    } else {
        pub_key.public_key.clone()
    };

    let reader: &[u8] = &hex::decode(remove_prefix_string).unwrap();

    let deserialized_elgamal_param = <ark_ec::twisted_edwards_extended::GroupAffine<
        ark_ed_on_bls12_377::EdwardsParameters,
    > as CanonicalDeserialize>::deserialize(reader)
    .unwrap();

    let elgamal_param =
        <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalParam::new(deserialized_elgamal_param);

    (elgamal_param, deserialized_pk)
}

#[test]
#[ignore]
fn test_encryption_decryption() -> Result<(), std::io::Error> {
    // loading public key
    let file_path = format!("./werewolf/fortune_teller_key.json");
    let mut file = File::open(file_path).unwrap();
    let mut output_string = String::new();
    file.read_to_string(&mut output_string)
        .expect("Failed to read file");

    let pub_key: ElGamalPubKey = serde_json::from_str(&output_string).unwrap();

    let remove_prefix_string = if let Some(stripped) = pub_key.public_key.strip_prefix("0x") {
        stripped.to_string()
    } else {
        pub_key.public_key.clone()
    };

    let reader: &[u8] = &hex::decode(remove_prefix_string).unwrap();

    let deserialized_pk = <ark_ec::twisted_edwards_extended::GroupAffine<
        ark_ed_on_bls12_377::EdwardsParameters,
    > as CanonicalDeserialize>::deserialize(reader)
    .unwrap();

    // loading secret key
    // let file_path = format!("./werewolf/{}/secret_key.json", opt.target.unwrap());
    let file_path = format!("./werewolf/{}/secret_key.json", 0);

    let mut file = File::open(file_path).unwrap();
    let mut output_string = String::new();
    file.read_to_string(&mut output_string)
        .expect("Failed to read file");

    let sec_key: ElGamalSecKey = serde_json::from_str(&output_string).unwrap();

    let remove_prefix_string = if let Some(stripped) = sec_key.secret_key.strip_prefix("0x") {
        stripped.to_string()
    } else {
        sec_key.secret_key.clone()
    };

    let reader: &[u8] = &hex::decode(remove_prefix_string).unwrap();

    let deserialized_sk =
        <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalSecretKey::new(
            <<ark_ec::twisted_edwards_extended::GroupProjective<
                ark_ed_on_bls12_377::EdwardsParameters,
            > as ark_ec::ProjectiveCurve>::ScalarField as CanonicalDeserialize>::deserialize(
                reader,
            )
            .unwrap(),
        );

    // loading elgamal param
    let file_path = format!("./werewolf/elgamal_param.json");
    let mut file = File::open(file_path).unwrap();
    let mut output_string = String::new();
    file.read_to_string(&mut output_string)
        .expect("Failed to read file");

    let data: ElGamalParam = serde_json::from_str(&output_string).unwrap();

    let remove_prefix_string = if let Some(stripped) = data.elgamal_param.strip_prefix("0x") {
        stripped.to_string()
    } else {
        pub_key.public_key.clone()
    };

    let reader: &[u8] = &hex::decode(remove_prefix_string).unwrap();

    let deserialized_elgamal_param = <ark_ec::twisted_edwards_extended::GroupAffine<
        ark_ed_on_bls12_377::EdwardsParameters,
    > as CanonicalDeserialize>::deserialize(reader)
    .unwrap();

    let elgamal_param =
        <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalParam::new(deserialized_elgamal_param);

    let rng = &mut test_rng();

    let a = GroupAffine::<EdwardsParameters>::rand(rng);

    let randomness = <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalRandomness::rand(rng);

    let encrypted_a = <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalScheme::encrypt(
        &elgamal_param,
        &deserialized_pk,
        &a,
        &randomness,
    )
    .unwrap();

    let decrypted_a = <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalScheme::decrypt(
        &elgamal_param,
        &deserialized_sk,
        &encrypted_a,
    )
    .unwrap();

    assert_eq!(a, decrypted_a);

    Ok(())
}
