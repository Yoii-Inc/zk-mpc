use ark_bls12_377::{Fr, FrParameters};
use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
use ark_ec::AffineCurve;
use ark_ff::BigInteger;
use ark_ff::FpParameters;
use ark_ff::PrimeField;
use ark_marlin::IndexProverKey;
use ark_mnt4_753::FqParameters;
use ark_serialize::{CanonicalDeserialize, Read};
use ark_std::test_rng;
use ark_std::PubUniformRand;
use ark_std::UniformRand;
use ark_std::{One, Zero};
use core::panic;
use mpc_algebra::encryption::elgamal::elgamal::Parameters;
use mpc_algebra::malicious_majority::*;
use mpc_algebra::BooleanWire;
use mpc_algebra::CommitmentScheme;
use mpc_algebra::EqualityZero;
use mpc_algebra::FromLocal;
use mpc_algebra::LessThan;
use mpc_algebra::Reveal;
use mpc_net::multi::MPCNetConnection;
use mpc_net::{MpcMultiNet as Net, MpcNet};
use rand::Rng;
use serde::Deserialize;
use std::sync::Arc;
use std::{fs::File, path::PathBuf};
use structopt::StructOpt;
use zk_mpc::circuits::LocalOrMPC;
use zk_mpc::circuits::{
    AnonymousVotingCircuit, DivinationCircuit, ElGamalLocalOrMPC, KeyPublicizeCircuit,
    RoleAssignmentCircuit, WinningJudgeCircuit,
};
use zk_mpc::input::InputWithCommit;
use zk_mpc::input::MpcInputTrait;
use zk_mpc::input::WerewolfKeyInput;
use zk_mpc::input::WerewolfMpcInput;
use zk_mpc::marlin::LocalMarlin;
use zk_mpc::marlin::MFr;
use zk_mpc::marlin::MpcMarlin;
use zk_mpc::marlin::{prove_and_verify, setup_and_index};
use zk_mpc::preprocessing;
use zk_mpc::serialize::{write_r, write_to_file};
use zk_mpc::she;
use zk_mpc::werewolf::utils::generate_random_commitment;
use zk_mpc::werewolf::utils::load_random_commitment;
use zk_mpc::werewolf::utils::load_random_value;
use zk_mpc::werewolf::{
    types::{GroupingParameter, Role, RoleData},
    utils::{calc_shuffle_matrix, generate_individual_shuffle_matrix},
};

use nalgebra as na;

#[derive(Debug, StructOpt, Clone)]
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

struct VoteArg {
    target_id: usize,
}

impl VoteArg {
    fn new(target_id: usize) -> Self {
        Self { target_id }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::from_args();

    println!("opt is {:?}", opt);

    // init mode is executed by one process. other modes are executed by all players.
    if opt.mode.as_str() == "init" {
        println!("Init mode");
        // initialize werewolf game
        initialize_game(&opt)?;

        // preprocessing MPC
        preprocessing_mpc(&opt)?;
    } else {
        let mut net =
            MPCNetConnection::init_from_path(&opt.clone().input.unwrap(), opt.id.unwrap() as u32);
        net.listen().await.unwrap();
        net.connect_to_all().await.unwrap();

        let net_arc = Arc::new(net);

        Net::simulate(net_arc, opt.clone(), |_, opt| async move {
            match opt.mode.as_str() {
                "preprocessing" => {
                    println!("Preprocessing mode");
                    // preprocessing calculation of werewolf game

                    preprocessing_werewolf(&opt).await.unwrap();
                }
                "role_assignment" => {
                    println!("Role assignment mode");
                    // role assignment

                    role_assignment(&opt).await.unwrap();
                }
                "night" => {
                    println!("Night mode");
                    // run the night phase
                    night_werewolf(&opt).await.unwrap();
                }
                "vote" => {
                    let mut net = MPCNetConnection::init_from_path(
                        &opt.clone().input.unwrap(),
                        opt.id.unwrap() as u32,
                    );
                    net.listen().await.unwrap();
                    net.connect_to_all().await.unwrap();

                    let net_arc = Arc::new(net);

                    Net::simulate(net_arc, opt, |_, opt| async move {
                        println!("Vote mode");
                        // run the vote phase
                        voting(&opt).await.unwrap();
                    })
                    .await;
                }
                "judgment" => {
                    println!("Judgment mode");
                    // run the judgement phase
                    winning_judgment(&opt).await.unwrap();
                }

                _ => {
                    // Err(std::io::Error::new(
                    //     std::io::ErrorKind::InvalidInput,
                    //     "Error: Invalid mode. Only init or night are supported",
                    // ));
                    panic!();
                }
            };
        })
        .await;
    }

    Ok(())
}

fn initialize_game(opt: &Opt) -> Result<(), std::io::Error> {
    // public.json
    let file_path = "./werewolf_game/public.json";
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
    // TODO: randomize
    let role = ["FortuneTeller", "Werewolf", "Villager"];
    for i in 0..opt.num_players.unwrap() {
        let file_path = format!("./werewolf_game/{}/role.json", i);
        File::create(&file_path)?;

        let datas = vec![("role".to_string(), role[i].to_string())];

        write_to_file(datas, &file_path).unwrap();
    }

    Ok(())
}

fn preprocessing_mpc(opt: &Opt) -> Result<(), std::io::Error> {
    // let opt = Opt::from_args();

    // preprocessing
    let mut rng = test_rng();
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
    write_r(
        opt.num_players.unwrap(),
        "werewolf_game",
        r_angle,
        r_bracket,
    )
    .unwrap();

    Ok(())
}

async fn preprocessing_werewolf(opt: &Opt) -> Result<(), std::io::Error> {
    // net init
    // TODO: changable
    let num_players = 3;

    let pedersen_param = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::setup(&mut test_rng()).unwrap();
    generate_random_commitment(&mut test_rng(), &pedersen_param).await;

    // dummmy input
    let mut pub_key_or_dummy_x = vec![Fr::from(0); num_players];
    let mut pub_key_or_dummy_y = vec![Fr::from(0); num_players];
    let is_fortune_teller = vec![Fr::from(0); num_players];

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
    mpc_input.set_private_input(Some((
        pub_key_or_dummy_x,
        pub_key_or_dummy_y,
        is_fortune_teller,
    )));
    mpc_input.generate_input(rng);

    let key_publicize_circuit = KeyPublicizeCircuit {
        mpc_input: mpc_input.clone(),
    };

    // prove
    let mpc_proof = MpcMarlin::prove(&mpc_index_pk, key_publicize_circuit, rng).unwrap();

    let proof = mpc_proof.reveal().await;

    // let pk = GroupAffine::<MpcEdwardsParameters> {
    //     x: mpc_input.pub_key.x.reveal(),
    //     y: mpc_input.pub_key.y.reveal(),
    //     infinity: mpc_input.pub_key.infinity.reveal(),
    // };

    let _pk_x: MFr = mpc_input
        .peculiar
        .clone()
        .unwrap()
        .pub_key_or_dummy_x
        .iter()
        .map(|x| x.input)
        .sum();

    let _pk_y: MFr = mpc_input
        .peculiar
        .clone()
        .unwrap()
        .pub_key_or_dummy_y
        .iter()
        .map(|x| x.input)
        .sum();

    let inputs = [];

    // verify
    let is_valid = LocalMarlin::verify(&index_vk, &inputs, &proof, rng).unwrap();
    assert!(is_valid);

    // save to file
    if Net.party_id() == 0 {
        let datas = vec![("public_key".to_string(), pk)];

        write_to_file(datas, "./werewolf_game/fortune_teller_key.json").unwrap();

        let secret_data = vec![("secret_key".to_string(), sk.0)];

        write_to_file(
            secret_data,
            format!("./werewolf_game/{}/secret_key.json", Net.party_id()).as_str(),
        )
        .unwrap();

        let elgamal_parameter_data = vec![("elgamal_param".to_string(), elgamal_params.generator)];

        write_to_file(elgamal_parameter_data, "./werewolf_game/elgamal_param.json").unwrap();
    }

    Ok(())
}

async fn role_assignment(opt: &Opt) -> Result<(), std::io::Error> {
    // init
    let grouping_parameter = GroupingParameter::new(
        vec![
            (Role::Villager, (1, false)),
            (Role::FortuneTeller, (1, false)),
            (Role::Werewolf, (1, false)),
        ]
        .into_iter()
        .collect(),
    );

    let n = grouping_parameter.get_num_players();
    let m = grouping_parameter.get_num_groups();

    let rng = &mut test_rng();

    let pedersen_param = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::setup(rng).unwrap();

    let player_randomness = load_random_value().await?;
    let player_commitment = load_random_commitment()?;

    // calc
    let shuffle_matrix = vec![
        generate_individual_shuffle_matrix(
            grouping_parameter.get_num_players(),
            grouping_parameter.get_num_groups(),
            rng,
        );
        2
    ];

    let mut inputs = vec![];

    for id in 0..n {
        let (role, role_val, player_ids) =
            calc_shuffle_matrix(&grouping_parameter, &shuffle_matrix, id).unwrap();
        println!("role is {:?}", role);
        println!("fellow is {:?}", player_ids);
        inputs.push(Fr::from(role_val as i32));
    }

    println!("inputs is {:?}", inputs);

    let randomness = (0..n)
        .map(|_| <Fr as LocalOrMPC<Fr>>::PedersenRandomness::rand(rng))
        .collect::<Vec<_>>();

    let commitment = (0..n)
        .map(|i| {
            <Fr as LocalOrMPC<Fr>>::PedersenComScheme::commit(
                &pedersen_param,
                &inputs[i].into_repr().to_bytes_le(),
                &randomness[i],
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    // prove
    let local_role_circuit = RoleAssignmentCircuit {
        num_players: n,
        max_group_size: grouping_parameter.get_max_group_size(),
        pedersen_param: pedersen_param.clone(),
        tau_matrix: na::DMatrix::<Fr>::zeros(n + m, n + m),
        shuffle_matrices: vec![na::DMatrix::<Fr>::zeros(n + m, n + m); 2],
        role_commitment: commitment,
        randomness,
        player_randomness: player_randomness.clone(),
        player_commitment: player_commitment.clone(),
    };

    let srs = LocalMarlin::universal_setup(1000000, 50000, 100000, rng).unwrap();
    let (index_pk, index_vk) = LocalMarlin::index(&srs, local_role_circuit).unwrap();
    let mpc_index_pk = IndexProverKey::from_public(index_pk);

    let mpc_pedersen_param = <MFr as LocalOrMPC<MFr>>::PedersenParam::from_local(&pedersen_param);

    let mpc_randomness = (0..n)
        .map(|_| <MFr as LocalOrMPC<MFr>>::PedersenRandomness::rand(rng))
        .collect::<Vec<_>>();

    let converted_inputs = inputs
        .iter()
        .map(|x| <MFr as LocalOrMPC<MFr>>::convert_input(&MFr::from_public(*x)))
        .collect::<Vec<_>>();

    let role_commitment = (0..n)
        .map(|i| {
            <MFr as LocalOrMPC<MFr>>::PedersenComScheme::commit(
                &mpc_pedersen_param,
                &converted_inputs[i],
                &mpc_randomness[i],
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    let mpc_role_circuit = RoleAssignmentCircuit {
        num_players: n,
        max_group_size: grouping_parameter.get_max_group_size(),
        pedersen_param: mpc_pedersen_param,
        tau_matrix: grouping_parameter.generate_tau_matrix(),
        shuffle_matrices: shuffle_matrix,
        randomness: mpc_randomness,
        role_commitment: role_commitment.clone(),
        player_randomness: player_randomness
            .iter()
            .map(|x| MFr::from_public(*x))
            .collect::<Vec<_>>(),
        player_commitment: player_commitment
            .iter()
            .map(|x| <MFr as LocalOrMPC<MFr>>::PedersenCommitment::from_public(*x))
            .collect::<Vec<_>>(),
    };

    let mut inputs = player_commitment
        .iter()
        .flat_map(|c| vec![c.x, c.y])
        .collect::<Vec<_>>();

    for commitment in role_commitment.iter() {
        inputs.push(commitment.reveal().await.x);
        inputs.push(commitment.reveal().await.y);
    }

    assert!(prove_and_verify(&mpc_index_pk, &index_vk, mpc_role_circuit.clone(), inputs).await);

    Ok(())
}

async fn night_werewolf(opt: &Opt) -> Result<(), std::io::Error> {
    // init

    let self_role = get_my_role();

    multi_divination().await?;

    println!("My role is {:?}", self_role);
    Ok(())
}

#[derive(Debug, Deserialize)]
struct ArgSecretKey {
    secret_key: String,
}

fn get_my_role() -> Role {
    let id = Net.party_id();

    println!("id is {:?}", id);

    // read role.json
    let file_path = format!("./werewolf_game/{}/role.json", id);
    let mut file = File::open(file_path).unwrap();
    let mut output_string = String::new();
    file.read_to_string(&mut output_string)
        .expect("Failed to read file");

    let data: RoleData = serde_json::from_str(&output_string).unwrap();

    let remove_prefix_string = if let Some(stripped) = data.role().strip_prefix("0x") {
        stripped.to_string()
    } else {
        data.role().clone()
    };

    let reader: &[u8] = &hex::decode(remove_prefix_string).unwrap();

    let deserialized_role = <String as CanonicalDeserialize>::deserialize(reader).unwrap();

    match deserialized_role.as_str() {
        "FortuneTeller" => Role::FortuneTeller,
        "Werewolf" => Role::Werewolf,
        "Villager" => Role::Villager,
        _ => panic!("Invalid role"),
    }
}

async fn multi_divination() -> Result<(), std::io::Error> {
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

    let _peculiar_is_werewolf_commitment: Vec<MpcEdwardsAffine> = mpc_input
        .peculiar
        .clone()
        .unwrap()
        .is_werewolf
        .iter()
        .map(|x| x.commitment)
        .collect::<Vec<_>>();

    let _peculiar_is_target_commitment: Vec<MpcEdwardsAffine> = mpc_input
        .peculiar
        .clone()
        .unwrap()
        .is_target
        .iter()
        .map(|x| x.commitment)
        .collect::<Vec<_>>();

    let elgamal_generator: Parameters<MpcEdwardsProjective> =
        mpc_input.clone().common.unwrap().elgamal_param;

    let elgamal_pubkey: MpcEdwardsAffine = mpc_input.clone().common.unwrap().pub_key;

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
    inputs.push(elgamal_generator.generator.reveal().await.x);
    inputs.push(elgamal_generator.generator.reveal().await.y);
    // elgamal pubkey
    inputs.push(elgamal_pubkey.reveal().await.x);
    inputs.push(elgamal_pubkey.reveal().await.y);

    // elgamal ciphertext
    inputs.push(enc_result.0.reveal().await.x);
    inputs.push(enc_result.0.reveal().await.y);
    inputs.push(enc_result.1.reveal().await.x);
    inputs.push(enc_result.1.reveal().await.y);

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

    let proof = mpc_proof.reveal().await;

    // verify
    let is_valid = LocalMarlin::verify(&index_vk, &inputs, &proof, rng).unwrap();
    assert!(is_valid);

    // save divination reesult
    let file_path = format!("./werewolf_game/{}/secret_key.json", 0);
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
    if Net.party_id() == 0 {
        let divination_result = <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalScheme::decrypt(
            &elgamal_generator.reveal().await,
            &deserialized_sk,
            &enc_result.reveal().await,
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
            format!("./werewolf_game/{}/divination_result.json", Net.party_id()).as_str(),
        )
        .unwrap();
    }

    Ok(())
}

async fn voting(opt: &Opt) -> Result<(), std::io::Error> {
    // init
    let rng = &mut test_rng();

    let pedersen_param = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::setup(rng).unwrap();

    let player_randomness = load_random_value().await?;
    let player_commitment = load_random_commitment()?;

    assert_eq!(player_randomness.len(), Net.n_parties());
    assert_eq!(player_commitment.len(), Net.n_parties());

    // calc
    let most_voted_id = Fr::from(1);
    let invalid_most_voted_id = Fr::from(0);

    // prove
    let local_voting_circuit = AnonymousVotingCircuit {
        is_target_id: vec![
            vec![Fr::from(0), Fr::from(1), Fr::from(0)],
            vec![Fr::from(0), Fr::from(1), Fr::from(0)],
            vec![Fr::from(0), Fr::from(0), Fr::from(1)],
        ],
        pedersen_param: pedersen_param.clone(),
        player_randomness: player_randomness.clone(),
        player_commitment: player_commitment.clone(),
    };

    let (mpc_index_pk, index_vk) = setup_and_index(local_voting_circuit);

    let rng = &mut test_rng();
    let mpc_pedersen_param = <MFr as LocalOrMPC<MFr>>::PedersenParam::from_local(&pedersen_param);

    let mpc_voting_circuit = AnonymousVotingCircuit {
        is_target_id: vec![
            vec![
                MFr::king_share(Fr::from(0), rng),
                MFr::king_share(Fr::from(1), rng),
                MFr::king_share(Fr::from(0), rng),
            ],
            vec![
                MFr::king_share(Fr::from(0), rng),
                MFr::king_share(Fr::from(1), rng),
                MFr::king_share(Fr::from(0), rng),
            ],
            vec![
                MFr::king_share(Fr::from(0), rng),
                MFr::king_share(Fr::from(0), rng),
                MFr::king_share(Fr::from(1), rng),
            ],
        ],
        pedersen_param: mpc_pedersen_param,
        player_randomness: player_randomness
            .iter()
            .map(|x| MFr::from_public(*x))
            .collect::<Vec<_>>(),
        player_commitment: player_commitment
            .iter()
            .map(|x| <MFr as LocalOrMPC<MFr>>::PedersenCommitment::from_public(*x))
            .collect::<Vec<_>>(),
    };

    let mut inputs = player_commitment
        .iter()
        .flat_map(|c| vec![c.x, c.y])
        .collect::<Vec<_>>();

    inputs.push(most_voted_id);
    let invalid_inputs = vec![invalid_most_voted_id];

    assert!(prove_and_verify(&mpc_index_pk, &index_vk, mpc_voting_circuit.clone(), inputs).await);

    assert!(!prove_and_verify(&mpc_index_pk, &index_vk, mpc_voting_circuit, invalid_inputs).await);

    println!("Player {} received the most votes", most_voted_id);

    Ok(())
}

async fn winning_judgment(opt: &Opt) -> Result<(), std::io::Error> {
    // init
    let player_num = 3;
    let num_alive = Fr::from(3);

    let rng = &mut test_rng();

    let am_werewolf_vec = (0..player_num)
        .map(|_| InputWithCommit::default())
        .collect::<Vec<_>>();

    let am_werewolf_val = (0..player_num)
        .map(|_| rng.gen_bool(0.5))
        .collect::<Vec<_>>();

    let mpc_am_werewolf_vec = (0..player_num)
        .map(|i| {
            let mut a: InputWithCommit<MFr> = InputWithCommit::default();
            a.allocation = i;
            a.input = MFr::from(am_werewolf_val[i]);
            a
        })
        .collect::<Vec<_>>();

    let pedersen_param = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::setup(rng).unwrap();
    let mpc_pedersen_param = <MFr as LocalOrMPC<MFr>>::PedersenParam::from_local(&pedersen_param);

    let common_randomness = <Fr as LocalOrMPC<Fr>>::PedersenRandomness::pub_rand(rng);
    let mpc_common_randomness =
        <MFr as LocalOrMPC<MFr>>::PedersenRandomness::from_public(common_randomness);

    let mpc_am_werewolf_vec = mpc_am_werewolf_vec
        .iter()
        .map(|x| x.generate_input(&mpc_pedersen_param, &mpc_common_randomness))
        .collect::<Vec<_>>();

    let player_randomness = load_random_value().await?;
    let player_commitment = load_random_commitment()?;

    // calc
    // TODO: correctly.

    let num_werewolf = mpc_am_werewolf_vec
        .iter()
        .fold(MFr::zero(), |acc, x| acc + x.input);
    let num_citizen = MFr::from_public(num_alive) - num_werewolf;
    let exists_werewolf = num_werewolf.is_zero_shared().await;

    let game_state = exists_werewolf.field() * MFr::from(2_u32)
        + (!exists_werewolf).field()
            * (num_werewolf.is_smaller_than(&num_citizen).await.field() * MFr::from(3_u32)
                + (MFr::one() - (num_werewolf.is_smaller_than(&num_citizen).await).field())
                    * MFr::from(1_u32));

    // prove
    let local_judgment_circuit = WinningJudgeCircuit {
        num_alive,
        pedersen_param: pedersen_param.clone(),
        am_werewolf: am_werewolf_vec.clone(),
        game_state: Fr::default(),

        player_randomness: player_randomness.clone(),
        player_commitment: player_commitment.clone(),
    };

    let (mpc_index_pk, index_vk) = setup_and_index(local_judgment_circuit);

    let mpc_pedersen_param = <MFr as LocalOrMPC<MFr>>::PedersenParam::from_local(&pedersen_param);

    let mpc_judgment_circuit = WinningJudgeCircuit {
        num_alive: MFr::from_public(num_alive),
        pedersen_param: mpc_pedersen_param,
        am_werewolf: mpc_am_werewolf_vec.clone(),
        game_state,
        player_randomness: player_randomness
            .iter()
            .map(|x| MFr::from_public(*x))
            .collect::<Vec<_>>(),
        player_commitment: player_commitment
            .iter()
            .map(|x| <MFr as LocalOrMPC<MFr>>::PedersenCommitment::from_public(*x))
            .collect::<Vec<_>>(),
    };

    let mut inputs = player_commitment
        .iter()
        .flat_map(|c| vec![c.x, c.y])
        .collect::<Vec<_>>();

    inputs.extend_from_slice(&[num_alive, game_state.reveal().await]);

    for iwc in mpc_am_werewolf_vec.iter() {
        inputs.push(iwc.commitment.reveal().await.x);
        inputs.push(iwc.commitment.reveal().await.y);
    }

    let invalid_inputs = vec![];

    assert!(
        prove_and_verify(
            &mpc_index_pk,
            &index_vk,
            mpc_judgment_circuit.clone(),
            inputs
        )
        .await
    );

    assert!(
        !prove_and_verify(
            &mpc_index_pk,
            &index_vk,
            mpc_judgment_circuit,
            invalid_inputs
        )
        .await
    );

    println!("am_werewolf? {:?}", am_werewolf_val);

    match game_state.reveal().await {
        ref state if *state == Fr::from(1) => println!("Werewolf win"),
        ref state if *state == Fr::from(2) => println!("Villager win"),
        ref state if *state == Fr::from(3) => println!("Game Continue"),
        _ => println!("Error"),
    }

    let self_role = get_my_role();

    multi_divination().await?;

    println!("My role is {:?}", self_role);

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
    let file_path = format!("./werewolf_game/fortune_teller_key.json");
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
    let file_path = format!("./werewolf_game/{}/secret_key.json", 0);

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

    let _deserialized_sk =
        <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalSecretKey::new(
            <<ark_ec::twisted_edwards_extended::GroupProjective<
                ark_ed_on_bls12_377::EdwardsParameters,
            > as ark_ec::ProjectiveCurve>::ScalarField as CanonicalDeserialize>::deserialize(
                reader,
            )
            .unwrap(),
        );

    // loading elgamal param
    let file_path = format!("./werewolf_game/elgamal_param.json");
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

#[cfg(test)]
mod tests {

    use mpc_algebra::channel::MpcSerNet;
    use mpc_net::LocalTestNet;

    use super::*;

    #[ignore]
    fn test_encryption_decryption() -> Result<(), std::io::Error> {
        // loading public key
        let file_path = format!("./werewolf_game/fortune_teller_key.json");
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
        let file_path = format!("./werewolf_game/{}/secret_key.json", 0);

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

        let deserialized_sk = <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalSecretKey::new(
            <<ark_ec::twisted_edwards_extended::GroupProjective<
                ark_ed_on_bls12_377::EdwardsParameters,
            > as ark_ec::ProjectiveCurve>::ScalarField as CanonicalDeserialize>::deserialize(
                reader,
            )
            .unwrap(),
        );

        // loading elgamal param
        let file_path = format!("./werewolf_game/elgamal_param.json");
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

        let a = GroupAffine::<ark_ed_on_bls12_377::EdwardsParameters>::rand(rng);

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

    #[ignore]
    #[tokio::test(flavor = "multi_thread")]
    async fn check_commitment() {
        const N_PARTIES: usize = 3;
        let testnet = LocalTestNet::new_local_testnet(N_PARTIES).await.unwrap();

        testnet
            .simulate_network_round((), |conn, _| async move {
                let rng = &mut test_rng();

                let pedersen_param = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::setup(rng).unwrap();

                let player_randomness = load_random_value().await.unwrap();
                let player_commitment = load_random_commitment().unwrap();

                let calculated_commitment = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::commit(
                    &pedersen_param,
                    &player_randomness[conn.party_id() as usize]
                        .into_repr()
                        .to_bytes_le(),
                    &<Fr as LocalOrMPC<Fr>>::PedersenRandomness::default(),
                )
                .unwrap();

                let res = Net.broadcast(&calculated_commitment).await;

                println!("{:?}, {:?}", player_commitment.len(), res.len());

                assert_eq!(player_commitment[0..N_PARTIES].to_vec(), res);
            })
            .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_voting() {
        const N_PARTIES: usize = 3;
        let testnet = LocalTestNet::new_local_testnet(N_PARTIES).await.unwrap();

        testnet
            .simulate_network_round((), |conn, _| async move {
                let opt = Opt {
                    mode: "voting".to_string(),
                    num_players: Some(3),
                    target: Some(1),
                    id: Some(conn.party_id() as usize),
                    input: Some(PathBuf::from("./data/3")),
                };
                voting(&opt).await.unwrap()
            })
            .await;
    }
}
