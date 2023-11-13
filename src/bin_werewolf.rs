use ark_bls12_377::FrParameters;
use ark_ff::FpParameters;
use ark_mnt4_753::FqParameters;

use serialize::{write_r, write_to_file};
use std::{fs::File, path::PathBuf};
use structopt::StructOpt;

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
        }
        "night" => {
            println!("Night mode");
            // run the night phase
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
