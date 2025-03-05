use ark_bls12_377::Fr;
use ark_std::test_rng;
use game::{player::Player, Game, GameRules};
use mpc_algebra::channel::MpcSerNet;
use mpc_algebra::Reveal;
use mpc_net::multi::MPCNetConnection;
use mpc_net::{MpcMultiNet as Net, MpcNet};
use std::io::{self, Write};
use std::path::PathBuf;
use structopt::StructOpt;
use zk_mpc::marlin::MFr;
use zk_mpc::werewolf::types::{GroupingParameter, Role};
use zk_mpc::werewolf::utils::generate_random_commitment;

pub mod game;

#[derive(Debug, StructOpt, Clone)]
struct Opt {
    // Player Id
    id: Option<usize>,

    // Input address file
    #[structopt(parse(from_os_str))]
    input: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::from_args();

    // init
    // Net::init_from_file(
    //     opt.input.clone().unwrap().to_str().unwrap(),
    //     opt.id.unwrap(),
    // );

    let mut net =
        MPCNetConnection::init_from_path(&opt.clone().input.unwrap(), opt.id.unwrap() as u32);
    net.listen().await.unwrap();
    net.connect_to_all().await.unwrap();

    Net::simulate(net, opt.clone(), |_, opt| async move {
        let game_rule = GameRules {
            min_players: 4,
            max_players: 10,
            werewolf_ratio: 0.3,
            seer_count: 1,
            grouping_parameter: GroupingParameter::new(
                vec![
                    (Role::Villager, (2, false)),
                    (Role::Werewolf, (1, false)),
                    (Role::FortuneTeller, (1, false)),
                ]
                .into_iter()
                .collect(),
            ),
        };

        let mut game = Game::new(register_players().await, game_rule);

        game.role_assignment(true).await;

        println!("{:?}", game.state.players);

        generate_random_commitment(&mut test_rng(), &game.state.pedersen_param).await;

        loop {
            night_phase(&mut game).await;
            if game.state.day > 1 {
                if let Some(winner) = game.check_victory_condition(true) {
                    println!("Game is over! {} wins!", winner);
                    break;
                }
            }
            morning_phase(&mut game).await;
            discussion_phase(&game);
            voting_phase(&mut game).await;

            if let Some(winner) = game.check_victory_condition(true) {
                println!("Game is over! {} wins!", winner);
                break;
            } else {
                println!("Despite the execution, a terrifying night is coming.");
            }

            game.next_phase();
        }
    })
    .await;

    Ok(())
}

async fn register_players() -> Vec<String> {
    let mut name;

    loop {
        print!("Please enter your player name (Press Enter to finish): ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        name = input.trim().to_string();

        if name.is_empty() {
            println!("Player name is empty.");
            continue;
        } else if name.len() >= 20 {
            println!("Player name must be less than 20 characters.");
            continue;
        } else {
            break;
        }
    }

    println!(
        "Registered player name \"{}\". Waiting for other players to register.",
        name
    );

    let mut bytes = vec![0u8; 20];
    bytes[..name.len()].copy_from_slice(name.as_bytes());
    Net.broadcast(&bytes)
        .await
        .into_iter()
        .map(|b| String::from_utf8_lossy(&b[..]).to_string())
        .collect()
}

async fn night_phase(game: &mut Game) {
    println!("\n--- Night Phase ---");
    let players = game.state.players.clone();

    let player = players
        .iter()
        .find(|p| p.id == Net.party_id() as usize)
        .unwrap();

    let mut events = Vec::new();

    match player.role {
        Some(Role::Villager) => {
            println!("You are a villager. Please wait until everyone has finished their actions.");
        }
        Some(Role::Werewolf) => {
            println!("You are a werewolf.");
        }
        Some(Role::FortuneTeller) => {
            println!("You are a fortune Teller. Please wait until other roles actions.");
        }
        None => todo!(),
    }

    let attack_target = get_werewolf_target(game, player);
    events.extend(game.werewolf_attack(attack_target).await);

    let seer_target = get_seer_target(game, player);
    events.extend(game.seer_divination(seer_target));

    for event in events {
        println!("{}", event);
    }
    wait_for_enter();
    println!("Waiting for all players to finish their actions.");
    wait_for_everyone();
    clear_screen();
}

fn wait_for_enter() {
    println!("Press Enter to continue.");
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
}

async fn wait_for_everyone() {
    let dummy = 0_u32;
    Net.broadcast(&dummy).await;
}

fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H"); // ANSI escape code for clearing the screen
    io::stdout().flush().unwrap();
}

fn get_werewolf_target(game: &Game, player: &Player) -> MFr {
    let mut target_id = Fr::default();

    if player.role.unwrap().is_werewolf() {
        println!(
            "{}, you are a werewolf. Choose your target to attack:",
            player.name
        );
        game.state
            .players
            .iter()
            .filter(|p| p.is_alive && !p.is_werewolf())
            .for_each(|p| println!("{}: {}", p.id, p.name));

        loop {
            print!("Enter the ID of your target: ");
            io::stdout().flush().unwrap();

            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            target_id = Fr::from(input.trim().parse().unwrap_or(0) as i32);

            if game
                .state
                .players
                .iter()
                .any(|p| Fr::from(p.id as i32) == target_id && p.is_alive && !p.is_werewolf())
            {
                break;
            } else {
                println!("Invalid selection. Please choose again.");
            }
        }
    } else {
        target_id = Fr::default();
    }

    return MFr::from_add_shared(target_id);
}

fn get_seer_target(game: &Game, player: &Player) -> MFr {
    let mut target_id = Fr::default();

    if player.role.unwrap() == Role::FortuneTeller {
        println!(
            "{}, you are a fortune teller. Choose a target to divine:",
            player.name
        );
        game.state
            .players
            .iter()
            .filter(|p| p.is_alive && p.id != player.id)
            .for_each(|p| println!("{}: {}", p.id, p.name));

        loop {
            print!("Enter the ID of your target: ");
            io::stdout().flush().unwrap();

            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            target_id = Fr::from(input.trim().parse().unwrap_or(0) as i32);

            if game
                .state
                .players
                .iter()
                .any(|p| Fr::from(p.id as i32) == target_id && p.is_alive && p.id != player.id)
            {
                break;
            } else {
                println!("Invalid selection. Please choose again.");
            }
        }
    } else {
        target_id = Fr::default();
    }

    return MFr::from_add_shared(target_id);
}

async fn morning_phase(game: &mut Game) {
    let events = game.morning_phase().await;
    for event in events {
        println!("{}", event);
    }
}

fn discussion_phase(game: &Game) {
    println!("\n--- Discussion Phase ---");
    let events = game.discussion_phase();
    for event in events {
        println!("{}", event);
    }

    println!("Players still alive:");
    game.state
        .players
        .iter()
        .filter(|p| p.is_alive)
        .for_each(|p| println!("{}: {}", p.id, p.name));

    println!("Please discuss. Press Enter when you are ready.");
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
}

async fn voting_phase(game: &mut Game) {
    println!("\n--- Voting Phase ---");
    let vote;

    let players = game.state.players.clone();

    let player = players
        .iter()
        .find(|p| p.id == Net.party_id() as usize)
        .unwrap();

    if player.is_alive {
        println!("{} please choose who to vote for:", player.name);
        game.state
            .players
            .iter()
            .filter(|p| p.is_alive && p.id != player.id)
            .for_each(|p| println!("{}: {}", p.id, p.name));

        loop {
            print!("Please enter the ID of the player you want to vote for: ");
            io::stdout().flush().unwrap();

            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            let target_id: usize = input.trim().parse().unwrap_or(usize::MAX);

            if game
                .state
                .players
                .iter()
                .any(|p| p.id == target_id && p.is_alive && p.id != player.id)
            {
                vote = target_id;
                break;
            } else {
                println!("Invalid selection. Please choose again.");
            }
        }
    } else {
        vote = usize::MAX; // The vote of a dead player is invalid.
    }
    clear_screen();

    if player.is_alive {
        println!(
            "You voted for {}. Please wait for other players to finish voting.",
            vote
        );
    } else {
        println!("You are dead, so your vote is invalid. Please wait for other players to finish voting.");
    }

    let votes = Net.broadcast(&vote).await;

    // TODO: prove and verify

    clear_screen();

    let events = game.voting_phase(votes, true).await;
    for event in events {
        println!("{}", event);
    }
}
