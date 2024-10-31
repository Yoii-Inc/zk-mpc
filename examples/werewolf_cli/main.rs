use ark_bls12_377::Fr;
use game::{player::Player, Game, GameRules};
use mpc_algebra::channel::MpcSerNet;
use mpc_algebra::Reveal;
use mpc_net::{MpcMultiNet as Net, MpcNet};
use std::io::{self, Write};
use std::path::PathBuf;
use structopt::StructOpt;
use zk_mpc::marlin::MFr;
use zk_mpc::werewolf::types::{GroupingParameter, Role};

pub mod game;

#[derive(Debug, StructOpt)]
struct Opt {
    // Player Id
    id: Option<usize>,

    // Input address file
    #[structopt(parse(from_os_str))]
    input: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // let stream = TcpStream::connect("127.0.0.1:8080").await?;
    // println!("サーバーに接続しました。");

    let opt = Opt::from_args();

    // init
    Net::init_from_file(
        opt.input.clone().unwrap().to_str().unwrap(),
        opt.id.unwrap(),
    );

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

    let mut game = Game::new(register_players(), game_rule);

    game.role_assignment(false);

    println!("{:?}", game.state.players);

    loop {
        night_phase(&mut game);
        morning_phase(&mut game);
        discussion_phase(&game);
        voting_phase(&mut game);

        if let Some(winner) = game.check_victory_condition() {
            println!("ゲーム終了！{}の勝利です！", winner);
            break;
        }

        game.next_phase();
    }

    Ok(())
}

fn register_players() -> Vec<String> {
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
        } else {
            break;
        }
    }

    println!(
        "Registered player name \"{}\". Waiting for other players to register.",
        name
    );

    Net::broadcast(&name)
}

fn night_phase(game: &mut Game) {
    println!("\n--- 夜のフェーズ ---");
    let players = game.state.players.clone();

    let player = players.iter().find(|p| p.id == Net::party_id()).unwrap();

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
    events.extend(game.werewolf_attack(attack_target));

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
    println!("Enterキーを押して次に進んでください。");
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
}

fn wait_for_everyone() {
    let dummy = 0_u32;
    Net::broadcast(&dummy);
}

fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H"); // ANSI escape code for clearing the screen
    io::stdout().flush().unwrap();
}

fn get_werewolf_target(game: &Game, player: &Player) -> MFr {
    let mut target_id = Fr::default();

    if player.role.unwrap().is_werewolf() {
        println!(
            "{}さん、あなたは人狼です。襲撃する対象を選んでください：",
            player.name
        );
        game.state
            .players
            .iter()
            .filter(|p| p.is_alive && !p.is_werewolf())
            .for_each(|p| println!("{}: {}", p.id, p.name));

        loop {
            print!("対象のIDを入力してください: ");
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
                println!("無効な選択です。もう一度選んでください。");
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
            "{}さん、あなたは占い師です。占う対象を選んでください：",
            player.name
        );
        game.state
            .players
            .iter()
            .filter(|p| p.is_alive && p.id != player.id)
            .for_each(|p| println!("{}: {}", p.id, p.name));

        loop {
            print!("対象のIDを入力してください: ");
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
                println!("無効な選択です。もう一度選んでください。");
            }
        }
    } else {
        target_id = Fr::default();
    }

    return MFr::from_add_shared(target_id);
}

fn morning_phase(game: &mut Game) {
    let events = game.morning_phase();
    for event in events {
        println!("{}", event);
    }
}

fn discussion_phase(game: &Game) {
    println!("\n--- 討論フェーズ ---");
    let events = game.discussion_phase();
    for event in events {
        println!("{}", event);
    }

    println!("生存しているプレイヤー：");
    game.state
        .players
        .iter()
        .filter(|p| p.is_alive)
        .for_each(|p| println!("{}: {}", p.id, p.name));

    println!("討論を行ってください。準備ができたらEnterキーを押してください。");
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
}

fn voting_phase(game: &mut Game) {
    println!("\n--- 投票フェーズ ---");
    let vote;

    let players = game.state.players.clone();

    let player = players.iter().find(|p| p.id == Net::party_id()).unwrap();

    if player.is_alive {
        println!("{}さん、投票する対象を選んでください：", player.name);
        game.state
            .players
            .iter()
            .filter(|p| p.is_alive && p.id != player.id)
            .for_each(|p| println!("{}: {}", p.id, p.name));

        loop {
            print!("対象のIDを入力してください: ");
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
                println!("無効な選択です。もう一度選んでください。");
            }
        }
    } else {
        vote = usize::MAX; // 死亡したプレイヤーの投票は無効
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

    let votes = Net::broadcast(&vote);

    // TODO: prove and verify

    clear_screen();

    let events = game.voting_phase(votes);
    for event in events {
        println!("{}", event);
    }
}
