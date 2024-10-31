use game::{player::Player, Game, GameRules};
use mpc_algebra::channel::MpcSerNet;
use mpc_net::{MpcMultiNet as Net, MpcNet};
use std::io::{self, Write};
use std::path::PathBuf;
use structopt::StructOpt;
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

    game.role_assignment();

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
    for player in &players {
        if player.is_alive {
            let mut events = Vec::new();
            match player.role {
                Some(Role::Werewolf) => {
                    let werewolf_target = get_werewolf_target(game, player);
                    events.extend(game.werewolf_attack(werewolf_target));
                }
                Some(Role::FortuneTeller) => {
                    let seer_target = get_seer_target(game, player);
                    events.extend(game.seer_divination(seer_target));
                }
                Some(Role::Villager) => {
                    println!(
                        "{}さん、あなたは村人です。次の人に渡してください。",
                        player.name
                    );
                }
                None => unreachable!(),
            }
            for event in events {
                println!("{}", event);
            }
            wait_for_enter();
            // 各プレイヤーのフェーズ後にCLIをフラッシュ
            clear_screen();
        }
    }
}

fn wait_for_enter() {
    println!("Enterキーを押して次に進んでください。");
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
}

fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H"); // ANSI escape code for clearing the screen
    io::stdout().flush().unwrap();
}

fn get_werewolf_target(game: &Game, werewolf: &Player) -> usize {
    println!(
        "{}さん、あなたは人狼です。襲撃する対象を選んでください：",
        werewolf.name
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
        let target_id: usize = input.trim().parse().unwrap_or(0);

        if game
            .state
            .players
            .iter()
            .any(|p| p.id == target_id && p.is_alive && !p.is_werewolf())
        {
            return target_id;
        } else {
            println!("無効な選択です。もう一度選んでください。");
        }
    }
}

fn get_seer_target(game: &Game, seer: &Player) -> usize {
    println!(
        "{}さん、あなたは占い師です。占う対象を選んでください：",
        seer.name
    );
    game.state
        .players
        .iter()
        .filter(|p| p.is_alive && p.id != seer.id)
        .for_each(|p| println!("{}: {}", p.id, p.name));

    loop {
        print!("対象のIDを入力してください: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let target_id: usize = input.trim().parse().unwrap_or(0);

        if game
            .state
            .players
            .iter()
            .any(|p| p.id == target_id && p.is_alive && p.id != seer.id)
        {
            return target_id;
        } else {
            println!("無効な選択です。もう一度選んでください。");
        }
    }
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
    let mut votes = Vec::new();

    for player in &game.state.players {
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
                    votes.push(target_id);
                    break;
                } else {
                    println!("無効な選択です。もう一度選んでください。");
                }
            }
        } else {
            votes.push(usize::MAX); // 死亡したプレイヤーの投票は無効
        }
        clear_screen();
    }

    let events = game.voting_phase(votes);
    for event in events {
        println!("{}", event);
    }
}
