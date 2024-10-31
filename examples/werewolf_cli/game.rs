use ark_bls12_377::Fr;
use ark_crypto_primitives::commitment::pedersen;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_ff::UniformRand;
use ark_marlin::IndexProverKey;
use ark_std::One;
use mpc_algebra::commitment::CommitmentScheme;
use mpc_algebra::BooleanWire;
use mpc_algebra::FromLocal;
use mpc_algebra::MpcBooleanField;
use mpc_algebra::Reveal;
use mpc_net::{MpcMultiNet as Net, MpcNet};
use nalgebra::DMatrix;
use player::Player;
use rand::Rng;
use zk_mpc::circuits::LocalOrMPC;
use zk_mpc::circuits::RoleAssignmentCircuit;
use zk_mpc::marlin::prove_and_verify;
use zk_mpc::marlin::LocalMarlin;
use zk_mpc::marlin::MFr;
use zk_mpc::werewolf::types::GroupingParameter;
use zk_mpc::werewolf::types::Role;
use zk_mpc::werewolf::utils::calc_shuffle_matrix;
use zk_mpc::werewolf::utils::generate_individual_shuffle_matrix;
use zk_mpc::werewolf::utils::load_random_commitment;
use zk_mpc::werewolf::utils::load_random_value;

pub mod player;
pub mod role;

pub struct Game {
    pub state: GameState,
    pub rules: GameRules,
}

pub struct GameState {
    pub players: Vec<Player>,
    pub current_phase: GamePhase,
    pub day: u32,
}

pub struct GameRules {
    pub min_players: usize,
    pub max_players: usize,
    pub werewolf_ratio: f32,
    pub seer_count: usize,
    pub grouping_parameter: GroupingParameter,
}

pub enum GamePhase {
    Night,
    Morning,
    Discussion,
    Voting,
}

impl Game {
    pub fn new(player_names: Vec<String>, rules: GameRules) -> Self {
        let players = player::create_players(player_names, None);

        Self {
            state: GameState {
                players,
                current_phase: GamePhase::Night,
                day: 1,
            },
            rules,
        }
    }

    pub fn role_assignment(&mut self, is_prove: bool) {
        let role = role::calc_role(self.state.players.len(), &self.rules);

        for (player, role) in self.state.players.iter_mut().zip(role) {
            player.role = Some(role);
        }

        if is_prove {
            // prove and verify
            if let Err(e) = self.prove_and_verify() {
                eprintln!("Failed to prove and verify: {}", e);
            }
        }
    }

    fn prove_and_verify(&self) -> Result<(), std::io::Error> {
        let n = self.state.players.len();
        let m = self.rules.grouping_parameter.get_num_groups();

        let rng = &mut ark_std::test_rng();

        let pedersen_param = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::setup(rng).unwrap();

        let player_randomness = load_random_value()?;
        let player_commitment = load_random_commitment()?;

        // calc
        let shuffle_matrix = vec![
            generate_individual_shuffle_matrix(
                self.rules.grouping_parameter.get_num_players(),
                self.rules.grouping_parameter.get_num_groups(),
                rng,
            );
            2
        ];

        let mut inputs = vec![];

        for id in 0..n {
            let (role, role_val, player_ids) =
                calc_shuffle_matrix(&self.rules.grouping_parameter, &shuffle_matrix, id).unwrap();
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

        let local_role_circuit = RoleAssignmentCircuit {
            num_players: n,
            max_group_size: self.rules.grouping_parameter.get_max_group_size(),
            pedersen_param: pedersen_param.clone(),
            tau_matrix: DMatrix::<Fr>::zeros(n + m, n + m),
            shuffle_matrices: vec![DMatrix::<Fr>::zeros(n + m, n + m); 2],
            role_commitment: commitment,
            randomness,
            player_randomness: player_randomness.clone(),
            player_commitment: player_commitment.clone(),
        };

        let srs = LocalMarlin::universal_setup(1000000, 50000, 100000, rng).unwrap();
        let (index_pk, index_vk) = LocalMarlin::index(&srs, local_role_circuit).unwrap();
        let mpc_index_pk = IndexProverKey::from_public(index_pk);

        let mpc_pedersen_param =
            <MFr as LocalOrMPC<MFr>>::PedersenParam::from_local(&pedersen_param);

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
            max_group_size: self.rules.grouping_parameter.get_max_group_size(),
            pedersen_param: mpc_pedersen_param,
            tau_matrix: self.rules.grouping_parameter.generate_tau_matrix(),
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

        role_commitment.iter().for_each(|x| {
            inputs.push(x.reveal().x);
            inputs.push(x.reveal().y);
        });

        assert!(prove_and_verify(
            &mpc_index_pk,
            &index_vk,
            mpc_role_circuit.clone(),
            inputs
        ));

        Ok(())
    }

    pub fn next_phase(&mut self) {
        self.state.current_phase = match self.state.current_phase {
            GamePhase::Night => GamePhase::Morning,
            GamePhase::Morning => GamePhase::Discussion,
            GamePhase::Discussion => GamePhase::Voting,
            GamePhase::Voting => {
                self.state.day += 1;
                GamePhase::Night
            }
        };
    }

    pub fn check_victory_condition(&self) -> Option<String> {
        let alive_players: Vec<&Player> =
            self.state.players.iter().filter(|p| p.is_alive).collect();
        let werewolf_count = alive_players.iter().filter(|p| p.is_werewolf()).count();
        let villager_count = alive_players.len() - werewolf_count;

        if werewolf_count == 0 {
            Some("村人".to_string())
        } else if werewolf_count >= villager_count {
            Some("人狼".to_string())
        } else {
            None
        }
    }

    pub fn werewolf_attack(&mut self, target_id: MFr) -> Vec<String> {
        let mut events = Vec::new();

        let am_werewolf = self
            .state
            .players
            .iter()
            .any(|p| p.id == Net::party_id() && p.role == Some(Role::Werewolf) && p.is_alive);

        // calc
        if let Some(target) =
            self.state.players.iter_mut().find(|p| {
                Fr::from(p.id as i32) == target_id.reveal() && p.is_alive && !p.is_werewolf()
            })
            {
                target.mark_for_death();
            if am_werewolf {
                events.push(format!("人狼が{}を襲撃対象に選びました。", target.name));
            }
            } else {
            if am_werewolf {
                events.push("無効な襲撃対象が選択されました。".to_string());
            }
        }

        events
    }

    pub fn seer_divination(&self, target_id: MFr) -> Vec<String> {
        let mut events = Vec::new();

        // get FortuneTeller
        let am_fortune_teller =
            self.state.players.iter().any(|p| {
                p.id == Net::party_id() && p.role == Some(Role::FortuneTeller) && p.is_alive
            });

        // calc
        if let Some(seer) = self
            .state
            .players
            .iter()
            .find(|p| p.role == Some(Role::FortuneTeller) && p.is_alive)
        {
            if let Some(target) = self.state.players.iter().find(|p| {
                Fr::from(p.id as i32) == target_id.reveal() && p.is_alive && p.id != seer.id
            }) {
                let role_name = if target.is_werewolf() {
                    "人狼"
                } else {
                    "人狼ではない"
                };
                if am_fortune_teller {
                events.push(format!(
                    "占い師が{}を占いました。結果：{}",
                    target.name, role_name
                ));
                }
            } else {
                if am_fortune_teller {
                events.push("無効な占い対象が選択されました。".to_string());
            }
        }
        }
        events
    }

    pub fn morning_phase(&mut self) -> Vec<String> {
        let mut events = Vec::new();

        for player in &mut self.state.players {
            if player.marked_for_death.reveal().is_one() && player.is_alive {
                player.kill(self.state.day);
                events.push(format!("{}が無残な姿で発見されました。", player.name));
                player.marked_for_death = MpcBooleanField::pub_false();
            }
        }

        if events.is_empty() {
            events.push("昨夜は誰も襲撃されませんでした。".to_string());
        }

        events
    }

    pub fn discussion_phase(&self) -> Vec<String> {
        vec!["討論フェーズが始まりました。".to_string()]
    }

    pub fn voting_phase(&mut self, votes: Vec<usize>) -> Vec<String> {
        let mut events = Vec::new();
        let mut vote_count = vec![0; self.state.players.len()];

        for (voter, &target) in self.state.players.iter().zip(votes.iter()) {
            if voter.is_alive {
                vote_count[target] += 1;
                events.push(format!(
                    "{}が{}に投票しました。",
                    voter.name, self.state.players[target].name
                ));
            }
        }

        let max_votes = *vote_count.iter().max().unwrap();
        // 最大票数を持つプレイヤーを見つける。投票が同数の場合は
        let max_voted_indexes = self
            .state
            .players
            .iter()
            .enumerate()
            .filter_map(|(i, p)| {
                if p.is_alive && vote_count[i] == max_votes {
                    Some(i)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        assert!(max_voted_indexes.len() >= 1);
        let executed_index = if max_voted_indexes.len() == 1 {
            max_voted_indexes[0]
        } else {
            // 投票が同数の場合は、ランダムに一人処刑される
            let random_index = rand::thread_rng().gen_range(0..max_voted_indexes.len());
            max_voted_indexes[random_index]
        };

        let player = &mut self.state.players[executed_index];
        player.kill(self.state.day);
        events.push(format!("{}が処刑されました。", player.name));

        events
    }
}

impl GameRules {
    pub fn new(
        min_players: usize,
        max_players: usize,
        werewolf_ratio: f32,
        seer_count: usize,
        grouping_parameter: GroupingParameter,
    ) -> Self {
        Self {
            min_players,
            max_players,
            werewolf_ratio,
            seer_count,
            grouping_parameter,
        }
    }
}
