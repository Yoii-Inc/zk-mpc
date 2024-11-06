use ark_bls12_377::Fr;
use ark_std::test_rng;
use rand::thread_rng;
use rand::{rngs::StdRng, seq::SliceRandom};
use zk_mpc::werewolf::types::Role;
use zk_mpc::werewolf::utils::{calc_shuffle_matrix, generate_individual_shuffle_matrix};

use super::GameRules;

pub fn assign_roles(player_count: usize, rules: &GameRules) -> Vec<Role> {
    let mut roles = vec![Role::Villager; player_count];
    let mut rng = thread_rng();

    let werewolf_count = (player_count as f32 * rules.werewolf_ratio).round() as usize;
    let seer_count = rules.seer_count;

    // assign roles
    for role in roles.iter_mut().take(werewolf_count) {
        *role = Role::Werewolf;
    }

    for role in roles.iter_mut().skip(werewolf_count).take(seer_count) {
        *role = Role::FortuneTeller;
    }

    // Shuffle randomly
    roles.shuffle(&mut rng);

    roles
}

pub(super) fn calc_role(player_count: usize, rules: &GameRules) -> Vec<Role> {
    let rng = &mut test_rng();

    let grouping_parameter = &rules.grouping_parameter;

    // 1. generate shuffle matrix for each player.
    let shuffle_matrix = vec![
        generate_individual_shuffle_matrix::<Fr, StdRng>(
            // grouping_parameter.get_num_players(),
            player_count,
            grouping_parameter.get_num_groups(),
            rng,
        );
        2
    ];

    // 2. calc role for each player.
    let mut outputs = vec![];

    for id in 0..player_count {
        let (role, _role_val, _player_ids) =
            calc_shuffle_matrix(grouping_parameter, &shuffle_matrix, id).unwrap();
        outputs.push(role);
    }

    outputs
}
