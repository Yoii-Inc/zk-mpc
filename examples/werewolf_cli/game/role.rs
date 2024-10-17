use rand::seq::SliceRandom;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use zk_mpc::werewolf::types::Role;

use super::GameRules;

pub fn assign_roles(player_count: usize, rules: &GameRules) -> Vec<Role> {
    let mut roles = vec![Role::Villager; player_count];
    let mut rng = thread_rng();

    let werewolf_count = (player_count as f32 * rules.werewolf_ratio).round() as usize;
    let seer_count = rules.seer_count;

    // 役割を割り当てる
    for role in roles.iter_mut().take(werewolf_count) {
        *role = Role::Werewolf;
    }

    for role in roles.iter_mut().skip(werewolf_count).take(seer_count) {
        *role = Role::FortuneTeller;
    }

    // ランダムに並び替える
    roles.shuffle(&mut rng);

    roles
}
