use ark_ff::PrimeField;
use nalgebra;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq, Hash, Ord, PartialOrd, Clone)]
pub enum Role {
    FortuneTeller,
    Werewolf,
    Villager,
}

#[derive(Debug, Deserialize)]
pub struct RoleData {
    role: String,
}

impl RoleData {
    pub fn role(&self) -> String {
        self.role.clone()
    }
}

pub struct GroupingParameter(BTreeMap<Role, (usize, bool)>);

impl GroupingParameter {
    pub fn new(input: BTreeMap<Role, (usize, bool)>) -> Self {
        Self(input)
    }

    // F: Field used in the MPC.
    pub fn generate_tau_matrix<F: PrimeField>(&self) -> nalgebra::DMatrix<F> {
        let num_players = self.get_num_players();
        let num_groups = self.get_num_groups();

        let mut tau =
            nalgebra::DMatrix::<F>::zeros(num_players + num_groups, num_players + num_groups);

        let mut player_index = 0;
        let mut group_index = 0;

        for (_, (count, is_not_alone)) in self.0.iter() {
            if *is_not_alone {
                assert!(
                    *count >= 2,
                    "Error: not alone group count must be greater than 2"
                );

                // group
                tau[(player_index, num_players + group_index)] = F::one();

                // player
                for _ in 0..*count - 1 {
                    tau[(player_index + 1, player_index)] = F::one();
                    player_index += 1;
                }
                tau[(num_players + group_index, player_index)] = F::one();
                player_index += 1;
                group_index += 1;
            } else {
                for _ in 0..*count {
                    // group
                    tau[(player_index, num_players + group_index)] = F::one();
                    // player
                    tau[(num_players + group_index, player_index)] = F::one();
                    player_index += 1;
                    group_index += 1;
                }
            }
        }

        tau
    }

    pub fn get_num_roles(&self) -> usize {
        self.0.len()
    }

    pub fn get_num_groups(&self) -> usize {
        self.0
            .values()
            .map(|(count, is_not_alone)| if *is_not_alone { 1 } else { *count })
            .sum()
    }

    pub fn get_num_players(&self) -> usize {
        self.0.values().map(|x| x.0).sum()
    }

    pub fn get_max_group_size(&self) -> usize {
        self.0
            .values()
            .map(|(count, is_not_alone)| if *is_not_alone { *count } else { 1 })
            .max()
            .expect("Error: No max value found")
    }

    pub fn get_corresponding_role(&self, role_id: usize) -> Role {
        let mut count = self.get_num_players();
        for (role, (role_count, is_not_alone)) in self.0.iter() {
            count += if *is_not_alone { 1 } else { *role_count };
            if role_id < count {
                return role.clone();
            }
        }

        panic!("Error: Invalid role id is given");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grouping_parameter() {
        let grouping_parameter = GroupingParameter::new(
            vec![
                (Role::Villager, (4, false)),
                (Role::FortuneTeller, (1, false)),
                (Role::Werewolf, (2, true)),
            ]
            .into_iter()
            .collect(),
        );

        // Villager, FortuneTeller, Werewolf
        assert_eq!(grouping_parameter.get_num_roles(), 3);

        // Villager: 1, 2, 3, 4, FortuneTeller: 1, Werewolfs: 1
        assert_eq!(grouping_parameter.get_num_groups(), 6);

        // Total 4 + 1 + 2 = 7
        assert_eq!(grouping_parameter.get_num_players(), 7);
    }
}
