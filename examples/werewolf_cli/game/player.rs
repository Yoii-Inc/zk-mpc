use crate::game::role::Role;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Player {
    pub id: usize,
    pub name: String,
    pub role: Role,
    pub is_alive: bool,
    pub death_day: Option<u32>,
    pub marked_for_death: bool,
}

impl Player {
    pub fn new(id: usize, name: String, role: Role) -> Self {
        Self {
            id,
            name,
            role,
            is_alive: true,
            death_day: None,
            marked_for_death: false,
        }
    }

    pub fn kill(&mut self, day: u32) {
        self.is_alive = false;
        self.death_day = Some(day);
    }

    pub fn is_werewolf(&self) -> bool {
        self.role.is_werewolf()
    }

    pub fn mark_for_death(&mut self) {
        self.marked_for_death = true;
    }
}

pub fn create_players(names: Vec<String>, roles: Vec<Role>) -> Vec<Player> {
    names
        .into_iter()
        .zip(roles)
        .enumerate()
        .map(|(id, (name, role))| Player::new(id, name, role))
        .collect()
}
