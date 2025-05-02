use crate::circuits::werewolf::{
    AnonymousVotingCircuit, DivinationCircuit, KeyPublicizeCircuit, RoleAssignmentCircuit,
    WinningJudgeCircuit,
};
use crate::circuits::{circuit::MySimpleCircuit, ElGamalLocalOrMPC, LocalOrMPC};
use crate::input::{InputWithCommit, WerewolfKeyInput, WerewolfMpcInput};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

// KeyPublicizeCircuitのserde::serializeを実装
impl<F: PrimeField + LocalOrMPC<F>> Serialize for KeyPublicizeCircuit<F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = Vec::new();
        self.mpc_input
            .serialize_unchecked(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de, F: PrimeField + LocalOrMPC<F>> Deserialize<'de> for KeyPublicizeCircuit<F> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::de::Deserialize::deserialize(deserializer)?;
        let mpc_input = WerewolfKeyInput::deserialize_unchecked(&mut &bytes[..])
            .map_err(serde::de::Error::custom)?;
        Ok(Self { mpc_input })
    }
}

// DivinationCircuitのserde::serializeを実装
impl<F: PrimeField + LocalOrMPC<F> + ElGamalLocalOrMPC<F>> Serialize for DivinationCircuit<F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = Vec::new();
        self.mpc_input
            .serialize_unchecked(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de, F: PrimeField + LocalOrMPC<F> + ElGamalLocalOrMPC<F>> Deserialize<'de>
    for DivinationCircuit<F>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::de::Deserialize::deserialize(deserializer)?;
        let mpc_input = WerewolfMpcInput::deserialize_unchecked(&mut &bytes[..])
            .map_err(serde::de::Error::custom)?;
        Ok(Self { mpc_input })
    }
}

// RoleAssignmentCircuitのserde::serializeを実装
impl<F: PrimeField + LocalOrMPC<F> + ElGamalLocalOrMPC<F>> Serialize for RoleAssignmentCircuit<F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = Vec::new();

        // // Serialize parameters
        // self.pedersen_param
        //     .serialize_unchecked(&mut bytes)
        //     .map_err(serde::ser::Error::custom)?;

        // // Serialize instances
        // self.tau_matrix
        //     .serialize_unchecked(&mut bytes)
        //     .map_err(serde::ser::Error::custom)?;

        // self.role_commitment
        //     .serialize_unchecked(&mut bytes)
        //     .map_err(serde::ser::Error::custom)?;

        // self.player_commitment
        //     .serialize_unchecked(&mut bytes)
        //     .map_err(serde::ser::Error::custom)?;

        // // Serialize witnesses
        // self.shuffle_matrices
        //     .serialize_unchecked(&mut bytes)
        //     .map_err(serde::ser::Error::custom)?;

        // self.randomness
        //     .serialize_unchecked(&mut bytes)
        //     .map_err(serde::ser::Error::custom)?;

        // self.player_randomness
        //     .serialize_unchecked(&mut bytes)
        //     .map_err(serde::ser::Error::custom)?;

        todo!("Serialize RoleAssignmentCircuit");

        serializer.serialize_bytes(&bytes)
    }
}

impl<'de, F: PrimeField + LocalOrMPC<F> + ElGamalLocalOrMPC<F>> Deserialize<'de>
    for RoleAssignmentCircuit<F>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // let bytes: Vec<u8> = serde::de::Deserialize::deserialize(deserializer)?;
        // let mut cursor = &bytes[..];

        // // Deserialize parameters
        // let pedersen_param = F::PedersenParam::deserialize_unchecked(&mut cursor)
        //     .map_err(serde::de::Error::custom)?;

        // // Deserialize instances
        // let tau_matrix = na::DMatrix::<F>::deserialize_unchecked(&mut cursor)
        //     .map_err(serde::de::Error::custom)?;

        // let role_commitment = Vec::<F::PedersenCommitment>::deserialize_unchecked(&mut cursor)
        //     .map_err(serde::de::Error::custom)?;

        // let player_commitment = Vec::<F::PedersenCommitment>::deserialize_unchecked(&mut cursor)
        //     .map_err(serde::de::Error::custom)?;

        // // Deserialize witnesses
        // let shuffle_matrices = Vec::<na::DMatrix<F>>::deserialize_unchecked(&mut cursor)
        //     .map_err(serde::de::Error::custom)?;

        // let randomness = Vec::<F::PedersenRandomness>::deserialize_unchecked(&mut cursor)
        //     .map_err(serde::de::Error::custom)?;

        // let player_randomness =
        //     Vec::<F>::deserialize_unchecked(&mut cursor).map_err(serde::de::Error::custom)?;

        // Ok(Self {
        //     num_players: player_randomness.len(),
        //     max_group_size: tau_matrix.nrows() - 1,
        //     pedersen_param,
        //     tau_matrix,
        //     role_commitment,
        //     player_commitment,
        //     shuffle_matrices,
        //     randomness,
        //     player_randomness,
        // })
        todo!("Deserialize RoleAssignmentCircuit");
    }
}

// AnonymousVotingCircuitのserde::serializeを実装
impl<F: PrimeField + LocalOrMPC<F> + ElGamalLocalOrMPC<F>> Serialize for AnonymousVotingCircuit<F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = Vec::new();

        // Serialize voting data
        self.is_target_id
            .serialize_unchecked(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        self.is_most_voted_id
            .serialize_unchecked(&mut bytes)
            .map_err(serde::ser::Error::custom)?;

        // Serialize Pedersen parameters
        self.pedersen_param
            .serialize_unchecked(&mut bytes)
            .map_err(serde::ser::Error::custom)?;

        // Serialize player data
        self.player_randomness
            .serialize_unchecked(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        self.player_commitment
            .serialize_unchecked(&mut bytes)
            .map_err(serde::ser::Error::custom)?;

        serializer.serialize_bytes(&bytes)
    }
}

impl<'de, F: PrimeField + LocalOrMPC<F> + ElGamalLocalOrMPC<F>> Deserialize<'de>
    for AnonymousVotingCircuit<F>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::de::Deserialize::deserialize(deserializer)?;
        let mut cursor = &bytes[..];

        // Deserialize voting data
        let is_target_id =
            Vec::<Vec<F>>::deserialize_unchecked(&mut cursor).map_err(serde::de::Error::custom)?;
        let is_most_voted_id =
            F::deserialize_unchecked(&mut cursor).map_err(serde::de::Error::custom)?;

        // Deserialize Pedersen parameters
        let pedersen_param = F::PedersenParam::deserialize_unchecked(&mut cursor)
            .map_err(serde::de::Error::custom)?;

        // Deserialize player data
        let player_randomness =
            Vec::<F>::deserialize_unchecked(&mut cursor).map_err(serde::de::Error::custom)?;
        let player_commitment = Vec::<F::PedersenCommitment>::deserialize_unchecked(&mut cursor)
            .map_err(serde::de::Error::custom)?;

        Ok(Self {
            is_target_id,
            is_most_voted_id,
            pedersen_param,
            player_randomness,
            player_commitment,
        })
    }
}

// WinningJudgeCircuitのserde::serializeを実装
impl<F: PrimeField + LocalOrMPC<F> + ElGamalLocalOrMPC<F>> Serialize for WinningJudgeCircuit<F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = Vec::new();

        // Serialize basic game state
        self.num_alive
            .serialize_unchecked(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        self.game_state
            .serialize_unchecked(&mut bytes)
            .map_err(serde::ser::Error::custom)?;

        // Serialize Pedersen parameters
        self.pedersen_param
            .serialize_unchecked(&mut bytes)
            .map_err(serde::ser::Error::custom)?;

        // Serialize werewolf data
        self.am_werewolf
            .serialize_unchecked(&mut bytes)
            .map_err(serde::ser::Error::custom)?;

        // Serialize player data
        self.player_randomness
            .serialize_unchecked(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        self.player_commitment
            .serialize_unchecked(&mut bytes)
            .map_err(serde::ser::Error::custom)?;

        serializer.serialize_bytes(&bytes)
    }
}

impl<'de, F: PrimeField + LocalOrMPC<F> + ElGamalLocalOrMPC<F>> Deserialize<'de>
    for WinningJudgeCircuit<F>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::de::Deserialize::deserialize(deserializer)?;
        let mut cursor = &bytes[..];

        // Deserialize basic game state
        let num_alive = F::deserialize_unchecked(&mut cursor).map_err(serde::de::Error::custom)?;
        let game_state = F::deserialize_unchecked(&mut cursor).map_err(serde::de::Error::custom)?;

        // Deserialize Pedersen parameters
        let pedersen_param = F::PedersenParam::deserialize_unchecked(&mut cursor)
            .map_err(serde::de::Error::custom)?;

        // Deserialize werewolf data
        let am_werewolf = Vec::<InputWithCommit<F>>::deserialize_unchecked(&mut cursor)
            .map_err(serde::de::Error::custom)?;

        // Deserialize player data
        let player_randomness =
            Vec::<F>::deserialize_unchecked(&mut cursor).map_err(serde::de::Error::custom)?;
        let player_commitment = Vec::<F::PedersenCommitment>::deserialize_unchecked(&mut cursor)
            .map_err(serde::de::Error::custom)?;

        Ok(Self {
            num_alive,
            pedersen_param,
            am_werewolf,
            game_state,
            player_randomness,
            player_commitment,
        })
    }
}

// MySimpleCircuitのserde::serializeを実装
impl<F: PrimeField> Serialize for MySimpleCircuit<F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = Vec::new();

        // Serialize voting data
        self.a
            .serialize_unchecked(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        self.b
            .serialize_unchecked(&mut bytes)
            .map_err(serde::ser::Error::custom)?;

        serializer.serialize_bytes(&bytes)
    }
}

impl<'de, F: PrimeField + LocalOrMPC<F> + ElGamalLocalOrMPC<F>> Deserialize<'de>
    for MySimpleCircuit<F>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::de::Deserialize::deserialize(deserializer)?;
        let mut cursor = &bytes[..];

        let a =
            Option::<F>::deserialize_unchecked(&mut cursor).map_err(serde::de::Error::custom)?;

        let b =
            Option::<F>::deserialize_unchecked(&mut cursor).map_err(serde::de::Error::custom)?;

        Ok(Self { a, b })
    }
}
