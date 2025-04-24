use std::io::Read;

use super::types::{GroupingParameter, Role};
use crate::{circuits::LocalOrMPC, serialize::write_to_file};

use ark_bls12_377::Fr;
use ark_ff::PrimeField;
use ark_ff::UniformRand;
use ark_serialize::CanonicalDeserialize;
use mpc_algebra::{channel::MpcSerNet, CommitmentScheme};
use mpc_net::{MpcMultiNet as Net, MpcNet};
use nalgebra::{DMatrix, DVector};
use rand::{seq::SliceRandom, Rng};

// Compute shuffle matrix and return role, raw role id, and player id in the same group.
pub fn calc_shuffle_matrix<F: PrimeField>(
    grouping_parameter: &GroupingParameter,
    shuffle_matrix: &[DMatrix<F>],
    id: usize,
) -> Result<(Role, usize, Option<Vec<usize>>), std::io::Error> {
    // parameters
    let n = grouping_parameter.get_num_players();
    let m = grouping_parameter.get_num_groups();

    // generate tau matrix
    let tau_matrix = grouping_parameter.generate_tau_matrix();

    // compute rho matrix
    let m_matrix = shuffle_matrix
        .iter()
        .fold(DMatrix::<F>::identity(n + m, n + m), |acc, x| acc * x);
    let rho_matrix = m_matrix.transpose() * tau_matrix * m_matrix;

    // iterate. get rho^1, rho^2, ..., rho^num_players
    let mut rho_sequence = Vec::with_capacity(n);
    let mut current_rho = rho_matrix.clone();
    for _ in 0..n {
        rho_sequence.push(current_rho.clone());
        current_rho *= rho_matrix.clone(); // rho^(i+1) = rho^i * rho
    }

    let mut unit_vec = DVector::<F>::zeros(n + m);
    unit_vec[id] = F::one();

    // player i: for each j in {1..n}, get rho^j(i)
    let result = rho_sequence
        .iter()
        .map(|rho| rho * unit_vec.clone())
        .map(|x| {
            let index = x.column(0).into_iter().enumerate().find_map(|(j, value)| {
                if *value != F::zero() {
                    Some(j)
                } else {
                    None
                }
            });
            index.unwrap_or_else(|| panic!("Error: No index found"))
        }) // search for the index of the one element
        .collect::<Vec<_>>();

    println!("player {:?} result is {:?}", id, result);

    // get role value. get val which is max value in result.
    let role_val = result.iter().max().expect("Failed to get max value");

    // get role
    let role = grouping_parameter.get_corresponding_role(*role_val);

    let mut fellow = result
        .iter()
        .filter(|x| **x != id && **x < n)
        .copied()
        .collect::<Vec<_>>();

    if fellow.is_empty() {
        Ok((role, *role_val, None))
    } else {
        fellow.sort();
        fellow.dedup();
        Ok((role, *role_val, Some(fellow)))
    }
}

pub fn generate_individual_shuffle_matrix<F: PrimeField, R: Rng>(
    n: usize,
    m: usize,
    rng: &mut R,
) -> DMatrix<F> {
    let mut shuffle_matrix = DMatrix::<F>::zeros(n + m, n + m);

    // generate permutation
    let mut permutation: Vec<usize> = (0..n).collect();
    permutation.shuffle(rng);

    // shuffle_matrix
    for i in 0..n {
        shuffle_matrix[(i, permutation[i])] = F::one();
    }

    for i in n..n + m {
        shuffle_matrix[(i, i)] = F::one();
    }

    shuffle_matrix
}

pub async fn generate_random_commitment<R: Rng>(
    rng: &mut R,
    pedersen_param: &<Fr as LocalOrMPC<Fr>>::PedersenParam,
) -> Vec<<Fr as LocalOrMPC<Fr>>::PedersenCommitment> {
    let random_value = Fr::rand(rng);

    let commitment = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::commit(
        pedersen_param,
        &random_value.convert_input(),
        &<Fr as LocalOrMPC<Fr>>::PedersenRandomness::default(),
    )
    .unwrap();

    // record random value
    let id = Net.party_id();
    let file_path = format!("./werewolf_game/{}/random.json", id);
    write_to_file(vec![("random".to_string(), random_value)], &file_path).unwrap();

    let commitment_vec = Net.broadcast(&commitment).await;
    let commitment_vec_data = commitment_vec
        .clone()
        .into_iter()
        .enumerate()
        .map(|(i, c)| (i.to_string(), c))
        .collect::<Vec<_>>();
    let file_path = "./werewolf_game/rand_commitmnet.json".to_string();
    write_to_file(commitment_vec_data, &file_path).unwrap();

    commitment_vec
}

// TODO: change to return mpc shared value
pub async fn load_random_value() -> Result<Vec<Fr>, std::io::Error> {
    let id = Net.party_id();
    let file_path = format!("./werewolf_game/{}/random.json", id);
    let mut file = std::fs::File::open(file_path)?;
    let mut output_string = String::new();
    file.read_to_string(&mut output_string)
        .expect("Failed to read file");

    let data: serde_json::Value = serde_json::from_str(&output_string)?;

    let data = data
        .as_object()
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to parse JSON data")
        })?
        .iter()
        .collect::<Vec<_>>();

    let random_value = data
        .iter()
        .map(|v| {
            let reader: &[u8] =
                &hex::decode(v.1.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
            Fr::deserialize(reader).unwrap()
        })
        .collect::<Vec<_>>()[0];

    let random_vec = Net.broadcast(&random_value).await;

    Ok(random_vec)
}

pub fn load_random_commitment(
) -> Result<Vec<<Fr as LocalOrMPC<Fr>>::PedersenCommitment>, std::io::Error> {
    let file_path = "./werewolf_game/rand_commitmnet.json".to_string();
    let mut file = std::fs::File::open(file_path)?;
    let mut output_string = String::new();
    file.read_to_string(&mut output_string)
        .expect("Failed to read file");

    let data: serde_json::Value = serde_json::from_str(&output_string)?;

    let data = data
        .as_object()
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to parse JSON data")
        })?
        .iter()
        .collect::<Vec<_>>();

    let commitment_vec = data
        .iter()
        .map(|v| {
            let reader: &[u8] =
                &hex::decode(v.1.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
            <Fr as LocalOrMPC<Fr>>::PedersenCommitment::deserialize(reader).unwrap()
        })
        .collect::<Vec<_>>();
    if commitment_vec.len() < Net.n_parties() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Commitment vector is too short",
        ));
    }
    let mut commitment_vec = commitment_vec;
    commitment_vec.resize(
        Net.n_parties(),
        <Fr as LocalOrMPC<Fr>>::PedersenCommitment::default(),
    );
    Ok(commitment_vec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marlin::MFr;
    use ark_std::test_rng;

    #[test]
    fn test_shuffle_matrix() {
        let grouping_parameter = GroupingParameter::new(
            vec![
                (Role::Villager, (4, false)),
                (Role::FortuneTeller, (1, false)),
                (Role::Werewolf, (2, true)),
            ]
            .into_iter()
            .collect(),
        );

        let shuffle_matrix = vec![generate_individual_shuffle_matrix(
            grouping_parameter.get_num_players(),
            grouping_parameter.get_num_groups(),
            &mut test_rng(),
        )];

        for id in 0..grouping_parameter.get_num_players() {
            let (role, _, player_ids) =
                calc_shuffle_matrix::<MFr>(&grouping_parameter, &shuffle_matrix, id).unwrap();
            println!("role is {:?}", role);
            println!("fellow is {:?}", player_ids);
        }
    }
}
