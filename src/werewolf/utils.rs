use ark_ff::PrimeField;
use nalgebra::{DMatrix, DVector};
use rand::{seq::SliceRandom, Rng};

use super::types::{GroupingParameter, Role};

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
