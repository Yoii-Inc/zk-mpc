use std::ops::{Add, Mul};

use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, UVPolynomial};
use ark_std::UniformRand;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::Rng;

use super::{cyclotomic_moduli, Encodedtext, Fq, Fr, SHEParameters, Texts};

pub type Plaintext = Fr;
pub type Plaintexts = Texts<Plaintext>;

pub trait Plaintextish {
    fn diagonalize(&self, length: usize) -> Plaintexts;
}

impl Plaintextish for Plaintext {
    fn diagonalize(&self, length: usize) -> Plaintexts {
        Plaintexts::from(&vec![*self; length])
    }
}

impl Plaintexts {
    pub fn rand<T: Rng>(params: &SHEParameters, rng: &mut T) -> Plaintexts {
        let res = (0..params.s).map(|_| Plaintext::rand(rng)).collect();
        Plaintexts { vals: res }
    }

    pub fn encode(&self, params: &SHEParameters) -> Encodedtext {
        let remainders = self.vals.clone();
        let moduli = cyclotomic_moduli(params.s);

        let result_vec = interpolate(&moduli, &remainders).unwrap();

        let result_vec_on_fq = result_vec
            .iter()
            .map(|&x| Fq::from(std::convert::Into::<BigUint>::into(x)))
            .collect::<Vec<Fq>>();

        Encodedtext {
            vals: result_vec_on_fq,
        }
    }
}

impl Mul<Plaintexts> for Plaintexts {
    type Output = Self;

    fn mul(self, other: Plaintexts) -> Self {
        let out_val = self
            .vals
            .iter()
            .zip(other.vals.iter())
            .map(|(&x, &y)| x * y)
            .collect();
        Self { vals: out_val }
    }
}

fn interpolate(eval_at: &Vec<Fr>, evals: &Vec<Fr>) -> Option<Vec<Fr>> {
    let n = eval_at.len();
    let m = evals.len();

    if n != m {
        return None;
    }

    // Computing the inverse for the interpolation
    let mut sca_inverse = Vec::new();
    for (j, x_j) in eval_at.iter().enumerate() {
        let mut sca = Fr::one();
        for (k, x_k) in eval_at.iter().enumerate() {
            if j == k {
                continue;
            }
            sca *= *x_j - x_k;
        }
        sca = sca.inverse().unwrap();
        sca_inverse.push(sca);
    }

    // Computing the lagrange polynomial for the interpolation
    let mut lang = Vec::new();
    for (j, _x_j) in eval_at.iter().enumerate() {
        let mut l_poly = DensePolynomial::from_coefficients_vec(vec![Fr::one()]);
        for (k, x_k) in eval_at.iter().enumerate() {
            if j == k {
                continue;
            }
            let tmp_poly = DensePolynomial::from_coefficients_vec(vec![-(*x_k), Fr::one()]);
            l_poly = l_poly.mul(&tmp_poly);
        }
        lang.push(l_poly);
    }

    let mut res = DensePolynomial::from_coefficients_vec(vec![Fr::zero()]);
    for (j, (_x_j, y_j)) in eval_at.iter().zip(evals.iter()).enumerate() {
        let l_poly = lang[j].mul(sca_inverse[j] * y_j);
        res = (&res).add(&l_poly);
    }

    let mut res_coeff = res.coeffs;

    if res_coeff.len() < n {
        res_coeff.extend(vec![Fr::zero(); n - res_coeff.len()]);
    }
    Some(res_coeff)
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use crate::she::substitute;

    use super::*;

    #[test]
    fn test_plaintext() {
        let pl_1: Plaintexts = Plaintexts::from_vec(vec![Fr::from(1), Fr::from(2)]);
        let pl_2: Plaintexts = Plaintexts::from_vec(vec![Fr::from(2), Fr::from(3)]);
        let pl_add = pl_1.clone() + pl_2.clone();
        let pl_add_expected = Plaintexts::from(&[Fr::from(1 + 2), Fr::from(2 + 3)]);
        assert_eq!(pl_add, pl_add_expected);

        let pl_vec: Vec<Plaintexts> = vec![pl_1.clone(), pl_2.clone()];
        let pl_sum: Plaintexts = pl_vec.iter().cloned().sum();
        assert_eq!(pl_sum, pl_add_expected);
    }

    #[test]
    fn test_interpolate() {
        let mut rng = thread_rng();

        let mut eval_at = Vec::new();
        let mut evals = Vec::new();
        for _ in 0..10 {
            eval_at.push(Fr::rand(&mut rng));
            evals.push(Fr::rand(&mut rng));
        }

        let res = interpolate(&eval_at, &evals).unwrap();

        for i in 0..10 {
            assert_eq!(evals[i], substitute(&res, &eval_at[i]));
        }

        println!("hello");
    }
}
