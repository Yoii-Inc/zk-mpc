use std::ops::{Add, Mul};

use ark_ff::{FftField, FftParameters, Field};
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    UVPolynomial,
};
use ark_std::log2;

/// Interpolate a polynomial such that it passes through specified points.
/// This function calculates an interpolated polynomial that passes through a set of given points.
///
/// # Arguments
///
/// * `eval_at` - A vector containing the x-values of the points to interpolate.
/// * `evals` - A vector containing the corresponding y-values of the points to interpolate.
///
/// # Returns
/// An `Option` containing the coefficients of the interpolated polynomial. Returns `None` if interpolation fails.
///
pub fn interpolate<F: FftField>(eval_at: &Vec<F>, evals: &Vec<F>) -> Option<Vec<F>> {
    let n = eval_at.len();
    let m = evals.len();

    if n != m {
        return None;
    }

    // Computing the inverse for the interpolation
    let mut sca_inverse = Vec::new();
    for (j, x_j) in eval_at.iter().enumerate() {
        let mut sca = F::one();
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
        let mut l_poly = DensePolynomial::from_coefficients_vec(vec![F::one()]);
        for (k, x_k) in eval_at.iter().enumerate() {
            if j == k {
                continue;
            }
            let tmp_poly = DensePolynomial::from_coefficients_vec(vec![-(*x_k), F::one()]);
            l_poly = l_poly.mul(&tmp_poly);
        }
        lang.push(l_poly);
    }

    let mut res = DensePolynomial::from_coefficients_vec(vec![F::zero()]);
    for (j, (_x_j, y_j)) in eval_at.iter().zip(evals.iter()).enumerate() {
        let l_poly = lang[j].mul(sca_inverse[j] * y_j);
        res = (&res).add(&l_poly);
    }

    let mut res_coeff = res.coeffs;

    if res_coeff.len() < n {
        res_coeff.extend(vec![F::zero(); n - res_coeff.len()]);
    }
    Some(res_coeff)
}

/// Substitute a value into a polynomial.
///
/// # Arguments
/// * `polynomial` - The polynomial to substitute into.
/// * `variable` - The value to substitute.
///
/// # Returns
/// The result of the substitution.
///
pub fn substitute<F: Field>(polynomial: &[F], variable: &F) -> F {
    let mut result = F::zero();
    for (i, coefficient) in polynomial.iter().enumerate() {
        result += *coefficient * variable.pow([i as u64]);
    }
    result
}

/// Compute the roots of the cyclotomic polynomial \Phi_(2 * length)(X) on F. where length is expected to be a power of two.
///
/// # Arguments
/// * `length` - The length of the roots.
///
/// # Returns
/// The vector of (2 * length)-th roots of the cyclotomic polynomial.
///
/// # Notes
/// The cyclotomic polynomial \Phi_N(X) is defined as the minimal polynomial of the primitive N-th root of unity.
/// If N is a power of two, then \Phi_N(X) = X^(N/2) + 1. For example, \Phi_8(X) = X^4 + 1.
/// let r is a one of the roots of the cyclotomic polynomial \Phi_N(X) on F, then returns [r, r^2, r^3, r^4, ..., r^length].
///
/// TWO_ADIC_ROOT_OF_UNITY = 2^s-th root of unity in Fp (s = F::FftParams::TWO_ADICITY).
///
pub fn cyclotomic_moduli<F: FftField>(length: usize) -> Vec<F> {
    let k = log2(length * 2);
    let s = F::FftParams::TWO_ADICITY;
    assert!(k < s);
    let m_root_of_unity = F::two_adic_root_of_unity().pow([2_u64.pow(s - k)]);
    let mut moduli = Vec::new();
    for i in 0..length {
        moduli.push(m_root_of_unity.pow([(2 * i + 1) as u64]));
    }

    moduli
}

fn poly_remainder<F: Field>(a: &[F], b: &[F], degree: usize) -> Vec<F> {
    let mut r = a.to_vec();

    while r.len() >= b.len() {
        let ratio = *r.last().unwrap() / b.last().unwrap();
        let degree = r.len() - b.len();

        let t: Vec<F> = b.iter().map(|&x| x * ratio).collect();

        for i in (0..t.len()).rev() {
            r[i + degree] -= t[i];
        }

        let _zero = F::zero();

        while let Some(_zero) = r.last() {
            r.pop();
        }
    }

    if r.len() < degree {
        r.extend(vec![F::zero(); degree - r.len()])
    }
    r
}

/// Compute the remainder of a polynomial division on F.
///
/// # Arguments
/// * `a` - The first polynomial.
/// * `b` - The second polynomial.
/// * `expect_length` - The degree of the remainder (Fill in 0 when it becomes shorter than that length.).
///
/// # Returns
/// The residue of the polynomial division a % b.
///
pub fn poly_remainder2<F: Field>(a: &[F], b: &[F], expect_length: usize) -> Vec<F> {
    let a_poly = DensePolynomial::from_coefficients_vec(a.to_vec());
    let b_poly = DensePolynomial::from_coefficients_vec(b.to_vec());

    let a_poly2 = DenseOrSparsePolynomial::from(a_poly);
    let b_poly2 = DenseOrSparsePolynomial::from(b_poly);

    let (_, res) = a_poly2.divide_with_q_and_r(&b_poly2).unwrap();

    let mut res_vec = res.coeffs;

    if res_vec.len() < expect_length {
        res_vec.extend(vec![F::zero(); expect_length - res_vec.len()])
    }

    res_vec
}

#[cfg(test)]
mod tests {
    use ark_ff::{Field, FpParameters};
    use ark_std::UniformRand;
    use num_bigint::BigUint;
    use num_traits::One;
    use rand::thread_rng;

    use super::*;
    use crate::she::SHEParameters;
    use ark_bls12_377::{Fr, FrParameters};
    use ark_mnt4_753::FqParameters;

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

    #[test]
    fn test_cyclotomic_moduli() {
        // Set the parameters for this instantiation of BV11
        let std_dev = 3.2; // Standard deviation for generating the error
        let s = 64;
        let p: BigUint = FrParameters::MODULUS.into();
        let q: BigUint = FqParameters::MODULUS.into();
        let degree = s;

        let she_params = SHEParameters::new(s, degree, p.clone(), q.clone(), std_dev);

        let res = cyclotomic_moduli::<Fr>(she_params.n);

        for v in res {
            assert_eq!(Fr::one(), v.pow([(s * 2) as u64]));
        }
        println!("hello");
    }
}
