use std::ops::{Add, Mul};

use ark_ff::{FftField, FftParameters, Field};
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    UVPolynomial,
};
use ark_std::log2;

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

pub fn substitute<F: Field>(polynomial: &[F], variable: &F) -> F {
    let mut result = F::zero();
    for (i, coefficient) in polynomial.iter().enumerate() {
        result += *coefficient * variable.pow([i as u64]);
    }
    result
}

pub fn cyclotomic_moduli<F: FftField>(length: usize) -> Vec<F> {
    // moduli: lengthは本来N-1だが、sで切り捨て
    // N-1個の根は、円分多項式Phi_N(X) on Fpの根である

    // N=sである。N * 2=mである。mは2の冪である。m=2^kであるとき(ただし、1<=k<47)、moduliは、TWO_ADIC_ROOT_OF_UNITY^{2^(47-k)}のi乗である。

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

        let zero = F::zero();

        while let Some(zero) = r.last() {
            r.pop();
        }
    }

    if r.len() < degree {
        r.extend(vec![F::zero(); degree - r.len()])
    }
    r
}

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

    use crate::she::SHEParameters;

    use super::super::Fr;
    use super::*;

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

    use super::super::{FqParameters, FrParameters};

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
