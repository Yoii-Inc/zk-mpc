use ark_poly::UVPolynomial;
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{One, Zero};
use rand::Rng;
use std::ops::{Add, Mul};

use crate::she::{
    cyclotomic_moduli, DenseOrSparsePolynomial, DensePolynomial, FpParameters, Fq, FqParameters,
    Fr, Plaintexts, SHEParameters, Texts,
};

use super::substitute;

pub type Encodedtext = Texts<Fq>;
impl Encodedtext {
    pub fn rand<T: Rng>(she_params: &SHEParameters, rng: &mut T) -> Encodedtext {
        let rand_plain_text = Plaintexts::rand(she_params, rng);
        rand_plain_text.encode(she_params)
    }

    pub fn get_degree(&self) -> usize {
        self.vals.len()
    }

    pub fn decode(&self, params: &SHEParameters) -> Plaintexts {
        // root: generator of Fp. N_root: N-th root of Fp.
        let root_of_cyclotomic = cyclotomic_moduli(params.n);

        // once into BigUint, -p/2~p/2
        let mut biguint_vec = self
            .vals
            .iter()
            .map(|&x_i| std::convert::Into::<BigUint>::into(x_i))
            .collect::<Vec<_>>();
        for bu in biguint_vec.iter_mut() {
            if *bu > params.q.clone() / 2u128 {
                *bu -= params.q.clone() % params.p.clone();
            }
        }

        // into Fr
        let polynomial = biguint_vec
            .iter()
            .map(|x_i| Fr::from(x_i.clone()))
            .collect::<Vec<_>>();

        let res = (0..params.s)
            .map(|i| substitute(&polynomial, &root_of_cyclotomic[i]))
            .collect();
        Plaintexts { vals: res }
    }

    pub fn each_element(&self) -> Vec<BigInt> {
        let biguint_vec = self
            .vals
            .iter()
            .map(|&x_i| std::convert::Into::<BigUint>::into(x_i))
            .collect::<Vec<_>>();

        let bigint_vec = biguint_vec
            .iter()
            .map(|x_i| {
                if x_i.clone() > std::convert::Into::<BigUint>::into(FqParameters::MODULUS) / 2_u32
                {
                    x_i.to_bigint().unwrap()
                        - std::convert::Into::<BigUint>::into(FqParameters::MODULUS)
                            .to_bigint()
                            .unwrap()
                } else {
                    x_i.to_bigint().unwrap()
                }
            })
            .collect::<Vec<_>>();

        bigint_vec
    }

    pub fn norm(&self) -> BigUint {
        let mut biguint_vec = self
            .vals
            .iter()
            .map(|&x_i| std::convert::Into::<BigUint>::into(x_i))
            .collect::<Vec<_>>();

        biguint_vec.iter_mut().for_each(|bu| {
            if *bu > std::convert::Into::<BigUint>::into(FqParameters::MODULUS) / 2_u32 {
                *bu = std::convert::Into::<BigUint>::into(FqParameters::MODULUS) - bu.clone();
            }
        });
        biguint_vec.iter().max().unwrap().clone()
    }
}

impl Mul<BigUint> for Encodedtext {
    type Output = Self;

    fn mul(self, other: BigUint) -> Self {
        let out_val = self
            .vals
            .iter()
            .map(|&x| x * Fq::from(other.clone()))
            .collect();
        Self { vals: out_val }
    }
}

impl Mul<Fq> for Encodedtext {
    type Output = Self;

    fn mul(self, other: Fq) -> Self {
        let out_val = self.vals.iter().map(|&x| x * other).collect();
        Self { vals: out_val }
    }
}

impl Mul<Encodedtext> for Encodedtext {
    type Output = Self;

    fn mul(self, other: Encodedtext) -> Self {
        let self_poly = DensePolynomial::from_coefficients_vec(self.vals.clone());
        let other_poly = DensePolynomial::from_coefficients_vec(other.vals.clone());
        let out_poly = (&self_poly).mul(&other_poly);

        let out_raw_val = out_poly.coeffs;

        // modulo Phi_m(X), m=N+1

        let mut modulo_poly: Vec<ark_ff::Fp768<FqParameters>> = vec![Fq::zero(); self.len().add(1)];
        modulo_poly[0] = Fq::one();
        modulo_poly[self.len()] = Fq::one();

        let out_val = poly_remainder2(&out_raw_val, &modulo_poly, self.len());
        Self { vals: out_val }
    }
}

fn poly_remainder(a: &[Fq], b: &[Fq], degree: usize) -> Vec<Fq> {
    let mut r = a.to_vec();

    while r.len() >= b.len() {
        let ratio = *r.last().unwrap() / b.last().unwrap();
        let degree = r.len() - b.len();

        let t: Vec<Fq> = b.iter().map(|&x| x * ratio).collect();

        for i in (0..t.len()).rev() {
            r[i + degree] -= t[i];
        }

        let _zero = Fq::zero();

        while let Some(_zero) = r.last() {
            r.pop();
        }
    }

    if r.len() < degree {
        r.extend(vec![Fq::zero(); degree - r.len()])
    }
    r
}

fn poly_remainder2(a: &[Fq], b: &[Fq], expect_length: usize) -> Vec<Fq> {
    let a_poly = DensePolynomial::from_coefficients_vec(a.to_vec());
    let b_poly = DensePolynomial::from_coefficients_vec(b.to_vec());

    let a_poly2 = DenseOrSparsePolynomial::from(a_poly);
    let b_poly2 = DenseOrSparsePolynomial::from(b_poly);

    let (_, res) = a_poly2.divide_with_q_and_r(&b_poly2).unwrap();

    let mut res_vec = res.coeffs;

    if res_vec.len() < expect_length {
        res_vec.extend(vec![Fq::zero(); expect_length - res_vec.len()])
    }

    res_vec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly_remainder() {
        let a = vec![Fq::from(1), Fq::from(2), Fq::from(3)];
        let b = vec![Fq::from(2), Fq::from(1)];
        let res = poly_remainder2(&a, &b, b.len() - 1);
        assert_eq!(res, vec![Fq::from(9)]);
    }

    #[test]
    fn test_encoded_text() {
        let et_1 = Encodedtext::from_vec(vec![Fq::from(1), Fq::from(2)]);
        let et_2 = Encodedtext::from_vec(vec![Fq::from(2), Fq::from(3)]);
        let et_add = et_1.clone() + et_2.clone();
        let et_add_expected = Encodedtext::from_vec(vec![Fq::from(1 + 2), Fq::from(2 + 3)]);

        assert_eq!(et_add, et_add_expected);

        let et_vec: Vec<Encodedtext> = vec![et_1, et_2];
        let et_sum: Encodedtext = et_vec.iter().cloned().sum();
        assert_eq!(et_sum, et_add_expected);
    }
}
