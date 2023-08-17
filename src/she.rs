use ark_bls12_377::{Fr, FrParameters};
use ark_ff::{BigInteger256, FftField, FftParameters, Field, FpParameters, PrimeField};
use ark_mnt4_753::{Fq, FqParameters};
use ark_poly::{
    polynomial::univariate::DensePolynomial, univariate::DenseOrSparsePolynomial, UVPolynomial,
};
use ark_std::{log2, UniformRand};
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{One, Zero};
use rand::{thread_rng, Rng};
use rand_distr::{num_traits::ToPrimitive, Distribution, Normal};
use std::{
    iter::Sum,
    ops::{Add, Mul, Neg, Sub},
};

pub struct SHEParameters {
    s: usize,
    N: usize,
    p: BigUint,
    q: BigUint,
    std_dev: f64,
}

pub type Plaintext = Fr;

pub trait Plaintextish {
    fn diagonalize(&self, length: usize) -> Plaintexts;
}

impl Plaintextish for Plaintext {
    fn diagonalize(&self, length: usize) -> Plaintexts {
        Plaintexts::new(vec![self.clone(); length])
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Plaintexts {
    m: Vec<Fr>,
}

#[derive(Clone, PartialEq, Debug)]
pub struct Encodedtext {
    x: Vec<Fq>, // \mathbb{Z}^N or Aq = Zq[X]/F(X) = Zq[X]/Phi_m(X)
    N: usize,   // expected length of x
}

#[derive(Clone, PartialEq, Debug)]
pub struct Ciphertext {
    c0: Encodedtext,
    c1: Encodedtext,
    c2: Encodedtext,
} // G=Aq^3

#[derive(Clone)]
pub struct SecretKey {
    s: Encodedtext,
}

#[derive(Clone)]
pub struct PublicKey {
    a: Encodedtext,
    b: Encodedtext,
}

impl SHEParameters {
    pub fn new(s: usize, N: usize, p: BigUint, q: BigUint, std_dev: f64) -> SHEParameters {
        SHEParameters {
            s,
            N,
            p,
            q,
            std_dev,
        }
    }
}

impl Plaintexts {
    pub fn new(val: Vec<Fr>) -> Plaintexts {
        Plaintexts { m: val }
    }

    pub fn rand<T: Rng>(params: &SHEParameters, rng: &mut T) -> Plaintexts {
        let res = (0..params.s).map(|_| Fr::rand(rng)).collect();
        Plaintexts { m: res }
    }

    pub fn encode(&self, params: &SHEParameters) -> Encodedtext {
        let remainders = self.m.clone();
        let moduli = cyclotomic_moduli(params.s);

        let result_vec = interpolate(&moduli, &remainders).unwrap();

        let result_vec_on_Fq = result_vec
            .iter()
            .map(|&x| Fq::from(std::convert::Into::<BigUint>::into(x)))
            .collect::<Vec<Fq>>();

        Encodedtext {
            x: result_vec_on_Fq,
            N: params.N,
        }
    }
}

impl Add for Plaintexts {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let mut res = vec![Fr::from(0); self.m.len()];
        for i in 0..self.m.len() {
            res[i] = self.m[i] + other.m[i];
        }
        Plaintexts { m: res }
    }
}

impl Sub for Plaintexts {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let mut res = vec![Fr::from(0); self.m.len()];
        for i in 0..self.m.len() {
            res[i] = self.m[i] - other.m[i];
        }
        Plaintexts { m: res }
    }
}

impl Sum for Plaintexts {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let sum_vec = iter
            .map(|plaintext| plaintext.m)
            .fold(Vec::new(), |mut acc, vec| {
                for (i, value) in vec.iter().enumerate() {
                    if i >= acc.len() {
                        acc.push(*value);
                    } else {
                        acc[i] = acc[i] + *value;
                    }
                }
                acc
            });
        Plaintexts { m: sum_vec }
    }
}

impl Neg for Plaintexts {
    type Output = Self;

    fn neg(self) -> Self {
        let mut result = vec![Fr::from(0); self.m.len()];
        for i in (0..result.len()) {
            result[i] = -self.m[i];
        }
        Plaintexts { m: result }
    }
}

// multiplication of plaintext: multiply element with same index
impl Mul for Plaintexts {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut result = Plaintexts::new(vec![Fr::from(0); self.m.len()]);
        for i in 0..result.m.len() {
            result.m[i] = self.m[i] * rhs.m[i];
        }
        result
    }
}

impl Encodedtext {
    pub fn new(x: Vec<Fq>, N: usize) -> Encodedtext {
        Encodedtext { x, N }
    }

    pub fn rand<T: Rng>(she_params: &SHEParameters, rng: &mut T) -> Encodedtext {
        let rand_plain_text = Plaintexts::rand(she_params, rng);
        rand_plain_text.encode(she_params)
    }

    pub fn get_degree(&self) -> usize {
        self.x.len()
    }

    pub fn decode(&self, params: &SHEParameters) -> Plaintexts {
        // root: generator of Fp. N_root: N-th root of Fp.
        let root_of_cyclotomic = cyclotomic_moduli(params.N);

        // once into BigUint, -p/2~p/2
        let mut biguint_vec = self
            .x
            .iter()
            .map(|&x_i| std::convert::Into::<BigUint>::into(x_i))
            .collect::<Vec<_>>();
        for i in 0..biguint_vec.len() {
            if biguint_vec[i] > params.q.clone() / 2u128 {
                biguint_vec[i] -= params.q.clone() % params.p.clone();
            }
        }

        // into Fr
        let polynomial = biguint_vec
            .iter()
            .map(|x_i| Fr::from(x_i.clone()))
            .collect();

        let res = (0..params.s)
            .map(|i| substitute(&polynomial, &root_of_cyclotomic[i]))
            .collect();
        Plaintexts { m: res }
    }

    // TODO: 正しく実装する。uintかintか迷う。
    // pub fn norm(&self) -> i128 {
    //     self.x.iter().map(|&x_i| x_i.abs()).max().unwrap()
    // }

    pub fn encrypt(&self, pk: &PublicKey, r: &Encodedtext, params: &SHEParameters) -> Ciphertext {
        let degree = self.x.len();
        let mut uvw = Vec::new();
        for chunk in r.x.chunks(degree) {
            uvw.push(chunk.to_vec());
        }
        let u = Encodedtext {
            x: uvw[0].clone(),
            N: params.N,
        };
        let v = Encodedtext {
            x: uvw[1].clone(),
            N: params.N,
        };
        let w = Encodedtext {
            x: uvw[2].clone(),
            N: params.N,
        };

        let c0 = pk.b.clone() * v.clone() + w * params.p.clone() + self.clone();
        let c1 = pk.a.clone() * v + u * params.p.clone();
        let c2 = Encodedtext {
            x: vec![Fq::zero(); degree],
            N: params.N,
        };

        Ciphertext::new(c0, c1, c2)
    }
}

impl Add for Encodedtext {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let mut res = vec![Fq::zero(); self.N];
        for i in 0..res.len() {
            res[i] = self.x[i] + other.x[i];
        }
        Self { x: res, N: self.N }
    }
}

impl Sub for Encodedtext {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let mut res = vec![Fq::zero(); self.x.len().max(other.x.len())];
        if other.x.is_empty() {
            return self;
        } else {
            for i in 0..res.len() {
                res[i] = self.x[i] - other.x[i];
            }
            Self { x: res, N: self.N }
        }
    }
}

// impl Mul<i128> for Encodedtext {
//     type Output = Self;

//     fn mul(self, other: i128) -> Self {
//         let out_val = self.x.iter().map(|&x| x * other).collect();
//         Self {
//             x: out_val,
//             q: self.q,
//         }
//         .modulo()
//     }
// }

impl Mul<BigUint> for Encodedtext {
    type Output = Self;

    fn mul(self, other: BigUint) -> Self {
        let out_val = self
            .x
            .iter()
            .map(|&x| x * Fq::from(other.clone()))
            .collect();
        Self {
            x: out_val,
            N: self.N,
        }
    }
}

impl Mul<Fq> for Encodedtext {
    type Output = Self;

    fn mul(self, other: Fq) -> Self {
        let out_val = self.x.iter().map(|&x| x * other).collect();
        Self {
            x: out_val,
            N: self.N,
        }
    }
}

impl Mul<Encodedtext> for Encodedtext {
    type Output = Self;

    fn mul(self, other: Encodedtext) -> Self {
        let self_poly = DensePolynomial::from_coefficients_vec(self.x.clone());
        let other_poly = DensePolynomial::from_coefficients_vec(other.x.clone());
        let out_poly = (&self_poly).mul(&other_poly);

        let out_raw_val = out_poly.coeffs;

        // modulo Phi_m(X), m=N+1

        let mut modulo_poly = vec![Fq::zero(); self.N + 1];
        modulo_poly[0] = Fq::one();
        modulo_poly[self.N] = Fq::one();

        let out_val = poly_remainder2(&out_raw_val, &modulo_poly, self.N);
        Self {
            x: out_val,
            N: self.N,
        }
    }
}

impl Ciphertext {
    pub fn new(c0: Encodedtext, c1: Encodedtext, c2: Encodedtext) -> Ciphertext {
        Ciphertext { c0, c1, c2 }
    }

    pub fn rand<T: Rng>(
        pk: &PublicKey,
        length: i32,
        rng: &mut T,
        params: &SHEParameters,
    ) -> Ciphertext {
        let et = Encodedtext::rand(params, rng);
        let r = get_gaussian(params, params.N * 3, rng);
        et.encrypt(pk, &r, params)
    }

    // pub fn get_q(&self) -> i128 {
    //     self.c0.q
    // }

    pub fn get_degree(&self) -> usize {
        self.c0.x.len()
    }

    pub fn decrypt(&self, sk: &SecretKey) -> Encodedtext {
        let sc1 = sk.s.clone() * self.c1.clone();
        let sc2 = sk.s.clone() * sk.s.clone() * self.c2.clone();

        self.c0.clone() - sc1 - sc2
    }
}

impl Add for Ciphertext {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            c0: self.c0 + other.c0,
            c1: self.c1 + other.c1,
            c2: self.c2 + other.c2,
        }
    }
}

impl Sub for Ciphertext {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self {
            c0: self.c0 - other.c0,
            c1: self.c1 - other.c1,
            c2: self.c2 - other.c2,
        }
    }
}

impl Mul<Fq> for Ciphertext {
    type Output = Self;

    fn mul(self, other: Fq) -> Self {
        Self {
            c0: self.c0 * other,
            c1: self.c1 * other,
            c2: self.c2 * other,
        }
    }
}

impl Mul<Ciphertext> for Ciphertext {
    type Output = Self;

    fn mul(self, other: Ciphertext) -> Self {
        let c0 = self.c0.clone() * other.c0.clone();
        let c1 = self.c0.clone() * other.c1.clone() + self.c1.clone() * other.c0.clone();
        let c2 = self.c1.clone() * other.c1.clone() * Fq::from(-1);
        Self { c0, c1, c2 }
    }
}

impl SecretKey {
    fn new(sk: Encodedtext) -> Self {
        Self { s: sk }
    }

    pub fn generate<T: Rng>(she_params: &SHEParameters, rng: &mut T) -> Self {
        let s = get_gaussian(she_params, she_params.N, rng);
        Self { s }
    }

    pub fn public_key_gen<T: Rng>(&self, she_params: &SHEParameters, rng: &mut T) -> PublicKey {
        let s = self.s.clone();
        let a = Encodedtext::rand(she_params, rng);

        let e = get_gaussian(she_params, she_params.N, rng);
        let b = a.clone() * s + e * she_params.p.clone();
        PublicKey { a, b }
    }
}

impl PublicKey {
    pub fn new(a: Encodedtext, b: Encodedtext) -> Self {
        Self { a, b }
    }
}

fn poly_remainder(a: &Vec<Fq>, b: &Vec<Fq>, degree: usize) -> Vec<Fq> {
    let mut r = a.to_vec();

    while r.len() >= b.len() {
        let ratio = r.last().unwrap().clone() / b.last().unwrap();
        let degree = r.len() - b.len();

        let t: Vec<Fq> = b.iter().map(|&x| x * ratio).collect();

        for i in (0..t.len()).rev() {
            r[i + degree] -= t[i];
        }

        let zero = Fq::zero();

        while let Some(zero) = r.last() {
            r.pop();
        }
    }

    if r.len() < degree {
        r.extend(vec![Fq::zero(); degree - r.len()])
    }
    r
}

fn poly_remainder2(a: &Vec<Fq>, b: &Vec<Fq>, expect_length: usize) -> Vec<Fq> {
    let mut a_poly = DensePolynomial::from_coefficients_vec(a.clone());
    let mut b_poly = DensePolynomial::from_coefficients_vec(b.clone());

    let a_poly2 = DenseOrSparsePolynomial::from(a_poly);
    let b_poly2 = DenseOrSparsePolynomial::from(b_poly);

    let (_, res) = a_poly2.divide_with_q_and_r(&b_poly2).unwrap();

    let mut res_vec = res.coeffs;

    if res_vec.len() < expect_length {
        res_vec.extend(vec![Fq::zero(); expect_length - res_vec.len()])
    }

    res_vec
}

pub fn get_gaussian<T: Rng>(
    she_params: &SHEParameters,
    dimension: usize,
    rng: &mut T,
) -> Encodedtext {
    let gaussian = Normal::new(0.0, she_params.std_dev).unwrap(); // ?
    let val: Vec<Fq> = (0..dimension)
        .map(|_| Fq::from(gaussian.sample(rng).abs() as u128))
        .collect();
    Encodedtext::new(val, dimension)
}

fn substitute(polynomial: &Vec<Fr>, variable: &Fr) -> Fr {
    let mut result = Fr::from(0);
    for (i, coefficient) in polynomial.iter().enumerate() {
        result += coefficient.clone() * variable.pow([i as u64]);
    }
    result
}

fn cyclotomic_moduli(length: usize) -> Vec<Fr> {
    // moduli: lengthは本来N-1だが、sで切り捨て
    // N-1個の根は、円分多項式Phi_N(X) on Fpの根である

    // N=sである。N * 2=mである。mは2の冪である。m=2^kであるとき(ただし、1<=k<47)、moduliは、TWO_ADIC_ROOT_OF_UNITY^{2^(47-k)}のi乗である。

    let k = log2(length * 2);
    let m_root_of_unity = Fr::two_adic_root_of_unity().pow([2_u64.pow(47 - k)]);
    let mut moduli = Vec::new();
    for i in 0..length {
        moduli.push(m_root_of_unity.pow([(2 * i + 1) as u64]));
    }

    moduli
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

fn is_power_of_two(n: usize) -> bool {
    n != 0 && (n & (n - 1)) == 0
}

mod tests {
    use crate::she;

    use super::*;

    #[test]
    fn test_poly_remainder() {
        let a = vec![Fq::from(1), Fq::from(2), Fq::from(3)];
        let b = vec![Fq::from(2), Fq::from(1)];
        let degree = 2;
        let res = poly_remainder2(&a, &b, b.len() - 1);
        assert_eq!(res, vec![Fq::from(9)]);
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

    #[test]
    fn test_cyclotomic_moduli() {
        let mut rng = thread_rng();

        // Set the parameters for this instantiation of BV11
        let std_dev = 3.2; // Standard deviation for generating the error
        let s = 64;
        let p: BigUint = FrParameters::MODULUS.into();
        let q: BigUint = FqParameters::MODULUS.into();
        let degree = s;

        let she_params = SHEParameters::new(s, degree, p.clone(), q.clone(), std_dev);

        let res = cyclotomic_moduli(she_params.N);

        for i in 0..res.len() {
            assert_eq!(Fr::one(), res[i].pow([(s * 2) as u64]));
        }
        println!("hello");
    }

    #[test]
    fn test_plaintext() {
        let pl_1: Plaintexts = Plaintexts::new(vec![Fr::from(1), Fr::from(2)]);
        let pl_2: Plaintexts = Plaintexts::new(vec![Fr::from(2), Fr::from(3)]);
        let pl_add = pl_1.clone().add(pl_2.clone());
        let pl_add_expected = Plaintexts::new(vec![Fr::from(1 + 2), Fr::from(2 + 3)]);
        assert_eq!(pl_add, pl_add_expected);

        let pl_vec: Vec<Plaintexts> = vec![pl_1.clone(), pl_2.clone()];
        let pl_sum: Plaintexts = pl_vec.iter().cloned().sum();
        assert_eq!(pl_sum, pl_add_expected);
    }

    #[test]
    fn test() {
        let mut rng = thread_rng();

        // // Set the parameters for this instantiation of BV11
        let std_dev = 3.2; // Standard deviation for generating the error
        let s = 64; // must be 2^k for 0 <= k <= 46
        assert!(is_power_of_two(s));
        assert!(s as u64 <= 2_u64.pow(46));
        let p: BigUint = FrParameters::MODULUS.into();
        let q: BigUint = FqParameters::MODULUS.into();
        let degree = s; // degree = length = N     Degree of polynomials used for encoding and encrypting messages

        let she_params = SHEParameters::new(s, degree, p, q, std_dev);

        // // Generate secret, public keys using the given parameters
        let secret_key = SecretKey::generate(&she_params, &mut rng);
        let public_key = secret_key.public_key_gen(&she_params, &mut rng);

        let pt = Plaintexts::rand(&she_params, &mut rng);
        let pt_2 = Plaintexts::rand(&she_params, &mut rng);
        let pt_3 = Plaintexts::rand(&she_params, &mut rng);

        let et = pt.encode(&she_params);
        let et_2 = pt_2.encode(&she_params);
        let et_3 = pt_3.encode(&she_params);

        let r = get_gaussian(&she_params, degree * 3, &mut rng);
        let r_2 = get_gaussian(&she_params, degree * 3, &mut rng);
        let r_3 = get_gaussian(&she_params, degree * 3, &mut rng);

        let ct = et.encrypt(&public_key, &r, &she_params);
        let ct_2 = et_2.encrypt(&public_key, &r_2, &she_params);
        let ct_3 = et_3.encrypt(&public_key, &r_3, &she_params);

        // Plain -> Encoded  -> Plain, uni text
        let dect = et.decode(&she_params);

        assert_eq!(pt, dect);

        // Plain -> Encoded -> Cipher -> Encoded -> Plain, uni text
        let dect = ct.decrypt(&secret_key);
        let decrypted_decoded_ct = dect.decode(&she_params);

        assert_eq!(pt, decrypted_decoded_ct);

        // Plain -> Encoded -> Cipher -> Encoded -> Plain, sum of 2 texts
        let expr_ct = ct.clone() + ct_2.clone(); // + ct_3.clone();
        let dect = expr_ct.decrypt(&secret_key).decode(&she_params);
        let expected_pt = pt.clone() + pt_2.clone();

        assert_eq!(expected_pt, dect);

        // Plain -> Encoded -> Plain, multiplication of 2 texts
        let expr_et = et.clone() * et_2.clone(); // + ct_3.clone();
        let dect = expr_et.decode(&she_params);
        let expected_pt = pt.clone() * pt_2.clone();

        assert_eq!(expected_pt, dect);

        // Plain -> Encoded -> Cipher -> Encoded -> Plain, multiplication of 2 texts
        let expr_ct = ct.clone() * ct_2.clone(); // + ct_3.clone();
        let dect = expr_ct.decrypt(&secret_key).decode(&she_params);
        let expected_pt = pt.clone() * pt_2.clone();

        assert_eq!(expected_pt, dect);

        // Plain -> Encoded -> Cipher -> Encoded -> Plain, multiplication and addition of 3 texts
        let expr_ct = ct.clone() * ct_2.clone() + ct_3.clone();
        let dect = expr_ct.decrypt(&secret_key).decode(&she_params);
        let expected_pt = pt.clone() * pt_2.clone() + pt_3.clone();

        assert_eq!(expected_pt, dect);
    }
}
