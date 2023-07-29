use ark_bls12_377::Fr;
use ark_ff::PrimeField;
use ark_std::UniformRand;
use num_bigint::{BigInt, ToBigInt};
use rand::{thread_rng, Rng};
use rand_distr::{num_traits::ToPrimitive, Distribution, Normal};
use std::ops::{Add, Mul, Neg, Sub};

#[derive(Clone)]
pub struct Plaintext(Vec<Fr>); // Finite field

#[derive(Clone, PartialEq, Debug)]
pub struct Encodedtext {
    x: Vec<i128>, // \mathbb{Z}^N or Aq = Zq[X]/F(X) = Zq[X]/Phi_m(X)
    q: i128,      // modulus of Aq
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
    p: i128,
}

impl Plaintext {
    pub fn new(val: Vec<Fr>) -> Plaintext {
        Plaintext { 0: val }
    }

    pub fn rand<T: Rng>(length_s: usize, rng: &mut T) -> Plaintext {
        let mut res = vec![Fr::from(0); length_s];
        for i in 0..length_s {
            res[i] = Fr::rand(rng);
        }
        Plaintext { 0: res }
    }

    // TODO: preprocessingの並列処理とセキュリティを考慮したのちに実装
    pub fn encode(&self) -> Encodedtext {
        let N = 10;
        let mut vec = vec![0; N];

        // let s = self.0[0].into_bigint().into();
        for i in 0..self.0.len() {
            vec[i] = self.0[i].into_bigint().0[0] as i128;
        }

        // let y = self.0[1].into_bigint();
        Encodedtext {
            //0: self.0.iter().map(|&x| x.0.to_i32().unwrap()).collect(),
            //x: self.0.iter().map(|&x| 0).collect(),
            x: vec,
            q: 83380292323641237751, //7427466391,
        }
    }
}

impl Add for Plaintext {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let mut res = vec![Fr::from(0); self.0.len()];
        for i in 0..self.0.len() {
            res[i] = self.0[i] + other.0[i];
        }
        Plaintext { 0: res }
    }
}

impl Sub for Plaintext {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let mut res = vec![Fr::from(0); self.0.len()];
        for i in 0..self.0.len() {
            res[i] = self.0[i] - other.0[i];
        }
        Plaintext { 0: res }
    }
}

impl Neg for Plaintext {
    type Output = Self;

    fn neg(self) -> Self {
        let mut result = vec![Fr::from(0); self.0.len()];
        for i in (0..result.len()) {
            result[i] = -self.0[i];
        }
        Plaintext { 0: result }
    }
}

impl Encodedtext {
    pub fn new(x: Vec<i128>, q: i128) -> Encodedtext {
        Encodedtext { x, q }
    }

    pub fn rand<T: Rng>(degree: i32, q: i128, rng: &mut T) -> Encodedtext {
        let mut res = vec![0; degree as usize];

        for i in 0..(degree as usize) {
            res[i] = rng.gen()
        }
        Encodedtext { x: res, q }
    }

    pub fn get_q(&self) -> i128 {
        self.q
    }

    pub fn get_degree(&self) -> usize {
        self.x.len()
    }

    // TODO: preprocessingの並列処理とセキュリティを考慮したのちに実装
    pub fn decode(&self) -> Plaintext {
        let mut res = vec![Fr::from(0); 1];
        res[0] = Fr::from(0);
        Plaintext { 0: res }
    }

    pub fn norm(&self) -> i128 {
        self.x.iter().map(|&x_i| x_i.abs()).max().unwrap()
    }

    fn modulo(&self) -> Encodedtext {
        let mut res = vec![0; self.x.len()];
        for i in 0..self.x.len() {
            res[i] = ((self.x[i] % self.q) + self.q) % self.q;
        }
        Encodedtext { x: res, q: self.q }
    }

    pub fn modulo_p(&self, p: i128) -> Encodedtext {
        let mut res = vec![0; self.x.len()];
        for i in 0..self.x.len() {
            res[i] = ((self.x[i] % p) + p) % p;
        }
        Encodedtext { x: res, q: self.q }
    }

    pub fn encrypt(&self, pk: &PublicKey, r: &Encodedtext) -> Ciphertext {
        let degree = self.x.len();
        let mut uvw = Vec::new();
        for chunk in r.x.chunks(degree) {
            uvw.push(chunk.to_vec());
        }
        let u = Encodedtext {
            x: uvw[0].clone(),
            q: self.q,
        };
        let v = Encodedtext {
            x: uvw[1].clone(),
            q: self.q,
        };
        let w = Encodedtext {
            x: uvw[2].clone(),
            q: self.q,
        };

        let c0 = pk.b.clone() * v.clone() + w * pk.p + self.clone();
        let c1 = pk.a.clone() * v + u * pk.p;
        let c2 = Encodedtext {
            x: vec![0; degree],
            q: self.q,
        };

        Ciphertext::new(c0, c1, c2)
    }
}

impl Add for Encodedtext {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let mut res = vec![0; self.x.len().max(other.x.len())];
        for i in 0..res.len() {
            res[i] = (self.x[i] + other.x[i]) % self.q;
        }
        Self { x: res, q: self.q }.modulo()
    }
}

impl Sub for Encodedtext {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let mut res = vec![0; self.x.len()];
        if other.x.is_empty() {
            return self.modulo();
        } else {
            for i in 0..self.x.len() {
                res[i] = (self.x[i] - other.x[i]) % self.q;
            }
            Self { x: res, q: self.q }.modulo()
        }
    }
}

impl Mul<i128> for Encodedtext {
    type Output = Self;

    fn mul(self, other: i128) -> Self {
        let out_val = self.x.iter().map(|&x| x * other).collect();
        Self {
            x: out_val,
            q: self.q,
        }
        .modulo()
    }
}

impl Mul<Encodedtext> for Encodedtext {
    type Output = Self;

    fn mul(self, other: Encodedtext) -> Self {
        let mut out_raw_val = vec![0; self.x.len() + other.x.len() - 1];
        for (i, self_i) in self.x.iter().enumerate() {
            for (j, other_j) in other.x.iter().enumerate() {
                let target_degree = i + j;
                let self_i_times_other_j_bigint: BigInt = (&self_i.to_bigint().unwrap() % self.q)
                    * (&other_j.to_bigint().unwrap() % self.q)
                    % self.q;
                out_raw_val[target_degree] += self_i_times_other_j_bigint.to_i128().unwrap();
                out_raw_val[target_degree] %= self.q;
            }
        }

        // modulo Phi_m(X)
        let modulo_poly = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]; // F(X) = X^10
        let out_val = poly_remainder(&out_raw_val, &modulo_poly, modulo_poly.len() - 1);
        Self {
            x: out_val,
            q: self.q,
        }
        .modulo()
    }
}

impl Ciphertext {
    pub fn new(c0: Encodedtext, c1: Encodedtext, c2: Encodedtext) -> Ciphertext {
        Ciphertext { c0, c1, c2 }
    }

    pub fn rand<T: Rng>(pk: &PublicKey, length: i32, q: i128, rng: &mut T) -> Ciphertext {
        let et = Encodedtext::rand(length, q, rng);
        let r = get_gaussian(3.2, (length * 3) as usize, q, rng);
        et.encrypt(pk, &r)
    }

    pub fn get_q(&self) -> i128 {
        self.c0.q
    }

    pub fn get_degree(&self) -> usize {
        self.c0.x.len()
    }

    pub fn decrypt(&self, sk: &SecretKey) -> Encodedtext {
        let sc1 = sk.s.clone() * self.c1.clone();
        let sc2 = sk.s.clone() * sk.s.clone() * self.c2.clone();
        let mut result = self.c0.clone() - sc1 - sc2;
        for i in 0..result.x.len() {
            if result.x[i] > result.q / 2 {
                result.x[i] -= result.q;
            } else if result.x[i] < -result.q / 2 {
                result.x[i] += result.q;
            }
        }
        result
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

impl Mul<i128> for Ciphertext {
    type Output = Self;

    fn mul(self, other: i128) -> Self {
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
        let c2 = self.c1.clone() * other.c1.clone() * (-1);
        Self { c0, c1, c2 }
    }
}

impl SecretKey {
    fn new(sk: Encodedtext) -> Self {
        Self { s: sk }
    }

    pub fn generate<T: Rng>(degree: i32, q: i128, std_dev: f64, rng: &mut T) -> Self {
        let s = get_gaussian(std_dev, degree as usize, q, rng);
        Self { s }
    }

    pub fn public_key_gen<T: Rng>(
        &self,
        degree: i32,
        p: i128,
        q: i128,
        std_dev: f64,
        rng: &mut T,
    ) -> PublicKey {
        let s = self.s.clone().modulo();
        let a = Encodedtext::rand(degree, q, rng).modulo();

        let e = get_gaussian(std_dev, degree as usize, q, rng);
        let b = a.clone() * s + e * p;
        PublicKey { a, b, p }
    }
}

impl PublicKey {
    pub fn new(a: Encodedtext, b: Encodedtext, p: i128) -> Self {
        Self { a, b, p }
    }
}

fn poly_remainder(a: &Vec<i128>, b: &Vec<i128>, degree: usize) -> Vec<i128> {
    let mut r = a.to_vec();

    while r.len() >= b.len() {
        let ratio = r.last().unwrap() / b.last().unwrap();
        let degree = r.len() - b.len();

        let t = b.iter().map(|&x| x * ratio).collect::<Vec<i128>>();

        for i in (0..t.len()).rev() {
            r[i + degree] -= t[i];
        }

        while let Some(&0) = r.last() {
            r.pop();
        }
    }

    if r.len() < degree {
        r.extend(vec![0; degree - r.len()])
    }
    r
}

pub fn get_gaussian<T: Rng>(std_dev: f64, dimension: usize, q: i128, rng: &mut T) -> Encodedtext {
    let gaussian = Normal::new(0.0, std_dev).unwrap(); // ?
    let val: Vec<i128> = (0..dimension)
        .map(|_| gaussian.sample(rng).abs() as i128)
        .collect();
    Encodedtext::new(val, q)
}

#[test]
fn test() {
    let mut rng = thread_rng();

    // // Set the parameters for this instantiation of BV11
    let std_dev = 3.2; // Standard deviation for generating the error
    let p = 41; // modulus 1
    let q: i128 = 7427466391; // modulus 2
    let degree = 10; // degree = length = N     Degree of polynomials used for encoding and encrypting messages

    // // Generate secret, public keys using the given parameters
    let secret_key = SecretKey::generate(degree, q, std_dev, &mut rng);
    let public_key = secret_key.public_key_gen(degree, p, q, std_dev, &mut rng);

    // let pt = Plaintext::rand(degree, t, &mut rng);
    // let et = pt.encode();

    let et = Encodedtext::rand(degree, q, &mut rng).modulo_p(p);
    let et_2 = Encodedtext::rand(degree, q, &mut rng).modulo_p(p);
    let et_3 = Encodedtext::rand(degree, q, &mut rng).modulo_p(p);

    let r = get_gaussian(std_dev, degree as usize * 3, q, &mut rng);
    let r_2 = get_gaussian(std_dev, degree as usize * 3, q, &mut rng);
    let r_3 = get_gaussian(std_dev, degree as usize * 3, q, &mut rng);

    let ct = et.encrypt(&public_key, &r);
    let ct_2 = et_2.encrypt(&public_key, &r_2);
    let ct_3 = et_3.encrypt(&public_key, &r_3);

    let expr_ct = (ct.clone() * ct_2.clone()) + ct_3.clone();

    let dect = expr_ct.decrypt(&secret_key).modulo_p(p);

    let expected_et = ((et * et_2) + et_3).modulo_p(p);

    assert_eq!(expected_et, dect);
}
