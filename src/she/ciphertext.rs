use rand::Rng;
use std::{
    iter::Sum,
    ops::{Add, AddAssign, Mul, Sub},
};

use crate::she::{get_gaussian, Encodedtext, Fq, PublicKey, SHEParameters, SecretKey};

#[derive(Clone, PartialEq, Debug)]
pub struct Ciphertext {
    c0: Encodedtext,
    c1: Encodedtext,
    c2: Encodedtext,
} // G=Aq^3

impl Ciphertext {
    pub fn zero(n: usize) -> Ciphertext {
        Ciphertext {
            c0: Encodedtext::zero(n),
            c1: Encodedtext::zero(n),
            c2: Encodedtext::zero(n),
        }
    }

    pub fn from(c0: Encodedtext, c1: Encodedtext, c2: Encodedtext) -> Ciphertext {
        assert!(c0.len() == c1.len());
        assert!(c1.len() == c2.len());
        Ciphertext { c0, c1, c2 }
    }

    pub fn rand<T: Rng>(pk: &PublicKey, rng: &mut T, params: &SHEParameters) -> Ciphertext {
        let et = Encodedtext::rand(params, rng);
        let r = get_gaussian(params, params.n * 3, rng);
        Ciphertext::encrypt_from(&et, pk, &r, params)
    }

    // pub fn get_q(&self) -> i128 {
    //     self.c0.q
    // }

    pub fn get_degree(&self) -> usize {
        self.c0.len()
    }

    pub fn encrypt_from(
        e: &Encodedtext,
        pk: &PublicKey,
        r: &Encodedtext,
        params: &SHEParameters,
    ) -> Ciphertext {
        let degree = e.vals.len();
        let mut uvw = Vec::new();
        for chunk in r.vals.chunks(degree) {
            uvw.push(chunk.to_vec());
        }
        let u = Encodedtext {
            vals: uvw[0].clone(),
        };
        let v = Encodedtext {
            vals: uvw[1].clone(),
        };
        let w = Encodedtext {
            vals: uvw[2].clone(),
        };

        let c0 = pk.b.clone() * v.clone() + w * params.p.clone() + e.clone();
        let c1 = pk.a.clone() * v + u * params.p.clone();
        let c2 = Encodedtext::zero(degree);

        Ciphertext::from(c0, c1, c2)
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

impl AddAssign for Ciphertext {
    fn add_assign(&mut self, rhs: Self) {
        self.c0 += rhs.c0;
        self.c1 += rhs.c1;
        self.c2 += rhs.c2;
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

impl Mul<Ciphertext> for Ciphertext {
    type Output = Self;

    fn mul(self, other: Ciphertext) -> Self {
        let c0 = self.c0.clone() * other.c0.clone();
        let c1 = self.c0.clone() * other.c1.clone() + self.c1.clone() * other.c0.clone();
        let c2 = -self.c1.clone() * other.c1.clone();
        Self { c0, c1, c2 }
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

impl Sum for Ciphertext {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        // let iter2 = iter.cloned();
        let mut iter2 = iter.peekable();
        let n: usize = iter2.peek().unwrap().get_degree();
        iter2.fold(Ciphertext::zero(n), |acc, ciphertext| acc + ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{FpParameters, Fq, FqParameters, FrParameters};
    use rand::thread_rng;

    use super::*;

    #[test]
    fn test_cipher_text() {
        let mut rng = thread_rng();
        let she_params = SHEParameters::new(
            2,
            2,
            FrParameters::MODULUS.into(),
            FqParameters::MODULUS.into(),
            3.2,
        );

        let secret_key = SecretKey::generate(&she_params, &mut rng);
        let public_key = secret_key.public_key_gen(&she_params, &mut rng);

        let et_1 = Encodedtext::from_vec(vec![Fq::from(1), Fq::from(2)]);
        let et_2 = Encodedtext::from_vec(vec![Fq::from(2), Fq::from(3)]);
        let r_1 = get_gaussian(&she_params, 2 * 3, &mut rng);
        let r_2 = get_gaussian(&she_params, 2 * 3, &mut rng);

        let ct_1 = Ciphertext::encrypt_from(&et_1, &public_key, &r_1, &she_params);
        let ct_2 = Ciphertext::encrypt_from(&et_2, &public_key, &r_2, &she_params);

        let ct_add = ct_1.clone() + ct_2.clone();

        let ct_vec: Vec<Ciphertext> = vec![ct_1, ct_2];
        let ct_sum: Ciphertext = ct_vec.iter().cloned().sum();
        assert_eq!(ct_sum, ct_add);
    }
}
