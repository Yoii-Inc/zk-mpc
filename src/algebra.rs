use std::ops::{Add, Mul};

use ark_std::UniformRand;
use num_traits::Zero;
use rand::Rng;

use super::she::*;

pub struct AngleShare {
    public_modifier: Plaintext,
    share: Vec<Plaintext>,
    mac: Vec<Plaintext>,
}

pub struct BracketShare {
    share: Vec<Plaintext>,
    mac: Vec<(Plaintext, Vec<Plaintext>)>,
}

pub enum MpcField {
    Angle(AngleShare),
    Bracket(BracketShare),
}

impl AngleShare {
    pub fn rand<T: Rng>(rng: &mut T) -> AngleShare {
        let n = 3;

        let alpha = Plaintext::rand(rng);

        // let res = (0..params.s).map(|_| Plaintext::rand(rng)).collect();
        // Plaintexts { m: res }

        // let share = (1..n).map(|_| Plaintext::rand(rng)).collect();

        // share.append(Plaintext::zero());

        // way2: use generate function
        let share = (0..n)
            .map(|_| Plaintext::rand(rng))
            .collect::<Vec<Plaintext>>();
        let public_modifier = Plaintext::zero();

        let mac = share.iter().map(|m_i| alpha * m_i).collect();

        AngleShare {
            public_modifier,
            share,
            mac,
        }
    }

    pub fn reveal(&self, alpha: &Plaintext) -> Plaintext {
        let original = self.share.iter().sum();

        let mac1: Plaintext = self.mac.iter().sum();
        let mac2 = *alpha * (self.public_modifier + original);

        assert_eq!(mac1, mac2);

        original
    }
}

impl Add for AngleShare {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        todo!()
    }
}

impl Mul for AngleShare {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        todo!()
    }
}

impl BracketShare {
    pub fn verify_bracket_share(&self) -> bool {
        let n = self.share.len();
        let mut flag = true;
        let original: Plaintext = self.share.iter().sum();
        for i in 0..n {
            let mac_sum = self
                .mac
                .iter()
                .map(|mac| mac.1[i].clone())
                .sum::<Plaintext>();

            if mac_sum != original.clone() * self.mac[i].0.clone() {
                flag = false;
            }
        }
        flag
    }

    pub fn reveal(&self) -> Plaintext {
        self.verify_bracket_share();
        self.share.iter().sum()
    }
}
