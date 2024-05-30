use crate::{BitAdd, BitwiseLessThan, FieldShare, MpcField, Reveal, UniformBitRand};
use ark_ff::{
    BigInteger, Field, FpParameters, One, PrimeField, SquareRootField, UniformRand, Zero,
};
use core::panic;
use mpc_trait::MpcWire;
use rand::Rng;
use std::ops::{BitAnd, BitOr, BitXor, Not};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct MpcBooleanField<F: Field, S: FieldShare<F>>(MpcField<F, S>);

pub trait BooleanWire: Clone + Copy + Not<Output = Self> + From<bool> {
    type Base;

    fn pub_true() -> Self;
    fn pub_false() -> Self;
    fn field(&self) -> Self::Base;
    fn and(self, other: Self) -> Self;
    fn or(self, other: Self) -> Self;
    fn xor(self, other: Self) -> Self;
}

impl<F: Field, S: FieldShare<F>> BooleanWire for MpcBooleanField<F, S> {
    type Base = MpcField<F, S>;

    fn pub_true() -> Self {
        Self(MpcField::one())
    }

    fn pub_false() -> Self {
        Self(MpcField::zero())
    }

    fn field(&self) -> MpcField<F, S> {
        self.0
    }

    fn and(self, other: Self) -> Self {
        Self(self.0 * other.0)
    }
    fn or(self, other: Self) -> Self {
        Self(self.0 + other.0 - (self.0 * other.0))
    }

    fn xor(self, other: Self) -> Self {
        Self(self.0 + other.0 - (self.0 * other.0 * MpcField::from(2u8)))
    }
}

impl<F: Field, S: FieldShare<F>> Not for MpcBooleanField<F, S> {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self(MpcField::one() - self.0)
    }
}

impl<F: Field, S: FieldShare<F>> BitAnd for MpcBooleanField<F, S> {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        self.and(rhs)
    }
}

impl<F: Field, S: FieldShare<F>> BitOr for MpcBooleanField<F, S> {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        self.or(rhs)
    }
}

impl<F: Field, S: FieldShare<F>> BitXor for MpcBooleanField<F, S> {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        self.xor(rhs)
    }
}

// from MpcBooleanField to MpcField
impl<F: Field, S: FieldShare<F>> From<MpcBooleanField<F, S>> for MpcField<F, S> {
    fn from(b: MpcBooleanField<F, S>) -> Self {
        b.0
    }
}

// from MpcField to MpcBooleanField
impl<F: Field, S: FieldShare<F>> From<MpcField<F, S>> for MpcBooleanField<F, S> {
    fn from(f: MpcField<F, S>) -> Self {
        Self(f)
    }
}

// from bool to MpcBooleanField
impl<F: Field, S: FieldShare<F>> From<bool> for MpcBooleanField<F, S> {
    fn from(b: bool) -> Self {
        if b {
            Self::pub_true()
        } else {
            Self::pub_false()
        }
    }
}

impl<F: PrimeField, S: FieldShare<F>> BitwiseLessThan for Vec<MpcBooleanField<F, S>> {
    type Output = MpcBooleanField<F, S>;

    fn is_smaller_than_le(&self, other: &Self) -> Self::Output {
        let modulus_size = F::Params::MODULUS_BITS as usize;
        assert_eq!(self.len(), modulus_size);
        assert_eq!(other.len(), modulus_size);

        // [c_i] = [a_i \oplus b_i]
        let c = self
            .iter()
            .zip(other.iter())
            .map(|(&a, &b)| a ^ b)
            .collect::<Vec<_>>();
        let rev_c = c.into_iter().rev().collect::<Vec<_>>();

        // d_i = OR_{j=i}^{modulus_size-1} c_j
        let mut d = vec![rev_c[0]];
        for i in 0..modulus_size - 1 {
            d.push(d[i] | rev_c[i + 1]);
        }
        d.reverse();

        let e = (0..modulus_size)
            .map(|i| {
                if i == modulus_size - 1 {
                    d[modulus_size - 1].field()
                } else {
                    d[i].field() - d[i + 1].field()
                }
            })
            .collect::<Vec<MpcField<F, S>>>();

        Self::Output::from(
            e.iter()
                .zip(other.iter())
                .map(|(&e, &b)| e * b.field())
                .sum::<MpcField<F, S>>(),
        )
    }
}

impl<F: PrimeField + SquareRootField, S: FieldShare<F>> UniformBitRand for MpcBooleanField<F, S> {
    type BaseField = MpcField<F, S>;

    fn bit_rand<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        let r = Self::BaseField::rand(rng);
        let r2 = (r * r).reveal();
        let mut root_r2;

        loop {
            root_r2 = r2.sqrt().unwrap();

            if !root_r2.is_zero() {
                break;
            }
        }

        Self(
            (r / Self::BaseField::from_public(root_r2) + Self::BaseField::one())
                / Self::BaseField::from_public(F::from(2u8)),
        )
    }

    fn rand_number_bitwise<R: Rng + ?Sized>(rng: &mut R) -> (Vec<Self>, Self::BaseField) {
        let modulus_size = F::Params::MODULUS_BITS as usize;

        let mut modulus_bits = F::Params::MODULUS
            .to_bits_le()
            .iter()
            .map(|&b| Self::from(b))
            .collect::<Vec<_>>();

        modulus_bits = modulus_bits[..modulus_size].to_vec();

        let valid_bits = loop {
            let bits = (0..modulus_size)
                .map(|_| Self::bit_rand(rng))
                .collect::<Vec<_>>();

            if bits
                .clone()
                .is_smaller_than_le(&modulus_bits)
                .field()
                .reveal()
                .is_one()
            {
                break bits;
            }
        };

        // bits to field elemetn (little endian)
        let num = valid_bits
            .iter()
            .map(|b| b.field())
            .rev()
            .fold(Self::BaseField::zero(), |acc, x| {
                acc * Self::BaseField::from_public(F::from(2u8)) + x
            });

        (valid_bits, num)
    }
}

impl<F: Field, S: FieldShare<F>> MpcWire for MpcBooleanField<F, S> {
    fn is_shared(&self) -> bool {
        self.field().is_shared()
    }

    fn publicize(&mut self) {
        self.field().publicize();
    }

    fn publicize_cow<'b>(&'b self) -> std::borrow::Cow<'b, Self> {
        if self.is_shared() {
            let mut s = self.clone();
            s.publicize();
            std::borrow::Cow::Owned(s)
        } else {
            std::borrow::Cow::Borrowed(self)
        }
    }
}

impl<F: Field, S: FieldShare<F>> BitAdd for Vec<MpcBooleanField<F, S>> {
    type Output = Self;

    fn carries(&self, other: &Self) -> Self::Output {
        match self.is_shared() {
            true => {
                assert_eq!(self.len(), other.len());
                let l = self.len(); // l is the bit length.

                let s_vec = self
                    .iter()
                    .zip(other.iter())
                    .map(|(a, b)| *a & *b)
                    .collect::<Vec<_>>();

                let p_vec = (0..l)
                    .map(|i| {
                        self[i].field() + other[i].field()
                            - MpcField::<F, S>::from_public(F::from(2u64)) * s_vec[i].field()
                    })
                    .collect::<Vec<_>>();

                let ret = (0..l)
                    .scan(MpcField::<F, S>::zero(), |is_s, i| {
                        *is_s = s_vec[i].field() + p_vec[i] * *is_s;
                        Some(*is_s)
                    })
                    .collect::<Vec<_>>();

                ret.into_iter().map(MpcBooleanField::<F, S>::from).collect()
            }
            false => {
                panic!("public is not expected here");
            }
        }
    }

    /// This function is used to add two bit vectors of lenght l.
    /// Returns a bit vector of length l+1 (bit length always increase by 1).
    fn bit_add(self, other: &Self) -> Self::Output {
        match self.is_shared() {
            true => {
                assert_eq!(self.len(), other.len());
                let l = self.len(); // l is the bit length.
                let c_vec = self.carries(other);

                (0..=l)
                    .map(|i| {
                        if i == 0 {
                            (self[0].field() + other[0].field()
                                - MpcField::<F, S>::from_public(F::from(2u64)) * c_vec[0].field())
                            .into()
                        } else if i == l {
                            c_vec[l - 1]
                        } else {
                            (self[i].field() + other[i].field() + c_vec[i - 1].field()
                                - MpcField::<F, S>::from_public(F::from(2u64)) * c_vec[i].field())
                            .into()
                        }
                    })
                    .collect()
            }
            false => {
                panic!("public is not expected here");
            }
        }
    }
}

impl<F: Field, S: FieldShare<F>> Reveal for MpcBooleanField<F, S> {
    type Base = F;
    #[inline]
    fn reveal(self) -> Self::Base {
        self.0.reveal()
    }
    #[inline]
    fn from_public(b: Self::Base) -> Self {
        if b == F::zero() {
            Self::pub_false()
        } else if b == F::one() {
            Self::pub_true()
        } else {
            panic!("not boolean")
        }
    }
    #[inline]
    fn from_add_shared(b: Self::Base) -> Self {
        MpcField::Shared(S::from_add_shared(b)).into()
    }
    #[inline]
    fn unwrap_as_public(self) -> Self::Base {
        match self.field() {
            MpcField::<F, S>::Shared(s) => s.unwrap_as_public(),
            MpcField::<F, S>::Public(s) => s,
        }
    }
    #[inline]
    fn king_share<R: Rng>(_f: Self::Base, _rng: &mut R) -> Self {
        todo!()
    }
    #[inline]
    fn king_share_batch<R: Rng>(_f: Vec<Self::Base>, _rng: &mut R) -> Vec<Self> {
        todo!()
    }
    fn init_protocol() {
        MpcField::<F, S>::init_protocol()
    }
    fn deinit_protocol() {
        MpcField::<F, S>::deinit_protocol()
    }
}
