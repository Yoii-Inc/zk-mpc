use mpc_trait::MpcWire;
use num_bigint::BigUint;
use rand::Rng;
use std::fmt::{self, Debug, Display};
use std::io::{self, Read, Write};
use std::iter::{Product, Sum};
use std::ops::*;
use std::str::FromStr;
use zeroize::Zeroize;

use log::debug;

use ark_ff::{poly_stub, prelude::*, FftField};
use ark_ff::{FromBytes, ToBytes};
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags,
};

use crate::share::field::FieldShare;
use crate::Reveal;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum MpcField<F: Field, S: FieldShare<F>> {
    Public(F),
    Shared(S),
}

impl<T: Field, S: FieldShare<T>> Reveal for MpcField<T, S> {
    type Base = T;
    #[inline]
    fn reveal(self) -> Self::Base {
        let result = match self {
            Self::Shared(s) => s.reveal(),
            Self::Public(s) => s,
        };
        // TODO Add appropriate assert
        result
    }
    #[inline]
    fn from_public(b: Self::Base) -> Self {
        MpcField::Public(b)
    }
    #[inline]
    fn from_add_shared(b: Self::Base) -> Self {
        MpcField::Shared(S::from_add_shared(b))
    }
    #[inline]
    fn unwrap_as_public(self) -> Self::Base {
        match self {
            Self::Shared(s) => todo!(),
            Self::Public(s) => s,
        }
    }
    #[inline]
    fn king_share<R: Rng>(f: Self::Base, rng: &mut R) -> Self {
        todo!()
    }
    #[inline]
    fn king_share_batch<R: Rng>(f: Vec<Self::Base>, rng: &mut R) -> Vec<Self> {
        todo!()
    }
    fn init_protocol() {
        todo!()
    }
    fn deinit_protocol() {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> Display for MpcField<F, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MpcField::Public(x) => write!(f, "{} (public)", x),
            MpcField::Shared(x) => write!(f, "{} (shared)", x),
        }
    }
}

impl<F: Field, S: FieldShare<F>> ToBytes for MpcField<F, S> {
    fn write<W: ark_serialize::Write>(&self, writer: W) -> io::Result<()> {
        match self {
            Self::Public(v) => v.write(writer),
            Self::Shared(_) => unimplemented!("write share: {}", self),
        }
    }
}

impl<F: Field, S: FieldShare<F>> FromBytes for MpcField<F, S> {
    fn read<R: Read>(_reader: R) -> io::Result<Self> {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> CanonicalSerialize for MpcField<F, S> {
    fn serialize<W: Write>(&self, writer: W) -> Result<(), ark_serialize::SerializationError> {
        match self {
            Self::Public(v) => v.serialize(writer),
            Self::Shared(_) => unimplemented!("serialize share: {}", self),
        }
    }

    fn serialized_size(&self) -> usize {
        match self {
            Self::Public(v) => v.serialized_size(),
            Self::Shared(_) => unimplemented!("serialized_size share: {}", self),
        }
    }
}

impl<F: Field, S: FieldShare<F>> CanonicalSerializeWithFlags for MpcField<F, S> {
    fn serialize_with_flags<W: Write, Fl: ark_serialize::Flags>(
        &self,
        _writer: W,
        _flags: Fl,
    ) -> Result<(), ark_serialize::SerializationError> {
        todo!()
    }

    fn serialized_size_with_flags<Fl: ark_serialize::Flags>(&self) -> usize {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> CanonicalDeserialize for MpcField<F, S> {
    fn deserialize<R: Read>(_reader: R) -> Result<Self, ark_serialize::SerializationError> {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> CanonicalDeserializeWithFlags for MpcField<F, S> {
    fn deserialize_with_flags<R: Read, Fl: ark_serialize::Flags>(
        _reader: R,
    ) -> Result<(Self, Fl), ark_serialize::SerializationError> {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> UniformRand for MpcField<F, S> {
    fn rand<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        Self::Shared(<S as UniformRand>::rand(rng))
    }
}

impl<F: Field, S: FieldShare<F>> AddAssign for MpcField<F, S> {
    fn add_assign(&mut self, rhs: Self) {
        self.add_assign(&rhs);
    }
}

impl<'a, F: Field, S: FieldShare<F>> AddAssign<&'a MpcField<F, S>> for MpcField<F, S> {
    fn add_assign(&mut self, rhs: &Self) {
        match self {
            MpcField::Public(a) => match rhs {
                MpcField::Public(b) => {
                    *a += b;
                }
                MpcField::Shared(b) => {
                    let mut tmp = *b;
                    tmp.shift(a);
                    *self = MpcField::Shared(tmp);
                }
            },
            MpcField::Shared(a) => match rhs {
                MpcField::Public(b) => {
                    a.shift(b);
                }
                MpcField::Shared(b) => {
                    a.add(b);
                }
            },
        }
    }
}

impl<F: Field, S: FieldShare<F>> Add for MpcField<F, S> {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self.add_assign(&rhs);
        self
    }
}

impl<'a, F: Field, S: FieldShare<F>> Add<&'a MpcField<F, S>> for MpcField<F, S> {
    type Output = Self;

    fn add(mut self, rhs: &'a MpcField<F, S>) -> Self::Output {
        self.add_assign(rhs);
        self
    }
}

impl<F: Field, S: FieldShare<F>> Sum for MpcField<F, S> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

impl<'a, F: Field, S: FieldShare<F>> Sum<&'a MpcField<F, S>> for MpcField<F, S> {
    fn sum<I: Iterator<Item = &'a MpcField<F, S>>>(iter: I) -> Self {
        iter.fold(Self::zero(), |x, y| x.add(y.clone()))
    }
}

impl<F: Field, S: FieldShare<F>> Neg for MpcField<F, S> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        match self {
            MpcField::Public(x) => MpcField::Public(-x),
            MpcField::Shared(mut x) => MpcField::Shared({
                x.neg();
                x
            }),
        }
    }
}

impl<F: Field, S: FieldShare<F>> SubAssign for MpcField<F, S> {
    fn sub_assign(&mut self, rhs: Self) {
        self.sub_assign(&rhs);
    }
}

impl<'a, F: Field, S: FieldShare<F>> SubAssign<&'a MpcField<F, S>> for MpcField<F, S> {
    fn sub_assign(&mut self, rhs: &Self) {
        match self {
            MpcField::Public(a) => match rhs {
                MpcField::Public(b) => {
                    *a -= b;
                }
                MpcField::Shared(b) => {
                    let mut tmp = *b;
                    tmp.neg().shift(a);
                    *self = MpcField::Shared(tmp);
                }
            },
            MpcField::Shared(a) => match rhs {
                MpcField::Public(b) => {
                    a.shift(&-*b);
                }
                MpcField::Shared(b) => {
                    a.sub(b);
                }
            },
        }
    }
}

impl<F: Field, S: FieldShare<F>> Sub for MpcField<F, S> {
    type Output = Self;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self.sub_assign(&rhs);
        self
    }
}

impl<'a, F: Field, S: FieldShare<F>> Sub<&'a MpcField<F, S>> for MpcField<F, S> {
    type Output = Self;

    fn sub(mut self, rhs: &'a MpcField<F, S>) -> Self::Output {
        self.sub_assign(rhs);
        self
    }
}

impl<F: Field, S: FieldShare<F>> MulAssign for MpcField<F, S> {
    fn mul_assign(&mut self, rhs: Self) {
        self.mul_assign(&rhs);
    }
}

impl<'a, F: Field, S: FieldShare<F>> MulAssign<&'a MpcField<F, S>> for MpcField<F, S> {
    fn mul_assign(&mut self, rhs: &'a MpcField<F, S>) {
        match self {
            MpcField::Public(a) => match rhs {
                MpcField::Public(b) => {
                    *a *= b;
                }
                MpcField::Shared(b) => {
                    todo!();
                }
            },
            MpcField::Shared(a) => match rhs {
                MpcField::Public(b) => {
                    a.scale(b);
                }
                MpcField::Shared(b) => {
                    // TODO implement correctly by using beaver triples
                    todo!()
                }
            },
        }
    }
}

impl<F: Field, S: FieldShare<F>> Mul for MpcField<F, S> {
    type Output = Self;

    fn mul(mut self, rhs: Self) -> Self::Output {
        self.mul_assign(&rhs);
        self
    }
}

impl<'a, F: Field, S: FieldShare<F>> Mul<&'a MpcField<F, S>> for MpcField<F, S> {
    type Output = Self;

    fn mul(mut self, rhs: &'a MpcField<F, S>) -> Self::Output {
        self.mul_assign(rhs);
        self
    }
}

impl<F: Field, S: FieldShare<F>> DivAssign for MpcField<F, S> {
    fn div_assign(&mut self, rhs: Self) {
        self.div_assign(&rhs);
    }
}

impl<'a, F: Field, S: FieldShare<F>> DivAssign<&'a MpcField<F, S>> for MpcField<F, S> {
    fn div_assign(&mut self, rhs: &'a MpcField<F, S>) {
        match self {
            MpcField::Public(a) => match rhs {
                MpcField::Public(b) => {
                    *a /= b;
                }
                MpcField::Shared(b) => {
                    todo!();
                }
            },
            MpcField::Shared(a) => match rhs {
                MpcField::Public(b) => {
                    a.scale(&b.inverse().unwrap());
                }
                MpcField::Shared(b) => {
                    // TODO implement correctly by using beaver triples
                    todo!()
                }
            },
        }
    }
}

impl<F: Field, S: FieldShare<F>> Div for MpcField<F, S> {
    type Output = Self;

    fn div(mut self, rhs: Self) -> Self::Output {
        self.div_assign(&rhs);
        self
    }
}

impl<'a, F: Field, S: FieldShare<F>> Div<&'a MpcField<F, S>> for MpcField<F, S> {
    type Output = Self;

    fn div(mut self, rhs: &'a MpcField<F, S>) -> Self::Output {
        self.div_assign(rhs);
        self
    }
}

impl<F: Field, S: FieldShare<F>> Product for MpcField<F, S> {
    fn product<I: Iterator<Item = Self>>(_iter: I) -> Self {
        todo!()
    }
}

impl<'a, F: Field, S: FieldShare<F>> Product<&'a MpcField<F, S>> for MpcField<F, S> {
    fn product<I: Iterator<Item = &'a MpcField<F, S>>>(_iter: I) -> Self {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> One for MpcField<F, S> {
    fn one() -> Self {
        MpcField::Public(F::one())
    }
}

impl<F: Field, S: FieldShare<F>> Zero for MpcField<F, S> {
    fn zero() -> Self {
        MpcField::Public(F::zero())
    }

    fn is_zero(&self) -> bool {
        match self {
            MpcField::Public(x) => x.is_zero(),
            MpcField::Shared(_x) => {
                debug!("Warning: is_zero on shared data. Returning false");
                false
            }
        }
    }
}

impl<F: Field, S: FieldShare<F>> Zeroize for MpcField<F, S> {
    fn zeroize(&mut self) {
        *self = MpcField::Public(F::zero());
    }
}

impl<F: Field, S: FieldShare<F>> Default for MpcField<F, S> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<F: Field, S: FieldShare<F>> From<bool> for MpcField<F, S> {
    fn from(value: bool) -> Self {
        MpcField::from_public(F::from(value))
    }
}

impl<F: Field, S: FieldShare<F>> From<u8> for MpcField<F, S> {
    fn from(value: u8) -> Self {
        MpcField::from_public(F::from(value))
    }
}

impl<F: Field, S: FieldShare<F>> From<u16> for MpcField<F, S> {
    fn from(value: u16) -> Self {
        MpcField::from_public(F::from(value))
    }
}

impl<F: Field, S: FieldShare<F>> From<u32> for MpcField<F, S> {
    fn from(value: u32) -> Self {
        MpcField::from_public(F::from(value))
    }
}

impl<F: Field, S: FieldShare<F>> From<u64> for MpcField<F, S> {
    fn from(value: u64) -> Self {
        MpcField::from_public(F::from(value))
    }
}

impl<F: Field, S: FieldShare<F>> From<u128> for MpcField<F, S> {
    fn from(value: u128) -> Self {
        MpcField::from_public(F::from(value))
    }
}

impl<F: PrimeField, S: FieldShare<F>> FromStr for MpcField<F, S> {
    type Err = F::Err;

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> From<BigUint> for MpcField<F, S> {
    fn from(_value: BigUint) -> Self {
        todo!()
    }
}

impl<F: PrimeField, S: FieldShare<F>> Into<BigUint> for MpcField<F, S> {
    fn into(self) -> BigUint {
        todo!()
    }
}

impl<F: PrimeField, S: FieldShare<F>> MpcWire for MpcField<F, S> {
    fn is_shared(&self) -> bool {
        match self {
            MpcField::Shared(_) => true,
            MpcField::Public(_) => false,
        }
    }
}

impl<F: PrimeField, S: FieldShare<F>> Field for MpcField<F, S> {
    type BasePrimeField = Self;

    fn extension_degree() -> u64 {
        todo!()
    }

    fn from_base_prime_field_elems(_elems: &[Self::BasePrimeField]) -> Option<Self> {
        todo!()
    }

    fn double(&self) -> Self {
        todo!()
    }

    fn double_in_place(&mut self) -> &mut Self {
        todo!()
    }

    fn from_random_bytes_with_flags<Fl: ark_serialize::Flags>(_bytes: &[u8]) -> Option<(Self, Fl)> {
        todo!()
    }

    fn square(&self) -> Self {
        todo!()
    }

    fn square_in_place(&mut self) -> &mut Self {
        *self *= self.clone();
        self
    }

    fn inverse(&self) -> Option<Self> {
        match self {
            Self::Public(x) => x.inverse().map(MpcField::Public),
            Self::Shared(x) => Some(MpcField::Shared(todo!())),
        }
    }

    fn inverse_in_place(&mut self) -> Option<&mut Self> {
        todo!()
    }

    fn frobenius_map(&mut self, _power: usize) {
        todo!()
    }

    fn has_univariate_div_qr() -> bool {
        true
    }
    fn univariate_div_qr<'a>(
        num: poly_stub::DenseOrSparsePolynomial<Self>,
        den: poly_stub::DenseOrSparsePolynomial<Self>,
    ) -> Option<(
        poly_stub::DensePolynomial<Self>,
        poly_stub::DensePolynomial<Self>,
    )> {
        use poly_stub::DenseOrSparsePolynomial::*;
        let shared_num = match num {
            DPolynomial(d) => Ok(d
                .into_owned()
                .coeffs
                .into_iter()
                .map(|c| match c {
                    MpcField::Shared(s) => s,
                    MpcField::Public(_) => panic!("public numerator"),
                })
                .collect()),
            SPolynomial(d) => Err(d
                .into_owned()
                .coeffs
                .into_iter()
                .map(|(i, c)| match c {
                    MpcField::Shared(s) => (i, s),
                    MpcField::Public(_) => panic!("public numerator"),
                })
                .collect()),
        };
        let pub_denom = match den {
            DPolynomial(d) => Ok(d
                .into_owned()
                .coeffs
                .into_iter()
                .map(|c| match c {
                    MpcField::Public(s) => s,
                    MpcField::Shared(_) => panic!("shared denominator"),
                })
                .collect()),
            SPolynomial(d) => Err(d
                .into_owned()
                .coeffs
                .into_iter()
                .map(|(i, c)| match c {
                    MpcField::Public(s) => (i, s),
                    MpcField::Shared(_) => panic!("shared denominator"),
                })
                .collect()),
        };
        S::univariate_div_qr(shared_num, pub_denom).map(|(q, r)| {
            (
                poly_stub::DensePolynomial {
                    coeffs: q.into_iter().map(|qc| MpcField::Shared(qc)).collect(),
                },
                poly_stub::DensePolynomial {
                    coeffs: r.into_iter().map(|rc| MpcField::Shared(rc)).collect(),
                },
            )
        })
    }
}

impl<F: PrimeField, S: FieldShare<F>> FftField for MpcField<F, S> {
    type FftParams = F::FftParams;

    fn two_adic_root_of_unity() -> Self {
        Self::from_public(F::two_adic_root_of_unity())
    }

    fn large_subgroup_root_of_unity() -> Option<Self> {
        F::large_subgroup_root_of_unity().map(Self::from_public)
    }

    fn multiplicative_generator() -> Self {
        Self::from_public(F::multiplicative_generator())
    }
}

impl<F: PrimeField, S: FieldShare<F>> PrimeField for MpcField<F, S> {
    type Params = F::Params;

    type BigInt = F::BigInt;

    fn from_repr(_repr: <Self as PrimeField>::BigInt) -> Option<Self> {
        todo!()
    }

    fn into_repr(&self) -> <Self as PrimeField>::BigInt {
        todo!()
    }
}

impl<F: PrimeField, S: FieldShare<F>> SquareRootField for MpcField<F, S> {
    fn legendre(&self) -> ark_ff::LegendreSymbol {
        todo!()
    }

    fn sqrt(&self) -> Option<Self> {
        todo!()
    }

    fn sqrt_in_place(&mut self) -> Option<&mut Self> {
        todo!()
    }
}

mod poly_impl {

    use crate::share::*;
    use crate::wire::*;
    use crate::Reveal;
    use ark_ff::PrimeField;
    use ark_poly::domain::{EvaluationDomain, GeneralEvaluationDomain};
    use ark_poly::evaluations::univariate::Evaluations;
    use ark_poly::univariate::DensePolynomial;

    impl<E: PrimeField, S: FieldShare<E>> Reveal for DensePolynomial<MpcField<E, S>> {
        type Base = DensePolynomial<E>;
        struct_reveal_simp_impl!(DensePolynomial; coeffs);
    }

    impl<F: PrimeField, S: FieldShare<F>> Reveal for Evaluations<MpcField<F, S>> {
        type Base = Evaluations<F>;

        fn reveal(self) -> Self::Base {
            Evaluations::from_vec_and_domain(
                self.evals.reveal(),
                GeneralEvaluationDomain::new(self.domain.size()).unwrap(),
            )
        }

        fn from_add_shared(b: Self::Base) -> Self {
            Evaluations::from_vec_and_domain(
                Reveal::from_add_shared(b.evals),
                GeneralEvaluationDomain::new(b.domain.size()).unwrap(),
            )
        }

        fn from_public(b: Self::Base) -> Self {
            Evaluations::from_vec_and_domain(
                Reveal::from_public(b.evals),
                GeneralEvaluationDomain::new(b.domain.size()).unwrap(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::AdditiveFieldShare;

    use super::*;

    type F = ark_bls12_377::Fr;
    type S = AdditiveFieldShare<F>;
    type MF = MpcField<F, S>;

    #[test]
    fn test_add() {
        let pub_a = MF::from_public(F::from(1u64));
        let pub_b = MF::from_public(F::from(2u64));

        let shared_a = MF::from_add_shared(F::from(1u64));
        let shared_b = MF::from_add_shared(F::from(2u64));

        let c = pub_a + pub_b;
        assert_eq!(c.reveal(), F::from(3u64));

        let c = pub_a + shared_b;
        assert_eq!(c.reveal(), F::from(3u64));

        let c = shared_a + shared_b;
        assert_eq!(c.reveal(), F::from(3u64));
    }

    #[test]
    fn test_sub() {
        let pub_a = MF::from_public(F::from(1u64));
        let pub_b = MF::from_public(F::from(2u64));

        let shared_a = MF::from_add_shared(F::from(1u64));
        let shared_b = MF::from_add_shared(F::from(2u64));

        let c = pub_a - pub_b;
        assert_eq!(c.reveal(), -F::from(1u64));

        let c = pub_a - shared_b;
        assert_eq!(c.reveal(), -F::from(1u64));

        let c = shared_a - shared_b;
        assert_eq!(c.reveal(), -F::from(1u64));
    }

    #[test]
    fn test_mul() {
        let pub_a = MF::from_public(F::from(1u64));
        let pub_b = MF::from_public(F::from(2u64));

        let shared_a = MF::from_add_shared(F::from(1u64));
        let shared_b = MF::from_add_shared(F::from(2u64));

        let c = pub_a * pub_b;
        assert_eq!(c.reveal(), F::from(2u64));

        let c = pub_a * shared_b;
        assert_eq!(c.reveal(), F::from(2u64));

        let c = shared_a * shared_b;
        assert_eq!(c.reveal(), F::from(2u64));
    }

    #[test]
    fn test_div() {
        let pub_a = MF::from_public(F::from(2u64));
        let pub_b = MF::from_public(F::from(1u64));

        let shared_a = MF::from_add_shared(F::from(2u64));
        let shared_b = MF::from_add_shared(F::from(1u64));

        let c = pub_a / pub_b;
        assert_eq!(c.reveal(), F::from(2u64));

        let c = pub_a / shared_b;
        assert_eq!(c.reveal(), F::from(2u64));

        let c = shared_a / shared_b;
        assert_eq!(c.reveal(), F::from(2u64));
    }

    #[test]
    fn test_sum() {
        let a = vec![
            MF::from_public(F::from(1u64)),
            MF::from_add_shared(F::from(2u64)),
            MF::from_public(F::from(3u64)),
        ];

        let result = a.iter().sum::<MF>();

        assert_eq!(result.reveal(), F::from(6u64));
    }
}
