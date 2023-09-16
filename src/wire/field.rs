use num_bigint::{BigInt, BigUint};
use std::fmt::{self, Debug, Display};
use std::io::{self, Read, Write};
use std::iter::{Product, Sum};
use std::ops::*;
use std::str::FromStr;
use zeroize::Zeroize;

use ark_ff::{prelude::*, FftField};
use ark_ff::{FromBytes, ToBytes};
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags,
};

use crate::share::field::FieldShare;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum MpcField<F: Field, S: FieldShare<F>> {
    Public(F),
    Shared(S),
}

impl<F: Field, S: FieldShare<F>> Display for MpcField<F, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> ToBytes for MpcField<F, S> {
    fn write<W: ark_serialize::Write>(&self, writer: W) -> io::Result<()> {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> FromBytes for MpcField<F, S> {
    fn read<R: Read>(reader: R) -> io::Result<Self> {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> CanonicalSerialize for MpcField<F, S> {
    fn serialize<W: Write>(&self, writer: W) -> Result<(), ark_serialize::SerializationError> {
        todo!()
    }

    fn serialized_size(&self) -> usize {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> CanonicalSerializeWithFlags for MpcField<F, S> {
    fn serialize_with_flags<W: Write, Fl: ark_serialize::Flags>(
        &self,
        writer: W,
        flags: Fl,
    ) -> Result<(), ark_serialize::SerializationError> {
        todo!()
    }

    fn serialized_size_with_flags<Fl: ark_serialize::Flags>(&self) -> usize {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> CanonicalDeserialize for MpcField<F, S> {
    fn deserialize<R: Read>(reader: R) -> Result<Self, ark_serialize::SerializationError> {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> CanonicalDeserializeWithFlags for MpcField<F, S> {
    fn deserialize_with_flags<R: Read, Fl: ark_serialize::Flags>(
        reader: R,
    ) -> Result<(Self, Fl), ark_serialize::SerializationError> {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> UniformRand for MpcField<F, S> {
    fn rand<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> AddAssign for MpcField<F, S> {
    fn add_assign(&mut self, rhs: Self) {
        todo!()
    }
}

impl<'a, F: Field, S: FieldShare<F>> AddAssign<&'a MpcField<F, S>> for MpcField<F, S> {
    fn add_assign(&mut self, rhs: &'a MpcField<F, S>) {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> Add for MpcField<F, S> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        todo!()
    }
}

impl<'a, F: Field, S: FieldShare<F>> Add<&'a MpcField<F, S>> for MpcField<F, S> {
    type Output = Self;

    fn add(self, rhs: &'a MpcField<F, S>) -> Self::Output {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> Sum for MpcField<F, S> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        todo!()
    }
}

impl<'a, F: Field, S: FieldShare<F>> Sum<&'a MpcField<F, S>> for MpcField<F, S> {
    fn sum<I: Iterator<Item = &'a MpcField<F, S>>>(iter: I) -> Self {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> Neg for MpcField<F, S> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> SubAssign for MpcField<F, S> {
    fn sub_assign(&mut self, rhs: Self) {
        todo!()
    }
}

impl<'a, F: Field, S: FieldShare<F>> SubAssign<&'a MpcField<F, S>> for MpcField<F, S> {
    fn sub_assign(&mut self, rhs: &'a MpcField<F, S>) {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> Sub for MpcField<F, S> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        todo!()
    }
}

impl<'a, F: Field, S: FieldShare<F>> Sub<&'a MpcField<F, S>> for MpcField<F, S> {
    type Output = Self;

    fn sub(self, rhs: &'a MpcField<F, S>) -> Self::Output {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> MulAssign for MpcField<F, S> {
    fn mul_assign(&mut self, rhs: Self) {
        todo!()
    }
}

impl<'a, F: Field, S: FieldShare<F>> MulAssign<&'a MpcField<F, S>> for MpcField<F, S> {
    fn mul_assign(&mut self, rhs: &'a MpcField<F, S>) {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> Mul for MpcField<F, S> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        todo!()
    }
}

impl<'a, F: Field, S: FieldShare<F>> Mul<&'a MpcField<F, S>> for MpcField<F, S> {
    type Output = Self;

    fn mul(self, rhs: &'a MpcField<F, S>) -> Self::Output {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> DivAssign for MpcField<F, S> {
    fn div_assign(&mut self, rhs: Self) {
        todo!()
    }
}

impl<'a, F: Field, S: FieldShare<F>> DivAssign<&'a MpcField<F, S>> for MpcField<F, S> {
    fn div_assign(&mut self, rhs: &'a MpcField<F, S>) {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> Div for MpcField<F, S> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        todo!()
    }
}

impl<'a, F: Field, S: FieldShare<F>> Div<&'a MpcField<F, S>> for MpcField<F, S> {
    type Output = Self;

    fn div(self, rhs: &'a MpcField<F, S>) -> Self::Output {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> Product for MpcField<F, S> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        todo!()
    }
}

impl<'a, F: Field, S: FieldShare<F>> Product<&'a MpcField<F, S>> for MpcField<F, S> {
    fn product<I: Iterator<Item = &'a MpcField<F, S>>>(iter: I) -> Self {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> One for MpcField<F, S> {
    fn one() -> Self {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> Zero for MpcField<F, S> {
    fn zero() -> Self {
        todo!()
    }

    fn is_zero(&self) -> bool {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> Zeroize for MpcField<F, S> {
    fn zeroize(&mut self) {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> Default for MpcField<F, S> {
    fn default() -> Self {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> From<bool> for MpcField<F, S> {
    fn from(value: bool) -> Self {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> From<u8> for MpcField<F, S> {
    fn from(value: u8) -> Self {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> From<u16> for MpcField<F, S> {
    fn from(value: u16) -> Self {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> From<u32> for MpcField<F, S> {
    fn from(value: u32) -> Self {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> From<u64> for MpcField<F, S> {
    fn from(value: u64) -> Self {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> From<u128> for MpcField<F, S> {
    fn from(value: u128) -> Self {
        todo!()
    }
}

impl<F: PrimeField, S: FieldShare<F>> FromStr for MpcField<F, S> {
    type Err = F::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> From<BigUint> for MpcField<F, S> {
    fn from(value: BigUint) -> Self {
        todo!()
    }
}

impl<F: PrimeField, S: FieldShare<F>> Into<BigUint> for MpcField<F, S> {
    fn into(self) -> BigUint {
        todo!()
    }
}

impl<F: PrimeField, S: FieldShare<F>> From<BigInt> for MpcField<F, S> {}

impl<F: PrimeField, S: FieldShare<F>> Field for MpcField<F, S> {
    type BasePrimeField = Self;

    fn extension_degree() -> u64 {
        todo!()
    }

    fn from_base_prime_field_elems(elems: &[Self::BasePrimeField]) -> Option<Self> {
        todo!()
    }

    fn double(&self) -> Self {
        todo!()
    }

    fn double_in_place(&mut self) -> &mut Self {
        todo!()
    }

    fn from_random_bytes_with_flags<Fl: ark_serialize::Flags>(bytes: &[u8]) -> Option<(Self, Fl)> {
        todo!()
    }

    fn square(&self) -> Self {
        todo!()
    }

    fn square_in_place(&mut self) -> &mut Self {
        todo!()
    }

    fn inverse(&self) -> Option<Self> {
        todo!()
    }

    fn inverse_in_place(&mut self) -> Option<&mut Self> {
        todo!()
    }

    fn frobenius_map(&mut self, power: usize) {
        todo!()
    }
}

impl<F: PrimeField, S: FieldShare<F>> FftField for MpcField<F, S> {
    type FftParams = F::FftParams;

    fn two_adic_root_of_unity() -> Self {
        todo!()
    }

    fn large_subgroup_root_of_unity() -> Option<Self> {
        todo!()
    }

    fn multiplicative_generator() -> Self {
        todo!()
    }
}

impl<F: PrimeField, S: FieldShare<F>> PrimeField for MpcField<F, S> {
    type Params = F::Params;

    type BigInt = F::BigInt;

    fn from_repr(repr: <Self as PrimeField>::BigInt) -> Option<Self> {
        todo!()
    }

    fn into_repr(&self) -> <Self as PrimeField>::BigInt {
        todo!()
    }
}
