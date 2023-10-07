use std::fmt::{self, Display};
use std::io::{self, Read};
use std::ops::*;

use std::iter::Sum;

use ark_ec::group::Group;
use ark_ff::prelude::*;
use ark_ff::{FromBytes, ToBytes};

use crate::share::group::GroupShare;
use crate::Reveal;

use super::field::MpcField;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum MpcGroup<G: Group, S: GroupShare<G>> {
    Public(G),
    Shared(S),
}

impl<G: Group, S: GroupShare<G>> Reveal for MpcGroup<G, S> {
    type Base = G;

    fn reveal(self) -> Self::Base {
        todo!()
    }

    fn from_add_shared(b: Self::Base) -> Self {
        todo!()
    }

    fn from_public(b: Self::Base) -> Self {
        Self::Public(b)
    }
}

// #[derive(Copy, Clone)]
// pub enum MpcGroupAffine<G: AffineCurve, S: GroupAffineShare<G>> {
//     Public(G),
//     Shared(S),
// }

impl<G: Group, S: GroupShare<G>> Display for MpcGroup<G, S> {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl<G: Group, S: GroupShare<G>> ToBytes for MpcGroup<G, S> {
    fn write<W: ark_serialize::Write>(&self, writer: W) -> io::Result<()> {
        match self {
            Self::Public(v) => v.write(writer),
            Self::Shared(_) => unimplemented!("write share: {}", self),
        }
    }
}

impl<G: Group, S: GroupShare<G>> FromBytes for MpcGroup<G, S> {
    fn read<R: Read>(_reader: R) -> io::Result<Self> {
        todo!()
    }
}

impl<G: Group, S: GroupShare<G>> UniformRand for MpcGroup<G, S> {
    fn rand<R: rand::Rng + ?Sized>(_rng: &mut R) -> Self {
        todo!()
    }
}

impl<G: Group, S: GroupShare<G>> Sum for MpcGroup<G, S> {
    fn sum<I: Iterator<Item = Self>>(_iter: I) -> Self {
        todo!()
    }
}

impl<'a, G: Group, S: GroupShare<G>> Sum<&'a MpcGroup<G, S>> for MpcGroup<G, S> {
    fn sum<I: Iterator<Item = &'a MpcGroup<G, S>>>(_iter: I) -> Self {
        todo!()
    }
}

impl<G: Group, S: GroupShare<G>> Neg for MpcGroup<G, S> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        todo!()
    }
}

impl<G: Group, S: GroupShare<G>> AddAssign for MpcGroup<G, S> {
    fn add_assign(&mut self, _rhs: Self) {
        todo!()
    }
}

impl<'a, G: Group, S: GroupShare<G>> AddAssign<&'a MpcGroup<G, S>> for MpcGroup<G, S> {
    fn add_assign(&mut self, _rhs: &'a MpcGroup<G, S>) {
        todo!()
    }
}

impl<G: Group, S: GroupShare<G>> Add for MpcGroup<G, S> {
    type Output = Self;

    fn add(self, _rhs: Self) -> Self::Output {
        todo!()
    }
}

impl<'a, G: Group, S: GroupShare<G>> Add<&'a MpcGroup<G, S>> for MpcGroup<G, S> {
    type Output = Self;

    fn add(self, _rhs: &'a MpcGroup<G, S>) -> Self::Output {
        todo!()
    }
}

impl<G: Group, S: GroupShare<G>> SubAssign for MpcGroup<G, S> {
    fn sub_assign(&mut self, _rhs: Self) {
        todo!()
    }
}

impl<'a, G: Group, S: GroupShare<G>> SubAssign<&'a MpcGroup<G, S>> for MpcGroup<G, S> {
    fn sub_assign(&mut self, _rhs: &'a MpcGroup<G, S>) {
        todo!()
    }
}

impl<G: Group, S: GroupShare<G>> Sub for MpcGroup<G, S> {
    type Output = Self;

    fn sub(self, _rhs: Self) -> Self::Output {
        todo!()
    }
}

impl<'a, G: Group, S: GroupShare<G>> Sub<&'a MpcGroup<G, S>> for MpcGroup<G, S> {
    type Output = Self;

    fn sub(self, _rhs: &'a MpcGroup<G, S>) -> Self::Output {
        todo!()
    }
}

impl<G: Group, S: GroupShare<G>> Zero for MpcGroup<G, S> {
    fn zero() -> Self {
        MpcGroup::Public(G::zero())
    }

    fn is_zero(&self) -> bool {
        todo!()
    }
}

impl<G: Group, S: GroupShare<G>> Default for MpcGroup<G, S> {
    fn default() -> Self {
        todo!()
    }
}

impl<T: Group, S: GroupShare<T>> MulAssign<MpcField<T::ScalarField, S::FieldShare>>
    for MpcGroup<T, S>
{
    #[inline]
    fn mul_assign(&mut self, other: MpcField<T::ScalarField, S::FieldShare>) {
        *self *= &other;
    }
}
impl<'a, T: Group, S: GroupShare<T>> MulAssign<&'a MpcField<T::ScalarField, S::FieldShare>>
    for MpcGroup<T, S>
{
    #[inline]
    fn mul_assign(&mut self, other: &MpcField<T::ScalarField, S::FieldShare>) {
        match self {
            // for some reason, a two-stage match (rather than a tuple match) avoids moving
            // self
            MpcGroup::Public(x) => match other {
                MpcField::Public(y) => {
                    *x *= *y;
                }
                MpcField::Shared(_y) => {
                    todo!()
                }
            },
            MpcGroup::Shared(_x) => match other {
                MpcField::Public(_y) => {
                    todo!()
                }
                MpcField::Shared(_y) => {
                    todo!()
                }
            },
        }
    }
}

impl<T: Group, S: GroupShare<T>> Group for MpcGroup<T, S> {
    type ScalarField = MpcField<T::ScalarField, S::FieldShare>;

    fn double(&self) -> Self {
        todo!()
    }

    fn double_in_place(&mut self) -> &mut Self {
        todo!()
    }
}
