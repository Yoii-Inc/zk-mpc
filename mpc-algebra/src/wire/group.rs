use std::fmt::{self, Display};
use std::io::{self, Read, Write};
use std::ops::*;

use std::iter::Sum;

use ark_ec::group::Group;
use ark_ff::prelude::*;
use ark_ff::{FromBytes, ToBytes};
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags,
};
use ark_serialize::{Flags, SerializationError};

use crate::share::group::GroupShare;
use crate::Reveal;

use super::field::MpcField;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum MpcGroup<G: Group, S: GroupShare<G>> {
    Public(G),
    Shared(S),
}

impl<T: Group, S: GroupShare<T>> MpcGroup<T, S> {
    pub fn map<TT: Group, SS: GroupShare<TT>, FT: Fn(T) -> TT, FS: Fn(S) -> SS>(
        self,
        ft: FT,
        fs: FS,
    ) -> MpcGroup<TT, SS> {
        match self {
            Self::Shared(s) => MpcGroup::Shared(fs(s)),
            Self::Public(s) => MpcGroup::Public(ft(s)),
        }
    }
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

impl<G: Group, S: GroupShare<G>> CanonicalSerialize for MpcGroup<G, S> {
    fn serialize<W: Write>(&self, _writer: W) -> Result<(), SerializationError> {
        todo!()
    }

    fn serialized_size(&self) -> usize {
        todo!()
    }
}

impl<G: Group, S: GroupShare<G>> CanonicalSerializeWithFlags for MpcGroup<G, S> {
    fn serialize_with_flags<W: Write, Fl: Flags>(
        &self,
        _writer: W,
        _flags: Fl,
    ) -> Result<(), SerializationError> {
        todo!()
    }

    fn serialized_size_with_flags<Fl: Flags>(&self) -> usize {
        todo!()
    }
}

impl<G: Group, S: GroupShare<G>> CanonicalDeserialize for MpcGroup<G, S> {
    fn deserialize<R: Read>(_reader: R) -> Result<Self, SerializationError> {
        todo!()
    }
}

impl<G: Group, S: GroupShare<G>> CanonicalDeserializeWithFlags for MpcGroup<G, S> {
    fn deserialize_with_flags<R: Read, Fl: Flags>(
        _reader: R,
    ) -> Result<(Self, Fl), SerializationError> {
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
    fn add_assign(&mut self, rhs: Self) {
        self.add_assign(&rhs);
    }
}

impl<'a, G: Group, S: GroupShare<G>> AddAssign<&'a MpcGroup<G, S>> for MpcGroup<G, S> {
    fn add_assign(&mut self, rhs: &'a MpcGroup<G, S>) {
        match self {
            MpcGroup::Public(a) => match rhs {
                MpcGroup::Public(b) => {
                    *a += b;
                }
                MpcGroup::Shared(b) => {
                    let mut tmp = *b;
                    tmp.shift(a);
                    *self = MpcGroup::Shared(tmp);
                }
            },
            MpcGroup::Shared(a) => match rhs {
                MpcGroup::Public(b) => {
                    a.shift(b);
                }
                MpcGroup::Shared(b) => {
                    a.add(b);
                }
            },
        }
    }
}

impl<G: Group, S: GroupShare<G>> Add for MpcGroup<G, S> {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self.add_assign(&rhs);
        self
    }
}

impl<'a, G: Group, S: GroupShare<G>> Add<&'a MpcGroup<G, S>> for MpcGroup<G, S> {
    type Output = Self;

    fn add(mut self, rhs: &'a MpcGroup<G, S>) -> Self::Output {
        self.add_assign(rhs);
        self
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
        *self + self
    }

    fn double_in_place(&mut self) -> &mut Self {
        *self += self.clone();
        self
    }
}
