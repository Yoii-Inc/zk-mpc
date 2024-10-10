use std::fmt::{self, Display};
use std::io::{self, Read, Write};
use std::marker::PhantomData;
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
use derivative::Derivative;
use mpc_net::{MpcMultiNet as Net, MpcNet};
use mpc_trait::MpcWire;

use crate::share::group::GroupShare;
use crate::{BeaverSource, Reveal};

use super::field::MpcField;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum MpcGroup<G: Group, S: GroupShare<G>> {
    Public(G),
    Shared(S),
}

#[derive(Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct DummyGroupTripleSource<T, S> {
    _scalar: PhantomData<T>,
    _share: PhantomData<S>,
}

impl<T: Group, S: GroupShare<T>> BeaverSource<S, S::FieldShare, S>
    for DummyGroupTripleSource<T, S>
{
    #[inline]
    fn triple(&mut self) -> (S, S::FieldShare, S) {
        (
            S::from_add_shared(T::zero()),
            <S::FieldShare as Reveal>::from_add_shared(if Net::am_king() {
                T::ScalarField::one()
            } else {
                T::ScalarField::zero()
            }),
            S::from_add_shared(T::zero()),
        )
    }
    #[inline]
    fn inv_pair(&mut self) -> (S::FieldShare, S::FieldShare) {
        (
            <S::FieldShare as Reveal>::from_add_shared(if Net::am_king() {
                T::ScalarField::one()
            } else {
                T::ScalarField::zero()
            }),
            <S::FieldShare as Reveal>::from_add_shared(if Net::am_king() {
                T::ScalarField::one()
            } else {
                T::ScalarField::zero()
            }),
        )
    }
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
        let result = match self {
            Self::Shared(s) => s.reveal(),
            Self::Public(s) => s,
        };
        super::macros::check_eq(result);
        result
    }

    #[inline]
    fn from_add_shared(b: Self::Base) -> Self {
        Self::Shared(S::from_add_shared(b))
    }

    #[inline]
    fn from_public(b: Self::Base) -> Self {
        Self::Public(b)
    }

    fn unwrap_as_public(self) -> Self::Base {
        match self {
            Self::Shared(s) => s.unwrap_as_public(),
            Self::Public(s) => s,
        }
    }
}

impl<G: Group, S: GroupShare<G>> Mul<MpcField<G::ScalarField, S::FieldShare>> for MpcGroup<G, S> {
    type Output = Self;
    #[inline]
    fn mul(mut self, other: MpcField<G::ScalarField, S::FieldShare>) -> Self::Output {
        self *= &other;
        self
    }
}

impl<G: Group, S: GroupShare<G>> Display for MpcGroup<G, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MpcGroup::Public(x) => write!(f, "{x} (public)"),
            MpcGroup::Shared(x) => write!(f, "{x} (shared)"),
        }
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
    fn rand<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        Self::Shared(<S as UniformRand>::rand(rng))
    }
}

impl<G: Group, S: GroupShare<G>> PubUniformRand for MpcGroup<G, S> {
    fn pub_rand<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        Self::Public(<G as PubUniformRand>::pub_rand(rng))
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
        match self {
            MpcGroup::Public(x) => MpcGroup::Public(-x),
            MpcGroup::Shared(mut x) => MpcGroup::Shared({
                x.neg();
                x
            }),
        }
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
    fn sub_assign(&mut self, rhs: Self) {
        self.sub_assign(&rhs);
    }
}

impl<'a, G: Group, S: GroupShare<G>> SubAssign<&'a MpcGroup<G, S>> for MpcGroup<G, S> {
    fn sub_assign(&mut self, rhs: &'a MpcGroup<G, S>) {
        match self {
            MpcGroup::Public(a) => match rhs {
                MpcGroup::Public(b) => {
                    *a -= b;
                }
                MpcGroup::Shared(b) => {
                    let mut tmp = *b;
                    tmp.neg().shift(a);
                    *self = MpcGroup::Shared(tmp);
                }
            },
            MpcGroup::Shared(a) => match rhs {
                MpcGroup::Public(b) => {
                    a.shift(&-*b);
                }
                MpcGroup::Shared(b) => {
                    a.sub(b);
                }
            },
        }
    }
}

impl<G: Group, S: GroupShare<G>> Sub for MpcGroup<G, S> {
    type Output = Self;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self.sub_assign(&rhs);
        self
    }
}

impl<'a, G: Group, S: GroupShare<G>> Sub<&'a MpcGroup<G, S>> for MpcGroup<G, S> {
    type Output = Self;

    fn sub(mut self, rhs: &'a MpcGroup<G, S>) -> Self::Output {
        self.sub_assign(rhs);
        self
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
                MpcField::Shared(y) => {
                    let t = MpcGroup::Shared(S::scale_pub_group(*x, y));
                    *self = t;
                }
            },
            MpcGroup::Shared(x) => match other {
                MpcField::Public(y) => {
                    x.scale_pub_scalar(y);
                }
                MpcField::Shared(y) => {
                    let t = x.scale(*y, &mut DummyGroupTripleSource::default());
                    *x = t;
                }
            },
        }
    }
}

impl<T: Group, S: GroupShare<T>> MpcWire for MpcGroup<T, S> {
    fn publicize(&mut self) {
        match self {
            MpcGroup::Public(_) => {}
            MpcGroup::Shared(s) => {
                *self = MpcGroup::Public(s.reveal());
            }
        }
        debug_assert!({
            let self_val = if let MpcGroup::Public(s) = self {
                *s
            } else {
                unreachable!()
            };
            super::macros::check_eq(self_val);
            true
        })
    }
    fn is_shared(&self) -> bool {
        match self {
            MpcGroup::Shared(_) => true,
            MpcGroup::Public(_) => false,
        }
    }
}

impl<T: Group, S: GroupShare<T>> Group for MpcGroup<T, S> {
    type ScalarField = MpcField<T::ScalarField, S::FieldShare>;

    fn double(&self) -> Self {
        *self + self
    }

    fn double_in_place(&mut self) -> &mut Self {
        *self += *self;
        self
    }
}

impl<T: Group, S: GroupShare<T>> MpcGroup<T, S> {
    pub fn all_public_or_shared(v: impl IntoIterator<Item = Self>) -> Result<Vec<T>, Vec<S>> {
        let mut out_a = Vec::new();
        let mut out_b = Vec::new();
        for s in v {
            match s {
                Self::Public(x) => out_a.push(x),
                Self::Shared(x) => out_b.push(x),
            }
        }
        if !out_a.is_empty() & !out_b.is_empty() {
            panic!("Heterogeous")
        } else if !out_b.is_empty() {
            Err(out_b)
        } else {
            Ok(out_a)
        }
    }
}
