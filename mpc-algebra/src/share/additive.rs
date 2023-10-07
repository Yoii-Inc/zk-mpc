use std::borrow::Cow;
use std::fmt::{self, Debug, Display, Formatter};
use std::hash::Hash;
use std::io::{self, Read, Write};
use std::marker::PhantomData;

use ark_ec::{group::Group, PairingEngine};
use ark_ff::{Field, FromBytes, ToBytes};
use ark_poly::UVPolynomial;
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Flags, SerializationError,
};
use ark_std::UniformRand;
use derivative::Derivative;

use crate::reveal::Reveal;
use crate::{DenseOrSparsePolynomial, DensePolynomial, SparsePolynomial};

use crate::channel::MpcSerNet;
use mpc_net::{MpcMultiNet as Net, MpcNet};

// use super::pairing::ExtendedPairingEngine;
// use super::group::GroupAffineShare;
use super::{
    field::{ExtFieldShare, FieldShare},
    group::GroupShare,
    pairing::PairingShare,
};

#[derive(Clone, Copy, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AdditiveFieldShare<T> {
    pub val: T,
}

impl<F: Field> AdditiveFieldShare<F> {
    fn poly_share<'a>(
        p: DenseOrSparsePolynomial<Self>,
    ) -> ark_poly::univariate::DenseOrSparsePolynomial<'a, F> {
        match p {
            Ok(p) => ark_poly::univariate::DenseOrSparsePolynomial::DPolynomial(Cow::Owned(
                Self::d_poly_share(p),
            )),
            Err(p) => ark_poly::univariate::DenseOrSparsePolynomial::SPolynomial(Cow::Owned(
                Self::s_poly_share(p),
            )),
        }
    }
    fn d_poly_share(p: DensePolynomial<Self>) -> ark_poly::univariate::DensePolynomial<F> {
        ark_poly::univariate::DensePolynomial::from_coefficients_vec(
            p.into_iter().map(|s| s.val).collect(),
        )
    }
    fn s_poly_share(p: SparsePolynomial<Self>) -> ark_poly::univariate::SparsePolynomial<F> {
        ark_poly::univariate::SparsePolynomial::from_coefficients_vec(
            p.into_iter().map(|(i, s)| (i, s.val)).collect(),
        )
    }
    fn poly_share2<'a>(
        p: DenseOrSparsePolynomial<F>,
    ) -> ark_poly::univariate::DenseOrSparsePolynomial<'a, F> {
        match p {
            Ok(p) => ark_poly::univariate::DenseOrSparsePolynomial::DPolynomial(Cow::Owned(
                ark_poly::univariate::DensePolynomial::from_coefficients_vec(p),
            )),
            Err(p) => ark_poly::univariate::DenseOrSparsePolynomial::SPolynomial(Cow::Owned(
                ark_poly::univariate::SparsePolynomial::from_coefficients_vec(p),
            )),
        }
    }
    fn d_poly_unshare(p: ark_poly::univariate::DensePolynomial<F>) -> DensePolynomial<Self> {
        p.coeffs
            .into_iter()
            .map(|s| Self::from_add_shared(s))
            .collect()
    }
}

impl<F: Field> Reveal for AdditiveFieldShare<F> {
    type Base = F;

    fn reveal(self) -> Self::Base {
        Net::broadcast(&self.val).into_iter().sum()
    }

    fn from_add_shared(b: Self::Base) -> Self {
        Self { val: b }
    }

    fn from_public(b: Self::Base) -> Self {
        todo!()
    }
}

impl<F: Field> FieldShare<F> for AdditiveFieldShare<F> {
    fn add(&mut self, other: &Self) -> &mut Self {
        self.val += &other.val;
        self
    }

    fn sub(&mut self, other: &Self) -> &mut Self {
        self.val -= &other.val;
        self
    }

    fn scale(&mut self, other: &F) -> &mut Self {
        self.val *= other;
        self
    }

    fn shift(&mut self, other: &F) -> &mut Self {
        if Net::am_king() {
            self.val += other;
        }
        self
    }

    fn univariate_div_qr<'a>(
        num: DenseOrSparsePolynomial<Self>,
        den: DenseOrSparsePolynomial<F>,
    ) -> Option<(DensePolynomial<Self>, DensePolynomial<Self>)> {
        let num = Self::poly_share(num);
        let den = Self::poly_share2(den);
        num.divide_with_q_and_r(&den)
            .map(|(q, r)| (Self::d_poly_unshare(q), Self::d_poly_unshare(r)))
    }
}

macro_rules! impl_field_basics {
    ($share:ident, $bound:ident) => {
        impl<T: $bound> Display for $share<T> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.val)
            }
        }
        impl<T: $bound> ToBytes for $share<T> {
            fn write<W: Write>(&self, _writer: W) -> io::Result<()> {
                todo!()
            }
        }
        impl<T: $bound> FromBytes for $share<T> {
            fn read<R: Read>(_reader: R) -> io::Result<Self> {
                todo!()
            }
        }
        impl<T: $bound> CanonicalSerialize for $share<T> {
            fn serialize<W: Write>(&self, _writer: W) -> Result<(), SerializationError> {
                todo!()
            }

            fn serialized_size(&self) -> usize {
                todo!()
            }
        }
        impl<T: $bound> CanonicalSerializeWithFlags for $share<T> {
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
        impl<T: $bound> CanonicalDeserialize for $share<T> {
            fn deserialize<R: Read>(_reader: R) -> Result<Self, SerializationError> {
                todo!()
            }
        }
        impl<T: $bound> CanonicalDeserializeWithFlags for $share<T> {
            fn deserialize_with_flags<R: Read, Fl: Flags>(
                _reader: R,
            ) -> Result<(Self, Fl), SerializationError> {
                todo!()
            }
        }
        impl<T: $bound> UniformRand for $share<T> {
            fn rand<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
                Self::from_add_shared(<T as UniformRand>::rand(rng))
            }
        }
    };
}

impl_field_basics!(AdditiveFieldShare, Field);

#[derive(Clone, Copy, Debug)]
pub struct AdditiveExtFieldShare<F: Field>(pub PhantomData<F>);

impl<F: Field> ExtFieldShare<F> for AdditiveExtFieldShare<F> {
    type Base = AdditiveFieldShare<F::BasePrimeField>;
    type Ext = AdditiveFieldShare<F>;
}

#[derive(Clone, Copy, Debug)]
pub struct MulExtFieldShare<F: Field>(pub PhantomData<F>);

impl<F: Field> ExtFieldShare<F> for MulExtFieldShare<F> {
    type Base = AdditiveFieldShare<F::BasePrimeField>;
    type Ext = AdditiveFieldShare<F>;
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "T:Clone"),
    Copy(bound = "T:Copy"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq"),
    PartialOrd(bound = "T: PartialOrd"),
    Ord(bound = "T: Ord"),
    Hash(bound = "T: Hash")
)]
pub struct AdditiveGroupShare<T> {
    pub val: T,
}

impl<G: Group> Reveal for AdditiveGroupShare<G> {
    type Base = G;

    fn reveal(self) -> Self::Base {
        todo!()
    }

    fn from_add_shared(b: Self::Base) -> Self {
        todo!()
    }

    fn from_public(b: Self::Base) -> Self {
        todo!()
    }
}

macro_rules! impl_group_basics {
    ($share:ident, $bound:ident) => {
        impl<T: $bound> Debug for $share<T> {
            fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
                todo!()
            }
        }
        impl<T: $bound> ToBytes for $share<T> {
            fn write<W: Write>(&self, _writer: W) -> io::Result<()> {
                todo!()
            }
        }
        impl<T: $bound> FromBytes for $share<T> {
            fn read<R: Read>(_reader: R) -> io::Result<Self> {
                todo!()
            }
        }
        impl<T: $bound> CanonicalSerialize for $share<T> {
            fn serialize<W: Write>(&self, _writer: W) -> Result<(), SerializationError> {
                todo!()
            }

            fn serialized_size(&self) -> usize {
                todo!()
            }
        }
        impl<T: $bound> CanonicalSerializeWithFlags for $share<T> {
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
        impl<T: $bound> CanonicalDeserialize for $share<T> {
            fn deserialize<R: Read>(_reader: R) -> Result<Self, SerializationError> {
                todo!()
            }
        }
        impl<T: $bound> CanonicalDeserializeWithFlags for $share<T> {
            fn deserialize_with_flags<R: Read, Fl: Flags>(
                _reader: R,
            ) -> Result<(Self, Fl), SerializationError> {
                todo!()
            }
        }
        impl<T: $bound> UniformRand for $share<T> {
            fn rand<R: rand::Rng + ?Sized>(_rng: &mut R) -> Self {
                todo!()
            }
        }
    };
}

impl_group_basics!(AdditiveGroupShare, Group);

impl<G: Group> GroupShare<G> for AdditiveGroupShare<G> {
    type FieldShare = AdditiveFieldShare<G::ScalarField>;
}

#[derive(Clone, Copy, Debug, Derivative)]
#[derivative(
    PartialEq(bound = "E::G1Affine: PartialEq"),
    Eq(bound = "E::G1Affine: Eq")
)]
pub struct AdditivePairingShare<E: PairingEngine>(pub PhantomData<E>);

impl<E: PairingEngine> PairingShare<E> for AdditivePairingShare<E> {
    type FrShare = AdditiveFieldShare<E::Fr>;
    type FqShare = AdditiveFieldShare<E::Fq>;
    type FqeShare = AdditiveExtFieldShare<E::Fqe>;
    // Not a typo. We want a multiplicative subgroup.
    type FqkShare = MulExtFieldShare<E::Fqk>;
    type G1AffineShare = AdditiveGroupShare<E::G1Affine>;
    type G2AffineShare = AdditiveGroupShare<E::G2Affine>;
    type G1ProjectiveShare = AdditiveGroupShare<E::G1Projective>;
    type G2ProjectiveShare = AdditiveGroupShare<E::G2Projective>;
}
