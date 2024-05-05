use std::borrow::Cow;
use std::fmt::{self, Debug, Display, Formatter};
use std::hash::Hash;
use std::io::{self, Read, Write};
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

use ark_ec::{group::Group, PairingEngine, ProjectiveCurve};
use ark_ff::BigInteger;
use ark_ff::{Field, FromBytes, ToBytes};
use ark_poly::UVPolynomial;
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Flags, SerializationError,
};
use ark_std::UniformRand;
use derivative::Derivative;
use rand::Rng;

use crate::reveal::Reveal;
use crate::{BeaverSource, DenseOrSparsePolynomial, DensePolynomial, Msm, SparsePolynomial};

use crate::channel::MPCSerNet;
use mpc_net::LocalTestNet as Net;

// use super::pairing::ExtendedPairingEngine;
// use super::group::GroupAffineShare;
use super::{
    field::{ExtFieldShare, FieldShare},
    group::GroupShare,
    pairing::{AffProjShare, PairingShare},
};

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct AdditiveFieldShare<T> {
    pub val: T,
    // reference to Net
    net: Arc<Mutex<Net>>,
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
        p.coeffs.into_iter().map(Self::from_add_shared).collect()
    }
}

impl<F: Field> Reveal for AdditiveFieldShare<F> {
    type Base = F;

    fn reveal(&self) -> Self::Base {
        self.net.broadcast(&self.val).into_iter().sum()
    }

    fn from_add_shared(b: Self::Base, net: Net) -> Self {
        Self { val: b, net }
    }

    fn from_public(f: Self::Base,  net: Net) -> Self {
        Self {
            val: if net. { f } else { F::zero() },
            net: self.net.clone(),
        }
    }

    fn unwrap_as_public(&self) -> Self::Base {
        self.val
    }
    fn king_share<R: Rng>(f: Self::Base, rng: &mut R) -> Self {
        let mut r: Vec<F> = (0..(Net::n_parties() - 1)).map(|_| F::rand(rng)).collect();
        let sum_r: F = r.iter().sum();
        r.push(f - sum_r);
        Self::from_add_shared(Net::receive_from_king(if Net::am_king() {
            Some(r)
        } else {
            None
        }))
    }
    fn king_share_batch<R: Rng>(f: Vec<Self::Base>, rng: &mut R) -> Vec<Self> {
        let mut rs: Vec<Vec<Self::Base>> = (0..(Net::n_parties() - 1))
            .map(|_| (0..f.len()).map(|_| F::rand(rng)).collect())
            .collect();
        let final_shares: Vec<Self::Base> = (0..rs[0].len())
            .map(|i| f[i] - &rs.iter().map(|r| &r[i]).sum())
            .collect();
        rs.push(final_shares);
        Net::receive_from_king(if Net::am_king() { Some(rs) } else { None })
            .into_iter()
            .map(Self::from_add_shared)
            .collect()
    }
}

impl<F: Field> FieldShare<F> for AdditiveFieldShare<F> {
    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<F> {
        let self_vec: Vec<F> = selfs.into_iter().map(|s| s.val).collect();
        let all_vals = Net::broadcast(&self_vec);
        (0..self_vec.len())
            .map(|i| all_vals.iter().map(|v| &v[i]).sum())
            .collect()
    }
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

    fn modulus_conversion<F2: ark_ff::PrimeField, S2: FieldShare<F2>>(&mut self) -> S2
    where
        F: ark_ff::PrimeField,
    {
        // TODO: bad implementation, so it's just for testing
        let revealed_val = self.reveal();
        let bits = revealed_val.into_repr().to_bits_le();
        let converted_val = F2::from_repr(BigInteger::from_bits_le(&bits)).unwrap();

        S2::king_share(converted_val, &mut ark_std::test_rng())
    }
}

macro_rules! impl_field_basics {
    ($share:ident, $bound:ident) => {
        impl<T: $bound> Display for $share<T> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.val)
            }
        }
        impl<T: $bound> Debug for $share<T> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{:?}", self.val)
            }
        }
        impl<T: $bound> ToBytes for $share<T> {
            fn write<W: Write>(&self, writer: W) -> io::Result<()> {
                self.val.write(writer)
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
            fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
                Self::from_add_shared(<T as UniformRand>::rand(rng))
            }
        }
    };
}

impl_field_basics!(AdditiveFieldShare, Field);

#[derive(Clone, Debug)]
pub struct AdditiveExtFieldShare<F: Field>(pub PhantomData<F>);

impl<F: Field> ExtFieldShare<F> for AdditiveExtFieldShare<F> {
    type Base = AdditiveFieldShare<F::BasePrimeField>;
    type Ext = AdditiveFieldShare<F>;
}

impl Copy for AdditiveExtFieldShare<crate::field::Fp> {}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct MulFieldShare<T> {
    pub val: T,
}

impl_field_basics!(MulFieldShare, Field);

impl<F: Field> Reveal for MulFieldShare<F> {
    type Base = F;

    fn reveal(self) -> F {
        Net::broadcast(&self.val).into_iter().product()
    }
    fn from_public(f: F) -> Self {
        Self {
            val: if Net::am_king() { f } else { F::one() },
        }
    }
    fn from_add_shared(f: F) -> Self {
        Self { val: f }
    }
    fn unwrap_as_public(self) -> F {
        self.val
    }
}

impl<F: Field> FieldShare<F> for MulFieldShare<F> {
    fn map_homo<FF: Field, SS: FieldShare<FF>, Fun: Fn(F) -> FF>(self, _f: Fun) -> SS {
        unimplemented!()
    }
    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<F> {
        let self_vec: Vec<F> = selfs.into_iter().map(|s| s.val).collect();
        let all_vals = Net::broadcast(&self_vec);
        (0..self_vec.len())
            .map(|i| all_vals.iter().map(|v| &v[i]).product())
            .collect()
    }

    fn add(&mut self, _other: &Self) -> &mut Self {
        unimplemented!("add for MulFieldShare")
    }

    fn scale(&mut self, other: &F) -> &mut Self {
        if Net::am_king() {
            self.val *= other;
        }
        self
    }

    fn shift(&mut self, _other: &F) -> &mut Self {
        unimplemented!("add for MulFieldShare")
    }

    fn beaver_mul<S: BeaverSource<Self, Self, Self>>(self, other: Self, _source: &mut S) -> Self {
        Self {
            val: self.val * other.val,
        }
    }

    fn batch_mul<S: BeaverSource<Self, Self, Self>>(
        mut xs: Vec<Self>,
        ys: Vec<Self>,
        _source: &mut S,
    ) -> Vec<Self> {
        for (x, y) in xs.iter_mut().zip(ys.iter()) {
            x.val *= y.val;
        }
        xs
    }

    fn inv<S: BeaverSource<Self, Self, Self>>(mut self, _source: &mut S) -> Self {
        self.val = self.val.inverse().unwrap();
        self
    }

    fn batch_inv<S: BeaverSource<Self, Self, Self>>(xs: Vec<Self>, source: &mut S) -> Vec<Self> {
        xs.into_iter().map(|x| x.inv(source)).collect()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MulExtFieldShare<F: Field>(pub PhantomData<F>);

impl<F: Field> ExtFieldShare<F> for MulExtFieldShare<F> {
    type Base = AdditiveFieldShare<F::BasePrimeField>;
    type Ext = AdditiveFieldShare<F>;
}

#[derive(Derivative)]
#[derivative(
    Default(bound = "T: Default"),
    Clone(bound = "T:Clone"),
    Copy(bound = "T:Copy"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq"),
    PartialOrd(bound = "T: PartialOrd"),
    Ord(bound = "T: Ord"),
    Hash(bound = "T: Hash")
)]
pub struct AdditiveGroupShare<T, M> {
    pub val: T,
    _phants: PhantomData<M>,
}

impl<G: Group, M> Reveal for AdditiveGroupShare<G, M> {
    type Base = G;

    fn reveal(self) -> Self::Base {
        Net::broadcast(&self.val).into_iter().sum()
    }

    fn from_add_shared(b: G) -> Self {
        Self {
            val: b,
            _phants: PhantomData,
        }
    }

    fn from_public(b: G) -> Self {
        Self {
            val: if Net::am_king() { b } else { G::zero() },
            _phants: PhantomData,
        }
    }

    fn unwrap_as_public(self) -> Self::Base {
        self.val
    }
    fn king_share<R: Rng>(f: Self::Base, rng: &mut R) -> Self {
        let mut r: Vec<G> = (0..(Net::n_parties() - 1)).map(|_| G::rand(rng)).collect();
        let sum_r: G = r.iter().sum();
        r.push(f - sum_r);
        Self::from_add_shared(Net::receive_from_king(if Net::am_king() {
            Some(r)
        } else {
            None
        }))
    }
    fn king_share_batch<R: Rng>(f: Vec<Self::Base>, rng: &mut R) -> Vec<Self> {
        let mut rs: Vec<Vec<Self::Base>> = (0..(Net::n_parties() - 1))
            .map(|_| (0..f.len()).map(|_| Self::Base::rand(rng)).collect())
            .collect();
        let final_shares: Vec<Self::Base> = (0..rs[0].len())
            .map(|i| f[i] - &rs.iter().map(|r| &r[i]).sum())
            .collect();
        rs.push(final_shares);
        Net::receive_from_king(if Net::am_king() { Some(rs) } else { None })
            .into_iter()
            .map(Self::from_add_shared)
            .collect()
    }
}

macro_rules! impl_group_basics {
    ($share:ident, $bound:ident) => {
        impl<T: $bound, M> Debug for $share<T, M> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{:?}", self.val)
            }
        }
        impl<T: $bound, M> ToBytes for $share<T, M> {
            fn write<W: Write>(&self, _writer: W) -> io::Result<()> {
                todo!()
            }
        }
        impl<T: $bound, M> FromBytes for $share<T, M> {
            fn read<R: Read>(_reader: R) -> io::Result<Self> {
                todo!()
            }
        }
        impl<T: $bound, M> CanonicalSerialize for $share<T, M> {
            fn serialize<W: Write>(&self, _writer: W) -> Result<(), SerializationError> {
                todo!()
            }

            fn serialized_size(&self) -> usize {
                todo!()
            }
        }
        impl<T: $bound, M> CanonicalSerializeWithFlags for $share<T, M> {
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
        impl<T: $bound, M> CanonicalDeserialize for $share<T, M> {
            fn deserialize<R: Read>(_reader: R) -> Result<Self, SerializationError> {
                todo!()
            }
        }
        impl<T: $bound, M> CanonicalDeserializeWithFlags for $share<T, M> {
            fn deserialize_with_flags<R: Read, Fl: Flags>(
                _reader: R,
            ) -> Result<(Self, Fl), SerializationError> {
                todo!()
            }
        }
        impl<T: $bound, M> UniformRand for $share<T, M> {
            fn rand<R: Rng + ?Sized>(_rng: &mut R) -> Self {
                todo!()
            }
        }
    };
}

impl_group_basics!(AdditiveGroupShare, Group);

impl<G: Group, M: Msm<G, G::ScalarField>> GroupShare<G> for AdditiveGroupShare<G, M> {
    type FieldShare = AdditiveFieldShare<G::ScalarField>;

    fn add(&mut self, other: &Self) -> &mut Self {
        self.val += &other.val;
        self
    }

    fn scale_pub_scalar(&mut self, scalar: &G::ScalarField) -> &mut Self {
        self.val *= *scalar;
        self
    }

    fn scale_pub_group(mut base: G, scalar: &Self::FieldShare) -> Self {
        base *= scalar.val;
        Self {
            val: base,
            _phants: PhantomData::default(),
        }
    }

    fn shift(&mut self, other: &G) -> &mut Self {
        if Net::am_king() {
            self.val += other;
        }
        self
    }

    fn multi_scale_pub_group(bases: &[G], scalars: &[Self::FieldShare]) -> Self {
        let scalars: Vec<G::ScalarField> = scalars.into_iter().map(|s| s.val.clone()).collect();
        Self::from_add_shared(M::msm(bases, &scalars))
    }
}

macro_rules! groups_share {
    ($struct_name:ident, $affine:ident, $proj:ident) => {
        pub struct $struct_name<E: PairingEngine>(pub PhantomData<E>);

        impl<E: PairingEngine> AffProjShare<E::Fr, E::$affine, E::$proj> for $struct_name<E> {
            type FrShare = AdditiveFieldShare<E::Fr>;
            type AffineShare = AdditiveGroupShare<E::$affine, super::msm::AffineMsm<E::$affine>>;
            type ProjectiveShare =
                AdditiveGroupShare<E::$proj, super::msm::ProjectiveMsm<E::$proj>>;

            fn sh_aff_to_proj(g: Self::AffineShare) -> Self::ProjectiveShare {
                g.map_homo(|s| s.into())
            }

            fn sh_proj_to_aff(g: Self::ProjectiveShare) -> Self::AffineShare {
                g.map_homo(|s| s.into())
            }

            fn add_sh_proj_sh_aff(
                mut a: Self::ProjectiveShare,
                o: &Self::AffineShare,
            ) -> Self::ProjectiveShare {
                a.val.add_assign_mixed(&o.val);
                a
            }
            fn add_sh_proj_pub_aff(
                mut a: Self::ProjectiveShare,
                o: &E::$affine,
            ) -> Self::ProjectiveShare {
                if Net::am_king() {
                    a.val.add_assign_mixed(&o);
                }
                a
            }
            fn add_pub_proj_sh_aff(_a: &E::$proj, _o: Self::AffineShare) -> Self::ProjectiveShare {
                unimplemented!()
            }
        }
    };
}

groups_share!(AdditiveG1Share, G1Affine, G1Projective);
groups_share!(AdditiveG2Share, G2Affine, G2Projective);

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
    type G1AffineShare = AdditiveGroupShare<E::G1Affine, super::msm::AffineMsm<E::G1Affine>>;
    type G2AffineShare = AdditiveGroupShare<E::G2Affine, super::msm::AffineMsm<E::G2Affine>>;
    type G1ProjectiveShare =
        AdditiveGroupShare<E::G1Projective, super::msm::ProjectiveMsm<E::G1Projective>>;
    type G2ProjectiveShare =
        AdditiveGroupShare<E::G2Projective, super::msm::ProjectiveMsm<E::G2Projective>>;

    type G1 = AdditiveG1Share<E>;
    type G2 = AdditiveG2Share<E>;
}
