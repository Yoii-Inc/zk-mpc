use std::fmt;
use std::fmt::Display;
use std::hash::Hash;
use std::io::{self, Read, Write};
use std::iter::{Product, Sum};
use std::marker::PhantomData;
use std::ops::*;

use zeroize::Zeroize;

use ark_ec::group::Group;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::bytes::{FromBytes, ToBytes};
use ark_ff::prelude::*;
use ark_ff::Field;
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Flags, SerializationError,
};

use super::super::share::field::ExtFieldShare;
use super::super::share::pairing::PairingShare;
use super::field::MpcField;
use super::group::MpcGroup;

use derivative::Derivative;

#[derive(Debug, Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = "E::G1Affine: PartialEq"),
    Eq(bound = "E::G1Affine: Eq"),
    Hash(bound = "E::G1Affine: Hash")
)]
pub struct MpcG1Affine<E: PairingEngine, PS: PairingShare<E>> {
    pub val: MpcGroup<E::G1Affine, PS::G1AffineShare>,
}

#[derive(Debug, Derivative, Clone, Copy, Eq)]
#[derivative(
    PartialEq(bound = "E::G1Affine: PartialEq"),
    Hash(bound = "E::G1Affine: Hash")
)]
pub struct MpcG1Projective<E: PairingEngine, PS: PairingShare<E>> {
    pub val: MpcGroup<E::G1Projective, PS::G1ProjectiveShare>,
}

#[derive(Debug, Clone, Derivative)]
#[derivative(Default(bound = "E::G1Prepared: Default"))]
pub struct MpcG1Prep<E: PairingEngine, PS: PairingShare<E>> {
    pub val: E::G1Prepared,
    _phantom: PhantomData<(E, PS)>,
}

#[derive(Debug, Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = "E::G1Affine: PartialEq"),
    Eq(bound = "E::G1Affine: Eq"),
    Hash(bound = "E::G1Affine: Hash")
)]
pub struct MpcG2Affine<E: PairingEngine, PS: PairingShare<E>> {
    pub val: MpcGroup<E::G2Affine, PS::G2AffineShare>,
}

#[derive(Debug, Derivative, Clone, Copy, Eq)]
#[derivative(
    PartialEq(bound = "E::G1Affine: PartialEq"),
    Hash(bound = "E::G1Affine: Hash")
)]
pub struct MpcG2Projective<E: PairingEngine, PS: PairingShare<E>> {
    pub val: MpcGroup<E::G2Projective, PS::G2ProjectiveShare>,
}

#[derive(Debug, Clone, Derivative)]
#[derivative(Default(bound = "E::G1Prepared: Default"))]
pub struct MpcG2Prep<E: PairingEngine, PS: PairingShare<E>> {
    pub val: E::G2Prepared,
    _phantom: PhantomData<(E, PS)>,
}

#[derive(Clone, Copy, Debug, Derivative)]
#[derivative(
    PartialEq(bound = "F: PartialEq"),
    Eq(bound = "F: Eq"),
    Hash(bound = "F:Hash"),
    PartialOrd(bound = "F:PartialOrd"),
    Ord(bound = "F:Ord")
)]
pub struct MpcExtField<F: Field, FS: ExtFieldShare<F>> {
    pub val: MpcField<F, FS::Ext>,
}

#[derive(Derivative)]
#[derivative(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MpcPairingEngine<E: PairingEngine, PS: PairingShare<E>> {
    _phantom: PhantomData<(E, PS)>,
}

impl<E: PairingEngine, PS: PairingShare<E>> PairingEngine for MpcPairingEngine<E, PS> {
    type Fr = MpcField<E::Fr, PS::FrShare>;
    type G1Projective = MpcG1Projective<E, PS>;
    type G1Affine = MpcG1Affine<E, PS>;
    type G1Prepared = MpcG1Prep<E, PS>;
    type G2Projective = MpcG2Projective<E, PS>;
    type G2Affine = MpcG2Affine<E, PS>;
    type G2Prepared = MpcG2Prep<E, PS>;
    type Fq = MpcField<E::Fq, PS::FqShare>;
    type Fqe = MpcExtField<E::Fqe, PS::FqeShare>;
    type Fqk = MpcExtField<E::Fqk, PS::FqkShare>;

    fn miller_loop<'a, I>(_i: I) -> Self::Fqk
    where
        I: IntoIterator<Item = &'a (Self::G1Prepared, Self::G2Prepared)>,
    {
        todo!()
    }

    fn final_exponentiation(_r: &Self::Fqk) -> Option<Self::Fqk> {
        todo!()
    }

    fn product_of_pairings<'a, I>(_i: I) -> Self::Fqk
    where
        I: IntoIterator<Item = &'a (Self::G1Prepared, Self::G2Prepared)>,
    {
        todo!()
    }

    fn pairing<G1, G2>(_p: G1, _q: G2) -> Self::Fqk
    where
        G1: Into<Self::G1Affine>,
        G2: Into<Self::G2Affine>,
    {
        todo!()
    }
}

macro_rules! impl_pairing_mpc_wrapper {
    ($wrapped:ident, $bound1:ident, $bound2:ident, $base:ident, $share:ident, $wrap:ident) => {
        impl<E: $bound1, PS: $bound2<E>> Display for $wrap<E, PS> {
            fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
                todo!()
            }
        }

        impl<E: $bound1, PS: $bound2<E>> ToBytes for $wrap<E, PS> {
            fn write<W: Write>(&self, _writer: W) -> io::Result<()> {
                todo!()
            }
        }

        impl<E: $bound1, PS: $bound2<E>> FromBytes for $wrap<E, PS> {
            fn read<R: Read>(_reader: R) -> io::Result<Self> {
                todo!()
            }
        }

        impl<E: $bound1, PS: $bound2<E>> CanonicalSerialize for $wrap<E, PS> {
            fn serialize<W: Write>(&self, _writer: W) -> Result<(), SerializationError> {
                todo!()
            }

            fn serialized_size(&self) -> usize {
                todo!()
            }
        }

        impl<E: $bound1, PS: $bound2<E>> CanonicalSerializeWithFlags for $wrap<E, PS> {
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

        impl<E: $bound1, PS: $bound2<E>> CanonicalDeserialize for $wrap<E, PS> {
            fn deserialize<R: Read>(_reader: R) -> Result<Self, SerializationError> {
                todo!()
            }
        }

        impl<E: $bound1, PS: $bound2<E>> CanonicalDeserializeWithFlags for $wrap<E, PS> {
            fn deserialize_with_flags<R: Read, Fl: Flags>(
                _reader: R,
            ) -> Result<(Self, Fl), SerializationError> {
                todo!()
            }
        }

        impl<E: $bound1, PS: $bound2<E>> UniformRand for $wrap<E, PS> {
            fn rand<R: rand::Rng + ?Sized>(_rng: &mut R) -> Self {
                todo!()
            }
        }

        impl<E: $bound1, PS: $bound2<E>> AddAssign for $wrap<E, PS> {
            fn add_assign(&mut self, _rhs: Self) {
                todo!()
            }
        }

        impl<'a, E: $bound1, PS: $bound2<E>> AddAssign<&'a $wrap<E, PS>> for $wrap<E, PS> {
            fn add_assign(&mut self, _rhs: &'a $wrap<E, PS>) {
                todo!()
            }
        }

        impl<E: $bound1, PS: $bound2<E>> Add for $wrap<E, PS> {
            type Output = Self;

            fn add(self, _rhs: Self) -> Self::Output {
                todo!()
            }
        }

        impl<'a, E: $bound1, PS: $bound2<E>> Add<&'a $wrap<E, PS>> for $wrap<E, PS> {
            type Output = Self;

            fn add(self, _rhs: &'a $wrap<E, PS>) -> Self::Output {
                todo!()
            }
        }

        impl<'a, E: $bound1, PS: $bound2<E>> SubAssign<&'a $wrap<E, PS>> for $wrap<E, PS> {
            fn sub_assign(&mut self, _rhs: &'a $wrap<E, PS>) {
                todo!()
            }
        }

        impl<E: $bound1, PS: $bound2<E>> SubAssign for $wrap<E, PS> {
            fn sub_assign(&mut self, _rhs: Self) {
                todo!()
            }
        }

        impl<E: $bound1, PS: $bound2<E>> Sub for $wrap<E, PS> {
            type Output = Self;

            fn sub(self, _rhs: Self) -> Self::Output {
                todo!()
            }
        }

        impl<'a, E: $bound1, PS: $bound2<E>> Sub<&'a $wrap<E, PS>> for $wrap<E, PS> {
            type Output = Self;

            fn sub(self, _rhs: &'a $wrap<E, PS>) -> Self::Output {
                todo!()
            }
        }

        impl<E: $bound1, PS: $bound2<E>> MulAssign for $wrap<E, PS> {
            fn mul_assign(&mut self, _rhs: Self) {
                todo!()
            }
        }

        impl<E: $bound1, PS: $bound2<E>> Neg for $wrap<E, PS> {
            type Output = Self;

            fn neg(self) -> Self::Output {
                todo!()
            }
        }

        impl<E: $bound1, PS: $bound2<E>> Sum for $wrap<E, PS> {
            fn sum<I: Iterator<Item = Self>>(_iter: I) -> Self {
                todo!()
            }
        }

        impl<'a, E: $bound1, PS: $bound2<E>> Sum<&'a $wrap<E, PS>> for $wrap<E, PS> {
            fn sum<I: Iterator<Item = &'a $wrap<E, PS>>>(_iter: I) -> Self {
                todo!()
            }
        }

        impl<E: $bound1, PS: $bound2<E>> Zero for $wrap<E, PS> {
            fn zero() -> Self {
                todo!()
            }

            fn is_zero(&self) -> bool {
                todo!()
            }
        }

        impl<E: $bound1, PS: $bound2<E>> Zeroize for $wrap<E, PS> {
            fn zeroize(&mut self) {
                todo!()
            }
        }

        impl<E: $bound1, PS: $bound2<E>> Default for $wrap<E, PS> {
            fn default() -> Self {
                todo!()
            }
        }
    };
}

macro_rules! impl_ext_field_wrapper {
    ($wrapped:ident, $wrap:ident) => {
        impl_pairing_mpc_wrapper!($wrapped, Field, ExtFieldShare, BasePrimeField, Ext, $wrap);

        impl<'a, F: Field, S: ExtFieldShare<F>> MulAssign<&'a $wrap<F, S>> for $wrap<F, S> {
            fn mul_assign(&mut self, _rhs: &'a $wrap<F, S>) {
                todo!()
            }
        }

        impl<F: Field, S: ExtFieldShare<F>> Mul for $wrap<F, S> {
            type Output = Self;

            fn mul(self, _rhs: Self) -> Self::Output {
                todo!()
            }
        }

        impl<'a, F: Field, S: ExtFieldShare<F>> Mul<&'a $wrap<F, S>> for $wrap<F, S> {
            type Output = Self;

            fn mul(self, _rhs: &'a $wrap<F, S>) -> Self::Output {
                todo!()
            }
        }

        impl<F: Field, S: ExtFieldShare<F>> DivAssign for $wrap<F, S> {
            fn div_assign(&mut self, _rhs: Self) {
                todo!()
            }
        }

        impl<'a, F: Field, S: ExtFieldShare<F>> DivAssign<&'a $wrap<F, S>> for $wrap<F, S> {
            fn div_assign(&mut self, _rhs: &'a $wrap<F, S>) {
                todo!()
            }
        }

        impl<F: Field, S: ExtFieldShare<F>> Div for $wrap<F, S> {
            type Output = Self;

            fn div(self, _rhs: Self) -> Self::Output {
                todo!()
            }
        }

        impl<'a, F: Field, S: ExtFieldShare<F>> Div<&'a $wrap<F, S>> for $wrap<F, S> {
            type Output = Self;

            fn div(self, _rhs: &'a $wrap<F, S>) -> Self::Output {
                todo!()
            }
        }

        impl<F: Field, S: ExtFieldShare<F>> One for $wrap<F, S> {
            fn one() -> Self {
                todo!()
            }
        }

        impl<F: Field, S: ExtFieldShare<F>> Product for $wrap<F, S> {
            fn product<I: Iterator<Item = Self>>(_iter: I) -> Self {
                todo!()
            }
        }

        impl<'a, F: Field, S: ExtFieldShare<F>> Product<&'a $wrap<F, S>> for $wrap<F, S> {
            fn product<I: Iterator<Item = &'a $wrap<F, S>>>(_iter: I) -> Self {
                todo!()
            }
        }

        impl<F: Field, S: ExtFieldShare<F>> From<bool> for $wrap<F, S> {
            fn from(_value: bool) -> Self {
                todo!()
            }
        }
        impl<F: Field, S: ExtFieldShare<F>> From<u8> for $wrap<F, S> {
            fn from(_value: u8) -> Self {
                todo!()
            }
        }
        impl<F: Field, S: ExtFieldShare<F>> From<u16> for $wrap<F, S> {
            fn from(_value: u16) -> Self {
                todo!()
            }
        }
        impl<F: Field, S: ExtFieldShare<F>> From<u32> for $wrap<F, S> {
            fn from(_value: u32) -> Self {
                todo!()
            }
        }
        impl<F: Field, S: ExtFieldShare<F>> From<u64> for $wrap<F, S> {
            fn from(_value: u64) -> Self {
                todo!()
            }
        }
        impl<F: Field, S: ExtFieldShare<F>> From<u128> for $wrap<F, S> {
            fn from(_value: u128) -> Self {
                todo!()
            }
        }
        impl<F: Field, S: ExtFieldShare<F>> Field for $wrap<F, S> {
            type BasePrimeField = MpcField<F::BasePrimeField, S::Base>;
            fn extension_degree() -> u64 {
                todo!()
            }

            fn from_base_prime_field_elems(
                _el: &[<Self as ark_ff::Field>::BasePrimeField],
            ) -> Option<Self> {
                todo!()
            }

            fn double(&self) -> Self {
                todo!()
            }

            fn double_in_place(&mut self) -> &mut Self {
                todo!()
            }

            fn from_random_bytes_with_flags<Fl: Flags>(_bytes: &[u8]) -> Option<(Self, Fl)> {
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

            fn frobenius_map(&mut self, _: usize) {
                todo!()
            }
        }
        impl<F: SquareRootField, S: ExtFieldShare<F>> SquareRootField for $wrap<F, S> {
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
    };
}

macro_rules! impl_pairing_curve_wrapper {
    ($wrapped:ident, $bound1:ident, $bound2:ident, $base:ident, $share:ident, $wrap:ident) => {
        impl_pairing_mpc_wrapper!($wrapped, $bound1, $bound2, $base, $share, $wrap);

        impl<E: $bound1, PS: $bound2<E>> MulAssign<MpcField<E::Fr, PS::FrShare>> for $wrap<E, PS> {
            fn mul_assign(&mut self, _rhs: MpcField<E::Fr, PS::FrShare>) {
                todo!()
            }
        }
    };
}

impl_pairing_curve_wrapper!(
    MpcGroup,
    PairingEngine,
    PairingShare,
    G1Affine,
    G1AffineShare,
    MpcG1Affine
);
impl_pairing_curve_wrapper!(
    MpcGroup,
    PairingEngine,
    PairingShare,
    G1Projective,
    G1ProjectiveShare,
    MpcG1Projective
);
impl_pairing_curve_wrapper!(
    MpcGroup,
    PairingEngine,
    PairingShare,
    G2Affine,
    G2AffineShare,
    MpcG2Affine
);
impl_pairing_curve_wrapper!(
    MpcGroup,
    PairingEngine,
    PairingShare,
    G2Projective,
    G2ProjectiveShare,
    MpcG2Projective
);

impl_ext_field_wrapper!(MpcField, MpcExtField);

macro_rules! impl_aff_proj {
    ($w_prep:ident, $prep:ident, $w_aff:ident, $w_pro:ident, $aff:ident, $pro:ident, $g_name:ident, $w_base:ident, $base:ident, $base_share:ident, $share_aff:ident, $share_proj:ident) => {
        impl<E: PairingEngine, PS: PairingShare<E>> Group for $w_aff<E, PS> {
            type ScalarField = MpcField<E::Fr, PS::FrShare>;

            fn double(&self) -> Self {
                todo!()
            }

            fn double_in_place(&mut self) -> &mut Self {
                todo!()
            }
        }
        impl<E: PairingEngine, PS: PairingShare<E>> From<$w_pro<E, PS>> for $w_aff<E, PS> {
            fn from(_p: $w_pro<E, PS>) -> Self {
                todo!()
            }
        }

        impl<E: PairingEngine, PS: PairingShare<E>> From<$w_aff<E, PS>> for $w_pro<E, PS> {
            fn from(_p: $w_aff<E, PS>) -> Self {
                todo!()
            }
        }

        impl<E: PairingEngine, PS: PairingShare<E>> From<$w_aff<E, PS>> for $w_prep<E, PS> {
            fn from(_p: $w_aff<E, PS>) -> Self {
                todo!()
            }
        }

        impl<E: PairingEngine, PS: PairingShare<E>> ToBytes for $w_prep<E, PS> {
            fn write<W: Write>(&self, _writer: W) -> io::Result<()> {
                todo!()
            }
        }

        impl<E: PairingEngine, PS: PairingShare<E>> AffineCurve for $w_aff<E, PS> {
            type ScalarField = MpcField<E::Fr, PS::FrShare>;
            const COFACTOR: &'static [u64] = E::$aff::COFACTOR;
            type BaseField = $w_base<E::$base, PS::$base_share>;
            type Projective = $w_pro<E, PS>;

            fn prime_subgroup_generator() -> Self {
                todo!()
            }

            fn from_random_bytes(_bytes: &[u8]) -> Option<Self> {
                todo!()
            }

            fn mul<S: Into<<Self::ScalarField as PrimeField>::BigInt>>(
                &self,
                _other: S,
            ) -> Self::Projective {
                todo!()
            }

            fn mul_by_cofactor_to_projective(&self) -> Self::Projective {
                todo!()
            }

            fn mul_by_cofactor_inv(&self) -> Self {
                todo!()
            }
        }

        impl<E: PairingEngine, PS: PairingShare<E>> ProjectiveCurve for $w_pro<E, PS> {
            type ScalarField = MpcField<E::Fr, PS::FrShare>;

            // aff?pro?
            const COFACTOR: &'static [u64] = E::$aff::COFACTOR;
            type BaseField = $w_base<E::$base, PS::$base_share>;
            type Affine = $w_aff<E, PS>;

            fn prime_subgroup_generator() -> Self {
                todo!()
            }
            fn batch_normalization(_v: &mut [Self]) {
                todo!()
            }
            fn is_normalized(&self) -> bool {
                todo!()
            }
            fn double_in_place(&mut self) -> &mut Self {
                todo!()
            }
            fn add_assign_mixed(&mut self, _other: &Self::Affine) {
                todo!()
            }
        }
    };
}

impl_aff_proj!(
    MpcG1Prep,
    G1Prepared,
    MpcG1Affine,
    MpcG1Projective,
    G1Affine,
    G1Projective,
    G1,
    MpcField,
    Fq,
    FqShare,
    G1AffineShare,
    G1ProjectiveShare
);

impl_aff_proj!(
    MpcG2Prep,
    G2Prepared,
    MpcG2Affine,
    MpcG2Projective,
    G2Affine,
    G2Projective,
    G2,
    MpcExtField,
    Fqe,
    FqeShare,
    G2AffineShare,
    G2ProjectiveShare
);
