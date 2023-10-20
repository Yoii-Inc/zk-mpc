use std::fmt;
use std::fmt::Display;
use std::hash::Hash;
use std::io::{self, Read, Write};
use std::iter::{Product, Sum};
use std::marker::PhantomData;
use std::ops::*;

use rand::Rng;
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

use mpc_trait::MpcWire;

use super::super::reveal::Reveal;
use super::super::share::field::ExtFieldShare;
use super::super::share::group::GroupShare;
use super::super::share::pairing::{AffProjShare, PairingShare};
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
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.val)
            }
        }

        impl<E: $bound1, PS: $bound2<E>> ToBytes for $wrap<E, PS> {
            fn write<W: Write>(&self, writer: W) -> io::Result<()> {
                self.val.write(writer)
            }
        }

        impl<E: $bound1, PS: $bound2<E>> FromBytes for $wrap<E, PS> {
            fn read<R: Read>(_reader: R) -> io::Result<Self> {
                todo!()
            }
        }

        impl<E: $bound1, PS: $bound2<E>> CanonicalSerialize for $wrap<E, PS> {
            fn serialize<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
                self.val.serialize(writer)
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
            fn rand<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
                Self {
                    val: $wrapped::rand(rng),
                }
            }
        }

        impl<E: $bound1, PS: $bound2<E>> PubUniformRand for $wrap<E, PS> {
            fn pub_rand<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
                Self {
                    val: $wrapped::pub_rand(rng),
                }
            }
        }

        impl<E: $bound1, PS: $bound2<E>> AddAssign for $wrap<E, PS> {
            fn add_assign(&mut self, rhs: Self) {
                self.add_assign(&rhs)
            }
        }

        impl<'a, E: $bound1, PS: $bound2<E>> AddAssign<&'a $wrap<E, PS>> for $wrap<E, PS> {
            fn add_assign(&mut self, rhs: &'a $wrap<E, PS>) {
                self.val += &rhs.val;
            }
        }

        impl<E: $bound1, PS: $bound2<E>> Add for $wrap<E, PS> {
            type Output = Self;

            fn add(mut self, rhs: Self) -> Self::Output {
                self.add_assign(&rhs);
                self
            }
        }

        impl<'a, E: $bound1, PS: $bound2<E>> Add<&'a $wrap<E, PS>> for $wrap<E, PS> {
            type Output = Self;

            fn add(mut self, rhs: &'a $wrap<E, PS>) -> Self::Output {
                self.add_assign(rhs);
                self
            }
        }

        impl<'a, E: $bound1, PS: $bound2<E>> SubAssign<&'a $wrap<E, PS>> for $wrap<E, PS> {
            fn sub_assign(&mut self, rhs: &'a $wrap<E, PS>) {
                self.val -= &rhs.val;
            }
        }

        impl<E: $bound1, PS: $bound2<E>> SubAssign for $wrap<E, PS> {
            fn sub_assign(&mut self, rhs: Self) {
                self.sub_assign(&rhs)
            }
        }

        impl<E: $bound1, PS: $bound2<E>> Sub for $wrap<E, PS> {
            type Output = Self;

            fn sub(mut self, rhs: Self) -> Self::Output {
                self.sub_assign(&rhs);
                self
            }
        }

        impl<'a, E: $bound1, PS: $bound2<E>> Sub<&'a $wrap<E, PS>> for $wrap<E, PS> {
            type Output = Self;

            fn sub(mut self, rhs: &'a $wrap<E, PS>) -> Self::Output {
                self.sub_assign(rhs);
                self
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
                Self {
                    val: $wrapped::zero(),
                }
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

        impl<E: $bound1, PS: $bound2<E>> MpcWire for $wrap<E, PS> {
            #[inline]
            fn publicize(&mut self) {
                self.val.publicize();
            }
            #[inline]
            fn is_shared(&self) -> bool {
                self.val.is_shared()
            }
        }
    };
}

macro_rules! impl_ext_field_wrapper {
    ($wrapped:ident, $wrap:ident) => {
        impl_pairing_mpc_wrapper!($wrapped, Field, ExtFieldShare, BasePrimeField, Ext, $wrap);

        impl<F: Field, S: ExtFieldShare<F>> Reveal for $wrap<F, S> {
            type Base = F;
            #[inline]
            fn reveal(self) -> F {
                self.val.reveal()
            }
            #[inline]
            fn from_public(_t: F) -> Self {
                // Self::wrap($wrapped::from_public(t))
                todo!()
            }
            #[inline]
            fn from_add_shared(_t: F) -> Self {
                // Self::wrap($wrapped::from_add_shared(t))
                todo!()
            }
            #[inline]
            fn unwrap_as_public(self) -> Self::Base {
                self.val.unwrap_as_public()
            }
            #[inline]
            fn king_share<R: Rng>(_f: Self::Base, _rng: &mut R) -> Self {
                unimplemented!()
            }
            #[inline]
            fn king_share_batch<R: Rng>(_f: Vec<Self::Base>, _rng: &mut R) -> Vec<Self> {
                unimplemented!()
            }
        }

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

        impl<E: $bound1, PS: $bound2<E>> Reveal for $wrap<E, PS> {
            type Base = E::$base;
            #[inline]
            fn reveal(self) -> Self::Base {
                self.val.reveal()
            }
            #[inline]
            fn from_public(t: Self::Base) -> Self {
                Self {
                    val: $wrapped::from_public(t),
                }
            }
            #[inline]
            fn from_add_shared(_t: Self::Base) -> Self {
                todo!()
            }
            #[inline]
            fn unwrap_as_public(self) -> Self::Base {
                // self.val.unwrap_as_public()
                todo!()
            }
            #[inline]
            fn king_share<R: Rng>(_f: Self::Base, _rng: &mut R) -> Self {
                unimplemented!()
            }
            #[inline]
            fn king_share_batch<R: Rng>(_f: Vec<Self::Base>, _rng: &mut R) -> Vec<Self> {
                unimplemented!()
            }
        }

        impl<E: $bound1, PS: $bound2<E>> Mul<MpcField<E::Fr, PS::FrShare>> for $wrap<E, PS> {
            type Output = Self;
            #[inline]
            fn mul(self, other: MpcField<E::Fr, PS::FrShare>) -> Self::Output {
                Self {
                    val: self.val.mul(other),
                }
            }
        }

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
        impl<E: PairingEngine, PS: PairingShare<E>> Reveal for $w_prep<E, PS> {
            type Base = E::$prep;
            #[inline]
            fn reveal(self) -> E::$prep {
                self.val
            }
            #[inline]
            fn from_public(g: E::$prep) -> Self {
                Self {
                    val: g,
                    _phantom: PhantomData::default(),
                }
            }
            #[inline]
            fn from_add_shared(_g: E::$prep) -> Self {
                panic!("Cannot add share a prepared curve")
            }
        }

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
            fn from(p: $w_pro<E, PS>) -> Self {
                Self {
                    val: p.val.map(|s| s.into(), PS::$g_name::sh_proj_to_aff),
                }
            }
        }

        impl<E: PairingEngine, PS: PairingShare<E>> From<$w_aff<E, PS>> for $w_pro<E, PS> {
            fn from(p: $w_aff<E, PS>) -> Self {
                Self {
                    val: p.val.map(|s| s.into(), PS::$g_name::sh_aff_to_proj),
                }
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
                unimplemented!("mul by bigint")
            }

            fn mul_by_cofactor_to_projective(&self) -> Self::Projective {
                todo!()
            }

            fn mul_by_cofactor_inv(&self) -> Self {
                todo!()
            }

            fn multi_scalar_mul(bases: &[Self], scalars: &[Self::ScalarField]) -> Self::Projective {
                let b = {
                    assert!(bases.iter().all(|b| !b.is_shared()));
                    let scalars_shared = scalars.first().map(|s| s.is_shared()).unwrap_or(true);
                    assert!(scalars.iter().all(|b| scalars_shared == b.is_shared()));
                    let bases =
                        MpcGroup::all_public_or_shared(bases.into_iter().map(|i| i.val.clone()))
                            .unwrap();
                    match MpcField::all_public_or_shared(scalars.into_iter().cloned()) {
                        Ok(pub_scalars) => {
                            // let t = start_timer!(|| "MSM inner");
                            let r = $w_pro {
                                // wat?
                                val: if true {
                                    // let t1 = start_timer!(|| "do msm");
                                    let r = <E::$aff as AffineCurve>::multi_scalar_mul(
                                        &bases,
                                        &pub_scalars,
                                    );
                                    // end_timer!(t1);
                                    // let t1 = start_timer!(|| "cast");
                                    let r = MpcGroup::Shared(
                                        <PS::$share_proj as Reveal>::from_public(r),
                                    );
                                    // end_timer!(t1);
                                    r
                                } else {
                                    MpcGroup::Public(<E::$aff as AffineCurve>::multi_scalar_mul(
                                        &bases,
                                        &pub_scalars,
                                    ))
                                },
                            };
                            // end_timer!(t);
                            r
                        }
                        Err(priv_scalars) => {
                            // let t = start_timer!(|| "MSM inner");
                            let r = $w_pro {
                                val: MpcGroup::Shared(PS::$g_name::sh_aff_to_proj(
                                    <PS::$share_aff as GroupShare<E::$aff>>::multi_scale_pub_group(
                                        &bases,
                                        &priv_scalars,
                                    ),
                                )),
                            };
                            // end_timer!(t);
                            r
                        }
                    }
                };
                // {
                //     let mut pa = a;
                //     let mut pb = b;
                //     pa.publicize();
                //     pb.publicize();
                //     println!("{}\n->\n{}", a, pa);
                //     println!("{}\n->\n{}", b, pb);
                //     println!("Check eq!");
                //     //assert_eq!(a, b);
                //     assert_eq!(pa, pb);
                // }
                b
            }

            fn scalar_mul<S: Into<Self::ScalarField>>(&self, other: S) -> Self::Projective {
                (*self * other.into()).into()
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
                // todo!()
            }
            fn is_normalized(&self) -> bool {
                todo!()
            }
            fn double_in_place(&mut self) -> &mut Self {
                self.val.double_in_place();
                self
            }
            fn add_assign_mixed(&mut self, other: &Self::Affine) {
                let new_self = match (&self.val, &other.val) {
                    (MpcGroup::Shared(a), MpcGroup::Shared(b)) => {
                        MpcGroup::Shared(PS::$g_name::add_sh_proj_sh_aff(a.clone(), b))
                    }
                    (MpcGroup::Shared(a), MpcGroup::Public(b)) => {
                        MpcGroup::Shared(PS::$g_name::add_sh_proj_pub_aff(a.clone(), b))
                    }
                    (MpcGroup::Public(a), MpcGroup::Shared(b)) => {
                        MpcGroup::Shared(PS::$g_name::add_pub_proj_sh_aff(a, b.clone()))
                    }
                    (MpcGroup::Public(a), MpcGroup::Public(b)) => MpcGroup::Public({
                        let mut a = a.clone();
                        a.add_assign_mixed(b);
                        a
                    }),
                };
                self.val = new_self;
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
