use ark_ec::group::Group;
use ark_ec::models::TEModelParameters as Parameters;
use ark_ec::twisted_edwards_extended::GroupAffine;
use ark_ec::twisted_edwards_extended::GroupProjective;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ed_on_bls12_377::EdwardsParameters;
use ark_ff::{Field, FromBytes, One, PrimeField, PubUniformRand, ToBytes, UniformRand, Zero};
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Flags, SerializationError,
};

use derivative::Derivative;
use mpc_net::{MpcMultiNet as Net, MpcNet};
use mpc_trait::MpcWire;
use rand::Rng;
use zeroize::Zeroize;

use std::fmt::{self, Display};
use std::io::{self, Read, Write};
use std::iter::Sum;
use std::marker::PhantomData;
use std::ops::*;

use crate::groups::curves::twisted_edwards::MpcAffineVar;
use crate::*;

pub trait APShare<P: Parameters>:
    AffProjShare<P::ScalarField, GroupAffine<P>, GroupProjective<P>>
{
    type BaseShare: FieldShare<P::BaseField>;
}

pub type AdditiveMpcEdwardsProjective =
    MpcGroupProjective<EdwardsParameters, AdditiveAffProjShare<EdwardsParameters>>;
pub type AdditiveMpcEdwardsAffine =
    MpcGroupAffine<EdwardsParameters, AdditiveAffProjShare<EdwardsParameters>>;

pub type SpdzMpcEdwardsProjective =
    MpcGroupProjective<EdwardsParameters, SpdzAffProjShare<EdwardsParameters>>;
pub type SpdzMpcEdwardsAffine =
    MpcGroupAffine<EdwardsParameters, SpdzAffProjShare<EdwardsParameters>>;

type AdditiveFqVar = MpcFpVar<honest_but_curious::MpcField<ark_ed_on_bls12_377::Fq>>;
pub type AdditiveMpcEdwardsVar = MpcAffineVar<EdwardsParameters, AdditiveFqVar>;

type SpdzFqVar = MpcFpVar<malicious_majority::MpcField<ark_ed_on_bls12_377::Fq>>;
pub type SpdzMpcEdwardsVar = MpcAffineVar<EdwardsParameters, SpdzFqVar>;

#[derive(Derivative)]
#[derivative(
    Clone(bound = "P:Parameters"),
    Copy(bound = "P: Parameters"),
    Debug(bound = "P: Parameters"),
    PartialEq(bound = "P: Parameters"),
    Hash(bound = "P: Parameters"),
    Eq(bound = "P: Parameters")
)]
pub struct MpcGroupAffine<P: Parameters, S: APShare<P>> {
    val: MpcGroup<GroupAffine<P>, S::AffineShare>,
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "P: Parameters"),
    Copy(bound = "P: Parameters"),
    Debug(bound = "P: Parameters"),
    PartialEq(bound = "P: Parameters"),
    Hash(bound = "P: Parameters"),
    Eq(bound = "P: Parameters")
)]
pub struct MpcGroupProjective<P: Parameters, S: APShare<P>> {
    val: MpcGroup<GroupProjective<P>, S::ProjectiveShare>,
}

#[derive(Derivative)]
#[derivative(
    Copy(bound = "P:Parameters"),
    Clone(bound = "P: Parameters"),
    Debug(bound = "P: Parameters")
)]
pub struct MpcGroupProjectiveVariant<P: Parameters> {
    pub x: MpcField<P::BaseField, AdditiveFieldShare<P::BaseField>>,
    pub y: MpcField<P::BaseField, AdditiveFieldShare<P::BaseField>>,
    pub t: MpcField<P::BaseField, AdditiveFieldShare<P::BaseField>>,
    pub z: MpcField<P::BaseField, AdditiveFieldShare<P::BaseField>>,
}

impl<P: Parameters> Reveal for MpcGroupProjectiveVariant<P> {
    type Base = GroupProjective<P>;

    fn reveal(self) -> Self::Base {
        Self::Base::new(
            self.x.reveal(),
            self.y.reveal(),
            self.t.reveal(),
            self.z.reveal(),
        )
    }

    fn from_add_shared(_b: Self::Base) -> Self {
        unimplemented!()
    }

    fn from_public(b: Self::Base) -> Self {
        Self {
            x: MpcField::<P::BaseField, AdditiveFieldShare<P::BaseField>>::from_public(b.x),
            y: MpcField::<P::BaseField, AdditiveFieldShare<P::BaseField>>::from_public(b.y),
            t: MpcField::<P::BaseField, AdditiveFieldShare<P::BaseField>>::from_public(b.t),
            z: MpcField::<P::BaseField, AdditiveFieldShare<P::BaseField>>::from_public(b.z),
        }
    }
}

impl<P: Parameters> MpcGroupProjectiveVariant<P>
where
    <P as ark_ec::ModelParameters>::BaseField: ark_ff::PrimeField,
{
    pub fn batch_normalization(v: &[Self]) -> Vec<Self> {
        let z_s = v.iter().map(|g| g.z).collect::<Vec<_>>();
        let inversed_z_s = z_s.iter().map(|z| z.inverse().unwrap()).collect::<Vec<_>>();

        v.iter()
            .zip(inversed_z_s.iter())
            .map(|(g, z)| {
                // let z = inversed_z_s.pop().unwrap();
                Self {
                    x: g.x * z,
                    y: g.y * z,
                    t: g.t * z,
                    z: MpcField::<P::BaseField, AdditiveFieldShare<P::BaseField>>::one(),
                }
            })
            .collect::<Vec<_>>()
    }
}

impl<P: Parameters, S: APShare<P>> Group for MpcGroupAffine<P, S> {
    type ScalarField = MpcField<P::ScalarField, S::FrShare>;

    fn double(&self) -> Self {
        todo!()
    }

    fn double_in_place(&mut self) -> &mut Self {
        todo!()
    }
}

// for MpcGroupProjective

impl<P: Parameters, S: APShare<P>> Reveal for MpcGroupProjective<P, S> {
    type Base = GroupProjective<P>;
    #[inline]
    fn reveal(self) -> Self::Base {
        self.val.reveal()
    }
    #[inline]
    fn from_public(t: Self::Base) -> Self {
        Self {
            val: MpcGroup::from_public(t),
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

impl<P: Parameters, S: APShare<P>> Display for MpcGroupProjective<P, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.val)
    }
}

impl<P: Parameters, S: APShare<P>> ToBytes for MpcGroupProjective<P, S> {
    fn write<W: Write>(&self, writer: W) -> io::Result<()> {
        self.val.write(writer)
    }
}

impl<P: Parameters, S: APShare<P>> FromBytes for MpcGroupProjective<P, S> {
    fn read<R: Read>(_reader: R) -> io::Result<Self> {
        todo!()
    }
}

impl<P: Parameters, S: APShare<P>> CanonicalSerialize for MpcGroupProjective<P, S> {
    fn serialize<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        self.val.serialize(writer)
    }

    fn serialized_size(&self) -> usize {
        todo!()
    }
}

impl<P: Parameters, S: APShare<P>> CanonicalSerializeWithFlags for MpcGroupProjective<P, S> {
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

impl<P: Parameters, S: APShare<P>> CanonicalDeserialize for MpcGroupProjective<P, S> {
    fn deserialize<R: Read>(_reader: R) -> Result<Self, SerializationError> {
        todo!()
    }
}

impl<P: Parameters, S: APShare<P>> CanonicalDeserializeWithFlags for MpcGroupProjective<P, S> {
    fn deserialize_with_flags<R: Read, Fl: Flags>(
        _reader: R,
    ) -> Result<(Self, Fl), SerializationError> {
        todo!()
    }
}

impl<P: Parameters, S: APShare<P>> UniformRand for MpcGroupProjective<P, S> {
    fn rand<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        Self {
            val: MpcGroup::rand(rng),
        }
    }
}

impl<P: Parameters, S: APShare<P>> PubUniformRand for MpcGroupProjective<P, S> {
    fn pub_rand<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        Self {
            val: MpcGroup::pub_rand(rng),
        }
    }
}

impl<P: Parameters, S: APShare<P>> AddAssign for MpcGroupProjective<P, S> {
    fn add_assign(&mut self, rhs: Self) {
        self.add_assign(&rhs)
    }
}

impl<'a, P: Parameters, S: APShare<P>> AddAssign<&'a MpcGroupProjective<P, S>>
    for MpcGroupProjective<P, S>
{
    fn add_assign(&mut self, rhs: &'a MpcGroupProjective<P, S>) {
        self.val += &rhs.val;
    }
}

impl<P: Parameters, S: APShare<P>> Add for MpcGroupProjective<P, S> {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self.add_assign(&rhs);
        self
    }
}

impl<'a, P: Parameters, S: APShare<P>> Add<&'a MpcGroupProjective<P, S>>
    for MpcGroupProjective<P, S>
{
    type Output = Self;

    fn add(mut self, rhs: &'a MpcGroupProjective<P, S>) -> Self::Output {
        self.add_assign(rhs);
        self
    }
}

impl<'a, P: Parameters, S: APShare<P>> SubAssign<&'a MpcGroupProjective<P, S>>
    for MpcGroupProjective<P, S>
{
    fn sub_assign(&mut self, rhs: &'a MpcGroupProjective<P, S>) {
        self.val -= &rhs.val;
    }
}

impl<P: Parameters, S: APShare<P>> SubAssign for MpcGroupProjective<P, S> {
    fn sub_assign(&mut self, rhs: Self) {
        self.sub_assign(&rhs)
    }
}

impl<P: Parameters, S: APShare<P>> Sub for MpcGroupProjective<P, S> {
    type Output = Self;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self.sub_assign(&rhs);
        self
    }
}

impl<'a, P: Parameters, S: APShare<P>> Sub<&'a MpcGroupProjective<P, S>>
    for MpcGroupProjective<P, S>
{
    type Output = Self;

    fn sub(mut self, rhs: &'a MpcGroupProjective<P, S>) -> Self::Output {
        self.sub_assign(rhs);
        self
    }
}

impl<P: Parameters, S: APShare<P>> MulAssign for MpcGroupProjective<P, S> {
    fn mul_assign(&mut self, _rhs: Self) {
        todo!()
    }
}

impl<P: Parameters, S: APShare<P>> Neg for MpcGroupProjective<P, S> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        todo!()
    }
}

impl<P: Parameters, S: APShare<P>> Sum for MpcGroupProjective<P, S> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), core::ops::Add::add)
    }
}

impl<'a, P: Parameters, S: APShare<P>> Sum<&'a MpcGroupProjective<P, S>>
    for MpcGroupProjective<P, S>
{
    fn sum<I: Iterator<Item = &'a MpcGroupProjective<P, S>>>(_iter: I) -> Self {
        todo!()
    }
}

impl<P: Parameters, S: APShare<P>> Zero for MpcGroupProjective<P, S> {
    fn zero() -> Self {
        Self {
            val: MpcGroup::zero(),
        }
    }

    fn is_zero(&self) -> bool {
        todo!()
    }
}

impl<P: Parameters, S: APShare<P>> Zeroize for MpcGroupProjective<P, S> {
    fn zeroize(&mut self) {
        todo!()
    }
}

impl<P: Parameters, S: APShare<P>> Default for MpcGroupProjective<P, S> {
    fn default() -> Self {
        todo!()
    }
}

impl<P: Parameters, S: APShare<P>> MpcWire for MpcGroupProjective<P, S> {
    #[inline]
    fn publicize(&mut self) {
        self.val.publicize();
    }
    #[inline]
    fn is_shared(&self) -> bool {
        self.val.is_shared()
    }
}

impl<P: Parameters, S: APShare<P>> MulAssign<MpcField<P::ScalarField, S::FrShare>>
    for MpcGroupProjective<P, S>
{
    fn mul_assign(&mut self, _rhs: MpcField<P::ScalarField, S::FrShare>) {
        todo!()
    }
}

impl<P: Parameters, S: APShare<P>> ProjectiveCurve for MpcGroupProjective<P, S>
where
    P::BaseField: PrimeField,
{
    const COFACTOR: &'static [u64] = GroupProjective::<P>::COFACTOR;

    type ScalarField = MpcField<P::ScalarField, S::FrShare>;

    type BaseField = MpcField<P::BaseField, S::BaseShare>;

    type Affine = MpcGroupAffine<P, S>;

    fn prime_subgroup_generator() -> Self {
        MpcGroupAffine::prime_subgroup_generator().into()
    }

    fn batch_normalization(v: &mut [Self]) {
        unimplemented!();
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
                MpcGroup::Shared(S::add_sh_proj_sh_aff(a.clone(), b))
            }
            (MpcGroup::Shared(a), MpcGroup::Public(b)) => {
                MpcGroup::Shared(S::add_sh_proj_pub_aff(a.clone(), b))
            }
            (MpcGroup::Public(a), MpcGroup::Shared(b)) => {
                MpcGroup::Shared(S::add_pub_proj_sh_aff(a, b.clone()))
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

// for MpcGroupAffine

impl<P: Parameters, S: APShare<P>> Reveal for MpcGroupAffine<P, S> {
    type Base = GroupAffine<P>;
    #[inline]
    fn reveal(self) -> Self::Base {
        self.val.reveal()
    }
    #[inline]
    fn from_public(t: Self::Base) -> Self {
        Self {
            val: MpcGroup::from_public(t),
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

impl<P: Parameters, S: APShare<P>> Display for MpcGroupAffine<P, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.val)
    }
}

impl<P: Parameters, S: APShare<P>> ToBytes for MpcGroupAffine<P, S> {
    fn write<W: Write>(&self, writer: W) -> io::Result<()> {
        self.val.write(writer)
    }
}

impl<P: Parameters, S: APShare<P>> FromBytes for MpcGroupAffine<P, S> {
    fn read<R: Read>(_reader: R) -> io::Result<Self> {
        todo!()
    }
}

impl<P: Parameters, S: APShare<P>> CanonicalSerialize for MpcGroupAffine<P, S> {
    fn serialize<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        self.val.serialize(writer)
    }

    fn serialized_size(&self) -> usize {
        todo!()
    }
}

impl<P: Parameters, S: APShare<P>> CanonicalSerializeWithFlags for MpcGroupAffine<P, S> {
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

impl<P: Parameters, S: APShare<P>> CanonicalDeserialize for MpcGroupAffine<P, S> {
    fn deserialize<R: Read>(_reader: R) -> Result<Self, SerializationError> {
        todo!()
    }
}

impl<P: Parameters, S: APShare<P>> CanonicalDeserializeWithFlags for MpcGroupAffine<P, S> {
    fn deserialize_with_flags<R: Read, Fl: Flags>(
        _reader: R,
    ) -> Result<(Self, Fl), SerializationError> {
        todo!()
    }
}

impl<P: Parameters, S: APShare<P>> UniformRand for MpcGroupAffine<P, S> {
    fn rand<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        Self {
            val: MpcGroup::rand(rng),
        }
    }
}

impl<P: Parameters, S: APShare<P>> PubUniformRand for MpcGroupAffine<P, S> {
    fn pub_rand<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        Self {
            val: MpcGroup::pub_rand(rng),
        }
    }
}

impl<P: Parameters, S: APShare<P>> AddAssign for MpcGroupAffine<P, S> {
    fn add_assign(&mut self, rhs: Self) {
        self.add_assign(&rhs)
    }
}

impl<'a, P: Parameters, S: APShare<P>> AddAssign<&'a MpcGroupAffine<P, S>>
    for MpcGroupAffine<P, S>
{
    fn add_assign(&mut self, rhs: &'a MpcGroupAffine<P, S>) {
        self.val += &rhs.val;
    }
}

impl<P: Parameters, S: APShare<P>> Add for MpcGroupAffine<P, S> {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self.add_assign(&rhs);
        self
    }
}

impl<'a, P: Parameters, S: APShare<P>> Add<&'a MpcGroupAffine<P, S>> for MpcGroupAffine<P, S> {
    type Output = Self;

    fn add(mut self, rhs: &'a MpcGroupAffine<P, S>) -> Self::Output {
        self.add_assign(rhs);
        self
    }
}

impl<'a, P: Parameters, S: APShare<P>> SubAssign<&'a MpcGroupAffine<P, S>>
    for MpcGroupAffine<P, S>
{
    fn sub_assign(&mut self, rhs: &'a MpcGroupAffine<P, S>) {
        self.val -= &rhs.val;
    }
}

impl<P: Parameters, S: APShare<P>> SubAssign for MpcGroupAffine<P, S> {
    fn sub_assign(&mut self, rhs: Self) {
        self.sub_assign(&rhs)
    }
}

impl<P: Parameters, S: APShare<P>> Sub for MpcGroupAffine<P, S> {
    type Output = Self;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self.sub_assign(&rhs);
        self
    }
}

impl<'a, P: Parameters, S: APShare<P>> Sub<&'a MpcGroupAffine<P, S>> for MpcGroupAffine<P, S> {
    type Output = Self;

    fn sub(mut self, rhs: &'a MpcGroupAffine<P, S>) -> Self::Output {
        self.sub_assign(rhs);
        self
    }
}

impl<P: Parameters, S: APShare<P>> MulAssign for MpcGroupAffine<P, S> {
    fn mul_assign(&mut self, _rhs: Self) {
        todo!()
    }
}

impl<P: Parameters, S: APShare<P>> Neg for MpcGroupAffine<P, S> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        todo!()
    }
}

impl<P: Parameters, S: APShare<P>> Sum for MpcGroupAffine<P, S> {
    fn sum<I: Iterator<Item = Self>>(_iter: I) -> Self {
        todo!()
    }
}

impl<'a, P: Parameters, S: APShare<P>> Sum<&'a MpcGroupAffine<P, S>> for MpcGroupAffine<P, S> {
    fn sum<I: Iterator<Item = &'a MpcGroupAffine<P, S>>>(_iter: I) -> Self {
        todo!()
    }
}

impl<P: Parameters, S: APShare<P>> Zero for MpcGroupAffine<P, S> {
    fn zero() -> Self {
        Self {
            val: MpcGroup::zero(),
        }
    }

    fn is_zero(&self) -> bool {
        todo!()
    }
}

impl<P: Parameters, S: APShare<P>> Zeroize for MpcGroupAffine<P, S> {
    fn zeroize(&mut self) {
        todo!()
    }
}

impl<P: Parameters, S: APShare<P>> Default for MpcGroupAffine<P, S> {
    fn default() -> Self {
        todo!()
    }
}

impl<P: Parameters, S: APShare<P>> MpcWire for MpcGroupAffine<P, S> {
    #[inline]
    fn publicize(&mut self) {
        self.val.publicize();
    }
    #[inline]
    fn is_shared(&self) -> bool {
        self.val.is_shared()
    }
}

impl<P: Parameters, S: APShare<P>> MulAssign<MpcField<P::ScalarField, S::FrShare>>
    for MpcGroupAffine<P, S>
{
    fn mul_assign(&mut self, rhs: MpcField<P::ScalarField, S::FrShare>) {
        todo!()
    }
}

impl<P: Parameters, S: APShare<P>> AffineCurve for MpcGroupAffine<P, S>
where
    P::BaseField: PrimeField,
{
    const COFACTOR: &'static [u64] = P::COFACTOR;

    type ScalarField = MpcField<P::ScalarField, S::FrShare>;

    type BaseField = MpcField<P::BaseField, S::BaseShare>;

    type Projective = MpcGroupProjective<P, S>;

    fn prime_subgroup_generator() -> Self {
        Self {
            val: MpcGroup::from_public(GroupAffine::<P>::new(
                P::AFFINE_GENERATOR_COEFFS.0,
                P::AFFINE_GENERATOR_COEFFS.1,
            )),
        }
    }

    fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
        todo!()
    }

    fn mul<T: Into<<Self::ScalarField as ark_ff::prelude::PrimeField>::BigInt>>(
        &self,
        other: T,
    ) -> Self::Projective {
        todo!()
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
            // let scalars_shared = scalars.first().map(|s| s.is_shared()).unwrap_or(true);
            // assert!(scalars.iter().all(|b| scalars_shared == b.is_shared()));
            let bases =
                MpcGroup::all_public_or_shared(bases.into_iter().map(|i| i.val.clone())).unwrap();
            match MpcField::all_public_or_shared(scalars.into_iter().cloned()) {
                Ok(pub_scalars) => {
                    // let t = start_timer!(|| "MSM inner");
                    let r = Self::Projective {
                        // wat?
                        val: if true {
                            // let t1 = start_timer!(|| "do msm");
                            let r = <GroupAffine<P> as AffineCurve>::multi_scalar_mul(
                                &bases,
                                &pub_scalars,
                            );
                            // end_timer!(t1);
                            // let t1 = start_timer!(|| "cast");
                            let r =
                                MpcGroup::Shared(<S::ProjectiveShare as Reveal>::from_public(r));
                            // end_timer!(t1);
                            r
                        } else {
                            MpcGroup::Public(<GroupAffine<P> as AffineCurve>::multi_scalar_mul(
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
                    let r = Self::Projective {
                        val: MpcGroup::Shared(S::sh_aff_to_proj(<S::AffineShare as GroupShare<
                            GroupAffine<P>,
                        >>::multi_scale_pub_group(
                            &bases, &priv_scalars
                        ))),
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
}

type FrShare<P: Parameters> = AdditiveFieldShare<P::ScalarField>;
type FqShare<P: Parameters> = AdditiveFieldShare<P::BaseField>;
type SpdzFrShare<P: Parameters> = SpdzFieldShare<P::ScalarField>;
type SpdzFqShare<P: Parameters> = SpdzFieldShare<P::BaseField>;

type AffineShare<P: Parameters> = AdditiveGroupShare<GroupAffine<P>, AffineMsm<GroupAffine<P>>>;
type ProjectiveShare<P: Parameters> =
    AdditiveGroupShare<GroupProjective<P>, crate::msm::ProjectiveMsm<GroupProjective<P>>>;

// type APShare<P> = AffProjShare<
//     P::ScalarField,
//     GroupAffine<P>,
//     GroupProjective<P>,
//     FrShare = AdditiveFieldShare<P::ScalarField>,
//     AffineShare = AffineShare<P>,
//     ProjectiveShare = ProjectiveShare<P>,
// >;

pub struct AdditiveAffProjShare<P: Parameters> {
    pub PhantomData: PhantomData<P>,
}

pub struct SpdzAffProjShare<P: Parameters> {
    pub PhantomData: PhantomData<P>,
}

impl<P: Parameters> AffProjShare<P::ScalarField, GroupAffine<P>, GroupProjective<P>>
    for AdditiveAffProjShare<P>
{
    type FrShare = FrShare<P>;
    type AffineShare = AdditiveGroupShare<GroupAffine<P>, AffineMsm<GroupAffine<P>>>;
    type ProjectiveShare =
        AdditiveGroupShare<GroupProjective<P>, ProjectiveMsm<GroupProjective<P>>>;

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
        o: &GroupAffine<P>,
    ) -> Self::ProjectiveShare {
        if Net::am_king() {
            a.val.add_assign_mixed(&o);
        }
        a
    }
    fn add_pub_proj_sh_aff(
        _a: &GroupProjective<P>,
        _o: Self::AffineShare,
    ) -> Self::ProjectiveShare {
        unimplemented!()
    }
}

impl<P: Parameters> APShare<P> for AdditiveAffProjShare<P> {
    type BaseShare = FqShare<P>;
}

impl<P: Parameters> AffProjShare<P::ScalarField, GroupAffine<P>, GroupProjective<P>>
    for SpdzAffProjShare<P>
{
    type FrShare = SpdzFrShare<P>;
    type AffineShare = SpdzGroupShare<GroupAffine<P>, AffineMsm<GroupAffine<P>>>;
    type ProjectiveShare = SpdzGroupShare<GroupProjective<P>, ProjectiveMsm<GroupProjective<P>>>;

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
        a.sh.val.add_assign_mixed(&o.sh.val);
        a
    }
    fn add_sh_proj_pub_aff(
        mut a: Self::ProjectiveShare,
        o: &GroupAffine<P>,
    ) -> Self::ProjectiveShare {
        if Net::am_king() {
            a.sh.val.add_assign_mixed(&o);
        }
        a
    }
    fn add_pub_proj_sh_aff(
        _a: &GroupProjective<P>,
        _o: Self::AffineShare,
    ) -> Self::ProjectiveShare {
        unimplemented!()
    }
}

impl<P: Parameters> APShare<P> for SpdzAffProjShare<P> {
    type BaseShare = SpdzFqShare<P>;
}

impl<P: Parameters, S: APShare<P>> From<MpcGroupAffine<P, S>> for MpcGroupProjective<P, S> {
    fn from(p: MpcGroupAffine<P, S>) -> MpcGroupProjective<P, S> {
        // Self::new(p.x, p.y, p.x * &p.y, P::BaseField::one())
        Self {
            val: p.val.map(|s| s.into(), S::sh_aff_to_proj),
        }
    }
}

impl<P: Parameters, S: APShare<P>> From<MpcGroupProjective<P, S>> for MpcGroupAffine<P, S> {
    fn from(p: MpcGroupProjective<P, S>) -> MpcGroupAffine<P, S> {
        Self {
            val: p.val.map(|s| s.into(), S::sh_proj_to_aff),
        }
    }
}

type hbc_BaseField<P: Parameters> = honest_but_curious::MpcField<P::BaseField>;

impl<P: Parameters, S: APShare<P>> MpcGroupProjective<P, S> {
    pub fn convert_xytz(&self) -> MpcGroupProjectiveVariant<P> {
        match self.val {
            MpcGroup::Shared(s) => {
                // 1. get unprocessed x, y
                let unprocessed = self.val.unwrap_as_public();

                // TODO: 2. generate shares and communicate
                let vec_x = (0..Net::n_parties())
                    .map(|i| {
                        hbc_BaseField::<P>::from_add_shared(if Net::party_id() == i {
                            unprocessed.x
                        } else {
                            P::BaseField::zero()
                        })
                    })
                    .collect::<Vec<hbc_BaseField<P>>>();

                let vec_y = (0..Net::n_parties())
                    .map(|i| {
                        hbc_BaseField::<P>::from_add_shared(if Net::party_id() == i {
                            unprocessed.y
                        } else {
                            P::BaseField::zero()
                        })
                    })
                    .collect::<Vec<hbc_BaseField<P>>>();

                let vec_t = (0..Net::n_parties())
                    .map(|i| {
                        hbc_BaseField::<P>::from_add_shared(if Net::party_id() == i {
                            unprocessed.t
                        } else {
                            P::BaseField::zero()
                        })
                    })
                    .collect::<Vec<hbc_BaseField<P>>>();

                let vec_z = (0..Net::n_parties())
                    .map(|i| {
                        hbc_BaseField::<P>::from_add_shared(if Net::party_id() == i {
                            unprocessed.z
                        } else {
                            P::BaseField::zero()
                        })
                    })
                    .collect::<Vec<hbc_BaseField<P>>>();

                // 3. summand and make converted share
                // addition of elliptic curve points in (x,y,t,z) form.
                let (sum_x, sum_y, sum_t, sum_z) = vec_x
                    .iter()
                    .zip(vec_y.iter())
                    .zip(vec_t.iter())
                    .zip(vec_z.iter())
                    .fold(
                        (
                            hbc_BaseField::<P>::zero(),
                            hbc_BaseField::<P>::one(),
                            hbc_BaseField::<P>::zero(),
                            hbc_BaseField::<P>::one(),
                        ),
                        |(acc_x, acc_y, acc_t, acc_z), (((&x, &y), &t), &z)| {
                            // A = x1 * x2
                            let a = acc_x * x;

                            // B = y1 * y2
                            let b = acc_y * y;

                            // C = d * t1 * t2
                            let c = hbc_BaseField::<P>::from_public(P::COEFF_D) * acc_t * t;

                            // D = z1 * z2
                            let d = acc_z * z;

                            // H = B - aA
                            let h = b - a * &hbc_BaseField::<P>::from_public(P::COEFF_A);

                            // E = (x1 + y1) * (x2 + y2) - A - B
                            let e = (acc_x + &acc_y) * &(x + y) - &a - &b;

                            // F = D - C
                            let f = d - &c;

                            // G = D + C
                            let g = d + &c;

                            // x3 = E * F
                            let sum_x = e * &f;

                            // y3 = G * H
                            let sum_y = g * &h;

                            // t3 = E * H
                            let sum_t = e * &h;

                            // z3 = F * G
                            let sum_z = f * &g;

                            (sum_x, sum_y, sum_t, sum_z)
                        },
                    );

                MpcGroupProjectiveVariant {
                    x: sum_x,
                    y: sum_y,
                    t: sum_t,
                    z: sum_z,
                }
            }
            MpcGroup::Public(s) => MpcGroupProjectiveVariant {
                x: hbc_BaseField::<P>::from_public(s.x),
                y: hbc_BaseField::<P>::from_public(s.y),
                t: hbc_BaseField::<P>::from_public(s.t),
                z: hbc_BaseField::<P>::from_public(s.z),
            },
        }
    }
}
