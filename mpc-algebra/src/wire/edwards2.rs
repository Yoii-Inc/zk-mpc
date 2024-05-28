use ark_ec::group::Group;
use ark_ec::models::TEModelParameters as Parameters;
use ark_ec::twisted_edwards_extended::GroupAffine;
use ark_ec::twisted_edwards_extended::GroupProjective;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ed_on_bls12_377::EdwardsParameters;
use ark_ff::PrimeField;
use ark_ff::{FromBytes, PubUniformRand, ToBytes, UniformRand, Zero};
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
use crate::honest_but_curious;
use crate::wire::field::MpcField;
use crate::AffProjShare;
use crate::AffineMsm;
use crate::GroupShare;
use crate::MpcFpVar;
use crate::ProjectiveMsm;
use crate::Reveal;
use crate::{AdditiveFieldShare, AdditiveGroupShare, MpcGroup};

pub type MpcEdwardsProjective = MpcGroupProjective<EdwardsParameters>;
pub type MpcEdwardsAffine = MpcGroupAffine<EdwardsParameters>;

type AdditiveFqVar = MpcFpVar<honest_but_curious::MpcField<ark_ed_on_bls12_377::Fq>>;
pub type AdditiveMpcEdwardsVar = MpcAffineVar<EdwardsParameters, AdditiveFqVar>;

#[derive(Derivative)]
#[derivative(
    Clone(bound = "P:Parameters"),
    Copy(bound = "P: Parameters"),
    Debug(bound = "P: Parameters"),
    PartialEq(bound = "P: Parameters"),
    Hash(bound = "P: Parameters"),
    Eq(bound = "P: Parameters")
)]
pub struct MpcGroupAffine<P: Parameters> {
    val: MpcGroup<
        GroupAffine<P>,
        AdditiveGroupShare<GroupAffine<P>, crate::msm::AffineMsm<GroupAffine<P>>>,
    >,
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
pub struct MpcGroupProjective<P: Parameters> {
    val: MpcGroup<
        GroupProjective<P>,
        AdditiveGroupShare<GroupProjective<P>, crate::msm::ProjectiveMsm<GroupProjective<P>>>,
    >,
}

impl<P: Parameters> Group for MpcGroupAffine<P> {
    type ScalarField = MpcField<P::ScalarField, AdditiveFieldShare<P::ScalarField>>;

    fn double(&self) -> Self {
        todo!()
    }

    fn double_in_place(&mut self) -> &mut Self {
        todo!()
    }
}

// for MpcGroupProjective

impl<P: Parameters> Reveal for MpcGroupProjective<P> {
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

impl<P: Parameters> Display for MpcGroupProjective<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.val)
    }
}

impl<P: Parameters> ToBytes for MpcGroupProjective<P> {
    fn write<W: Write>(&self, writer: W) -> io::Result<()> {
        self.val.write(writer)
    }
}

impl<P: Parameters> FromBytes for MpcGroupProjective<P> {
    fn read<R: Read>(_reader: R) -> io::Result<Self> {
        todo!()
    }
}

impl<P: Parameters> CanonicalSerialize for MpcGroupProjective<P> {
    fn serialize<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        self.val.serialize(writer)
    }

    fn serialized_size(&self) -> usize {
        todo!()
    }
}

impl<P: Parameters> CanonicalSerializeWithFlags for MpcGroupProjective<P> {
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

impl<P: Parameters> CanonicalDeserialize for MpcGroupProjective<P> {
    fn deserialize<R: Read>(_reader: R) -> Result<Self, SerializationError> {
        todo!()
    }
}

impl<P: Parameters> CanonicalDeserializeWithFlags for MpcGroupProjective<P> {
    fn deserialize_with_flags<R: Read, Fl: Flags>(
        _reader: R,
    ) -> Result<(Self, Fl), SerializationError> {
        todo!()
    }
}

impl<P: Parameters> UniformRand for MpcGroupProjective<P> {
    fn rand<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        Self {
            val: MpcGroup::rand(rng),
        }
    }
}

impl<P: Parameters> PubUniformRand for MpcGroupProjective<P> {
    fn pub_rand<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        Self {
            val: MpcGroup::pub_rand(rng),
        }
    }
}

impl<P: Parameters> AddAssign for MpcGroupProjective<P> {
    fn add_assign(&mut self, rhs: Self) {
        self.add_assign(&rhs)
    }
}

impl<'a, P: Parameters> AddAssign<&'a MpcGroupProjective<P>> for MpcGroupProjective<P> {
    fn add_assign(&mut self, rhs: &'a MpcGroupProjective<P>) {
        self.val += &rhs.val;
    }
}

impl<P: Parameters> Add for MpcGroupProjective<P> {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self.add_assign(&rhs);
        self
    }
}

impl<'a, P: Parameters> Add<&'a MpcGroupProjective<P>> for MpcGroupProjective<P> {
    type Output = Self;

    fn add(mut self, rhs: &'a MpcGroupProjective<P>) -> Self::Output {
        self.add_assign(rhs);
        self
    }
}

impl<'a, P: Parameters> SubAssign<&'a MpcGroupProjective<P>> for MpcGroupProjective<P> {
    fn sub_assign(&mut self, rhs: &'a MpcGroupProjective<P>) {
        self.val -= &rhs.val;
    }
}

impl<P: Parameters> SubAssign for MpcGroupProjective<P> {
    fn sub_assign(&mut self, rhs: Self) {
        self.sub_assign(&rhs)
    }
}

impl<P: Parameters> Sub for MpcGroupProjective<P> {
    type Output = Self;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self.sub_assign(&rhs);
        self
    }
}

impl<'a, P: Parameters> Sub<&'a MpcGroupProjective<P>> for MpcGroupProjective<P> {
    type Output = Self;

    fn sub(mut self, rhs: &'a MpcGroupProjective<P>) -> Self::Output {
        self.sub_assign(rhs);
        self
    }
}

impl<P: Parameters> MulAssign for MpcGroupProjective<P> {
    fn mul_assign(&mut self, _rhs: Self) {
        todo!()
    }
}

impl<P: Parameters> Neg for MpcGroupProjective<P> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        todo!()
    }
}

impl<P: Parameters> Sum for MpcGroupProjective<P> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), core::ops::Add::add)
    }
}

impl<'a, P: Parameters> Sum<&'a MpcGroupProjective<P>> for MpcGroupProjective<P> {
    fn sum<I: Iterator<Item = &'a MpcGroupProjective<P>>>(_iter: I) -> Self {
        todo!()
    }
}

impl<P: Parameters> Zero for MpcGroupProjective<P> {
    fn zero() -> Self {
        Self {
            val: MpcGroup::zero(),
        }
    }

    fn is_zero(&self) -> bool {
        todo!()
    }
}

impl<P: Parameters> Zeroize for MpcGroupProjective<P> {
    fn zeroize(&mut self) {
        todo!()
    }
}

impl<P: Parameters> Default for MpcGroupProjective<P> {
    fn default() -> Self {
        todo!()
    }
}

impl<P: Parameters> MpcWire for MpcGroupProjective<P> {
    #[inline]
    fn publicize(&mut self) {
        self.val.publicize();
    }
    #[inline]
    fn is_shared(&self) -> bool {
        self.val.is_shared()
    }
}

impl<P: Parameters> MulAssign<MpcField<P::ScalarField, AdditiveFieldShare<P::ScalarField>>>
    for MpcGroupProjective<P>
{
    fn mul_assign(&mut self, _rhs: MpcField<P::ScalarField, AdditiveFieldShare<P::ScalarField>>) {
        todo!()
    }
}

impl<P: Parameters> ProjectiveCurve for MpcGroupProjective<P>
where
    P::BaseField: PrimeField,
{
    const COFACTOR: &'static [u64] = GroupProjective::<P>::COFACTOR;

    type ScalarField = MpcField<P::ScalarField, AdditiveFieldShare<P::ScalarField>>;

    type BaseField = MpcField<P::BaseField, AdditiveFieldShare<P::BaseField>>;

    type Affine = MpcGroupAffine<P>;

    fn prime_subgroup_generator() -> Self {
        MpcGroupAffine::prime_subgroup_generator().into()
    }

    fn batch_normalization(v: &mut [Self]) {
        todo!()
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
                MpcGroup::Shared(AdditiveAffProjShare::add_sh_proj_sh_aff(a.clone(), b))
            }
            (MpcGroup::Shared(a), MpcGroup::Public(b)) => {
                MpcGroup::Shared(AdditiveAffProjShare::add_sh_proj_pub_aff(a.clone(), b))
            }
            (MpcGroup::Public(a), MpcGroup::Shared(b)) => {
                MpcGroup::Shared(AdditiveAffProjShare::add_pub_proj_sh_aff(a, b.clone()))
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

impl<P: Parameters> Reveal for MpcGroupAffine<P> {
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

impl<P: Parameters> Display for MpcGroupAffine<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.val)
    }
}

impl<P: Parameters> ToBytes for MpcGroupAffine<P> {
    fn write<W: Write>(&self, writer: W) -> io::Result<()> {
        self.val.write(writer)
    }
}

impl<P: Parameters> FromBytes for MpcGroupAffine<P> {
    fn read<R: Read>(_reader: R) -> io::Result<Self> {
        todo!()
    }
}

impl<P: Parameters> CanonicalSerialize for MpcGroupAffine<P> {
    fn serialize<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        self.val.serialize(writer)
    }

    fn serialized_size(&self) -> usize {
        todo!()
    }
}

impl<P: Parameters> CanonicalSerializeWithFlags for MpcGroupAffine<P> {
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

impl<P: Parameters> CanonicalDeserialize for MpcGroupAffine<P> {
    fn deserialize<R: Read>(_reader: R) -> Result<Self, SerializationError> {
        todo!()
    }
}

impl<P: Parameters> CanonicalDeserializeWithFlags for MpcGroupAffine<P> {
    fn deserialize_with_flags<R: Read, Fl: Flags>(
        _reader: R,
    ) -> Result<(Self, Fl), SerializationError> {
        todo!()
    }
}

impl<P: Parameters> UniformRand for MpcGroupAffine<P> {
    fn rand<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        Self {
            val: MpcGroup::rand(rng),
        }
    }
}

impl<P: Parameters> PubUniformRand for MpcGroupAffine<P> {
    fn pub_rand<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        Self {
            val: MpcGroup::pub_rand(rng),
        }
    }
}

impl<P: Parameters> AddAssign for MpcGroupAffine<P> {
    fn add_assign(&mut self, rhs: Self) {
        self.add_assign(&rhs)
    }
}

impl<'a, P: Parameters> AddAssign<&'a MpcGroupAffine<P>> for MpcGroupAffine<P> {
    fn add_assign(&mut self, rhs: &'a MpcGroupAffine<P>) {
        self.val += &rhs.val;
    }
}

impl<P: Parameters> Add for MpcGroupAffine<P> {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self.add_assign(&rhs);
        self
    }
}

impl<'a, P: Parameters> Add<&'a MpcGroupAffine<P>> for MpcGroupAffine<P> {
    type Output = Self;

    fn add(mut self, rhs: &'a MpcGroupAffine<P>) -> Self::Output {
        self.add_assign(rhs);
        self
    }
}

impl<'a, P: Parameters> SubAssign<&'a MpcGroupAffine<P>> for MpcGroupAffine<P> {
    fn sub_assign(&mut self, rhs: &'a MpcGroupAffine<P>) {
        self.val -= &rhs.val;
    }
}

impl<P: Parameters> SubAssign for MpcGroupAffine<P> {
    fn sub_assign(&mut self, rhs: Self) {
        self.sub_assign(&rhs)
    }
}

impl<P: Parameters> Sub for MpcGroupAffine<P> {
    type Output = Self;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self.sub_assign(&rhs);
        self
    }
}

impl<'a, P: Parameters> Sub<&'a MpcGroupAffine<P>> for MpcGroupAffine<P> {
    type Output = Self;

    fn sub(mut self, rhs: &'a MpcGroupAffine<P>) -> Self::Output {
        self.sub_assign(rhs);
        self
    }
}

impl<P: Parameters> MulAssign for MpcGroupAffine<P> {
    fn mul_assign(&mut self, _rhs: Self) {
        todo!()
    }
}

impl<P: Parameters> Neg for MpcGroupAffine<P> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        todo!()
    }
}

impl<P: Parameters> Sum for MpcGroupAffine<P> {
    fn sum<I: Iterator<Item = Self>>(_iter: I) -> Self {
        todo!()
    }
}

impl<'a, P: Parameters> Sum<&'a MpcGroupAffine<P>> for MpcGroupAffine<P> {
    fn sum<I: Iterator<Item = &'a MpcGroupAffine<P>>>(_iter: I) -> Self {
        todo!()
    }
}

impl<P: Parameters> Zero for MpcGroupAffine<P> {
    fn zero() -> Self {
        Self {
            val: MpcGroup::zero(),
        }
    }

    fn is_zero(&self) -> bool {
        todo!()
    }
}

impl<P: Parameters> Zeroize for MpcGroupAffine<P> {
    fn zeroize(&mut self) {
        todo!()
    }
}

impl<P: Parameters> Default for MpcGroupAffine<P> {
    fn default() -> Self {
        todo!()
    }
}

impl<P: Parameters> MpcWire for MpcGroupAffine<P> {
    #[inline]
    fn publicize(&mut self) {
        self.val.publicize();
    }
    #[inline]
    fn is_shared(&self) -> bool {
        self.val.is_shared()
    }
}

impl<P: Parameters> MulAssign<MpcField<P::ScalarField, AdditiveFieldShare<P::ScalarField>>>
    for MpcGroupAffine<P>
{
    fn mul_assign(&mut self, rhs: MpcField<P::ScalarField, AdditiveFieldShare<P::ScalarField>>) {
        todo!()
    }
}

impl<P: Parameters> AffineCurve for MpcGroupAffine<P>
where
    P::BaseField: PrimeField,
{
    const COFACTOR: &'static [u64] = P::COFACTOR;

    type ScalarField = MpcField<P::ScalarField, AdditiveFieldShare<P::ScalarField>>;

    type BaseField = MpcField<P::BaseField, AdditiveFieldShare<P::BaseField>>;

    type Projective = MpcGroupProjective<P>;

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

    fn mul<S: Into<<Self::ScalarField as ark_ff::prelude::PrimeField>::BigInt>>(
        &self,
        other: S,
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
                                MpcGroup::Shared(<ProjectiveShare<P> as Reveal>::from_public(r));
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
                        val: MpcGroup::Shared(AdditiveAffProjShare::sh_aff_to_proj(
                            <AffineShare<P> as GroupShare<GroupAffine<P>>>::multi_scale_pub_group(
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
}

type FrShare<P: Parameters> = AdditiveFieldShare<P::ScalarField>;
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

impl<P: Parameters> From<MpcGroupAffine<P>> for MpcGroupProjective<P> {
    fn from(p: MpcGroupAffine<P>) -> MpcGroupProjective<P> {
        // Self::new(p.x, p.y, p.x * &p.y, P::BaseField::one())
        Self {
            val: p
                .val
                .map(|s| s.into(), AdditiveAffProjShare::sh_aff_to_proj),
        }
    }
}

impl<P: Parameters> From<MpcGroupProjective<P>> for MpcGroupAffine<P> {
    fn from(p: MpcGroupProjective<P>) -> MpcGroupAffine<P> {
        Self {
            val: p
                .val
                .map(|s| s.into(), AdditiveAffProjShare::sh_proj_to_aff),
        }
    }
}
