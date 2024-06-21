use ark_ec::{group::Group, AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::Field;

use super::{
    field::{ExtFieldShare, FieldShare},
    group::GroupShare,
};

use std::fmt::Debug;

// pub trait ExtendedPairingEngine: PairingEngine {
//     type GroupedG1Projective: ProjectiveCurve<
//             BaseField = Self::Fq,
//             ScalarField = Self::Fr,
//             Affine = Self::GroupedG1Affine,
//         > + From<Self::GroupedG1Affine>
//         + Into<Self::GroupedG1Affine>
//         + MulAssign<Self::Fr>
//         // needed due to https://github.com/rust-lang/rust/issues/69640
//         + Group<ScalarField = Self::Fr>;

//     type GroupedG1Affine: AffineCurve<
//             BaseField = Self::Fq,
//             ScalarField = Self::Fr,
//             Projective = Self::GroupedG1Projective,
//         > + From<Self::GroupedG1Projective>
//         + Into<Self::GroupedG1Projective>
//         + Into<Self::G1Prepared>
//         + Group<ScalarField = Self::Fr>;

//     type GroupedG2Projective: ProjectiveCurve<
//             BaseField = Self::Fqe,
//             ScalarField = Self::Fr,
//             Affine = Self::GroupedG2Affine,
//         > + From<Self::GroupedG2Affine>
//         + Into<Self::GroupedG2Affine>
//         + MulAssign<Self::Fr>
//         // needed due to https://github.com/rust-lang/rust/issues/69640
//         + Group<ScalarField = Self::Fr>;

//     type GroupedG2Affine: AffineCurve<
//             BaseField = Self::Fqe,
//             ScalarField = Self::Fr,
//             Projective = Self::GroupedG2Projective,
//         > + From<Self::GroupedG2Projective>
//         + Into<Self::GroupedG2Projective>
//         + Into<Self::G2Prepared>
//         + Group<ScalarField = Self::Fr>;
// }

pub trait GroupedAffine<C: AffineCurve> {}

impl<C: AffineCurve> GroupedAffine<C> for C {}

pub trait GroupedProjective<C: ProjectiveCurve> {}

pub trait AffProjShare<
    Fr: Field,
    A: AffineCurve<ScalarField = Fr> + Group,
    P: ProjectiveCurve<Affine = A>,
>: 'static
{
    type FrShare: FieldShare<Fr>;
    type AffineShare: GroupShare<A, FieldShare = Self::FrShare>;
    type ProjectiveShare: GroupShare<P, FieldShare = Self::FrShare>;

    fn sh_aff_to_proj(g: Self::AffineShare) -> Self::ProjectiveShare;
    fn sh_proj_to_aff(g: Self::ProjectiveShare) -> Self::AffineShare;

    fn add_sh_proj_sh_aff(
        _a: Self::ProjectiveShare,
        _o: &Self::AffineShare,
    ) -> Self::ProjectiveShare {
        unimplemented!()
    }
    fn add_sh_proj_pub_aff(_a: Self::ProjectiveShare, _o: &A) -> Self::ProjectiveShare {
        unimplemented!()
    }
    fn add_pub_proj_sh_aff(_a: &P, _o: Self::AffineShare) -> Self::ProjectiveShare {
        unimplemented!()
    }
}

pub trait PairingShare<E: PairingEngine>:
    Clone + Copy + Debug + 'static + Send + Sync + PartialEq + Eq
{
    type FrShare: FieldShare<E::Fr>;
    type FqShare: FieldShare<E::Fq>;
    type FqeShare: ExtFieldShare<E::Fqe>;

    // warning: maybe wrong
    type FqkShare: ExtFieldShare<E::Fqk>;

    type G1AffineShare: GroupShare<E::G1Affine, FieldShare = Self::FrShare>;
    type G2AffineShare: GroupShare<E::G2Affine, FieldShare = Self::FrShare>;
    type G1ProjectiveShare: GroupShare<E::G1Projective, FieldShare = Self::FrShare>;
    type G2ProjectiveShare: GroupShare<E::G2Projective, FieldShare = Self::FrShare>;

    type G1: AffProjShare<
        E::Fr,
        E::G1Affine,
        E::G1Projective,
        FrShare = Self::FrShare,
        AffineShare = Self::G1AffineShare,
        ProjectiveShare = Self::G1ProjectiveShare,
    >;
    type G2: AffProjShare<
        E::Fr,
        E::G2Affine,
        E::G2Projective,
        FrShare = Self::FrShare,
        AffineShare = Self::G2AffineShare,
        ProjectiveShare = Self::G2ProjectiveShare,
    >;
}
