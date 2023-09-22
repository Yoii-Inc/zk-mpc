use ark_ec::{group::Group, AffineCurve, PairingEngine, ProjectiveCurve};

use super::{
    field::{ExtFieldShare, FieldShare},
    group::GroupShare,
};

use std::{fmt::Debug, ops::MulAssign};

pub trait ExtendedPairingEngine: PairingEngine {
    type GroupedG1Projective: ProjectiveCurve<
            BaseField = Self::Fq,
            ScalarField = Self::Fr,
            Affine = Self::GroupedG1Affine,
        > + From<Self::GroupedG1Affine>
        + Into<Self::GroupedG1Affine>
        + MulAssign<Self::Fr>
        // needed due to https://github.com/rust-lang/rust/issues/69640
        + Group<ScalarField = Self::Fr>;

    type GroupedG1Affine: AffineCurve<
            BaseField = Self::Fq,
            ScalarField = Self::Fr,
            Projective = Self::GroupedG1Projective,
        > + From<Self::GroupedG1Projective>
        + Into<Self::GroupedG1Projective>
        + Into<Self::G1Prepared>
        + Group<ScalarField = Self::Fr>;

    type GroupedG2Projective: ProjectiveCurve<
            BaseField = Self::Fqe,
            ScalarField = Self::Fr,
            Affine = Self::GroupedG2Affine,
        > + From<Self::GroupedG2Affine>
        + Into<Self::GroupedG2Affine>
        + MulAssign<Self::Fr>
        // needed due to https://github.com/rust-lang/rust/issues/69640
        + Group<ScalarField = Self::Fr>;

    type GroupedG2Affine: AffineCurve<
            BaseField = Self::Fqe,
            ScalarField = Self::Fr,
            Projective = Self::GroupedG2Projective,
        > + From<Self::GroupedG2Projective>
        + Into<Self::GroupedG2Projective>
        + Into<Self::G2Prepared>
        + Group<ScalarField = Self::Fr>;
}

pub trait PairingShare<E: ExtendedPairingEngine>:
    Clone + Copy + Debug + 'static + Send + Sync + PartialEq + Eq
{
    type FrShare: FieldShare<E::Fr>;
    type FqShare: FieldShare<E::Fq>;
    type FqeShare: ExtFieldShare<E::Fqe>;

    // warning: maybe wrong
    type FqkShare: ExtFieldShare<E::Fqk>;

    // type hoge: E::G1Affine;

    type G1AffineShare: GroupShare<E::GroupedG1Affine>;
    type G2AffineShare: GroupShare<E::GroupedG2Affine>;
    type G1ProjectiveShare: GroupShare<E::GroupedG1Projective>;
    type G2ProjectiveShare: GroupShare<E::GroupedG2Projective>;
}
