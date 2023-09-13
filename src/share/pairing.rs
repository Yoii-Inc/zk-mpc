use ark_ec::PairingEngine;

use super::{
    field::{ExtFieldShare, FieldShare},
    group::GroupShare,
};

pub trait PairingShare<E: PairingEngine> {
    type FqShare: FieldShare<E::Fq>;
    type FqeShare: ExtFieldShare<E::Fqe>;

    // warning: maybe wrong
    type FqkShare: ExtFieldShare<E::Fqk>;

    type G1AffineShare: GroupShare<E::G1Affine>;
    type G2AffineShare: GroupShare<E::G2Affine>;
    type G1ProjectiveShare: GroupShare<E::G1Projective>;
    type G2ProjectiveShare: GroupShare<E::G2Projective>;
}
