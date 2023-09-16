use ark_ec::{group::Group, AffineCurve};

use crate::share::group::{GroupAffineShare, GroupShare};

pub enum MpcGroup<G: Group, S: GroupShare<G>> {
    Public(G),
    Shared(S),
}

pub enum MpcGroupAffine<G: AffineCurve, S: GroupAffineShare<G>> {
    Public(G),
    Shared(S),
}
