use ark_ec::{group::Group, AffineCurve};

use crate::share::group::GroupShare;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum MpcGroup<G: Group, S: GroupShare<G>> {
    Public(G),
    Shared(S),
}

// #[derive(Copy, Clone)]
// pub enum MpcGroupAffine<G: AffineCurve, S: GroupAffineShare<G>> {
//     Public(G),
//     Shared(S),
// }
