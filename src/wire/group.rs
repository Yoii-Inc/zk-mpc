use ark_ec::group::Group;

use crate::share::group::GroupShare;

pub enum MpcGroup<G: Group, S: GroupShare<G>> {
    Public(G),
    Shared(S),
}
