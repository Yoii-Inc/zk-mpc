use ark_ec::group::Group;
use ark_ff::prelude::*;
use ark_ff::ToBytes;
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags,
};
use std::fmt::Debug;
use std::hash::Hash;

use crate::BeaverSource;
use crate::Reveal;

use super::field::FieldShare;

pub trait GroupShare<G: Group>:
    Clone
    + Copy
    + Debug
    + Send
    + Sync
    + Eq
    + Hash
    + CanonicalSerialize
    + CanonicalDeserialize
    + CanonicalSerializeWithFlags
    + CanonicalDeserializeWithFlags
    + UniformRand
    + ToBytes
    + 'static
    + Reveal<Base = G>
{
    type FieldShare: FieldShare<G::ScalarField>;

    fn map_homo<G2: Group, S2: GroupShare<G2>, Fun: Fn(G) -> G2>(self, f: Fun) -> S2 {
        S2::from_add_shared(f(self.unwrap_as_public()))
    }

    fn add(&mut self, other: &Self) -> &mut Self;

    fn shift(&mut self, other: &G) -> &mut Self;
}

// pub trait GroupAffineShare<G: AffineCurve>:
//     Clone
//     + Copy
//     + Debug
//     + Send
//     + Sync
//     + Hash
//     + Ord
//     + CanonicalSerialize
//     + CanonicalDeserialize
//     + CanonicalSerializeWithFlags
//     + CanonicalDeserializeWithFlags
//     + UniformRand
//     + ToBytes
//     + 'static
// {
// }
