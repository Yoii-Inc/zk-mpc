use ark_ec::group::Group;
use ark_ff::prelude::*;
use ark_ff::ToBytes;
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags,
};
use std::fmt::Debug;
use std::hash::Hash;

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
{
    type FieldShare: FieldShare<G::ScalarField>;
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
