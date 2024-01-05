use ark_ec::group::Group;
use ark_ff::prelude::*;
use ark_ff::ToBytes;
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags,
};
use std::fmt::Debug;
use std::hash::Hash;

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

    fn open(&self) -> G {
        <Self as Reveal>::reveal(*self)
    }

    fn map_homo<G2: Group, S2: GroupShare<G2>, Fun: Fn(G) -> G2>(self, f: Fun) -> S2 {
        S2::from_add_shared(f(self.unwrap_as_public()))
    }

    fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<G> {
        selfs.into_iter().map(|s| s.open()).collect()
    }

    fn add(&mut self, other: &Self) -> &mut Self;

    fn sub(&mut self, other: &Self) -> &mut Self {
        let mut t = other.clone();
        t.neg();
        t.add(&self);
        *self = t;
        self
    }

    fn neg(&mut self) -> &mut Self {
        self.scale_pub_scalar(&-<G::ScalarField as ark_ff::One>::one())
    }

    fn scale_pub_scalar(&mut self, scalar: &G::ScalarField) -> &mut Self;

    fn scale_pub_group(base: G, scalar: &Self::FieldShare) -> Self;

    fn shift(&mut self, other: &G) -> &mut Self;

    /// Compute \sum_i (s_i * g_i)
    /// where the s_i are shared and the g_i are public.
    fn multi_scale_pub_group(bases: &[G], scalars: &[Self::FieldShare]) -> Self {
        bases
            .iter()
            .zip(scalars.iter())
            .map(|(g, s)| Self::scale_pub_group(*g, s))
            .fold(Self::from_public(G::zero()), |mut acc, n| {
                acc.add(&n);
                acc
            })
    }
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
