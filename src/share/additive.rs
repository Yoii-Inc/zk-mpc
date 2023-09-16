use std::marker::PhantomData;

use ark_ec::{group::Group, PairingEngine};
use ark_ff::{Field, FromBytes, ToBytes};
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags,
};
use ark_std::UniformRand;

use crate::reveal::Reveal;

use super::{field::FieldShare, pairing::PairingShare};

#[derive(Clone, Copy, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AdditiveFieldShare<T> {
    pub val: T,
}

impl<F: Field> Reveal for AdditiveFieldShare<F> {
    type Base = F;

    fn reveal(&self) -> Self::Base {
        todo!()
    }
}

impl<F: Field> FieldShare<F> for AdditiveFieldShare<F> {}

impl<F: Field> ToBytes for AdditiveFieldShare<F> {}

impl<F: Field> FromBytes for AdditiveFieldShare<F> {}

impl<F: Field> CanonicalSerialize for AdditiveFieldShare<F> {}

impl<F: Field> CanonicalSerializeWithFlags for AdditiveFieldShare<F> {}

impl<F: Field> CanonicalDeserialize for AdditiveFieldShare<F> {}

impl<F: Field> CanonicalDeserializeWithFlags for AdditiveFieldShare<F> {}

impl<F: Field> UniformRand for AdditiveFieldShare<F> {}

pub struct AdditiveExtFieldShare<F: Field>(pub PhantomData<F>);

pub struct MulExtFieldShare<F: Field>(pub PhantomData<F>);

pub struct AdditiveGroupShare<T> {
    pub val: T,
}

impl<G: Group> Reveal for AdditiveGroupShare<G> {
    type Base = G;

    fn reveal(&self) -> Self::Base {
        todo!()
    }
}

pub struct AdditivePairingShare<E: PairingEngine>(pub PhantomData<E>);

impl<E: PairingEngine> PairingShare<E> for AdditivePairingShare<E> {
    type FrShare = AdditiveFieldShare<E::Fr>;
    type FqShare = AdditiveFieldShare<E::Fq>;
    type FqeShare = AdditiveExtFieldShare<E::Fqe>;
    // Not a typo. We want a multiplicative subgroup.
    type FqkShare = MulExtFieldShare<E::Fqk>;
    type G1AffineShare = AdditiveGroupShare<E::G1Affine>;
    type G2AffineShare = AdditiveGroupShare<E::G2Affine>;
    type G1ProjectiveShare = AdditiveGroupShare<E::G1Projective>;
    type G2ProjectiveShare = AdditiveGroupShare<E::G2Projective>;
}
