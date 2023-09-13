use std::marker::PhantomData;

use ark_ec::{group::Group, PairingEngine};
use ark_ff::Field;

use crate::reveal::Reveal;

pub struct AdditiveFieldShare<T> {
    pub val: T,
}

impl<F: Field> Reveal for AdditiveFieldShare<F> {
    type Base = F;

    fn reveal(&self) -> Self::Base {
        todo!()
    }
}

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
