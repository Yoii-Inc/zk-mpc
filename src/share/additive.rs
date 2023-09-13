use std::marker::PhantomData;

use ark_ec::{group::Group, PairingEngine};
use ark_ff::Field;

pub struct AdditiveFieldShare<F: Field> {
    _phantom: PhantomData<F>,
}

pub struct AdditiveGroupShare<G: Group> {
    _phantom: PhantomData<G>,
}

pub struct AdditivePairingShare<E: PairingEngine> {
    _phantom: PhantomData<E>,
}
