use ark_ff::prelude::*;
use ark_ff::{Field, ToBytes};
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags,
};
use std::fmt::Debug;
use std::hash::Hash;

pub trait FieldShare<F: Field>:
    Clone
    + Copy
    + Debug
    + Send
    + Sync
    + Hash
    + Ord
    + CanonicalSerialize
    + CanonicalDeserialize
    + CanonicalSerializeWithFlags
    + CanonicalDeserializeWithFlags
    + UniformRand
    + ToBytes
    + 'static
{
}

pub trait ExtFieldShare<F: Field>: Clone + Copy + Debug + 'static {
    type Base: FieldShare<F::BasePrimeField>;
    type Ext: FieldShare<F>;
}
