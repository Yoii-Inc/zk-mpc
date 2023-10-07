use ark_ff::prelude::*;
use ark_ff::{Field, ToBytes};
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags,
};
use std::fmt::{Debug, Display};
use std::hash::Hash;

pub trait FieldShare<F: Field>:
    Clone
    + Copy
    + Display
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
    fn add(&mut self, other: &Self) -> &mut Self;

    fn sub(&mut self, other: &Self) -> &mut Self {
        let mut t = other.clone();
        t.neg();
        t.add(&self);
        *self = t;
        self
    }

    fn neg(&mut self) -> &mut Self {
        self.scale(&-<F as ark_ff::One>::one())
    }

    fn shift(&mut self, other: &F) -> &mut Self;

    fn scale(&mut self, other: &F) -> &mut Self;

    fn univariate_div_qr<'a>(
        _num: DenseOrSparsePolynomial<Self>,
        _den: DenseOrSparsePolynomial<F>,
    ) -> Option<(DensePolynomial<Self>, DensePolynomial<Self>)> {
        todo!("Implement generic poly div")
    }
}

pub type DensePolynomial<T> = Vec<T>;
pub type SparsePolynomial<T> = Vec<(usize, T)>;
pub type DenseOrSparsePolynomial<T> = Result<DensePolynomial<T>, SparsePolynomial<T>>;

pub trait ExtFieldShare<F: Field>: Clone + Copy + Debug + 'static {
    type Base: FieldShare<F::BasePrimeField>;
    type Ext: FieldShare<F>;
}
