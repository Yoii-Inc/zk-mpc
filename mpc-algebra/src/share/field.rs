use ark_ff::prelude::*;
use ark_ff::{Field, ToBytes};
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags,
};
use core::panic;
use std::fmt::{Debug, Display};
use std::hash::Hash;

use crate::{BeaverSource, Reveal};

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
    + Reveal<Base = F>
{
    fn open(&self) -> F {
        <Self as Reveal>::reveal(*self)
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
        self.scale(&-<F as ark_ff::One>::one())
    }

    fn shift(&mut self, other: &F) -> &mut Self;

    fn scale(&mut self, other: &F) -> &mut Self;

    fn mul<S: BeaverSource<Self, Self, Self>>(self, other: Self, source: &mut S) -> Self {
        let (mut x, mut y, z) = source.triple();

        let s = self;
        let o = other;

        let sx = {
            let mut t = s;
            t.add(&x).open()
        };

        let oy = {
            let mut t = o;
            t.add(&y).open()
        };

        let mut result = z;
        result.sub(y.scale(&sx)).sub(x.scale(&oy)).shift(&(sx * oy));
        #[cfg(debug_assertions)]
        {
            let a = s.reveal();
            let b = o.reveal();
            let r = result.reveal();
            if a * b != r {
                // println!("Bad multiplication!.\n{}\n*\n{}\n=\n{}", a, b, r);
                panic!("Bad multiplication");
            }
        }
        result
    }

    fn inv<S: BeaverSource<Self, Self, Self>>(self, source: &mut S) -> Self {
        let (x, mut y) = source.inv_pair();
        let xa = x.mul(self, source).open().inverse().unwrap();
        *y.scale(&xa)
    }

    fn div<S: BeaverSource<Self, Self, Self>>(self, other: Self, source: &mut S) -> Self {
        let o_inv = other.inv(source);
        self.mul(o_inv, source)
    }

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
