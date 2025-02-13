use ark_ff::prelude::*;
use ark_ff::{Field, ToBytes};
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags,
};
use core::panic;
use futures::future::join_all;
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
    async fn open(&self) -> F {
        <Self as Reveal>::reveal(*self).await
    }

    fn map_homo<FF: Field, SS: FieldShare<FF>, Fun: Fn(F) -> FF>(self, f: Fun) -> SS {
        SS::from_add_shared(f(self.unwrap_as_public()))
    }

    async fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<F> {
        join_all(selfs.into_iter().map(|s| async move { s.open().await })).await
    }

    fn add(&mut self, other: &Self) -> &mut Self;

    fn sub(&mut self, other: &Self) -> &mut Self {
        let mut t = *other;
        t.neg();
        t.add(self);
        *self = t;
        self
    }

    fn neg(&mut self) -> &mut Self {
        self.scale(&-<F as ark_ff::One>::one())
    }

    fn shift(&mut self, other: &F) -> &mut Self;

    fn scale(&mut self, other: &F) -> &mut Self;

    async fn beaver_mul<S: BeaverSource<Self, Self, Self>>(
        self,
        other: Self,
        source: &mut S,
    ) -> Self {
        let (mut x, mut y, z) = source.triple();

        let s = self;
        let o = other;

        let sx = {
            let mut t = s;
            t.add(&x).open().await
        };

        let oy = {
            let mut t = o;
            t.add(&y).open().await
        };

        let mut result = z;
        result.sub(y.scale(&sx)).sub(x.scale(&oy)).shift(&(sx * oy));
        #[cfg(debug_assertions)]
        {
            let a = s.reveal().await;
            let b = o.reveal().await;
            let r = result.reveal().await;
            if a * b != r {
                // println!("Bad multiplication!.\n{}\n*\n{}\n=\n{}", a, b, r);
                panic!("Bad multiplication");
            }
        }
        result
    }

    async fn batch_mul<S: BeaverSource<Self, Self, Self>>(
        xs: Vec<Self>,
        ys: Vec<Self>,
        source: &mut S,
    ) -> Vec<Self> {
        let ss = xs;
        let os = ys;
        let (xs, ys, zs) = source.triples(ss.len());
        // output: z - open(s + x)y - open(o + y)x + open(s + x)open(o + y)
        //         xy - sy - xy - ox - yx + so + sy + xo + xy
        //         so
        let sxs = Self::batch_open(ss.into_iter().zip(xs.iter()).map(|(mut s, x)| {
            s.add(x);
            s
        }))
        .await;
        let oys = Self::batch_open(os.into_iter().zip(ys.iter()).map(|(mut o, y)| {
            o.add(y);
            o
        }))
        .await;
        zs.into_iter()
            .zip(ys.into_iter())
            .zip(xs.into_iter())
            .enumerate()
            .map(|(i, ((mut z, mut y), mut x))| {
                z.sub(y.scale(&sxs[i]))
                    .sub(x.scale(&oys[i]))
                    .shift(&(sxs[i] * oys[i]));
                z
            })
            .collect()
    }

    async fn inv<S: BeaverSource<Self, Self, Self>>(self, source: &mut S) -> Self {
        let (x, mut y) = source.inv_pair();
        let xa = x
            .beaver_mul(self, source)
            .await
            .open()
            .await
            .inverse()
            .unwrap();
        *y.scale(&xa)
    }

    async fn batch_inv<S: BeaverSource<Self, Self, Self>>(
        xs: Vec<Self>,
        source: &mut S,
    ) -> Vec<Self> {
        let (bs, cs) = source.inv_pairs(xs.len());
        cs.into_iter()
            .zip(
                Self::batch_open(Self::batch_mul(xs, bs, source).await)
                    .await
                    .into_iter()
                    .map(|i| i.inverse().unwrap()),
            )
            .map(|(mut c, i)| {
                c.scale(&i);
                c
            })
            .collect()
    }

    async fn beaver_div<S: BeaverSource<Self, Self, Self>>(
        self,
        other: Self,
        source: &mut S,
    ) -> Self {
        let o_inv = other.inv(source).await;
        self.beaver_mul(o_inv, source).await
    }

    async fn batch_div<S: BeaverSource<Self, Self, Self>>(
        xs: Vec<Self>,
        ys: Vec<Self>,
        source: &mut S,
    ) -> Vec<Self> {
        Self::batch_mul(xs, Self::batch_inv(ys, source).await, source).await
    }

    fn univariate_div_qr<'a>(
        _num: DenseOrSparsePolynomial<Self>,
        _den: DenseOrSparsePolynomial<F>,
    ) -> Option<(DensePolynomial<Self>, DensePolynomial<Self>)> {
        todo!("Implement generic poly div")
    }

    fn modulus_conversion<F2: PrimeField, S2: FieldShare<F2>>(&mut self) -> S2
    where
        F: PrimeField,
    {
        todo!()
    }
}

pub type DensePolynomial<T> = Vec<T>;
pub type SparsePolynomial<T> = Vec<(usize, T)>;
pub type DenseOrSparsePolynomial<T> = Result<DensePolynomial<T>, SparsePolynomial<T>>;

pub trait ExtFieldShare<F: Field>: Clone + Copy + Debug + 'static {
    type Base: FieldShare<F::BasePrimeField>;
    type Ext: FieldShare<F>;
}
