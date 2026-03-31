use crate::{BitAdd, BitwiseLessThan, FieldShare, MpcField, Reveal, UniformBitRand};
use ark_ff::{
    BigInteger, Field, FpParameters, One, PrimeField, SquareRootField, UniformRand, Zero,
};
use core::panic;
use mpc_trait::MpcWire;
use rand::Rng;
use std::ops::{BitAnd, BitOr, BitXor, Not};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct MpcBooleanField<F: Field, S: FieldShare<F>>(MpcField<F, S>);

pub trait BooleanWire: Clone + Copy + Not<Output = Self> + From<bool> {
    type Base;

    fn pub_true() -> Self;
    fn pub_false() -> Self;
    fn field(&self) -> Self::Base;
    fn and(self, other: Self) -> Self;
    fn or(self, other: Self) -> Self;
    fn xor(self, other: Self) -> Self;
}

impl<F: Field, S: FieldShare<F>> BooleanWire for MpcBooleanField<F, S> {
    type Base = MpcField<F, S>;

    fn pub_true() -> Self {
        Self(MpcField::one())
    }

    fn pub_false() -> Self {
        Self(MpcField::zero())
    }

    fn field(&self) -> MpcField<F, S> {
        self.0
    }

    fn and(self, other: Self) -> Self {
        Self(self.0 * other.0)
    }
    fn or(self, other: Self) -> Self {
        Self(self.0 + other.0 - (self.0 * other.0))
    }

    fn xor(self, other: Self) -> Self {
        Self(self.0 + other.0 - (self.0 * other.0 * MpcField::from(2u8)))
    }
}

impl<F: Field, S: FieldShare<F>> Not for MpcBooleanField<F, S> {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self(MpcField::one() - self.0)
    }
}

impl<F: Field, S: FieldShare<F>> BitAnd for MpcBooleanField<F, S> {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        self.and(rhs)
    }
}

impl<F: Field, S: FieldShare<F>> BitOr for MpcBooleanField<F, S> {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        self.or(rhs)
    }
}

impl<F: Field, S: FieldShare<F>> BitXor for MpcBooleanField<F, S> {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        self.xor(rhs)
    }
}

// from MpcBooleanField to MpcField
impl<F: Field, S: FieldShare<F>> From<MpcBooleanField<F, S>> for MpcField<F, S> {
    fn from(b: MpcBooleanField<F, S>) -> Self {
        b.0
    }
}

// from MpcField to MpcBooleanField
impl<F: Field, S: FieldShare<F>> From<MpcField<F, S>> for MpcBooleanField<F, S> {
    fn from(f: MpcField<F, S>) -> Self {
        Self(f)
    }
}

// from bool to MpcBooleanField
impl<F: Field, S: FieldShare<F>> From<bool> for MpcBooleanField<F, S> {
    fn from(b: bool) -> Self {
        if b {
            Self::pub_true()
        } else {
            Self::pub_false()
        }
    }
}

impl<F: PrimeField, S: FieldShare<F>> BitwiseLessThan for Vec<MpcBooleanField<F, S>> {
    type Output = MpcBooleanField<F, S>;

    fn is_smaller_than_le(&self, other: &Self) -> Self::Output {
        let modulus_size = F::Params::MODULUS_BITS as usize;
        assert_eq!(self.len(), modulus_size);
        assert_eq!(other.len(), modulus_size);

        // c_i = a_i xor b_i, computed with batched products.
        let c = MpcBooleanField::<F, S>::batch_xor(self, other);
        let mut d = c.into_iter().rev().collect::<Vec<_>>();

        // Prefix-OR on reversed bits using a parallel-prefix schedule.
        // This reduces the interaction depth from O(n) to O(log n).
        let mut offset = 1usize;
        while offset < modulus_size {
            let mut lhs = Vec::with_capacity(modulus_size - offset);
            let mut rhs = Vec::with_capacity(modulus_size - offset);
            let mut idx = Vec::with_capacity(modulus_size - offset);
            for i in offset..modulus_size {
                lhs.push(d[i]);
                rhs.push(d[i - offset]);
                idx.push(i);
            }
            let ors = MpcBooleanField::<F, S>::batch_or(&lhs, &rhs);
            for (i, v) in idx.into_iter().zip(ors.into_iter()) {
                d[i] = v;
            }
            offset <<= 1;
        }
        d.reverse();

        let e = (0..modulus_size)
            .map(|i| {
                if i == modulus_size - 1 {
                    d[modulus_size - 1].field()
                } else {
                    d[i].field() - d[i + 1].field()
                }
            })
            .collect::<Vec<MpcField<F, S>>>();

        let mut prod = e;
        let other_fields = other.iter().map(|b| b.field()).collect::<Vec<_>>();
        <MpcField<F, S> as Field>::batch_product_in_place(&mut prod, &other_fields);
        Self::Output::from(prod.into_iter().sum::<MpcField<F, S>>())
    }
}

impl<F: PrimeField + SquareRootField, S: FieldShare<F>> UniformBitRand for MpcBooleanField<F, S> {
    type BaseField = MpcField<F, S>;

    async fn bit_rand<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        Self::rand_bits_batched_internal(rng, 1).await[0]
    }

    async fn rand_number_bitwise<R: Rng + ?Sized>(rng: &mut R) -> (Vec<Self>, Self::BaseField) {
        let modulus_size = F::Params::MODULUS_BITS as usize;

        let mut modulus_bits = F::Params::MODULUS
            .to_bits_le()
            .iter()
            .map(|&b| Self::from(b))
            .collect::<Vec<_>>();

        modulus_bits = modulus_bits[..modulus_size].to_vec();

        let valid_bits = loop {
            let bits = Self::rand_bits_batched_internal(rng, modulus_size).await;
            if bits
                .is_smaller_than_le(&modulus_bits)
                .field()
                .reveal()
                .await
                .is_one()
            {
                break bits;
            }
        };

        // bits to field element (little endian)
        let num = valid_bits
            .iter()
            .map(|b| b.field())
            .rev()
            .fold(Self::BaseField::zero(), |acc, x| {
                acc * Self::BaseField::from_public(F::from(2u8)) + x
            });

        (valid_bits, num)
    }

    async fn rand_number_bitwise_less_than_half_modulus<R: Rng + ?Sized>(
        rng: &mut R,
    ) -> (Vec<Self>, Self::BaseField) {
        let modulus_size = F::Params::MODULUS_BITS as usize;

        let mut half_modulus_bits = F::Params::MODULUS_MINUS_ONE_DIV_TWO
            .to_bits_le()
            .iter()
            .map(|&b| Self::from(b))
            .collect::<Vec<_>>();

        half_modulus_bits = half_modulus_bits[..modulus_size].to_vec();

        let valid_bits = loop {
            let bits = Self::rand_bits_batched_internal(rng, modulus_size).await;
            if bits
                .is_smaller_than_le(&half_modulus_bits)
                .field()
                .reveal()
                .await
                .is_one()
            {
                break bits;
            }
        };

        // bits to field element (little endian)
        let num = valid_bits
            .iter()
            .map(|b| b.field())
            .rev()
            .fold(Self::BaseField::zero(), |acc, x| {
                acc * Self::BaseField::from_public(F::from(2u8)) + x
            });

        (valid_bits, num)
    }
}

impl<F: Field, S: FieldShare<F>> MpcWire for MpcBooleanField<F, S> {
    fn is_shared(&self) -> bool {
        self.field().is_shared()
    }

    fn publicize(&mut self) {
        self.field().publicize();
    }

    fn publicize_cow<'b>(&'b self) -> std::borrow::Cow<'b, Self> {
        if self.is_shared() {
            let mut s = self.clone();
            s.publicize();
            std::borrow::Cow::Owned(s)
        } else {
            std::borrow::Cow::Borrowed(self)
        }
    }
}

impl<F: PrimeField, S: FieldShare<F>> MpcBooleanField<F, S> {
    pub(crate) fn batch_and(lhs: &[Self], rhs: &[Self]) -> Vec<Self> {
        assert_eq!(lhs.len(), rhs.len());
        let mut prods = lhs.iter().map(|x| x.field()).collect::<Vec<_>>();
        let rhs_fields = rhs.iter().map(|x| x.field()).collect::<Vec<_>>();
        <MpcField<F, S> as Field>::batch_product_in_place(&mut prods, &rhs_fields);
        prods.into_iter().map(Self::from).collect()
    }

    pub(crate) fn batch_or(lhs: &[Self], rhs: &[Self]) -> Vec<Self> {
        assert_eq!(lhs.len(), rhs.len());
        let ands = Self::batch_and(lhs, rhs);
        lhs.iter()
            .zip(rhs.iter())
            .zip(ands.into_iter())
            .map(|((&a, &b), ab)| Self::from(a.field() + b.field() - ab.field()))
            .collect()
    }

    pub(crate) fn batch_xor(lhs: &[Self], rhs: &[Self]) -> Vec<Self> {
        assert_eq!(lhs.len(), rhs.len());
        let two = MpcField::<F, S>::from(2u8);
        let ands = Self::batch_and(lhs, rhs);
        lhs.iter()
            .zip(rhs.iter())
            .zip(ands.into_iter())
            .map(|((&a, &b), ab)| Self::from(a.field() + b.field() - (ab.field() * two)))
            .collect()
    }
}

impl<F: PrimeField + SquareRootField, S: FieldShare<F>> MpcBooleanField<F, S> {
    async fn bit_rand_single_slow<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        loop {
            let r = MpcField::<F, S>::rand(rng);
            let r2 = (r * r).reveal().await;
            let root_r2 = r2.sqrt().unwrap();
            if !root_r2.is_zero() {
                return Self(
                    (r / MpcField::<F, S>::from_public(root_r2) + MpcField::<F, S>::one())
                        / MpcField::<F, S>::from_public(F::from(2u8)),
                );
            }
        }
    }

    async fn rand_bits_batched_internal<R: rand::Rng + ?Sized>(rng: &mut R, n: usize) -> Vec<Self> {
        let mut rs = (0..n)
            .map(|_| MpcField::<F, S>::rand(rng))
            .collect::<Vec<_>>();
        let mut squares = rs.clone();
        <MpcField<F, S> as Field>::batch_product_in_place(&mut squares, &rs);
        let opened_squares = S::batch_open(
            squares
                .into_iter()
                .map(|x| match x {
                    MpcField::Shared(s) => s,
                    MpcField::Public(v) => S::from_public(v),
                })
                .collect::<Vec<_>>(),
        )
        .await;

        let mut bits = Vec::with_capacity(n);
        for (r, r2) in rs.drain(..).zip(opened_squares.into_iter()) {
            let root_r2 = r2.sqrt().unwrap();
            if root_r2.is_zero() {
                bits.push(Self::bit_rand_single_slow(rng).await);
            } else {
                bits.push(Self(
                    (r / MpcField::<F, S>::from_public(root_r2) + MpcField::<F, S>::one())
                        / MpcField::<F, S>::from_public(F::from(2u8)),
                ));
            }
        }
        bits
    }
}

impl<F: Field, S: FieldShare<F>> BitAdd for Vec<MpcBooleanField<F, S>> {
    type Output = Self;

    fn carries(&self, other: &Self) -> Self::Output {
        match self.is_shared() {
            true => {
                assert_eq!(self.len(), other.len());
                let l = self.len(); // l is the bit length.

                let s_vec = MpcBooleanField::<F, S>::batch_and(self, other);
                let p_vec = MpcBooleanField::<F, S>::batch_xor(self, other);

                // Parallel-prefix carry computation.
                // For each bit i, maintain (G_i, P_i) where carry_i = G_i and:
                // combine((G, P), (g, p)) = (G + P * g, P * p).
                let mut g_vec = s_vec.iter().map(|b| b.field()).collect::<Vec<_>>();
                let mut p_fields = p_vec.iter().map(|b| b.field()).collect::<Vec<_>>();

                let mut offset = 1usize;
                while offset < l {
                    let m = l - offset;
                    let mut lhs_p = Vec::with_capacity(m);
                    let mut rhs_g = Vec::with_capacity(m);
                    let mut rhs_p = Vec::with_capacity(m);
                    let mut idx = Vec::with_capacity(m);

                    for i in offset..l {
                        lhs_p.push(p_fields[i]);
                        rhs_g.push(g_vec[i - offset]);
                        rhs_p.push(p_fields[i - offset]);
                        idx.push(i);
                    }

                    let mut p_times_g = lhs_p.clone();
                    <MpcField<F, S> as Field>::batch_product_in_place(&mut p_times_g, &rhs_g);

                    let mut p_times_p = lhs_p;
                    <MpcField<F, S> as Field>::batch_product_in_place(&mut p_times_p, &rhs_p);

                    for ((i, pg), pp) in idx
                        .into_iter()
                        .zip(p_times_g.into_iter())
                        .zip(p_times_p.into_iter())
                    {
                        g_vec[i] = g_vec[i] + pg;
                        p_fields[i] = pp;
                    }

                    offset <<= 1;
                }

                g_vec
                    .into_iter()
                    .map(MpcBooleanField::<F, S>::from)
                    .collect()
            }
            false => {
                panic!("public is not expected here");
            }
        }
    }

    /// This function is used to add two bit vectors of lenght l.
    /// Returns a bit vector of length l+1 (bit length always increase by 1).
    fn bit_add(self, other: &Self) -> Self::Output {
        match self.is_shared() {
            true => {
                assert_eq!(self.len(), other.len());
                let l = self.len(); // l is the bit length.
                let c_vec = self.carries(other);

                (0..=l)
                    .map(|i| {
                        if i == 0 {
                            (self[0].field() + other[0].field()
                                - MpcField::<F, S>::from_public(F::from(2u64)) * c_vec[0].field())
                            .into()
                        } else if i == l {
                            c_vec[l - 1]
                        } else {
                            (self[i].field() + other[i].field() + c_vec[i - 1].field()
                                - MpcField::<F, S>::from_public(F::from(2u64)) * c_vec[i].field())
                            .into()
                        }
                    })
                    .collect()
            }
            false => {
                panic!("public is not expected here");
            }
        }
    }
}

impl<F: Field, S: FieldShare<F>> Reveal for MpcBooleanField<F, S> {
    type Base = F;
    #[inline]
    async fn reveal(self) -> Self::Base {
        self.0.reveal().await
    }
    #[inline]
    fn from_public(b: Self::Base) -> Self {
        if b == F::zero() {
            Self::pub_false()
        } else if b == F::one() {
            Self::pub_true()
        } else {
            panic!("not boolean")
        }
    }
    #[inline]
    fn from_add_shared(b: Self::Base) -> Self {
        MpcField::Shared(S::from_add_shared(b)).into()
    }
    #[inline]
    fn unwrap_as_public(self) -> Self::Base {
        match self.field() {
            MpcField::<F, S>::Shared(s) => s.unwrap_as_public(),
            MpcField::<F, S>::Public(s) => s,
        }
    }
    #[inline]
    fn king_share<R: Rng>(_f: Self::Base, _rng: &mut R) -> Self {
        todo!()
    }
    #[inline]
    fn king_share_batch<R: Rng>(_f: Vec<Self::Base>, _rng: &mut R) -> Vec<Self> {
        todo!()
    }
    fn init_protocol() {
        MpcField::<F, S>::init_protocol()
    }
    fn deinit_protocol() {
        MpcField::<F, S>::deinit_protocol()
    }
}
