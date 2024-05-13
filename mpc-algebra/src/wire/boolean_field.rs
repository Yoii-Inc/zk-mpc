use std::ops::{BitAnd, BitOr, BitXor, Not};

use ark_ff::{Field, One, PrimeField};

use crate::{FieldShare, MpcField};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct MpcBooleanField<F: PrimeField, S: FieldShare<F>> {
    inner: MpcField<F, S>,
}

impl<F: PrimeField, S: FieldShare<F>> MpcBooleanField<F, S> {
    pub fn new_unchecked(inner: MpcField<F, S>) -> Self {
        Self { inner }
    }

    // return as field
    pub fn into_field(self) -> MpcField<F, S> {
        self.inner
    }

    pub fn new(inner: MpcField<F, S>) -> Self {
        // TODO; check if inner is boolean
        Self { inner }
    }

    pub fn and(self, other: Self) -> Self {
        Self {
            inner: self.inner * other.inner,
        }
    }
    
    pub fn or(self, other: Self) -> Self {
        Self {
            inner: self.inner + other.inner - (self.inner * other.inner),
        }
    }

    pub fn xor(self, other: Self) -> Self {
        Self {
            inner: self.inner + other.inner - (self.inner * other.inner).double(),
        
        }
    }
}

impl<F: PrimeField, S: FieldShare<F>> Not for MpcBooleanField<F, S> {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self {
            inner: MpcField::one() - self.inner,
        }
    }
}

impl<F: PrimeField, S: FieldShare<F>> BitAnd for MpcBooleanField<F, S> {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        self.and(rhs)
    }
}

impl<F: PrimeField, S: FieldShare<F>> BitOr for MpcBooleanField<F, S> {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        self.or(rhs)
    }
}

impl<F: PrimeField, S: FieldShare<F>> BitXor for MpcBooleanField<F, S> {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        self.xor(rhs)
    }
}

// from MpcBooleanField to MpcField
impl<F: PrimeField, S: FieldShare<F>> From<MpcBooleanField<F, S>> for MpcField<F, S> {
    fn from(b: MpcBooleanField<F, S>) -> Self {
        b.inner
    }
}