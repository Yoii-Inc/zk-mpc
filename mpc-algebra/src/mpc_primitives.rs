use ark_ff::BigInteger;
use ark_ff::PrimeField;
use rand::Rng;

use crate::boolean_field::BooleanWire;

pub trait UniformBitRand: Sized {
    type BaseField;

    async fn bit_rand<R: Rng + ?Sized>(rng: &mut R) -> Self;
    // little-endian
    async fn rand_number_bitwise<R: Rng + ?Sized>(rng: &mut R) -> (Vec<Self>, Self::BaseField);
    async fn rand_number_bitwise_less_than_half_modulus<R: Rng + ?Sized>(
        rng: &mut R,
    ) -> (Vec<Self>, Self::BaseField);
}

pub trait BitwiseLessThan {
    type Output;

    fn is_smaller_than_le(&self, other: &Self) -> Self::Output;
}

pub trait LessThan {
    type Output;

    async fn is_smaller_or_equal_than_mod_minus_one_div_two(&self) -> Self::Output;
    async fn is_smaller_than(&self, other: &Self) -> Self::Output;
}

pub trait LogicalOperations {
    type Output;

    async fn kary_and(&self) -> Self::Output;

    async fn kary_or(&self) -> Self::Output;
}

pub trait EqualityZero {
    type Output: BooleanWire<Base = Self>;
    async fn is_zero_shared(&self) -> Self::Output;

    fn sync_is_zero_shared(&self) -> Self::Output {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.is_zero_shared())
        })
    }
}

pub trait BitDecomposition {
    type BooleanField: BooleanWire<Base = Self>;

    async fn bit_decomposition(&self) -> Vec<Self::BooleanField>;

    fn sync_bit_decomposition(&self) -> Vec<Self::BooleanField> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.bit_decomposition())
        })
    }
}

pub trait BitAdd {
    type Output;

    fn carries(&self, other: &Self) -> Self::Output;

    fn bit_add(self, other: &Self) -> Self::Output;
}

pub trait ModulusConversion<F: PrimeField>: PrimeField {
    async fn modulus_conversion(&mut self) -> F {
        let bits = self.into_repr().to_bits_le();
        F::from_repr(BigInteger::from_bits_le(&bits)).unwrap()
    }

    fn sync_modulus_conversion(&mut self) -> F {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.modulus_conversion())
        })
    }
}
