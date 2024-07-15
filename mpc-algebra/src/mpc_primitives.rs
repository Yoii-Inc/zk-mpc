use rand::Rng;

use crate::boolean_field::BooleanWire;

pub trait UniformBitRand: Sized {
    type BaseField;

    fn bit_rand<R: Rng + ?Sized>(rng: &mut R) -> Self;
    // little-endian
    fn rand_number_bitwise<R: Rng + ?Sized>(rng: &mut R) -> (Vec<Self>, Self::BaseField);
    fn rand_number_bitwise_less_than_half_modulus<R: Rng + ?Sized>(
        rng: &mut R,
    ) -> (Vec<Self>, Self::BaseField);
}

pub trait BitwiseLessThan {
    type Output;

    fn is_smaller_than_le(&self, other: &Self) -> Self::Output;
}

pub trait LessThan {
    type Output;

    fn is_smaller_or_equal_than_mod_minus_one_div_two(&self) -> Self::Output;
    fn is_smaller_than(&self, other: &Self) -> Self::Output;
}

pub trait LogicalOperations {
    type Output;

    fn kary_and(&self) -> Self::Output;

    fn kary_or(&self) -> Self::Output;
}

pub trait EqualityZero {
    type Output: BooleanWire<Base = Self>;
    fn is_zero_shared(&self) -> Self::Output;
}

pub trait BitDecomposition {
    type BooleanField: BooleanWire<Base = Self>;

    fn bit_decomposition(&self) -> Vec<Self::BooleanField>;
}

pub trait BitAdd {
    type Output;

    fn carries(&self, other: &Self) -> Self::Output;

    fn bit_add(self, other: &Self) -> Self::Output;
}
