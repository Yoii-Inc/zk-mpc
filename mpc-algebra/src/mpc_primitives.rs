use rand::Rng;

pub trait UniformBitRand: Sized {
    fn bit_rand<R: Rng + ?Sized>(rng: &mut R) -> Self;
    // little-endian
    fn rand_number_bitwise<R: Rng + ?Sized>(rng: &mut R) -> (Vec<Self>, Self);
}

pub trait BitwiseLessThan {
    type Output;

    fn is_smaller_than_le(&self, other: &Self) -> Self::Output;
}

pub trait LessThan : UniformBitRand {
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
    fn is_zero_shared(&self) -> Self;
}

pub trait BitDecomposition {
    type Output;

    fn bit_decomposition(&self) -> Self::Output;
}

pub trait BitAdd {
    type Output;

    fn carries(&self, other: &Self) -> Self::Output;

    fn bit_add(self, other: &Self) -> Self::Output;
}
