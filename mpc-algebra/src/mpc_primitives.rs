use rand::Rng;

pub trait UniformBitRand: Sized {
    fn bit_rand<R: Rng + ?Sized>(rng: &mut R) -> Self;

    // big-endian
    fn bits_rand<R: Rng + ?Sized>(rng: &mut R) -> (Vec<Self>, Self);
}

pub trait BitwiseLessThan {
    type Output;

    fn bitwise_lt(&self, other: &Self) -> Self::Output;
}

pub trait LogicalOperations {
    type Output;

    fn unbounded_fan_in_and(&self) -> Self::Output;

    fn unbounded_fan_in_or(&self) -> Self::Output;
}

pub trait EqualityZero {
    fn is_zero_shared(&self) -> Self;
}
