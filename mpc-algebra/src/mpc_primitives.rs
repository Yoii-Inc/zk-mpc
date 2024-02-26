use rand::Rng;

pub trait UniformBitRand: Sized {
    fn bit_rand<R: Rng + ?Sized>(rng: &mut R) -> Self;

    // big-endian
    fn bits_rand<R: Rng + ?Sized>(rng: &mut R) -> (Vec<Self>, Self);
}

pub trait LogicalOperations {
    type Output;

    fn unbounded_fan_in_and(&self) -> Self::Output;

    fn unbounded_fan_in_or(&self) -> Self::Output;
}
