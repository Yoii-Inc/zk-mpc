use rand::Rng;

pub trait UniformBitRand: Sized {
    fn bit_rand<R: Rng + ?Sized>(rng: &mut R) -> Self;

    // big-endian
    fn bits_rand<R: Rng + ?Sized>(rng: &mut R) -> (Vec<Self>, Self);
}
