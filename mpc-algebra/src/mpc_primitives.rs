use rand::Rng;

pub trait UniformBitRand: Sized {
    fn bit_rand<R: Rng + ?Sized>(rng: &mut R) -> Self;
}
