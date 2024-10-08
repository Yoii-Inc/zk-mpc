use crate::MpcWire;
use ark_std::rand::Rng;
pub use ark_std::UniformRand;

pub trait PubUniformRand: Sized + MpcWire + UniformRand {
    fn pub_rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        <Self as UniformRand>::rand(rng)
    }
}
