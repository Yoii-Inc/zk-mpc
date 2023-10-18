pub mod additive;
pub use additive::*;
pub mod field;
pub use field::*;
pub mod group;
pub use group::*;
pub mod pairing;
pub use pairing::*;

pub trait BeaverSource<A, B, C>: Clone {
    fn triple(&mut self) -> (A, B, C);
    fn inv_pair(&mut self) -> (B, B);
}
