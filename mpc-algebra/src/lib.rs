// #![feature(associated_type_defaults)]

pub mod reveal;
pub use reveal::*;
pub mod share;
pub use share::*;
pub mod wire;
pub use wire::*;
pub mod mpc_primitives;
pub use mpc_primitives::*;
pub mod r1cs_helper;
pub use r1cs_helper::*;
pub mod commitment;
pub use commitment::*;
pub mod crh;
pub mod encryption;

pub mod channel;

pub mod honest_but_curious {
    use super::{
        share::additive::*,
        share::msm::NaiveMsm,
        wire::{boolean_field, edwards2, field, group, pairing, uint8},
    };
    pub type MpcField<F> = field::MpcField<F, AdditiveFieldShare<F>>;
    pub type MpcGroup<G> = group::MpcGroup<G, AdditiveGroupShare<G, NaiveMsm<G>>>;
    pub type MpcG1Affine<E> = pairing::MpcG1Affine<E, AdditivePairingShare<E>>;
    pub type MpcG2Affine<E> = pairing::MpcG2Affine<E, AdditivePairingShare<E>>;
    pub type MpcG1Projective<E> = pairing::MpcG1Projective<E, AdditivePairingShare<E>>;
    pub type MpcG2Projective<E> = pairing::MpcG2Projective<E, AdditivePairingShare<E>>;
    pub type MpcG1Prep<E> = pairing::MpcG1Prep<E, AdditivePairingShare<E>>;
    pub type MpcG2Prep<E> = pairing::MpcG2Prep<E, AdditivePairingShare<E>>;
    pub type MpcPairingEngine<E> = pairing::MpcPairingEngine<E, AdditivePairingShare<E>>;

    pub type MpcU8Field<F> = uint8::MpcU8Field<F, AdditiveFieldShare<F>>;

    pub type MpcEdwardsAffine = edwards2::AdditiveMpcEdwardsAffine;
    pub type MpcEdwardsProjective = edwards2::AdditiveMpcEdwardsProjective;

    pub type AffProjShare<P> = edwards2::AdditiveAffProjShare<P>;

    pub type MpcEdwardsVar = edwards2::AdditiveMpcEdwardsVar;

    pub type MpcBooleanField<F> = boolean_field::MpcBooleanField<F, AdditiveFieldShare<F>>;
}
pub mod malicious_majority {
    use super::{
        share::msm::NaiveMsm,
        share::spdz::*,
        wire::{boolean_field, edwards2, field, group, pairing, uint8},
    };
    pub type MpcField<F> = field::MpcField<F, SpdzFieldShare<F>>;
    pub type MpcGroup<G> = group::MpcGroup<G, SpdzGroupShare<G, NaiveMsm<G>>>;
    pub type MpcG1Affine<E> = pairing::MpcG1Affine<E, SpdzPairingShare<E>>;
    pub type MpcG2Affine<E> = pairing::MpcG2Affine<E, SpdzPairingShare<E>>;
    pub type MpcG1Projective<E> = pairing::MpcG1Projective<E, SpdzPairingShare<E>>;
    pub type MpcG2Projective<E> = pairing::MpcG2Projective<E, SpdzPairingShare<E>>;
    pub type MpcG1Prep<E> = pairing::MpcG1Prep<E, SpdzPairingShare<E>>;
    pub type MpcG2Prep<E> = pairing::MpcG2Prep<E, SpdzPairingShare<E>>;
    pub type MpcPairingEngine<E> = pairing::MpcPairingEngine<E, SpdzPairingShare<E>>;

    pub type MpcU8Field<F> = uint8::MpcU8Field<F, SpdzFieldShare<F>>;

    pub type MpcEdwardsAffine = edwards2::SpdzMpcEdwardsAffine;
    pub type MpcEdwardsProjective = edwards2::SpdzMpcEdwardsProjective;

    pub type AffProjShare<P> = edwards2::SpdzAffProjShare<P>;

    pub type MpcEdwardsVar = edwards2::SpdzMpcEdwardsVar;

    pub type MpcBooleanField<F> = boolean_field::MpcBooleanField<F, SpdzFieldShare<F>>;
}
