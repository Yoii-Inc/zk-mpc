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

pub mod channel;

pub mod honest_but_curious {
    use super::{
        share::additive::*,
        share::msm::NaiveMsm,
        wire::{field, group, pairing},
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

    // pub type MpcEdwardsParameters = edwards::AdditiveMpcEdwardsParameters;
    // pub type MpcEdwardsAffine = edwards::AdditiveMpcEdwardsAffine;
    // pub type MpcEdwardsProjective = edwards::AdditiveMpcEdwardsProjective;

    // pub type MpcEdwardsVar = edwards::AdditiveMpcEdwardsVar;
}
pub mod malicious_majority {
    use super::{
        share::msm::NaiveMsm,
        share::spdz::*,
        wire::{field, group, pairing},
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

    // pub type MpcEdwardsParameters = edwards::SpdzMpcEdwardsParameters;
    // pub type MpcEdwardsAffine = edwards::SpdzMpcEdwardsAffine;
    // pub type MpcEdwardsProjective = edwards::SpdzMpcEdwardsProjective;

    // pub type MpcEdwardsVar = edwards::SpdzMpcEdwardsVar;
}
