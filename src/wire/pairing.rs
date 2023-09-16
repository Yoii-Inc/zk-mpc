use std::marker::PhantomData;

use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::Field;

use super::super::share::field::ExtFieldShare;
use super::super::share::pairing::PairingShare;
use super::field::MpcField;
use super::group::{MpcGroup, MpcGroupAffine};

use derivative::Derivative;

pub struct MpcG1Affine<E: PairingEngine, PS: PairingShare<E>> {
    pub val: MpcGroupAffine<E::G1Affine, PS::G1AffineShare>,
}

pub struct MpcG1Projective<E: PairingEngine, PS: PairingShare<E>> {
    pub val: MpcGroup<E::G1Projective, PS::G1ProjectiveShare>,
}

pub struct MpcG1Prep<E: PairingEngine, PS: PairingShare<E>> {
    pub val: E::G1Prepared,
    _phantom: PhantomData<(E, PS)>,
}

pub struct MpcG2Affine<E: PairingEngine, PS: PairingShare<E>> {
    pub val: MpcGroupAffine<E::G2Affine, PS::G2AffineShare>,
}

pub struct MpcG2Projective<E: PairingEngine, PS: PairingShare<E>> {
    pub val: MpcGroup<E::G2Projective, PS::G2ProjectiveShare>,
}

pub struct MpcG2Prep<E: PairingEngine, PS: PairingShare<E>> {
    pub val: E::G2Prepared,
    _phantom: PhantomData<(E, PS)>,
}

pub struct MpcExtField<F: Field, FS: ExtFieldShare<F>> {
    pub val: MpcField<F, FS::Ext>,
}

#[derive(Derivative)]
#[derivative(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MpcPairingEngine<E: PairingEngine, PS: PairingShare<E>> {
    _phantom: PhantomData<(E, PS)>,
}

impl<E: PairingEngine, PS: PairingShare<E>> PairingEngine for MpcPairingEngine<E, PS> {
    type Fr = MpcField<E::Fr, PS::FrShare>;
    type G1Projective = MpcG1Projective<E, PS>;
    type G1Affine = MpcG1Affine<E, PS>;
    type G1Prepared = MpcG1Prep<E, PS>;
    type G2Projective = MpcG2Projective<E, PS>;
    type G2Affine = MpcG2Affine<E, PS>;
    type G2Prepared = MpcG2Prep<E, PS>;
    type Fq = MpcField<E::Fq, PS::FqShare>;
    type Fqe = MpcExtField<E::Fqe, PS::FqeShare>;
    type Fqk = MpcExtField<E::Fqk, PS::FqkShare>;

    fn miller_loop<'a, I>(i: I) -> Self::Fqk
    where
        I: IntoIterator<Item = &'a (Self::G1Prepared, Self::G2Prepared)>,
    {
        todo!()
    }

    fn final_exponentiation(r: &Self::Fqk) -> Option<Self::Fqk> {
        todo!()
    }

    fn product_of_pairings<'a, I>(i: I) -> Self::Fqk
    where
        I: IntoIterator<Item = &'a (Self::G1Prepared, Self::G2Prepared)>,
    {
        todo!()
    }

    fn pairing<G1, G2>(p: G1, q: G2) -> Self::Fqk
    where
        G1: Into<Self::G1Affine>,
        G2: Into<Self::G2Affine>,
    {
        todo!()
    }
}
