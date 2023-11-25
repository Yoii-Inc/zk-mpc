use ark_bls12_377::Fr;
use ark_crypto_primitives::CommitmentScheme;
use ark_ff::PrimeField;

use mpc_net::{MpcMultiNet as Net, MpcNet};
use rand::Rng;

use crate::{circuits::LocalOrMPC, marlin::MFr};

pub struct SampleMpcInput<F: PrimeField + LocalOrMPC<F>> {
    pub mode: InputMode,
    pub peculiar: Vec<Option<PeculiarInput<F>>>,
    pub common: Option<CommonInput<F>>,
}

// Party-dependent values used in the circuit
#[derive(Clone)]
pub struct PeculiarInput<F: PrimeField + LocalOrMPC<F>> {
    pub a: InputWithCommit<F>,
    pub b: InputWithCommit<F>,
}

// Common values used in the circuit
pub struct CommonInput<F: PrimeField + LocalOrMPC<F>> {
    pub pedersen_param: F::PedersenParam,
}

// A private value and its commitments
#[derive(Clone, Default)]
pub struct InputWithCommit<F: PrimeField + LocalOrMPC<F>> {
    pub allocation: usize,
    pub input: F,
    pub input_bit: Vec<F>,
    pub randomness_bit: Vec<F>,
    pub commitment: F::PedersenCommitment,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum InputMode {
    Init,
    PublicSet,
    PrivateSet,
    Shared,
}

pub trait MpcInputTrait {
    type Base;
    fn get_mode(&self) -> InputMode;
    fn init() -> Self;
    fn set_public_input<R: Rng>(&self, rng: &mut R) -> Self;
    fn set_private_input(&self) -> Self;
    fn generate_input(&self) -> Self;
}

impl MpcInputTrait for SampleMpcInput<MFr> {
    type Base = Fr;

    fn get_mode(&self) -> InputMode {
        self.mode
    }

    fn init() -> Self {
        Self {
            mode: InputMode::Init,
            peculiar: vec![None; 3],
            common: None,
        }
    }

    fn set_public_input<R: Rng>(&self, rng: &mut R) -> Self {
        assert_eq!(self.get_mode(), InputMode::Init);

        let pedersen_param = <MFr as LocalOrMPC<MFr>>::PedersenComScheme::setup(rng).unwrap();

        self.mode = InputMode::PublicSet;
        self.common = Some(CommonInput { pedersen_param });

        *self
    }

    fn set_private_input(&self) -> Self {
        assert_eq!(self.get_mode(), InputMode::PublicSet);

        let num_peer = self.peculiar.len();

        self.mode = InputMode::PrivateSet;
        self.peculiar[Net::party_id()] = Some(PeculiarInput {
            a: InputWithCommit::default(),
            b: InputWithCommit::default(),
        });

        *self
    }

    fn generate_input(&self) -> Self {
        assert_eq!(self.get_mode(), InputMode::PrivateSet);
        unimplemented!()
    }
}
