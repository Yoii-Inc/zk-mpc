use ark_bls12_377::Fr;
use ark_crypto_primitives::CommitmentScheme;
use ark_ff::{BigInteger, PrimeField};

use ark_ec::twisted_edwards_extended::GroupAffine;
use ark_std::PubUniformRand;
use ark_std::UniformRand;
use mpc_algebra::MpcEdwardsParameters;
use mpc_algebra::Reveal;
use mpc_algebra::ToLocal;
use mpc_algebra::ToMPC;
use mpc_net::{MpcMultiNet as Net, MpcNet};
use rand::Rng;

use crate::circuits::LocalOrMPC;
use crate::marlin::MFr;

#[derive(Clone)]
pub struct SampleMpcInput<F: PrimeField + LocalOrMPC<F>> {
    pub mode: InputMode,
    pub peculiar: Option<PeculiarInput<F>>,
    pub common: Option<CommonInput<F>>,
}

// Party-dependent values used in the circuit
#[derive(Clone)]
pub struct PeculiarInput<F: PrimeField + LocalOrMPC<F>> {
    pub a: InputWithCommit<F>,
    pub b: InputWithCommit<F>,
}

// Common values used in the circuit
#[derive(Clone)]
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
pub enum InputMode {
    Init,
    PublicSet,
    PrivateSet,
    Shared,
    Local,
}

pub trait MpcInputTrait {
    type Base;
    fn get_mode(&self) -> InputMode;
    fn init() -> Self;
    fn set_public_input<R: Rng>(&mut self, rng: &mut R);
    fn set_private_input(&mut self);
    fn generate_input<R: Rng>(&mut self, rng: &mut R);
    fn rand<R: Rng>(rng: &mut R) -> Self;
}

impl MpcInputTrait for SampleMpcInput<MFr> {
    type Base = Fr;

    fn get_mode(&self) -> InputMode {
        self.mode
    }

    fn init() -> Self {
        Self {
            mode: InputMode::Init,
            peculiar: None,
            common: None,
        }
    }

    fn set_public_input<R: Rng>(&mut self, rng: &mut R) {
        assert_eq!(self.get_mode(), InputMode::Init);

        let pedersen_param = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::setup(rng).unwrap();

        self.mode = InputMode::PublicSet;
        self.common = Some(CommonInput {
            pedersen_param: pedersen_param.to_mpc(),
        });
    }

    fn set_private_input(&mut self) {
        assert_eq!(self.get_mode(), InputMode::PublicSet);

        // let num_peer = self.peculiar.len();

        self.mode = InputMode::PrivateSet;
        let mut a = InputWithCommit::default();
        let mut b = InputWithCommit::default();
        a.allocation = 0;
        b.allocation = 1;
        self.peculiar = Some(PeculiarInput { a, b });
    }

    fn generate_input<R: Rng>(&mut self, rng: &mut R) {
        assert_eq!(self.get_mode(), InputMode::PrivateSet);

        self.mode = InputMode::Shared;

        let common_randomness = <MFr as LocalOrMPC<MFr>>::PedersenRandomness::pub_rand(rng);

        let a = match Net::party_id() {
            0 => {
                let mut a = self.clone().peculiar.unwrap().a;

                a.input = MFr::rand(rng);
                a.input_bit = a
                    .input
                    .clone()
                    // .reveal()
                    .into_repr()
                    .to_bits_le()
                    .iter()
                    .map(|b| MFr::from_add_shared(Fr::from(*b)))
                    .collect::<Vec<_>>();

                // let randomness = <MFr as LocalOrMPC<MFr>>::PedersenRandomness::pub_rand(rng);
                a.randomness_bit = common_randomness
                    .0
                    .into_repr()
                    .to_bits_le()
                    .iter()
                    .map(|b| MFr::from(*b))
                    .collect::<Vec<_>>();

                let h_x = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::commit(
                    &self.clone().common.unwrap().pedersen_param.to_local(),
                    &a.input.clone().reveal().into_repr().to_bytes_le(),
                    &common_randomness.clone().reveal(),
                )
                .unwrap();

                let h_x_mpc = GroupAffine::<MpcEdwardsParameters>::new(
                    MFr::from_add_shared(h_x.x),
                    MFr::from_add_shared(h_x.y),
                );
                a.commitment = h_x_mpc.reveal().to_mpc();
                a
            }
            _ => {
                let mut a = self.clone().peculiar.unwrap().a;

                a.input = MFr::from_add_shared(Fr::default());
                a.input_bit = a
                    .input
                    .clone()
                    // .reveal()
                    .into_repr()
                    .to_bits_le()
                    .iter()
                    .map(|_b| MFr::from_add_shared(Fr::from(false)))
                    .collect::<Vec<_>>();

                // let randomness = <MFr as LocalOrMPC<MFr>>::PedersenRandomness::default();
                a.randomness_bit = common_randomness
                    .0
                    .into_repr()
                    .to_bits_le()
                    .iter()
                    .map(|b| MFr::from(*b))
                    .collect::<Vec<_>>();

                let _h_x = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::commit(
                    &self.clone().common.unwrap().pedersen_param.to_local(),
                    &a.input.clone().reveal().into_repr().to_bytes_le(),
                    &common_randomness.clone().reveal(),
                )
                .unwrap();

                let h_x_mpc = GroupAffine::<MpcEdwardsParameters>::new(
                    MFr::from_add_shared(Fr::default()),
                    MFr::from_add_shared(Fr::default()),
                );
                a.commitment = h_x_mpc.reveal().to_mpc();
                a
            }
        };

        let b = match Net::party_id() {
            1 => {
                let mut b = self.clone().peculiar.unwrap().b;

                b.input = MFr::rand(rng);
                b.input_bit = b
                    .input
                    .clone()
                    // .reveal()
                    .into_repr()
                    .to_bits_le()
                    .iter()
                    .map(|b| MFr::from_add_shared(Fr::from(*b)))
                    .collect::<Vec<_>>();

                // let randomness = <MFr as LocalOrMPC<MFr>>::PedersenRandomness::pub_rand(rng);
                b.randomness_bit = common_randomness
                    .0
                    .into_repr()
                    .to_bits_le()
                    .iter()
                    .map(|b| MFr::from(*b))
                    .collect::<Vec<_>>();

                let h_x = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::commit(
                    &self.clone().common.unwrap().pedersen_param.to_local(),
                    &b.input.clone().reveal().into_repr().to_bytes_le(),
                    &common_randomness.clone().reveal(),
                )
                .unwrap();

                let h_x_mpc = GroupAffine::<MpcEdwardsParameters>::new(
                    MFr::from_add_shared(h_x.x),
                    MFr::from_add_shared(h_x.y),
                );
                b.commitment = h_x_mpc.reveal().to_mpc();
                b
            }
            _ => {
                let mut a = self.clone().peculiar.unwrap().b;

                a.input = MFr::from_add_shared(Fr::default());
                a.input_bit = a
                    .input
                    .clone()
                    // .reveal()
                    .into_repr()
                    .to_bits_le()
                    .iter()
                    .map(|_b| MFr::from_add_shared(Fr::from(false)))
                    .collect::<Vec<_>>();

                // let randomness = <MFr as LocalOrMPC<MFr>>::PedersenRandomness::default();
                a.randomness_bit = common_randomness
                    .0
                    .into_repr()
                    .to_bits_le()
                    .iter()
                    .map(|b| MFr::from(*b))
                    .collect::<Vec<_>>();

                let _h_x = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::commit(
                    &self.clone().common.unwrap().pedersen_param.to_local(),
                    &a.input.clone().reveal().into_repr().to_bytes_le(),
                    &common_randomness.clone().reveal(),
                )
                .unwrap();

                let h_x_mpc = GroupAffine::<MpcEdwardsParameters>::new(
                    MFr::from_add_shared(Fr::default()),
                    MFr::from_add_shared(Fr::default()),
                );
                a.commitment = h_x_mpc.reveal().to_mpc();
                a
            }
        };

        let peculiar = PeculiarInput { a, b };

        self.peculiar = Some(peculiar);
    }

    fn rand<R: Rng>(_rng: &mut R) -> Self {
        unimplemented!()
    }
}

impl MpcInputTrait for SampleMpcInput<Fr> {
    type Base = Fr;

    fn get_mode(&self) -> InputMode {
        todo!()
    }

    fn init() -> Self {
        todo!()
    }

    fn set_public_input<R: Rng>(&mut self, _rng: &mut R) {
        todo!()
    }

    fn set_private_input(&mut self) {
        todo!()
    }

    fn generate_input<R: Rng>(&mut self, _rng: &mut R) {
        todo!()
    }

    fn rand<R: Rng>(rng: &mut R) -> Self {
        let mode = InputMode::Local;

        let params = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::setup(rng).unwrap();

        let input_a = Fr::rand(rng);
        let input_bit = input_a
            .into_repr()
            .to_bits_le()
            .iter()
            .map(|b| Fr::from(*b))
            .collect::<Vec<_>>();

        let a_bytes = input_a.into_repr().to_bytes_le();

        //// randomness
        let randomness = <Fr as LocalOrMPC<Fr>>::PedersenRandomness::pub_rand(rng);

        let open_bit = randomness
            .0
            .into_repr()
            .to_bits_le()
            .iter()
            .map(|b| Fr::from(*b))
            .collect::<Vec<_>>();

        let a = InputWithCommit {
            allocation: 0,
            input: input_a,
            input_bit,
            randomness_bit: open_bit,
            commitment: <Fr as LocalOrMPC<Fr>>::PedersenComScheme::commit(
                &params,
                &a_bytes,
                &randomness,
            )
            .unwrap(),
        };
        Self {
            mode,
            peculiar: Some(PeculiarInput {
                a: a.clone(),
                b: a.clone(),
            }),
            common: Some(CommonInput {
                pedersen_param: params,
            }),
        }
    }
}
