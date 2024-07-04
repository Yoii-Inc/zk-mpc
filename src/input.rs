use std::marker::PhantomData;

use ark_bls12_377::Fr;
use ark_ff::{BigInteger, PrimeField};

use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
use ark_ec::twisted_edwards_extended::GroupAffine;
use ark_ec::AffineCurve;
use ark_ff::Field;
use ark_std::PubUniformRand;
use ark_std::UniformRand;
use derivative::Derivative;
use mpc_algebra::{FieldShare, FromLocal, Reveal, ToLocal};
use mpc_net::{MpcMultiNet as Net, MpcNet};
use num_traits::One;
use num_traits::Zero;
use rand::Rng;

use mpc_algebra::commitment::pedersen::{Parameters, Randomness as MpcRandomness};
use mpc_algebra::CommitmentScheme;

// use mpc_algebra::honest_but_curious::*;
use mpc_algebra::malicious_majority::*;

type MFr = MpcField<Fr>;

use crate::circuits::ElGamalLocalOrMPC;
use crate::circuits::LocalOrMPC;

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
    pub randomness: F::PedersenRandomness,
    pub commitment: F::PedersenCommitment,
}

impl InputWithCommit<MFr> {
    pub fn generate_input(
        &self,
        pedersen_param: &Parameters<MpcEdwardsProjective>,
        common_randomness: &MpcRandomness<MpcEdwardsProjective>,
    ) -> Self {
        let mut iwc = self.clone();
        iwc.input = iwc.input.generate_share(iwc.allocation);

        iwc.randomness = *common_randomness;

        let h_x = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::commit(
            &pedersen_param.to_local(),
            &iwc.input.clone().reveal().into_repr().to_bytes_le(),
            &common_randomness.clone().reveal(),
        )
        .unwrap();

        let h_x_mpc = MpcEdwardsAffine::from_public(h_x.clone());

        iwc.commitment = h_x_mpc;

        iwc
    }
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
    type Peculiar;
    type Common;

    fn get_mode(&self) -> InputMode;
    fn init() -> Self;
    fn set_public_input<R: Rng>(&mut self, rng: &mut R, input: Option<Self::Common>);
    fn set_private_input(&mut self, input: Option<Self::Peculiar>);
    fn generate_input<R: Rng>(&mut self, rng: &mut R);
    fn rand<R: Rng>(rng: &mut R) -> Self;
}

impl MpcInputTrait for SampleMpcInput<MFr> {
    type Base = Fr;
    type Peculiar = (Fr, Fr);
    type Common = CommonInput<MFr>;

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

    fn set_public_input<R: Rng>(&mut self, rng: &mut R, _input: Option<Self::Common>) {
        assert_eq!(self.get_mode(), InputMode::Init);

        let pedersen_param = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::setup(rng).unwrap();

        self.mode = InputMode::PublicSet;
        self.common = Some(CommonInput {
            pedersen_param: Parameters::<MpcEdwardsProjective>::from_local(&pedersen_param),
        });
    }

    fn set_private_input(&mut self, input: Option<Self::Peculiar>) {
        assert_eq!(self.get_mode(), InputMode::PublicSet);

        // let num_peer = self.peculiar.len();

        self.mode = InputMode::PrivateSet;
        let mut a = InputWithCommit::default();
        let mut b = InputWithCommit::default();
        a.allocation = 0;
        b.allocation = 1;

        match input {
            None => (),
            Some((a_value, b_value)) => {
                if Net::party_id() == a.allocation {
                    a.input = MFr::from_add_shared(a_value);
                }
                if Net::party_id() == b.allocation {
                    b.input = MFr::from_add_shared(b_value);
                }
            }
        }

        self.peculiar = Some(PeculiarInput { a, b });
    }

    fn generate_input<R: Rng>(&mut self, rng: &mut R) {
        assert_eq!(self.get_mode(), InputMode::PrivateSet);

        self.mode = InputMode::Shared;

        let common_randomness = <MFr as LocalOrMPC<MFr>>::PedersenRandomness::pub_rand(rng);

        let a = self.clone().peculiar.unwrap().a.generate_input(
            &self.clone().common.unwrap().pedersen_param,
            &common_randomness,
        );

        let b = self.clone().peculiar.unwrap().b.generate_input(
            &self.clone().common.unwrap().pedersen_param,
            &common_randomness,
        );

        let peculiar = PeculiarInput { a, b };

        self.peculiar = Some(peculiar);
    }

    fn rand<R: Rng>(_rng: &mut R) -> Self {
        unimplemented!()
    }
}

impl MpcInputTrait for SampleMpcInput<Fr> {
    type Base = Fr;

    type Peculiar = PeculiarInput<Fr>;
    type Common = CommonInput<Fr>;

    fn get_mode(&self) -> InputMode {
        todo!()
    }

    fn init() -> Self {
        todo!()
    }

    fn set_public_input<R: Rng>(&mut self, _rng: &mut R, _input: Option<Self::Common>) {
        todo!()
    }

    fn set_private_input(&mut self, _input: Option<Self::Peculiar>) {
        todo!()
    }

    fn generate_input<R: Rng>(&mut self, _rng: &mut R) {
        todo!()
    }

    fn rand<R: Rng>(rng: &mut R) -> Self {
        let mode = InputMode::Local;

        let params = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::setup(rng).unwrap();

        let input_a = Fr::rand(rng);

        let a_bytes = input_a.into_repr().to_bytes_le();

        //// randomness
        let randomness = <Fr as LocalOrMPC<Fr>>::PedersenRandomness::pub_rand(rng);

        let a = InputWithCommit {
            allocation: 0,
            input: input_a,
            randomness: randomness.clone(),
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

#[derive(Clone)]
pub struct WerewolfKeyInput<F: PrimeField + LocalOrMPC<F>> {
    pub mode: InputMode,
    pub peculiar: Option<WerewolfKeyPeculiarInput<F>>,
    pub common: Option<CommonInput<F>>,
}

#[derive(Clone)]
pub struct WerewolfKeyPeculiarInput<F: PrimeField + LocalOrMPC<F>> {
    pub pub_key_or_dummy_x: Vec<InputWithCommit<F>>,
    pub pub_key_or_dummy_y: Vec<InputWithCommit<F>>,
    pub is_fortune_teller: Vec<InputWithCommit<F>>,
}

impl MpcInputTrait for WerewolfKeyInput<MFr> {
    type Base = Fr;

    type Peculiar = (Vec<Fr>, Vec<Fr>, Vec<Fr>);
    type Common = CommonInput<MFr>;

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

    fn set_public_input<R: Rng>(&mut self, rng: &mut R, _input: Option<Self::Common>) {
        assert_eq!(self.get_mode(), InputMode::Init);

        let pedersen_param = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::setup(rng).unwrap();

        self.mode = InputMode::PublicSet;
        self.common = Some(CommonInput {
            pedersen_param: Parameters::<MpcEdwardsProjective>::from_local(&pedersen_param),
        });
    }

    fn set_private_input(&mut self, input: Option<Self::Peculiar>) {
        assert_eq!(self.get_mode(), InputMode::PublicSet);

        self.mode = InputMode::PrivateSet;

        let mut pub_key_or_dummy_x = vec![InputWithCommit::default(); 3];
        let mut pub_key_or_dummy_y = vec![InputWithCommit::default(); 3];

        let mut is_fortune_teller = vec![InputWithCommit::default(); 3];

        for i in 0..2 {
            pub_key_or_dummy_x[i].allocation = i;
            pub_key_or_dummy_y[i].allocation = i;
            is_fortune_teller[i].allocation = i;
        }

        match input {
            None => (),
            Some((x_values, y_values, is_fortune_teller_value)) => {
                for i in 0..2 {
                    pub_key_or_dummy_x[i].input = MFr::from_public(x_values[i]);
                    pub_key_or_dummy_y[i].input = MFr::from_public(y_values[i]);
                    is_fortune_teller[i].input = MFr::from_public(is_fortune_teller_value[i]);
                }
            }
        }

        self.peculiar = Some(WerewolfKeyPeculiarInput {
            pub_key_or_dummy_x,
            pub_key_or_dummy_y,
            is_fortune_teller,
        });
    }

    fn generate_input<R: Rng>(&mut self, rng: &mut R) {
        assert_eq!(self.get_mode(), InputMode::PrivateSet);

        self.mode = InputMode::Shared;

        let common_randomness = <MFr as LocalOrMPC<MFr>>::PedersenRandomness::pub_rand(rng);

        let pk_x = self.clone().peculiar.unwrap().pub_key_or_dummy_x;
        let pk_x_processed = pk_x
            .iter()
            .map(|iwc| {
                iwc.generate_input(
                    &self.clone().common.unwrap().pedersen_param,
                    &common_randomness,
                )
            })
            .collect::<Vec<_>>();

        let pk_y = self.clone().peculiar.unwrap().pub_key_or_dummy_y;

        let pk_y_processed = pk_y
            .iter()
            .map(|iwc| {
                iwc.generate_input(
                    &self.clone().common.unwrap().pedersen_param,
                    &common_randomness,
                )
            })
            .collect::<Vec<_>>();

        let is_ft = self.clone().peculiar.unwrap().is_fortune_teller;

        let is_ft_processed = is_ft
            .iter()
            .map(|iwc| {
                iwc.generate_input(
                    &self.clone().common.unwrap().pedersen_param,
                    &common_randomness,
                )
            })
            .collect::<Vec<_>>();

        let peculiar = WerewolfKeyPeculiarInput {
            pub_key_or_dummy_x: pk_x_processed,
            pub_key_or_dummy_y: pk_y_processed,
            is_fortune_teller: is_ft_processed,
        };

        self.peculiar = Some(peculiar);
    }

    fn rand<R: Rng>(_rng: &mut R) -> Self {
        unimplemented!()
    }
}

impl MpcInputTrait for WerewolfKeyInput<Fr> {
    type Base = Fr;

    type Peculiar = WerewolfKeyPeculiarInput<Fr>;
    type Common = CommonInput<Fr>;

    fn get_mode(&self) -> InputMode {
        unimplemented!()
    }

    fn init() -> Self {
        unimplemented!()
    }

    fn set_public_input<R: Rng>(&mut self, _rng: &mut R, _input: Option<Self::Common>) {
        unimplemented!()
    }

    fn set_private_input(&mut self, _input: Option<Self::Peculiar>) {
        unimplemented!()
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
            randomness_bit: open_bit.clone(),
            commitment: <Fr as LocalOrMPC<Fr>>::PedersenComScheme::commit(
                &params,
                &a_bytes,
                &randomness,
            )
            .unwrap(),
        };

        let input_b = Fr::rand(rng);
        let input_b_bit = input_b
            .into_repr()
            .to_bits_le()
            .iter()
            .map(|b| Fr::from(*b))
            .collect::<Vec<_>>();

        let _b_bytes = input_b.into_repr().to_bytes_le();

        let b = InputWithCommit {
            allocation: 0,
            input: input_b,
            input_bit: input_b_bit,
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
            peculiar: Some(WerewolfKeyPeculiarInput {
                pub_key_or_dummy_x: vec![a.clone(); 3],
                pub_key_or_dummy_y: vec![a.clone(); 3],
                is_fortune_teller: vec![b.clone(); 3],
            }),
            common: Some(CommonInput {
                pedersen_param: params,
            }),
        }
    }
}

#[derive(Clone)]
pub struct WerewolfMpcInput<F: PrimeField + LocalOrMPC<F> + ElGamalLocalOrMPC<F>> {
    pub mode: InputMode,
    pub peculiar: Option<WerewolfPeculiarInput<F>>,
    pub common: Option<WerewolfCommonInput<F>>,
}

#[derive(Clone)]
pub struct WerewolfPeculiarInput<F: PrimeField + LocalOrMPC<F> + ElGamalLocalOrMPC<F>> {
    pub is_werewolf: Vec<InputWithCommit<F>>,
    pub is_target: Vec<InputWithCommit<F>>,

    pub randomness: F::ElGamalRandomness,
    pub randomness_bit: Vec<F>,
}

#[derive(Clone)]
pub struct WerewolfCommonInput<F: PrimeField + LocalOrMPC<F> + ElGamalLocalOrMPC<F>> {
    pub pedersen_param: F::PedersenParam,
    pub elgamal_param: F::ElGamalParam,
    pub pub_key: F::ElGamalPubKey,
}

impl MpcInputTrait for WerewolfMpcInput<MFr> {
    type Base = Fr;

    type Peculiar = (Vec<Fr>, Vec<Fr>);
    // type Common = WerewolfCommonInput<MFr>;
    type Common = (
        <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalParam,
        <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalPubKey,
    );

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

    fn set_public_input<R: Rng>(&mut self, rng: &mut R, input: Option<Self::Common>) {
        assert_eq!(self.get_mode(), InputMode::Init);

        let pedersen_param = <Fr as LocalOrMPC<Fr>>::PedersenComScheme::setup(rng).unwrap();

        let elgamal_param = <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalScheme::setup(rng).unwrap();

        let (pk, _sk) =
            <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalScheme::keygen(&elgamal_param, rng).unwrap();

        let mut mpc_elgamal_param =
            <MFr as ElGamalLocalOrMPC<MFr>>::ElGamalParam::from_public(elgamal_param.clone());

        let mut mpc_pk = <MFr as ElGamalLocalOrMPC<MFr>>::ElGamalPubKey::from_public(pk);

        match input {
            None => (),
            Some((elgamal_param, _pub_key)) => {
                for _i in 0..2 {
                    mpc_elgamal_param = <MFr as ElGamalLocalOrMPC<MFr>>::ElGamalParam::from_public(
                        elgamal_param.clone(),
                    );
                    mpc_pk = <MFr as ElGamalLocalOrMPC<MFr>>::ElGamalPubKey::from_public(pk);
                }
            }
        }

        self.mode = InputMode::PublicSet;
        self.common = Some(WerewolfCommonInput {
            pedersen_param: Parameters::<MpcEdwardsProjective>::from_local(&pedersen_param),
            elgamal_param: mpc_elgamal_param,
            pub_key: mpc_pk,
        });
    }

    fn set_private_input(&mut self, input: Option<Self::Peculiar>) {
        assert_eq!(self.get_mode(), InputMode::PublicSet);

        // let num_peer = self.peculiar.len();

        self.mode = InputMode::PrivateSet;
        let mut is_werewolf = vec![InputWithCommit::default(); 3];
        let mut is_target = vec![InputWithCommit::default(); 3];

        for i in 0..2 {
            is_werewolf[i].allocation = i;
            is_target[i].allocation = i;
        }

        match input {
            None => (),
            Some((is_werewolf_values, is_target_values)) => {
                for i in 0..2 {
                    assert!(is_werewolf_values[i].is_zero() || is_werewolf_values[i].is_one());
                    assert!(is_target_values[i].is_zero() | is_target_values[i].is_one());
                    is_werewolf[i].input = MFr::from_public(is_werewolf_values[i]);
                    is_target[i].input = MFr::from_public(is_target_values[i]);
                }
            }
        }

        let rng = &mut ark_std::test_rng();

        let local_randomness = <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalRandomness::rand(rng);

        let mpc_randomness = <MFr as ElGamalLocalOrMPC<MFr>>::ElGamalRandomness::from_public(
            local_randomness.clone(),
        );

        let local_randomness_bit = local_randomness
            .0
            .into_repr()
            .to_bits_le()
            .iter()
            .map(|b| Fr::from(*b))
            .collect::<Vec<_>>();

        let mpc_randomness_bit = local_randomness_bit
            .iter()
            .map(|b| MFr::from_public(*b))
            .collect::<Vec<_>>();

        self.peculiar = Some(WerewolfPeculiarInput {
            is_werewolf,
            is_target,
            randomness: mpc_randomness,
            randomness_bit: mpc_randomness_bit,
        });
    }

    fn generate_input<R: Rng>(&mut self, rng: &mut R) {
        assert_eq!(self.get_mode(), InputMode::PrivateSet);

        self.mode = InputMode::Shared;

        let common_randomness = <MFr as LocalOrMPC<MFr>>::PedersenRandomness::pub_rand(rng);

        let is_werewolf = self.clone().peculiar.unwrap().is_werewolf;
        let is_werewolf = is_werewolf
            .iter()
            .map(|iwc| {
                iwc.generate_input(
                    &self.clone().common.unwrap().pedersen_param,
                    &common_randomness,
                )
            })
            .collect::<Vec<_>>();

        let is_target = is_werewolf.clone();

        let elgamal_randomness = self.clone().peculiar.unwrap().randomness;
        let elgamal_randomness_bit = self.clone().peculiar.unwrap().randomness_bit;

        let peculiar = WerewolfPeculiarInput {
            is_werewolf,
            is_target,
            randomness: elgamal_randomness,
            randomness_bit: elgamal_randomness_bit,
        };

        self.peculiar = Some(peculiar);
    }

    fn rand<R: Rng>(_rng: &mut R) -> Self {
        unimplemented!()
    }
}

impl MpcInputTrait for WerewolfMpcInput<Fr> {
    type Base = Fr;

    type Peculiar = WerewolfPeculiarInput<Fr>;
    type Common = WerewolfCommonInput<Fr>;

    fn get_mode(&self) -> InputMode {
        unimplemented!()
    }

    fn init() -> Self {
        unimplemented!()
    }

    fn set_public_input<R: Rng>(&mut self, _rng: &mut R, _input: Option<Self::Common>) {
        unimplemented!()
    }

    fn set_private_input(&mut self, _input: Option<Self::Peculiar>) {
        unimplemented!()
    }

    fn generate_input<R: Rng>(&mut self, _rng: &mut R) {
        unimplemented!()
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

        let target_id = 1;
        let is_werewolf_vec = vec![Fr::from(0), Fr::from(1), Fr::from(0)];

        // input parameters
        let elgamal_params = <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalScheme::setup(rng).unwrap();

        let (pk, _sk) =
            <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalScheme::keygen(&elgamal_params, rng).unwrap();

        let message = match is_werewolf_vec[target_id].is_one() {
            true => <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalPlaintext::prime_subgroup_generator(),
            false => <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalPlaintext::default(),
        };

        let randomness = <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalRandomness::rand(rng);

        let randomness_bit = randomness
            .0
            .into_repr()
            .to_bits_le()
            .iter()
            .map(|b| Fr::from(*b))
            .collect::<Vec<_>>();

        let _output = <Fr as ElGamalLocalOrMPC<Fr>>::ElGamalScheme::encrypt(
            &elgamal_params,
            &pk,
            &message,
            &randomness,
        )
        .unwrap();

        Self {
            mode,
            peculiar: Some(WerewolfPeculiarInput {
                is_werewolf: vec![a.clone(); 3],
                is_target: vec![a.clone(); 3],
                randomness,
                randomness_bit,
            }),
            common: Some(WerewolfCommonInput {
                pedersen_param: params,
                elgamal_param: elgamal_params,
                pub_key: pk,
            }),
        }
    }
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct DummyShareSource<T, S> {
    _scalar: PhantomData<T>,
    _share: PhantomData<S>,
}

impl<T: Field, S: FieldShare<T>> DummyShareSource<T, S> {
    pub fn zero(&mut self) -> S {
        S::from_add_shared(T::zero())
    }

    pub fn rand<R: Rng>(&mut self, rng: &mut R) -> S {
        S::from_add_shared(T::rand(rng))
    }
}

pub trait MpcSharePhase<F, S> {
    fn generate_share(&self, allocator: usize) -> Self;
}

impl<F: Field, S: FieldShare<F>> MpcSharePhase<F, S> for mpc_algebra::MpcField<F, S> {
    fn generate_share(&self, allocator: usize) -> Self {
        let mut share_source = DummyShareSource::<F, S>::default();

        let r = share_source.zero();

        // TODO: implement correctly.
        let sum_r = r.reveal();

        if Net::party_id() != allocator {
            mpc_algebra::MpcField::Shared(r)
        } else {
            Self::from_add_shared(self.unwrap_as_public() + r.unwrap_as_public() + sum_r)
        }
    }
}
