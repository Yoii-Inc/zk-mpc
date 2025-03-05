use std::path::PathBuf;

use ark_crypto_primitives::{CommitmentScheme, CRH};
use ark_ff::{BigInteger, BigInteger256, FpParameters, PrimeField, UniformRand};
use ark_ff::{One, Zero};
use ark_poly::reveal;
use ark_std::PubUniformRand;
use ark_std::{end_timer, start_timer};
use log::debug;
use mpc_algebra::boolean_field::MpcBooleanField;
use mpc_algebra::honest_but_curious::MpcEdwardsProjective;
use mpc_algebra::pedersen::Randomness;
use mpc_algebra::{
    edwards2, share, AdditiveFieldShare, BitAdd, BitDecomposition, BitwiseLessThan, BooleanWire,
    CommitmentScheme as MpcCommitmentScheme, EqualityZero, LessThan, LogicalOperations,
    /* MpcEdwardsProjective,*/ MpcField, Reveal, UniformBitRand,
};
use mpc_net::multi::MPCNetConnection;
use mpc_net::{MpcMultiNet as Net, MpcNet};

use rand::rngs::StdRng;
use rand::SeedableRng;
use structopt::StructOpt;

use futures::future::join_all;
#[derive(Debug, StructOpt)]
#[structopt(name = "example", about = "An example of StructOpt usage.")]
struct Opt {
    /// Id
    id: usize,

    /// Input file
    #[structopt(parse(from_os_str))]
    input: PathBuf,
}

type F = ark_bls12_377::Fr;
type S = AdditiveFieldShare<F>;
type MF = MpcField<F, S>;
type MBF = MpcBooleanField<F, S>;

async fn test_add() {
    // init communication protocol

    // calculate
    let pub_a = MF::from_public(F::from(1u64));
    let pub_b = MF::from_public(F::from(2u64));

    let c = pub_a + pub_b;
    assert_eq!(c.reveal().await, F::from(3u64));
}

async fn test_sub() {
    let pub_a = MF::from_public(F::from(1u64));
    let pub_b = MF::from_public(F::from(2u64));

    let c = pub_a - pub_b;
    assert_eq!(c.reveal().await, -F::from(1u64));
}

async fn test_mul() {
    let pub_a = MF::from_public(F::from(1u64));
    let pub_b = MF::from_public(F::from(2u64));

    let c = pub_a * pub_b;
    assert_eq!(c.reveal().await, F::from(2u64));
}

async fn test_div() {
    let pub_a = MF::from_public(F::from(2u64));
    let pub_b = MF::from_public(F::from(1u64));

    let c = pub_a / pub_b;
    assert_eq!(c.reveal().await, F::from(2u64));
}

async fn test_sum() {
    let a = [
        MF::from_public(F::from(1u64)),
        MF::from_public(F::from(2u64)),
        MF::from_public(F::from(3u64)),
    ];

    let result = a.iter().sum::<MF>();

    assert_eq!(result.reveal().await, F::from(6u64));
}

async fn test_bit_rand() {
    let rng = &mut StdRng::from_entropy();
    let mut counter = [0, 0, 0];

    for _ in 0..1000 {
        let a = MBF::bit_rand(rng).await.reveal().await;

        if a.is_zero() {
            counter[0] += 1;
        } else if a.is_one() {
            counter[1] += 1;
        } else {
            counter[2] += 1;
        }
    }

    assert_eq!(counter[2], 0); // should be 0 (no other value than 0 or 1 is allowed in the current implementation
    println!("{:?}", counter);
}

async fn test_rand_number_bitwise() {
    let rng = &mut StdRng::from_entropy();

    for _ in 0..10 {
        let (a, b) = MBF::rand_number_bitwise(rng).await;

        let revealed_a = a.iter().map(|x| x.sync_reveal()).collect::<Vec<_>>();
        let revealed_b = b.reveal().await;

        // bits representation is given in little-endian

        let a_as_bigint =
            BigInteger256::from_bits_le(&revealed_a.iter().map(|x| x.is_one()).collect::<Vec<_>>());

        assert!(
            a_as_bigint
                < <ark_ff::Fp256<ark_bls12_377::FrParameters> as ark_ff::PrimeField>::Params::MODULUS
        );

        let a_as_field = F::from_repr(a_as_bigint).unwrap();

        assert_eq!(a_as_field, revealed_b);
    }
}

async fn test_bitwise_lt() {
    let modulus_size =
        <ark_ff::Fp256<ark_bls12_377::FrParameters> as ark_ff::PrimeField>::Params::MODULUS_BITS;

    let rng = &mut StdRng::from_entropy();

    for _ in 0..10 {
        let mut a = Vec::with_capacity(modulus_size as usize);
        let mut b = Vec::with_capacity(modulus_size as usize);

        for _ in 0..modulus_size {
            a.push(MBF::bit_rand(rng).await);
            b.push(MBF::bit_rand(rng).await);
        }

        let a_bigint = BigInteger256::from_bits_le(
            &join_all(a.iter().map(|x| async move { x.reveal().await.is_one() })).await,
        );

        let b_bigint = BigInteger256::from_bits_le(
            &join_all(b.iter().map(|x| async move { x.reveal().await.is_one() })).await,
        );

        let res_1 = a_bigint < b_bigint;
        let res_2 = a.is_smaller_than_le(&b);

        assert_eq!(res_1, res_2.reveal().await.is_one());
    }
}

async fn test_interval_test_half_modulus() {
    let rng = &mut StdRng::from_entropy();
    let half_modulus =
        <<ark_ff::Fp256<ark_bls12_377::FrParameters> as ark_ff::PrimeField>::Params>::MODULUS_MINUS_ONE_DIV_TWO;

    let n = 10;
    let timer = start_timer!(|| format!("interval_test_half_modulus test x {}", n));
    // TODO: Test boundary conditions
    for _ in 0..n {
        let shared = MF::rand(rng);
        let res = shared
            .is_smaller_or_equal_than_mod_minus_one_div_two()
            .await;
        assert_eq!(
            res.reveal().await,
            if shared.reveal().await.into_repr() < half_modulus {
                F::one()
            } else {
                F::zero()
            }
        );
    }
    end_timer!(timer);
}

async fn test_less_than() {
    let rng = &mut StdRng::from_entropy();

    let n = 10;
    let timer = start_timer!(|| format!("less_than test x {}", n));
    for _ in 0..n {
        let a = MF::rand(rng);
        let b = MF::rand(rng);

        let res = a.is_smaller_than(&b).await;
        if res.reveal().await.is_one() != (a.reveal().await < b.reveal().await) {
            println!("a: {:?}, b: {:?}", a.reveal().await, b.reveal().await);
            println!("res: {:?}", res.reveal().await);
            assert_eq!(
                res.reveal().await.is_one(),
                a.reveal().await < b.reveal().await
            );
        }
    }
    end_timer!(timer);
}

async fn test_and() {
    let rng = &mut StdRng::from_entropy();

    let a00 = vec![MBF::pub_false(), MBF::pub_true()];
    let a10 = vec![MBF::pub_true(), MBF::pub_false()];
    let a11 = vec![MBF::pub_true(), MBF::pub_true()];

    assert_eq!(a00.kary_and().await.reveal().await, F::zero());
    assert_eq!(a10.kary_and().await.reveal().await, F::zero());
    assert_eq!(a11.kary_and().await.reveal().await, F::one());

    let mut counter = [0, 0];

    for _ in 0..100 {
        let mut a = Vec::with_capacity(3);

        for _ in 0..3 {
            a.push(MBF::bit_rand(rng).await);
        }

        let res = a.kary_and().await;

        println!("unbounded and is {:?}", res.reveal().await);
        if res.reveal().await.is_zero() {
            counter[0] += 1;
        } else if res.reveal().await.is_one() {
            counter[1] += 1;
        }
    }
    println!("AND counter is {:?}", counter);
}

async fn test_or() {
    let rng = &mut StdRng::from_entropy();

    let a00 = vec![MBF::pub_false(), MBF::pub_false()];
    let a10 = vec![MBF::pub_true(), MBF::pub_false()];
    let a11 = vec![MBF::pub_true(), MBF::pub_true()];

    assert_eq!(a00.kary_or().await.reveal().await, F::zero());
    assert_eq!(a10.kary_or().await.reveal().await, F::one());
    assert_eq!(a11.kary_or().await.reveal().await, F::one());

    let mut counter = [0, 0];

    for _ in 0..100 {
        let mut a = Vec::with_capacity(3);

        for _ in 0..3 {
            a.push(MBF::bit_rand(rng).await);
        }

        let res = a.kary_or().await;

        // println!("unbounded or is {:?}", res.reveal());
        if res.reveal().await.is_zero() {
            counter[0] += 1;
        } else if res.reveal().await.is_one() {
            counter[1] += 1;
        }
    }
    println!("OR counter is {:?}", counter);
}

async fn test_xor() {
    let mut rng = ark_std::test_rng();
    let mut counter = [0, 0];

    for _ in 0..100 {
        let a = MBF::bit_rand(&mut rng).await;
        let b = MBF::bit_rand(&mut rng).await;

        let res = a ^ b;

        println!("unbounded and is {:?}", res.reveal().await);
        assert_eq!(
            res.reveal().await.is_one(),
            a.reveal().await.is_one() ^ b.reveal().await.is_one()
        );
        if res.reveal().await.is_zero() {
            counter[0] += 1;
        } else if res.reveal().await.is_one() {
            counter[1] += 1;
        }
    }
    println!("AND counter is {:?}", counter);
}

async fn test_equality_zero() {
    let mut rng = ark_std::test_rng();

    // a is zero
    let a = MF::from_add_shared(F::zero());
    let res = a.is_zero_shared().await;
    assert!(res.reveal().await.is_one());

    // a is not zero
    let a = MF::from_add_shared(F::one());
    let res = a.is_zero_shared().await;
    assert!(res.reveal().await.is_zero());

    let n = 10;
    let timer = start_timer!(|| format!("is_zero_shared test x {}", n));
    // a is random number
    for _ in 0..n {
        let a = MF::rand(&mut rng);

        let res = a.is_zero_shared().await;

        assert_eq!(a.reveal().await.is_zero(), res.reveal().await.is_one());
        assert_eq!(!a.reveal().await.is_zero(), res.reveal().await.is_zero());
    }
    end_timer!(timer);
}

async fn test_carries() {
    // a = 0101 = 5, b = 1100= 12
    let mut a = vec![MBF::from_add_shared(F::zero()); 4];
    let mut b = vec![MBF::from_add_shared(F::zero()); 4];
    // TODO: improve how to initialize
    a[0] = a[0] | MBF::pub_true();
    a[2] = a[2] | MBF::pub_true();
    b[2] = b[2] | MBF::pub_true();
    b[3] = b[3] | MBF::pub_true();

    // TODO: better way to initialize

    let c = a.carries(&b);

    // expected carries: 1100
    assert_eq!(
        c.reveal().await,
        vec![F::zero(), F::zero(), F::one(), F::one()]
    );

    // a = 010011 = 19, b = 101010= 42
    let mut a = vec![MBF::from_add_shared(F::from(0u64)); 6];
    let mut b = vec![MBF::from_add_shared(F::from(0u64)); 6];
    a[0] = a[0] | MBF::pub_true();
    a[1] = a[1] | MBF::pub_true();
    a[4] = a[4] | MBF::pub_true();
    b[1] = b[1] | MBF::pub_true();
    b[3] = b[3] | MBF::pub_true();
    b[5] = b[5] | MBF::pub_true();

    let c = a.carries(&b);

    // expected carries: 000010
    assert_eq!(
        c.reveal().await,
        vec![
            F::zero(),
            F::one(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero()
        ]
    );
}

async fn test_bit_add() {
    let rng = &mut StdRng::from_entropy();

    let (rand_a, a) = MBF::rand_number_bitwise(rng).await;
    let (rand_b, b) = MBF::rand_number_bitwise(rng).await;

    let c_vec = rand_a.bit_add(&rand_b);

    let c = c_vec
        .reveal()
        .await
        .iter()
        .rev()
        .fold(F::zero(), |acc, x| acc * F::from(2u64) + x);

    assert_eq!(c, (a + b).reveal().await);
}

async fn test_bit_decomposition() {
    let rng = &mut StdRng::from_entropy();

    let random = MF::rand(rng);

    let bit = random.bit_decomposition().await;

    let res = bit
        .reveal()
        .await
        .iter()
        .rev()
        .fold(F::zero(), |acc, x| acc * F::from(2u64) + x);

    assert_eq!(res, random.reveal().await);
}

pub const PERDERSON_WINDOW_SIZE: usize = 256;
pub const PERDERSON_WINDOW_NUM: usize = 1;

#[derive(Clone)]
pub struct Window;
impl ark_crypto_primitives::crh::pedersen::Window for Window {
    const WINDOW_SIZE: usize = PERDERSON_WINDOW_SIZE;
    const NUM_WINDOWS: usize = PERDERSON_WINDOW_NUM;
}

impl mpc_algebra::crh::pedersen::Window for Window {
    const WINDOW_SIZE: usize = PERDERSON_WINDOW_SIZE;
    const NUM_WINDOWS: usize = PERDERSON_WINDOW_NUM;
}

type LocalPed = ark_crypto_primitives::commitment::pedersen::Commitment<
    ark_ed_on_bls12_377::EdwardsProjective,
    Window,
>;
type MpcPed = mpc_algebra::commitment::pedersen::Commitment<MpcEdwardsProjective, Window>;

async fn test_pedersen_commitment() {
    let rng = &mut ark_std::test_rng();

    let x = ark_ed_on_bls12_377::Fr::rand(rng);
    let mpc_x = MpcField::<ark_ed_on_bls12_377::Fr, AdditiveFieldShare<ark_ed_on_bls12_377::Fr>>::from_public(x);

    let x_bytes = x.into_repr().to_bytes_le();

    // mpc calculation
    let mpc_parameters = MpcPed::setup(rng).unwrap();

    let randomness = Randomness::<MpcEdwardsProjective>::rand(rng);

    let result_mpc = MpcPed::commit(
        &mpc_parameters,
        &<MpcPed as MpcCommitmentScheme>::Input::new(mpc_x),
        &randomness,
    )
    .unwrap();

    // local calculation
    let local_parameters = ark_crypto_primitives::commitment::pedersen::Parameters {
        randomness_generator: mpc_parameters.randomness_generator.clone().reveal().await,
        generators: mpc_parameters.generators.reveal().await,
    };

    let local_randomness =
        ark_crypto_primitives::commitment::pedersen::Randomness(randomness.0.reveal().await);

    let result_local =
        <LocalPed as CommitmentScheme>::commit(&local_parameters, &x_bytes, &local_randomness)
            .unwrap();

    assert_eq!(result_local, result_mpc.reveal().await);
}

async fn test_share() {
    let rng = &mut ark_std::test_rng();

    for i in 0..100 {
        let init = F::pub_rand(rng);
        let share = MF::king_share(init, rng);
        let revealed = share.reveal().await;

        assert_eq!(revealed, init);
    }
}

#[tokio::main]
async fn main() {
    env_logger::builder().format_timestamp(None).init();
    debug!("Start");
    let opt = Opt::from_args();
    println!("{:?}", opt);

    let mut net = MPCNetConnection::init_from_path(&opt.input, opt.id as u32);
    net.listen().await.unwrap();
    net.connect_to_all().await.unwrap();

    Net::simulate(net, (), |_, _| async {
        println!("Test started");
        test_add().await;
        println!("Test add passed");
        test_sub().await;
        println!("Test sub passed");
        test_mul().await;
        println!("Test mul passed");
        test_div().await;
        println!("Test div passed");
        test_sum().await;
        println!("Test sum passed");

        test_bit_rand().await;
        println!("Test bit_rand passed");
        test_less_than().await;
        println!("Test less_than passed");
        test_interval_test_half_modulus().await;
        println!("Test interval_test_half_modulus passed");
        test_rand_number_bitwise().await;
        println!("Test rand_number_bitwise passed");
        test_bitwise_lt().await;
        println!("Test bitwise_lt passed");
        test_and().await;
        println!("Test and passed");
        test_or().await;
        println!("Test or passed");
        test_xor().await;
        println!("Test xor passed");
        test_equality_zero().await;
        println!("Test equality_zero passed");

        test_carries().await;
        println!("Test carries passed");
        test_bit_add().await;
        println!("Test bit_add passed");
        test_bit_decomposition().await;
        println!("Test bit_decomposition passed");

        test_pedersen_commitment().await;
        println!("Test pedersen commitment passed");

        test_share().await;
        println!("Tes_t share passed");
    })
    .await;
}
