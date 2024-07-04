use std::path::PathBuf;

use ark_crypto_primitives::{CommitmentScheme, CRH};
use ark_ff::PubUniformRand;
use ark_ff::{BigInteger, BigInteger256, FpParameters, PrimeField, UniformRand};
use ark_ff::{One, Zero};
use ark_poly::reveal;
use ark_std::PubUniformRand;
use ark_std::{end_timer, start_timer};
use log::debug;
use mpc_algebra::pedersen::Randomness;
use mpc_algebra::boolean_field::MpcBooleanField;
use mpc_algebra::{
    edwards2, share, AdditiveFieldShare, BitAdd, BitDecomposition, BitwiseLessThan, BooleanWire,
    CommitmentScheme as MpcCommitmentScheme, EqualityZero, LessThan,
    LogicalOperations,
    MpcEdwardsProjective, MpcField, Reveal, UniformBitRand,
};
use mpc_net::{MpcMultiNet as Net, MpcNet};

use rand::thread_rng;
use structopt::StructOpt;

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

fn test_add() {
    // init communication protocol

    // calculate
    let pub_a = MF::from_public(F::from(1u64));
    let pub_b = MF::from_public(F::from(2u64));

    let c = pub_a + pub_b;
    assert_eq!(c.reveal(), F::from(3u64));
}

fn test_sub() {
    let pub_a = MF::from_public(F::from(1u64));
    let pub_b = MF::from_public(F::from(2u64));

    let c = pub_a - pub_b;
    assert_eq!(c.reveal(), -F::from(1u64));
}

fn test_mul() {
    let pub_a = MF::from_public(F::from(1u64));
    let pub_b = MF::from_public(F::from(2u64));

    let c = pub_a * pub_b;
    assert_eq!(c.reveal(), F::from(2u64));
}

fn test_div() {
    let pub_a = MF::from_public(F::from(2u64));
    let pub_b = MF::from_public(F::from(1u64));

    let c = pub_a / pub_b;
    assert_eq!(c.reveal(), F::from(2u64));
}

fn test_sum() {
    let a = [
        MF::from_public(F::from(1u64)),
        MF::from_public(F::from(2u64)),
        MF::from_public(F::from(3u64)),
    ];

    let result = a.iter().sum::<MF>();

    assert_eq!(result.reveal(), F::from(6u64));
}

fn test_bit_rand() {
    let mut rng = thread_rng();
    let mut counter = [0, 0, 0];

    for _ in 0..1000 {
        let a = MBF::bit_rand(&mut rng).reveal();

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

fn test_rand_number_bitwise() {
    let mut rng = thread_rng();

    for _ in 0..10 {
        let (a, b) = MBF::rand_number_bitwise(&mut rng);

        let revealed_a = a.iter().map(|x| x.reveal()).collect::<Vec<_>>();
        let revealed_b = b.reveal();

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

fn test_bitwise_lt() {
    let modulus_size =
        <ark_ff::Fp256<ark_bls12_377::FrParameters> as ark_ff::PrimeField>::Params::MODULUS_BITS;

    let rng = &mut thread_rng();

    for _ in 0..10 {
        let a = (0..modulus_size)
            .map(|_| MBF::bit_rand(rng))
            .collect::<Vec<_>>();
        let b = (0..modulus_size)
            .map(|_| MBF::bit_rand(rng))
            .collect::<Vec<_>>();

        let a_bigint =
            BigInteger256::from_bits_le(&a.iter().map(|x| x.reveal().is_one()).collect::<Vec<_>>());

        let b_bigint =
            BigInteger256::from_bits_le(&b.iter().map(|x| x.reveal().is_one()).collect::<Vec<_>>());

        let res_1 = a_bigint < b_bigint;
        let res_2 = a.is_smaller_than_le(&b);

        assert_eq!(res_1, res_2.reveal().is_one());
    }
}

fn test_interval_test_half_modulus() {
    let rng = &mut thread_rng();
    let half_modulus =
        <<ark_ff::Fp256<ark_bls12_377::FrParameters> as ark_ff::PrimeField>::Params>::MODULUS_MINUS_ONE_DIV_TWO;

    let n = 10;
    let timer = start_timer!(|| format!("interval_test_half_modulus test x {}", n));
    // TODO: Test boundary conditions
    for _ in 0..n {
        let shared = MF::rand(rng);
        let res = shared.is_smaller_or_equal_than_mod_minus_one_div_two();
        assert_eq!(
            res.reveal(),
            if shared.reveal().into_repr() < half_modulus {
                F::one()
            } else {
                F::zero()
            }
        );
    }
    end_timer!(timer);
}

fn test_less_than() {
    let rng = &mut thread_rng();

    let n = 10;
    let timer = start_timer!(|| format!("less_than test x {}", n));
    for _ in 0..n {
        let a = MF::rand(rng);
        let b = MF::rand(rng);

        let res = a.is_smaller_than(&b);
        if res.reveal().is_one() != (a.reveal() < b.reveal()) {
            println!("a: {:?}, b: {:?}", a.reveal(), b.reveal());
            println!("res: {:?}", res.reveal());
            assert_eq!(res.reveal().is_one(), a.reveal() < b.reveal());
        }
    }
    end_timer!(timer);
}

fn test_and() {
    let mut rng = ark_std::test_rng();

    let a00 = vec![MBF::pub_false(), MBF::pub_true()];
    let a10 = vec![MBF::pub_true(), MBF::pub_false()];
    let a11 = vec![MBF::pub_true(), MBF::pub_true()];

    assert_eq!(a00.kary_and().reveal(), F::zero());
    assert_eq!(a10.kary_and().reveal(), F::zero());
    assert_eq!(a11.kary_and().reveal(), F::one());

    let mut counter = [0, 0];

    for _ in 0..100 {
        let a = (0..3).map(|_| MBF::bit_rand(&mut rng)).collect::<Vec<_>>();

        let res = a.kary_and();

        println!("unbounded and is {:?}", res.reveal());
        if res.reveal().is_zero() {
            counter[0] += 1;
        } else if res.reveal().is_one() {
            counter[1] += 1;
        }
    }
    println!("AND counter is {:?}", counter);
}

fn test_or() {
    let mut rng = thread_rng();

    let a00 = vec![MBF::pub_false(), MBF::pub_false()];
    let a10 = vec![MBF::pub_true(), MBF::pub_false()];
    let a11 = vec![MBF::pub_true(), MBF::pub_true()];

    assert_eq!(a00.kary_or().reveal(), F::zero());
    assert_eq!(a10.kary_or().reveal(), F::one());
    assert_eq!(a11.kary_or().reveal(), F::one());

    let mut counter = [0, 0];

    for _ in 0..100 {
        let a = (0..3).map(|_| MBF::bit_rand(&mut rng)).collect::<Vec<_>>();

        let res = a.kary_or();

        // println!("unbounded or is {:?}", res.reveal());
        if res.reveal().is_zero() {
            counter[0] += 1;
        } else if res.reveal().is_one() {
            counter[1] += 1;
        }
    }
    println!("OR counter is {:?}", counter);
}

fn test_xor() {
    let mut rng = ark_std::test_rng();
    let mut counter = [0, 0];

    for _ in 0..100 {
        let a = MBF::bit_rand(&mut rng);
        let b = MBF::bit_rand(&mut rng);

        let res = a ^ b;

        println!("unbounded and is {:?}", res.reveal());
        assert_eq!(
            res.reveal().is_one(),
            a.reveal().is_one() ^ b.reveal().is_one()
        );
        if res.reveal().is_zero() {
            counter[0] += 1;
        } else if res.reveal().is_one() {
            counter[1] += 1;
        }
    }
    println!("AND counter is {:?}", counter);
}

fn test_equality_zero() {
    let mut rng = ark_std::test_rng();

    // a is zero
    let a = MF::from_add_shared(F::zero());
    let res = a.is_zero_shared();
    assert!(res.reveal().is_one());

    // a is not zero
    let a = MF::from_add_shared(F::one());
    let res = a.is_zero_shared();
    assert!(res.reveal().is_zero());

    let n = 10;
    let timer = start_timer!(|| format!("is_zero_shared test x {}", n));
    // a is random number
    for _ in 0..n {
        let a = MF::rand(&mut rng);

        let res = a.is_zero_shared();

        assert_eq!(a.reveal().is_zero(), res.reveal().is_one());
        assert_eq!(!a.reveal().is_zero(), res.reveal().is_zero());
    }
    end_timer!(timer);
}

fn test_carries() {
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
    assert_eq!(c.reveal(), vec![F::zero(), F::zero(), F::one(), F::one()]);

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
        c.reveal(),
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

fn test_bit_add() {
    let rng = &mut thread_rng();

    let (rand_a, a) = MBF::rand_number_bitwise(rng);
    let (rand_b, b) = MBF::rand_number_bitwise(rng);

    let c_vec = rand_a.bit_add(&rand_b);

    let c = c_vec
        .reveal()
        .iter()
        .rev()
        .fold(F::zero(), |acc, x| acc * F::from(2u64) + x);

    assert_eq!(c, (a + b).reveal());
}

fn test_bit_decomposition() {
    let rng = &mut thread_rng();

    let random = MF::rand(rng);

    let bit = random.bit_decomposition();

    let res = bit
        .reveal()
        .iter()
        .rev()
        .fold(F::zero(), |acc, x| acc * F::from(2u64) + x);

    assert_eq!(res, random.reveal());
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
type MpcPed = mpc_algebra::commitment::pedersen::Commitment<edwards2::MpcEdwardsProjective, Window>;

fn test_pedersen_commitment() {
    let rng = &mut ark_std::test_rng();

    let x = F::rand(rng);
    let x_bytes = x.into_repr().to_bytes_le();
    let x_bits = x.into_repr().to_bits_le();

    // mpc calculation
    let mpc_parameters = MpcPed::setup(rng).unwrap();

    let scalar_x_bytes = if Net::am_king() {
        x_bits
        .iter()
        .map(|b| {
            MpcField::<ark_ed_on_bls12_377::Fr, AdditiveFieldShare<ark_ed_on_bls12_377::Fr>>::from_add_shared(ark_ed_on_bls12_377::Fr::from(*b))
        })
        .collect::<Vec<_>>()
    } else {
        x_bits
        .iter()
        .map(|b| {
            MpcField::<ark_ed_on_bls12_377::Fr, AdditiveFieldShare<ark_ed_on_bls12_377::Fr>>::from_add_shared(ark_ed_on_bls12_377::Fr::zero())
        })
        .collect::<Vec<_>>()
    };

    let randomness = Randomness::<MpcEdwardsProjective>::rand(rng);

    let result_mpc = MpcPed::commit(&mpc_parameters, &scalar_x_bytes, &randomness).unwrap();

    // local calculation
    let local_parameters = ark_crypto_primitives::commitment::pedersen::Parameters {
        randomness_generator: mpc_parameters.randomness_generator.clone().reveal(),
        generators: mpc_parameters.generators.reveal(),
    };

    let local_randomness =
        ark_crypto_primitives::commitment::pedersen::Randomness(randomness.0.reveal());

    let result_local = LocalPed::commit(&local_parameters, &x_bytes, &local_randomness).unwrap();

    assert_eq!(result_local, result_mpc.reveal());
}

fn test_share() {
    let rng = &mut ark_std::test_rng();

    for i in 0..100 {
        let init = F::pub_rand(rng);
        let share = MF::king_share(init, rng);
        let revealed = share.reveal();

        assert_eq!(revealed, init);
    }
}

fn main() {
    env_logger::builder().format_timestamp(None).init();
    debug!("Start");
    let opt = Opt::from_args();
    println!("{:?}", opt);
    Net::init_from_file(opt.input.to_str().unwrap(), opt.id);

    println!("Test started");
    test_add();
    println!("Test add passed");
    test_sub();
    println!("Test sub passed");
    test_mul();
    println!("Test mul passed");
    test_div();
    println!("Test div passed");
    test_sum();
    println!("Test sum passed");

    test_bit_rand();
    println!("Test bit_rand passed");
    test_less_than();
    println!("Test less_than passed");
    test_interval_test_half_modulus();
    println!("Test interval_test_half_modulus passed");
    test_rand_number_bitwise();
    println!("Test rand_number_bitwise passed");
    test_bitwise_lt();
    println!("Test bitwise_lt passed");
    test_and();
    println!("Test and passed");
    test_or();
    println!("Test or passed");
    test_xor();
    println!("Test xor passed");
    test_equality_zero();
    println!("Test equality_zero passed");

    test_carries();
    println!("Test carries passed");
    test_bit_add();
    println!("Test bit_add passed");
    test_bit_decomposition();
    println!("Test bit_decomposition passed");

    test_pedersen_commitment();
    println!("Test pedersen commitment passed");

    test_share();
    println!("Test share passed");
}
