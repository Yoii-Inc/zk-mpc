use std::path::PathBuf;

use ark_ff::{BigInteger, BigInteger256, Field, FpParameters, PrimeField, UniformRand};
use ark_ff::{One, Zero};
use ark_poly::reveal;
use log::debug;
use mpc_algebra::{
    AdditiveFieldShare, BitwiseLessThan, EqualityZero, LogicalOperations, MpcField, Reveal,
    UniformBitRand,
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
    let a = vec![
        MF::from_public(F::from(1u64)),
        MF::from_public(F::from(2u64)),
        MF::from_public(F::from(3u64)),
    ];

    let result = a.iter().sum::<MF>();

    assert_eq!(result.reveal(), F::from(6u64));
}

fn test_bit_rand() {
    let mut rng = ark_std::test_rng();
    let mut counter = [0, 0, 0];

    for _ in 0..1000 {
        let a = MF::bit_rand(&mut rng).reveal();

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
        let (a, b) = MF::rand_number_bitwise(&mut rng);

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
            .map(|_| MF::bit_rand(rng))
            .collect::<Vec<_>>();
        let b = (0..modulus_size)
            .map(|_| MF::bit_rand(rng))
            .collect::<Vec<_>>();

        let a_bigint =
            BigInteger256::from_bits_le(&a.iter().map(|x| x.reveal().is_one()).collect::<Vec<_>>());

        let b_bigint =
            BigInteger256::from_bits_le(&b.iter().map(|x| x.reveal().is_one()).collect::<Vec<_>>());

        let res_1 = a_bigint < b_bigint;
        let res_2 = a.bitwise_lt(&b);

        assert_eq!(res_1, res_2.reveal().is_one());
    }
}

fn test_and() {
    let mut rng = ark_std::test_rng();

    let a00 = vec![MF::zero(), MF::zero()];
    let a10 = vec![MF::one(), MF::zero()];
    let a11 = vec![MF::one(), MF::one()];

    assert_eq!(a00.unbounded_fan_in_and().reveal(), F::zero());
    assert_eq!(a10.unbounded_fan_in_and().reveal(), F::zero());
    assert_eq!(a11.unbounded_fan_in_and().reveal(), F::one());

    let mut counter = [0, 0];

    for _ in 0..100 {
        let a = (0..3).map(|_| MF::bit_rand(&mut rng)).collect::<Vec<_>>();

        let res = a.unbounded_fan_in_and();

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
    let mut rng = ark_std::test_rng();

    let a00 = vec![MF::zero(), MF::zero()];
    let a10 = vec![MF::one(), MF::zero()];
    let a11 = vec![MF::one(), MF::one()];

    assert_eq!(a00.unbounded_fan_in_or().reveal(), F::zero());
    assert_eq!(a10.unbounded_fan_in_or().reveal(), F::one());
    assert_eq!(a11.unbounded_fan_in_or().reveal(), F::one());

    let mut counter = [0, 0];

    for _ in 0..100 {
        let a = (0..3).map(|_| MF::bit_rand(&mut rng)).collect::<Vec<_>>();

        let res = a.unbounded_fan_in_or();

        println!("unbounded or is {:?}", res.reveal());
        if res.reveal().is_zero() {
            counter[0] += 1;
        } else if res.reveal().is_one() {
            counter[1] += 1;
        }
    }
    println!("OR counter is {:?}", counter);
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

    // a is random number
    for _ in 0..10 {
        let a = MF::rand(&mut rng);

        let res = a.is_zero_shared();

        assert_eq!(a.reveal().is_zero(), res.reveal().is_one());
        assert_eq!(!a.reveal().is_zero(), res.reveal().is_zero());
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
    test_rand_number_bitwise();
    println!("Test rand_number_bitwise passed");
    test_bitwise_lt();
    println!("Test bitwise_lt passed");
    test_and();
    println!("Test and passed");
    test_or();
    println!("Test or passed");
    test_equality_zero();
    println!("Test equality_zero passed");
}
