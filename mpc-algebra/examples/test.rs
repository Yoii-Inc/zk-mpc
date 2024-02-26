use std::path::PathBuf;

use ark_ff::{One, Zero};
use ark_poly::reveal;
use log::debug;
use mpc_algebra::{
    AdditiveFieldShare, EqualityZero, LogicalOperations, MpcField, Reveal, UniformBitRand,
};
use mpc_net::{MpcMultiNet as Net, MpcNet};

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

fn test_bits_rand() {
    let mut rng = ark_std::test_rng();

    let (a, b) = MF::bits_rand(&mut rng);

    let revealed_a = a.iter().map(|x| x.reveal()).collect::<Vec<_>>();
    let revealed_b = b.reveal();

    // bits representation is given in big-endian
    let sum = revealed_a
        .iter()
        .fold(F::zero(), |acc, x| acc * F::from(2) + x);

    assert_eq!(sum, revealed_b);
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

    let mut counter = [0, 0];

    // a is zero
    let a = MF::from_add_shared(F::zero());
    let res = a.is_zero_shared();
    assert!(res.reveal().is_one());

    // a is not zero
    let a = MF::from_add_shared(F::one());
    let res = a.is_zero_shared();
    assert!(res.reveal().is_zero());

    // a is random bit
    for _ in 0..10 {
        let a = MF::bit_rand(&mut rng);

        let res = a.is_zero_shared();

        println!("is_zero is {:?}", res.reveal());

        if res.reveal().is_zero() {
            counter[0] += 1;
        } else if res.reveal().is_one() {
            counter[1] += 1;
        }
    }
    println!("{:?}", counter);
}

fn main() {
    env_logger::builder().format_timestamp(None).init();
    debug!("Start");
    let opt = Opt::from_args();
    println!("{:?}", opt);
    Net::init_from_file(opt.input.to_str().unwrap(), opt.id);

    test_add();
    test_sub();
    test_mul();
    test_div();
    test_sum();

    test_bit_rand();
    test_bits_rand();
    test_and();
    test_or();
    test_equality_zero();
}
