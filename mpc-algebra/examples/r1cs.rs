use std::path::PathBuf;

use ark_ff::UniformRand;
use ark_ff::Zero;
use ark_r1cs_std::alloc::AllocVar;
use ark_relations::r1cs::{ConstraintSystem, SynthesisError};
use log::debug;
use mpc_algebra::{AdditiveFieldShare, MpcBoolean, MpcEqGadget, MpcField, MpcFpVar, Reveal};
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

fn test_equality_zero() -> Result<(), SynthesisError> {
    let cs = ConstraintSystem::<MF>::new_ref();

    // failure case
    let a = MF::rand(&mut thread_rng());
    let a_var = MpcFpVar::new_witness(cs.clone(), || Ok(a))?;

    a_var.is_zero()?.enforce_equal(&MpcBoolean::FALSE)?;

    assert!(!cs.is_satisfied().unwrap());

    // success case
    let zero = MF::from_add_shared(F::zero());
    let zero_var = MpcFpVar::new_witness(cs.clone(), || Ok(zero))?;

    zero_var.is_zero()?.enforce_equal(&MpcBoolean::TRUE)?;

    Ok(())
}

fn main() {
    env_logger::builder().format_timestamp(None).init();
    debug!("Start");
    let opt = Opt::from_args();
    println!("{:?}", opt);
    Net::init_from_file(opt.input.to_str().unwrap(), opt.id);

    println!("Test started");
    test_equality_zero();
}
