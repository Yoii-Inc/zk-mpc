use std::path::PathBuf;

use log::debug;
use mpc_algebra::{AdditiveFieldShare, MpcField, Reveal};
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

fn main() {
    env_logger::builder().format_timestamp(None).init();
    debug!("Start");
    let opt = Opt::from_args();
    println!("{:?}", opt);
    Net::init_from_file(opt.input.to_str().unwrap(), opt.id);

    test_add();
}
