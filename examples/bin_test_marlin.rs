use mpc_net::{MpcMultiNet as Net, MpcNet};
use std::path::PathBuf;
use structopt::StructOpt;

use zk_mpc::marlin;

#[derive(Debug, StructOpt)]
#[structopt(name = "example", about = "An example of StructOpt usage.")]
struct Opt {
    /// Id
    id: usize,

    /// Input file
    #[structopt(parse(from_os_str))]
    input: PathBuf,
}

fn main() {
    let opt = Opt::from_args();
    Net::init_from_file(opt.input.to_str().unwrap(), opt.id);
    marlin::mpc_test_prove_and_verify(1);
    marlin::mpc_test_prove_and_verify_pedersen(1);
    marlin::test_equality_zero(1);
    marlin::test_bit_decomposition(1);
    marlin::test_enforce_smaller_eq_than(5);
}
