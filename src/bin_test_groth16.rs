use mpc_net::{MpcMultiNet as Net, MpcNet};
use std::path::PathBuf;
use structopt::StructOpt;

mod circuits;
mod groth16;
mod input;

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
    // groth16::mpc_test_prove_and_verify(1);
}
