use log::debug;
use mpc_net::{MpcMultiNet, MpcNet};

use std::path::PathBuf;
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

fn main() {
    env_logger::builder()
        .format_timestamp(None)
        .format_module_path(false)
        .init();
    debug!("Start");
    let opt = Opt::from_args();
    println!("{:?}", opt);
    MpcMultiNet::init_from_file(opt.input.to_str().unwrap(), opt.id);
    let all = MpcMultiNet::broadcast_bytes(&[opt.id as u8]);
    println!("{:?}", all);
    let r = MpcMultiNet::worker_send_or_leader_receive(&[opt.id as u8]);
    let all = MpcMultiNet::worker_receive_or_leader_send(r);
    println!("{:?}", all);
    // TODO
    MpcMultiNet::uninit();
}
