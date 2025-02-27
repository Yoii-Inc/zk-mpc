use mpc_net::{multi::MPCNetConnection, MpcMultiNet as Net};
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

#[tokio::main]
async fn main() {
    let opt = Opt::from_args();

    let mut net = MPCNetConnection::init_from_path(&opt.input, opt.id as u32);
    net.listen().await.unwrap();
    net.connect_to_all().await.unwrap();

    Net::simulate(net, |_| async {
        zk_mpc::groth16::mpc_test_prove_and_verify::<
            ark_bls12_377::Bls12_377,
            mpc_algebra::AdditivePairingShare<ark_bls12_377::Bls12_377>,
        >(1)
        .await;
    })
    .await;
}
