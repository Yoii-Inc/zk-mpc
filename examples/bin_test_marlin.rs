use mpc_net::{multi::MPCNetConnection, MpcMultiNet as Net};
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

#[tokio::main]
async fn main() {
    let opt = Opt::from_args();

    let mut net = MPCNetConnection::init_from_path(&opt.input, opt.id as u32);
    net.listen().await.unwrap();
    net.connect_to_all().await.unwrap();

    Net::simulate(net, (), |_, _| async {
        marlin::mpc_test_prove_and_verify(1).await;
        marlin::mpc_test_prove_and_verify_pedersen(1).await;
        marlin::test_equality_zero(1).await;
        marlin::test_not_equality_zero(10).await;
        marlin::test_bit_decomposition(1).await;
        marlin::test_enforce_smaller_eq_than(3).await;
        marlin::test_smaller_than(5).await;
    })
    .await;
}
