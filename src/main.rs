mod input_circuit;
mod preprocessing;
mod she;

use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "example", about = "An example of StructOpt usage.")]
struct Opt {
    input_file_path: String,
}

#[derive(Debug, Deserialize)]
struct ArgInput {
    x: u128,
    h_x: u128,
}

fn main() {
    let opt = Opt::from_args();

    let mut file = File::open(opt.input_file_path).expect("Failed to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Failed to read file");

    let data: ArgInput = serde_json::from_str(&contents).unwrap();
    println!("{:?}", data);
}
