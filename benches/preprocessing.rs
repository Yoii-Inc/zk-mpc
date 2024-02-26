use ark_bls12_377::FrParameters;
use ark_ff::FpParameters;
use ark_mnt4_753::FqParameters;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use zk_mpc::preprocessing::triple;

use zk_mpc::preprocessing::zkpopk;
use zk_mpc::she::Ciphertext;
use zk_mpc::she::SHEParameters;
use zk_mpc::she::SecretKey;

fn hoge(n: u64) -> u64 {
    match n {
        0 => 1,
        1 => 1,
        n => hoge(n - 1) + hoge(n - 2),
    }
}

fn preprocessing_benchmark(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let parameters = zkpopk::Parameters::new(
        black_box(1),
        black_box(2),
        std::convert::Into::<num_bigint::BigUint>::into(FrParameters::MODULUS)
            / black_box(2) as u32,
        black_box(1),
        black_box(6),
        black_box(2),
    );
    let she_params = SHEParameters::new(
        parameters.get_n(),
        parameters.get_n(),
        FrParameters::MODULUS.into(),
        FqParameters::MODULUS.into(),
        black_box(3.2),
    );

    let sk = SecretKey::generate(&she_params, &mut rng);
    let pk = sk.public_key_gen(&she_params, &mut rng);

    let e_alpha = Ciphertext::rand(&pk, &mut rng, &she_params);
    c.bench_function("generation triples", |b| {
        b.iter(|| triple(&e_alpha, &pk, &sk, &parameters, &she_params))
    });

    c.bench_function("generation triples2", |b| {
        b.iter(|| triple(&e_alpha, &pk, &sk, &parameters, &she_params))
    });
}

criterion_group!(benches, preprocessing_benchmark);
criterion_main!(benches);
