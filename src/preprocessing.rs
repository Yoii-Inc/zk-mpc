pub mod zkpopk {

    use crate::she::{Ciphertext, Encodedtext, Plaintexts, PublicKey, SHEParameters};

    use ark_ff::FpParameters;
    use ark_mnt4_753::{Fq, FqParameters};
    use num_bigint::{BigInt, BigUint, ToBigInt, UniformBigInt};
    use num_integer::Integer;
    use num_traits::Zero;
    use rand::{thread_rng, Rng};
    use rand_distr::uniform::UniformSampler;

    pub struct Parameters {
        v: i32,
        n: usize,
        tau: BigUint,
        sec: i32,
        d: i32,
        rho: i32,
    }

    impl Parameters {
        pub fn new(v: i32, n: usize, tau: BigUint, sec: i32, d: i32, rho: i32) -> Self {
            Self {
                v,
                n,
                tau,
                sec,
                d,
                rho,
            }
        }

        pub fn get_sec(&self) -> i32 {
            self.sec
        }

        pub fn get_d(&self) -> i32 {
            self.d
        }

        pub fn get_n(&self) -> usize {
            self.n
        }
    }

    pub struct Instance {
        pk: PublicKey,
        c: Vec<Ciphertext>,
    }

    impl Instance {
        pub fn new(pk: PublicKey, c: Vec<Ciphertext>) -> Self {
            Self { pk, c }
        }
    }

    pub struct Witness {
        m: Vec<Plaintexts>,
        x: Vec<Encodedtext>,
        r: Vec<Encodedtext>,
    }

    impl Witness {
        pub fn new(m: Vec<Plaintexts>, x: &[Encodedtext], r: &[Encodedtext]) -> Self {
            Self {
                m,
                x: x.to_vec(),
                r: r.to_vec(),
            }
        }
    }

    pub struct Proof {
        a: Vec<Ciphertext>,  //G^V
        z: Vec<Encodedtext>, //\mathbb{Z}^{N\times V}
        t: Vec<Encodedtext>, //\mathbb{Z}^{V\times d}
    }

    struct ZKPoPK {
        parameters: Parameters,
        instance: Instance,
        witness: Witness,
    }

    pub fn prove(
        parameters: &Parameters,
        witness: &Witness,
        instance: &Instance,
        she_params: &SHEParameters,
    ) -> Proof {
        // step 1
        let u: Vec<Encodedtext> = generate_u(parameters, witness, she_params);
        let s: Vec<Encodedtext> = generate_s(parameters);

        #[allow(clippy::needless_range_loop)]
        for i in 0..parameters.v as usize {
            assert_eq!(u[i].get_degree(), { parameters.n });
            let _m_i = &witness.m[i].encode(she_params);
        }
        let y: Vec<Encodedtext> = witness
            .m
            .iter()
            .zip(u.iter())
            .map(|(m_i, u_i)| m_i.encode(she_params) + u_i.clone())
            .collect();

        // step 2
        let a: Vec<Ciphertext> = y
            .iter()
            .zip(s.iter())
            .map(|(y_i, s_i)| {
                Ciphertext::encrypt_from(&y_i, &instance.pk, &s_i.clone(), she_params)
            })
            .collect();

        // step 3
        //let commit_a = commit(a);

        // step 4
        let e = hash(&a, &instance.c, parameters);

        // step 5
        let m_e: Vec<Vec<u128>> = generate_m_e(&e, parameters);

        let z: Vec<Encodedtext> = y
            .iter()
            .zip(m_e.iter())
            .map(|(y_i, row)| y_i.clone() + dot_product2(row, &witness.x))
            .collect();

        let t: Vec<Encodedtext> = s
            .iter()
            .zip(m_e.iter())
            .map(|(s_i, row)| s_i.clone() + dot_product2(row, &witness.r))
            .collect();

        Proof { a, z, t }
    }

    fn generate_u(
        parameters: &Parameters,
        witness: &Witness,
        she_params: &SHEParameters,
    ) -> Vec<Encodedtext> {
        let mut rng = rand::thread_rng();
        let upper_bound_y: BigUint =
            128 * parameters.n * parameters.tau.clone() * parameters.sec.pow(2) as usize / 2_u32;

        let upper_bound_u: Vec<Vec<BigInt>> = witness
            .m
            .iter()
            .map(|m_i| {
                m_i.encode(she_params)
                    .each_element()
                    .iter()
                    .map(|m_i_encoded_j| upper_bound_y.to_bigint().unwrap() - m_i_encoded_j)
                    .collect::<Vec<BigInt>>()
            })
            .collect();

        let lower_bound_u: Vec<Vec<BigInt>> = witness
            .m
            .iter()
            .map(|m_i| {
                m_i.encode(she_params)
                    .each_element()
                    .iter()
                    .map(|m_i_encoded_j| -upper_bound_y.to_bigint().unwrap() - m_i_encoded_j)
                    .collect::<Vec<BigInt>>()
            })
            .collect();

        (0..parameters.v as usize)
            .map(|i| {
                let mut vec = Vec::new();
                for j in 0..parameters.n {
                    let sampler = UniformBigInt::new(
                        lower_bound_u[i][j].clone(),
                        upper_bound_u[i][j].clone(),
                    );
                    let value: BigInt = sampler.sample(&mut rng);
                    if value < BigInt::zero() {
                        let rem = value.mod_floor(
                            &std::convert::Into::<BigUint>::into(FqParameters::MODULUS)
                                .to_bigint()
                                .unwrap(),
                        );
                        vec.push(Fq::from(rem.to_biguint().unwrap()));
                    } else {
                        vec.push(Fq::from(value.to_biguint().unwrap()));
                    }
                }
                Encodedtext::from_vec(vec)
            })
            .collect::<Vec<Encodedtext>>()
    }

    fn generate_s(parameters: &Parameters) -> Vec<Encodedtext> {
        let mut rng = rand::thread_rng();
        let upper_bound_s = 128 * parameters.d * parameters.rho * parameters.sec.pow(2) / 2;
        let s: Vec<Vec<i32>> = (0..parameters.v)
            .map(|_| {
                (0..parameters.d)
                    .map(|_| rng.gen_range(-upper_bound_s..upper_bound_s))
                    .collect::<Vec<i32>>()
            })
            .collect();
        s.iter()
            .map(|s_i| Encodedtext::from_vec(s_i.iter().map(|&s| Fq::from(s)).collect()))
            .collect()
    }

    // TODO: Implement hash function. output is sec bit.
    fn hash(_a: &[Ciphertext], _c: &[Ciphertext], parameters: &Parameters) -> Vec<bool> {
        //let rng = &mut thread_rng();
        let mut rng: rand::rngs::StdRng = rand::SeedableRng::seed_from_u64(10);
        (0..parameters.sec).map(|_| rng.gen_bool(0.5)).collect()
    }

    fn generate_m_e(e: &[bool], parameters: &Parameters) -> Vec<Vec<u128>> {
        let m_e: Vec<Vec<u128>> = (0..parameters.v)
            .map(|i| {
                (0..parameters.sec)
                    .map(|k| {
                        if i - k + 1 >= 1 && i - k < parameters.sec {
                            e[(i - k) as usize] as u128
                        } else {
                            0
                        }
                    })
                    .collect()
            })
            .collect();
        m_e
    }

    pub fn verify(
        proof: &Proof,
        parameters: &Parameters,
        instance: &Instance,
        she_params: &SHEParameters,
    ) -> Result<(), ()> {
        // step 6
        let e = hash(&proof.a, &instance.c, parameters);
        let d: Vec<Ciphertext> = proof
            .z
            .iter()
            .zip(proof.t.iter())
            .map(|(z_i, t_i)| {
                Ciphertext::encrypt_from(&z_i, &instance.pk, &t_i.clone(), she_params)
            })
            .collect();

        // step 7
        let m_e: Vec<Vec<u128>> = generate_m_e(&e, parameters);

        let rhs: Vec<Ciphertext> = m_e
            .iter()
            .zip(proof.a.iter())
            .map(|(row, a_i)| a_i.clone() + dot_product3(row, &instance.c, parameters))
            .collect();

        assert_eq!(d, rhs);

        let norm_z = proof.z.iter().map(|z_i| z_i.norm()).max().unwrap();

        assert!(
            norm_z
                < (BigUint::from(128_usize)
                    * BigUint::from(parameters.n)
                    * parameters.tau.clone()
                    * BigUint::from(parameters.sec.pow(2) as usize)) as BigUint
        );

        let norm_t = proof.t.iter().map(|t_i| t_i.norm()).max().unwrap();

        assert!(
            norm_t
                < (BigUint::from(128_usize)
                    * BigUint::from(parameters.d as usize)
                    * BigUint::from(parameters.rho as usize)
                    * BigUint::from(parameters.sec.pow(2) as usize)) as BigUint
        );

        Ok(())
    }

    fn dot_product(row: &Vec<i32>, x: &Vec<i32>) -> i32 {
        assert_eq!(row.len(), x.len(), "Vector dimensions must match!");

        let mut sum = 0;

        for i in 0..row.len() {
            sum += row[i] * x[i];
        }

        sum
    }

    fn dot_product2(row: &Vec<u128>, x: &Vec<Encodedtext>) -> Encodedtext {
        assert_eq!(row.len(), x.len(), "Vector dimensions must match!");

        let mut sum = Encodedtext::from_vec(vec![Fq::zero(); x[0].get_degree()]);

        for i in 0..row.len() {
            sum += x[i].clone() * Fq::from(row[i]);
        }

        sum
    }

    fn dot_product3(row: &Vec<u128>, c: &Vec<Ciphertext>, parameters: &Parameters) -> Ciphertext {
        assert_eq!(row.len(), c.len(), "Vector dimensions must match!");

        let _rng = &mut thread_rng();

        let mut sum = Ciphertext::from(
            Encodedtext::from_vec(vec![Fq::zero(); parameters.n]),
            Encodedtext::from_vec(vec![Fq::zero(); parameters.n]),
            Encodedtext::from_vec(vec![Fq::zero(); parameters.n]),
        );

        for i in 0..row.len() {
            sum += c[i].clone() * Fq::from(row[i]);
        }

        sum
    }

    #[cfg(test)]
    mod tests {
        use ark_bls12_377::{FqParameters, Fr, FrParameters};
        use ark_ff::FpParameters;
        use num_bigint::BigUint;

        use crate::she::SecretKey;

        use super::*;

        #[test]
        fn test_proof() {
            let mut rng = thread_rng();
            // /let length = 10;
            let parameters = Parameters {
                v: 7, // 2*sec-1
                n: 2, // degree
                tau: std::convert::Into::<BigUint>::into(FrParameters::MODULUS) / 2_u32,
                sec: 4,
                d: 6, // 3*N
                rho: 2,
            };

            let she_params = SHEParameters::new(
                parameters.n,
                parameters.n,
                FrParameters::MODULUS.into(),
                FqParameters::MODULUS.into(),
                3.2,
            );

            let m =
                vec![Plaintexts::from_vec(vec![Fr::from(0); parameters.n]); parameters.v as usize];
            let x: Vec<Encodedtext> =
                vec![Encodedtext::rand(&she_params, &mut rng); parameters.sec as usize];
            let r: Vec<Encodedtext> =
                vec![
                    Encodedtext::from_vec(vec![Fq::zero(); parameters.d as usize]);
                    parameters.sec as usize
                ];

            let witness = Witness::new(m, &x, &r);

            let sk = SecretKey::generate(&she_params, &mut rng);

            let pk = sk.public_key_gen(&she_params, &mut rng);

            let c: Vec<Ciphertext> = x
                .iter()
                .zip(r.iter())
                .map(|(x_i, r_i)| Ciphertext::encrypt_from(&x_i, &pk, &r_i.clone(), &she_params))
                .collect();
            let instance = Instance::new(pk.clone(), c);

            let proof = prove(&parameters, &witness, &instance, &she_params);

            verify(&proof, &parameters, &instance, &she_params).unwrap();
        }
    }
}

use std::ops::Add;

use crate::she::Plaintextish;

use super::she::{
    get_gaussian, Ciphertext, Encodedtext, Plaintext, Plaintexts, PublicKey, SHEParameters,
    SecretKey,
};
use ark_bls12_377::Fr;
use ark_mnt4_753::Fq;
use ark_std::UniformRand;
use num_traits::Zero;
use rand::thread_rng;
use zkpopk::Parameters;

enum CiphertextOpiton {
    NewCiphertext,
    NoNewCiphertext,
}

fn reshare(
    e_m: Ciphertext,
    enc: CiphertextOpiton,
    parameters: &Parameters,
    pk: &PublicKey,
    sk: &SecretKey,
    she_params: &SHEParameters,
) -> (Vec<Plaintexts>, Option<Ciphertext>) {
    let n = 3;

    // step 1
    let mut rng = thread_rng();

    //let f: Vec<Plaintext> = (0..n).map(|_| Fr::rand(rng)).collect();
    let f: Vec<Plaintexts> = (0..n)
        .map(|_| Plaintexts::rand(she_params, &mut rng))
        .collect();

    // // step 2
    //let e_f_vec: Vec<i32> = f.iter().map(|&f_i| encode(f_i)).collect();
    let r = get_gaussian(she_params, parameters.get_n() * 3, &mut rng);
    let e_f_vec: Vec<Ciphertext> = f
        .iter()
        .map(|f_i| Ciphertext::encrypt_from(&f_i.encode(she_params), pk, &r, she_params))
        .collect();

    // step 3
    for i in 0..n {
        let f_i = &f[i];
        let e_f_i = &e_f_vec[i];

        let instance = zkpopk::Instance::new(pk.clone(), vec![e_f_i.clone()]);

        let _r2: Vec<Encodedtext> =
            vec![
                Encodedtext::from_vec(vec![Fq::zero(); parameters.get_d() as usize]);
                parameters.get_sec() as usize
            ];
        let witness = zkpopk::Witness::new(
            vec![f_i.clone()],
            &[f_i.encode(she_params)],
            &vec![r.clone(); parameters.get_sec() as usize],
        );

        let proof = zkpopk::prove(parameters, &witness, &instance, she_params);

        zkpopk::verify(&proof, parameters, &instance, she_params).unwrap();
    }

    // step4
    let e_f = e_f_vec.into_iter().sum::<Ciphertext>();
    let e_mf = e_m + e_f.clone();

    // step 5
    let mf: Plaintexts = e_mf.decrypt(sk).decode(she_params);

    // step 6
    let mut m: Vec<Plaintexts> = vec![Plaintexts::rand(she_params, &mut rng); n];
    m[0] = mf.clone() - f[0].clone();

    for i in 1..n {
        m[i] = -f[i].clone();
    }

    // step 7
    let e_m_new = Ciphertext::encrypt_from(&mf.encode(she_params), pk, &r, she_params) - e_f;

    match enc {
        _new_ciphertext => (m, Some(e_m_new)),
        _no_new_ciphertext => (m, None),
    }
}

#[derive(Debug, Clone)]
pub struct AngleShares {
    public_modifier: Plaintexts,
    share: Vec<Plaintexts>,
    mac: Vec<Plaintexts>,
}

impl Add<Plaintexts> for AngleShares {
    type Output = AngleShares;
    fn add(self, rhs: Plaintexts) -> Self::Output {
        let mut ret = self.clone();
        // TODO: reduce clone
        ret.public_modifier = ret.public_modifier.clone() - rhs.clone();
        // add rhs for each item in ret.share
        ret.share[0] = ret.share[0].clone() + rhs;
        ret
    }
}

fn generate_angle_share(
    m_vec: Vec<Plaintexts>,
    e_m: Ciphertext,
    e_alpha: &Ciphertext,
    parameters: &Parameters,
    pk: &PublicKey,
    sk: &SecretKey,
    she_params: &SHEParameters,
) -> AngleShares {
    let e_malpha = e_m * e_alpha.clone();

    let (gamma_vec, _) = reshare(
        e_malpha,
        CiphertextOpiton::NoNewCiphertext,
        parameters,
        pk,
        sk,
        she_params,
    );

    AngleShares {
        public_modifier: Plaintexts::from_vec(vec![Fr::from(0); parameters.get_n()]),
        share: m_vec,
        mac: gamma_vec,
    }
}

// TODO: Implement for Plaintext instead of Plaintexts
fn verify_angle_share(angle_share: &AngleShares, alpha: &Plaintexts) -> bool {
    let mac_1: Plaintexts = angle_share.mac.iter().cloned().sum();
    let original: Plaintexts = angle_share.share.iter().cloned().sum();
    let mac_2: Plaintexts = alpha.clone() * (angle_share.public_modifier.clone() + original);
    if mac_1 == mac_2 {
        return true;
    }
    false
}

pub struct BracketShares {
    share: Vec<Plaintexts>,
    mac: Vec<(Plaintexts, Vec<Plaintexts>)>,
}

fn bracket(
    m_vec: Vec<Plaintexts>,
    e_m: Ciphertext,
    parameters: &Parameters,
    pk: &PublicKey,
    sk: &SecretKey,
    she_params: &SHEParameters,
) -> BracketShares {
    let n = 3;

    let mut rng = thread_rng();

    // step 1
    // let beta_vec: Vec<SecretKey> = (0..n)
    //     .map(|_| SecretKey::generate(she_params, &mut rng))
    //     .collect();
    let beta_vec: Vec<Plaintexts> = (0..n)
        .map(|_| Plaintexts::rand(she_params, &mut rng))
        .collect();

    let r = get_gaussian(she_params, parameters.get_n() * 3, &mut rng);

    let e_beta_vec: Vec<Ciphertext> = beta_vec
        .iter()
        .map(|beta_i| Ciphertext::encrypt_from(&beta_i.encode(she_params), pk, &r, she_params))
        .collect();

    let e_gamma_vec: Vec<Ciphertext> = e_beta_vec
        .iter()
        .map(|e_beta_i| e_beta_i.clone() * e_m.clone())
        .collect();

    // step 2
    let gamma_vecvec: Vec<Vec<Plaintexts>> = e_gamma_vec
        .iter()
        .map(|e_gamma_i| {
            let (gamma_vec, _) = reshare(
                e_gamma_i.clone(),
                CiphertextOpiton::NoNewCiphertext,
                parameters,
                pk,
                sk,
                she_params,
            );
            gamma_vec
        })
        .collect();

    // step 3
    // step 4
    let mac: Vec<(Plaintexts, Vec<Plaintexts>)> = (0..n)
        .map(|i| {
            (
                beta_vec[i].clone(),
                (0..n)
                    .map(|j| gamma_vecvec[j][i].clone())
                    .collect::<Vec<Plaintexts>>(),
            )
        })
        .collect();

    BracketShares { share: m_vec, mac }
}

fn verify_bracket_share(bracket_share: &BracketShares, _parameters: &Parameters) -> bool {
    let n = bracket_share.share.len();
    let mut flag = true;
    let original: Plaintexts = bracket_share.share.iter().cloned().sum();
    for i in 0..n {
        let mac_sum = bracket_share
            .mac
            .iter()
            .map(|mac| mac.1[i].clone())
            .sum::<Plaintexts>();

        if mac_sum != original.clone() * bracket_share.mac[i].0.clone() {
            flag = false;
        }
    }
    flag
}

// initialize
pub fn initialize(parameters: &Parameters, she_params: &SHEParameters) -> BracketShares {
    let n = 3;

    let mut rng = thread_rng();

    // step 1
    //pk = keygendec

    let sk = SecretKey::generate(she_params, &mut rng);
    let pk = sk.public_key_gen(she_params, &mut rng);

    let r = get_gaussian(she_params, parameters.get_n() * 3, &mut rng);

    // step 2
    let beta: Vec<Plaintext> = (0..n).map(|_| Plaintext::rand(&mut rng)).collect();

    // step 3
    let alpha_vec: Vec<Plaintext> = (0..n).map(|_| Plaintext::rand(&mut rng)).collect();

    // step 4
    let diagonalized_alpha_vec: Vec<Plaintexts> = alpha_vec
        .iter()
        .map(|alpha_i| alpha_i.diagonalize(parameters.get_n()))
        .collect();

    let diagonalized_beta: Vec<Plaintexts> = beta
        .iter()
        .map(|beta_i| beta_i.diagonalize(parameters.get_n()))
        .collect();

    let e_alpha_vec: Vec<Ciphertext> = diagonalized_alpha_vec
        .iter()
        .map(|alpha_i| Ciphertext::encrypt_from(&alpha_i.encode(she_params), &pk, &r, she_params))
        .collect();
    let e_beta_vec: Vec<Ciphertext> = diagonalized_beta
        .iter()
        .map(|beta_i| Ciphertext::encrypt_from(&beta_i.encode(she_params), &pk, &r, she_params))
        .collect();

    // step 5
    // ZKPoPK
    for i in 0..n {
        let instance_alpha = zkpopk::Instance::new(pk.clone(), vec![e_alpha_vec[i].clone()]);

        let witness_alpha = zkpopk::Witness::new(
            vec![diagonalized_alpha_vec[i].clone()],
            &[diagonalized_alpha_vec[i].encode(she_params)],
            &vec![r.clone(); parameters.get_sec() as usize],
        );

        let proof_alpha = zkpopk::prove(parameters, &witness_alpha, &instance_alpha, she_params);

        let instance_beta = zkpopk::Instance::new(pk.clone(), vec![e_beta_vec[i].clone()]);

        let witness_beta = zkpopk::Witness::new(
            vec![diagonalized_beta[i].clone()],
            &[diagonalized_beta[i].encode(she_params)],
            &vec![r.clone(); parameters.get_sec() as usize],
        );

        let proof_beta = zkpopk::prove(parameters, &witness_beta, &instance_beta, she_params);

        zkpopk::verify(&proof_alpha, parameters, &instance_alpha, she_params).unwrap();
        zkpopk::verify(&proof_beta, parameters, &instance_beta, she_params).unwrap();
    }

    // step 6
    let e_alpha = e_alpha_vec.clone().into_iter().sum::<Ciphertext>();

    bracket(
        diagonalized_alpha_vec,
        e_alpha,
        parameters,
        &pk,
        &sk,
        she_params,
    )
}

pub fn pair(
    e_alpha: &Ciphertext,
    pk: &PublicKey,
    sk: &SecretKey,
    parameters: &Parameters,
    she_params: &SHEParameters,
) -> (BracketShares, AngleShares) {
    let n = 3;
    let mut rng = thread_rng();

    let r = get_gaussian(she_params, parameters.get_n() * 3, &mut rng);

    // step 1
    let r_vec: Vec<Plaintexts> = (0..n)
        .map(|_| Plaintexts::rand(she_params, &mut rng))
        .collect();

    // step 2
    let e_r_vec: Vec<Ciphertext> = r_vec
        .iter()
        .map(|r_vec_i| Ciphertext::encrypt_from(&r_vec_i.encode(she_params), pk, &r, she_params))
        .collect();

    // step 3
    for i in 0..n {
        let r_i = &r_vec[i];
        let e_r_i = &e_r_vec[i];

        let instance = zkpopk::Instance::new(pk.clone(), vec![e_r_i.clone()]);

        let witness = zkpopk::Witness::new(
            vec![r_i.clone()],
            &[r_i.encode(she_params)],
            &vec![r.clone(); parameters.get_sec() as usize],
        );

        let proof = zkpopk::prove(parameters, &witness, &instance, she_params);

        zkpopk::verify(&proof, parameters, &instance, she_params).unwrap();
    }

    // step 4
    let e_r_sum = e_r_vec.into_iter().sum::<Ciphertext>();

    let r_bracket = bracket(
        r_vec.clone(),
        e_r_sum.clone(),
        parameters,
        pk,
        sk,
        she_params,
    );
    let r_angle = generate_angle_share(r_vec, e_r_sum, e_alpha, parameters, pk, sk, she_params);

    (r_bracket, r_angle)
}

pub fn triple(
    e_alpha: &Ciphertext,
    pk: &PublicKey,
    sk: &SecretKey,
    parameters: &Parameters,
    she_params: &SHEParameters,
) -> (AngleShares, AngleShares, AngleShares) {
    let n = 3;
    let mut rng = thread_rng();

    let r = get_gaussian(she_params, parameters.get_n() * 3, &mut rng);

    // step 1
    let a_vec: Vec<Plaintexts> = (0..n)
        .map(|_| Plaintexts::rand(she_params, &mut rng))
        .collect();
    let b_vec: Vec<Plaintexts> = (0..n)
        .map(|_| Plaintexts::rand(she_params, &mut rng))
        .collect();

    // step 2
    let e_a_vec: Vec<Ciphertext> = a_vec
        .iter()
        .map(|a_vec_i| Ciphertext::encrypt_from(&a_vec_i.encode(she_params), pk, &r, she_params))
        .collect();
    let e_b_vec: Vec<Ciphertext> = b_vec
        .iter()
        .map(|b_vec_i| Ciphertext::encrypt_from(&b_vec_i.encode(she_params), pk, &r, she_params))
        .collect();

    // step 3
    for i in 0..n {
        let instance_a = zkpopk::Instance::new(pk.clone(), vec![e_a_vec[i].clone()]);

        let witness_a = zkpopk::Witness::new(
            vec![a_vec[i].clone()],
            &[a_vec[i].encode(she_params)],
            &vec![r.clone(); parameters.get_sec() as usize],
        );

        let proof_a = zkpopk::prove(parameters, &witness_a, &instance_a, she_params);

        let instance_b = zkpopk::Instance::new(pk.clone(), vec![e_b_vec[i].clone()]);

        let witness_b = zkpopk::Witness::new(
            vec![b_vec[i].clone()],
            &[b_vec[i].encode(she_params)],
            &vec![r.clone(); parameters.get_sec() as usize],
        );

        let proof_b = zkpopk::prove(parameters, &witness_b, &instance_b, she_params);

        zkpopk::verify(&proof_a, parameters, &instance_a, she_params).unwrap();
        zkpopk::verify(&proof_b, parameters, &instance_b, she_params).unwrap();
    }

    // step 4
    let e_a = e_a_vec.into_iter().sum::<Ciphertext>();

    let e_b = e_b_vec.into_iter().sum::<Ciphertext>();

    // step 5
    let a_angle = generate_angle_share(a_vec, e_a.clone(), e_alpha, parameters, pk, sk, she_params);
    let b_angle = generate_angle_share(b_vec, e_b.clone(), e_alpha, parameters, pk, sk, she_params);

    // step 6
    let e_c = e_a * e_b;

    // step 7
    let (c_vec, ct) = reshare(
        e_c,
        CiphertextOpiton::NewCiphertext,
        parameters,
        pk,
        sk,
        she_params,
    );

    // step 8
    let c_angle = generate_angle_share(c_vec, ct.unwrap(), e_alpha, parameters, pk, sk, she_params);

    (a_angle, b_angle, c_angle)
}

#[cfg(test)]
mod tests {
    use ark_bls12_377::FrParameters;
    use ark_ff::FpParameters;
    use ark_mnt4_753::FqParameters;

    use super::*;

    #[test]
    fn test_reshare() {
        let mut rng = rand::thread_rng();

        let parameters = zkpopk::Parameters::new(
            1,
            2,
            std::convert::Into::<num_bigint::BigUint>::into(FrParameters::MODULUS) / 2_u32,
            1,
            6,
            2,
        );
        let she_params = SHEParameters::new(
            parameters.get_n(),
            parameters.get_n(),
            FrParameters::MODULUS.into(),
            FqParameters::MODULUS.into(),
            3.2,
        );

        let sk = SecretKey::generate(&she_params, &mut rng);
        let pk = sk.public_key_gen(&she_params, &mut rng);

        let e_m = Ciphertext::rand(&pk, &mut rng, &she_params);

        let (_m_vec, ct) = reshare(
            e_m.clone(),
            CiphertextOpiton::NewCiphertext,
            &parameters,
            &pk,
            &sk,
            &she_params,
        );
        let ct = ct.unwrap();

        //assert_eq!(e_m.decrypt(&sk).decode(), m_vec.iter().sum::<Plaintext>());

        assert_eq!(
            e_m.decrypt(&sk).decode(&she_params),
            ct.decrypt(&sk).decode(&she_params)
        );
    }

    #[test]
    fn test_angle() {
        let n = 3;

        let mut rng = rand::thread_rng();

        let parameters = zkpopk::Parameters::new(
            1,
            2,
            std::convert::Into::<num_bigint::BigUint>::into(FrParameters::MODULUS) / 2_u32,
            1,
            6,
            2,
        );
        let she_params = SHEParameters::new(
            parameters.get_n(),
            parameters.get_n(),
            FrParameters::MODULUS.into(),
            FqParameters::MODULUS.into(),
            3.2,
        );

        let sk = SecretKey::generate(&she_params, &mut rng);
        let pk = sk.public_key_gen(&she_params, &mut rng);

        let r = get_gaussian(&she_params, parameters.get_n() * 3, &mut rng);

        let m_vec: Vec<Plaintexts> = (0..n)
            .map(|_| Plaintexts::rand(&she_params, &mut rng))
            .collect();
        let m_sum = m_vec.iter().cloned().sum::<Plaintexts>();

        let e_m = Ciphertext::encrypt_from(&m_sum.encode(&she_params), &pk, &r, &she_params);

        let e_alpha = Ciphertext::rand(&pk, &mut rng, &she_params);

        let result = generate_angle_share(m_vec, e_m, &e_alpha, &parameters, &pk, &sk, &she_params);

        assert!(verify_angle_share(
            &result,
            &e_alpha.decrypt(&sk).decode(&she_params)
        ));

        // test with non-zero public modifier
        let const_plain: Plaintexts = Plaintexts::from_vec(vec![Fr::from(5); parameters.get_n()]);
        let result_added_const: AngleShares = result + const_plain;
        assert!(verify_angle_share(
            &result_added_const,
            &e_alpha.decrypt(&sk).decode(&she_params)
        ));
    }

    #[test]
    fn test_bracket() {
        let n = 3;
        let mut rng = rand::thread_rng();

        let parameters = zkpopk::Parameters::new(
            1,
            2,
            std::convert::Into::<num_bigint::BigUint>::into(FrParameters::MODULUS) / 2_u32,
            1,
            6,
            2,
        );
        let she_params = SHEParameters::new(
            parameters.get_n(),
            parameters.get_n(),
            FrParameters::MODULUS.into(),
            FqParameters::MODULUS.into(),
            3.2,
        );

        let sk = SecretKey::generate(&she_params, &mut rng);
        let pk = sk.public_key_gen(&she_params, &mut rng);

        let r = get_gaussian(&she_params, parameters.get_n() * 3, &mut rng);

        let m_vec: Vec<Plaintexts> = (0..n)
            .map(|_| Plaintexts::rand(&she_params, &mut rng))
            .collect();

        let sum = m_vec.iter().cloned().sum::<Plaintexts>();

        let e_m = Ciphertext::encrypt_from(&sum.encode(&she_params), &pk, &r, &she_params);

        let result = bracket(m_vec, e_m, &parameters, &pk, &sk, &she_params);

        assert!(verify_bracket_share(&result, &parameters));
    }

    #[test]
    fn test_initialize() {
        let parameters = zkpopk::Parameters::new(
            1,
            2,
            std::convert::Into::<num_bigint::BigUint>::into(FrParameters::MODULUS) / 2_u32,
            1,
            6,
            2,
        );
        let she_params = SHEParameters::new(
            parameters.get_n(),
            parameters.get_n(),
            FrParameters::MODULUS.into(),
            FqParameters::MODULUS.into(),
            3.2,
        );

        let bracket_diag_alpha = initialize(&parameters, &she_params);

        assert!(verify_bracket_share(&bracket_diag_alpha, &parameters));
    }

    #[test]
    fn test_pair() {
        let mut rng = rand::thread_rng();
        let parameters = zkpopk::Parameters::new(
            1,
            2,
            std::convert::Into::<num_bigint::BigUint>::into(FrParameters::MODULUS) / 2_u32,
            1,
            6,
            2,
        );
        let she_params = SHEParameters::new(
            parameters.get_n(),
            parameters.get_n(),
            FrParameters::MODULUS.into(),
            FqParameters::MODULUS.into(),
            3.2,
        );

        let sk = SecretKey::generate(&she_params, &mut rng);
        let pk = sk.public_key_gen(&she_params, &mut rng);

        let e_alpha = Ciphertext::rand(&pk, &mut rng, &she_params);

        let (r_bracket, r_angle) = pair(&e_alpha, &pk, &sk, &parameters, &she_params);

        assert!(verify_bracket_share(&r_bracket, &parameters));
        assert!(verify_angle_share(
            &r_angle,
            &e_alpha.decrypt(&sk).decode(&she_params)
        ));
    }

    #[test]
    fn test_triple() {
        let mut rng = rand::thread_rng();
        let parameters = zkpopk::Parameters::new(
            1,
            2,
            std::convert::Into::<num_bigint::BigUint>::into(FrParameters::MODULUS) / 2_u32,
            1,
            6,
            2,
        );
        let she_params = SHEParameters::new(
            parameters.get_n(),
            parameters.get_n(),
            FrParameters::MODULUS.into(),
            FqParameters::MODULUS.into(),
            3.2,
        );

        let sk = SecretKey::generate(&she_params, &mut rng);
        let pk = sk.public_key_gen(&she_params, &mut rng);

        let e_alpha = Ciphertext::rand(&pk, &mut rng, &she_params);

        let (a_angle, b_angle, c_angle) = triple(&e_alpha, &pk, &sk, &parameters, &she_params);

        assert!(verify_angle_share(
            &a_angle,
            &e_alpha.decrypt(&sk).decode(&she_params)
        ));
        assert!(verify_angle_share(
            &b_angle,
            &e_alpha.decrypt(&sk).decode(&she_params)
        ));
        assert!(verify_angle_share(
            &c_angle,
            &e_alpha.decrypt(&sk).decode(&she_params)
        ));

        let a_original = a_angle.share.iter().cloned().sum::<Plaintexts>();
        let b_original = b_angle.share.iter().cloned().sum::<Plaintexts>();
        let c_original = c_angle.share.iter().cloned().sum::<Plaintexts>();

        assert_eq!(a_original.clone() * b_original.clone(), c_original.clone());
    }
}
