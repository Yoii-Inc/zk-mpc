pub mod ZKPoPK {

    use crate::she::{self, get_gaussian, SHEParameters};

    use super::super::she::{Ciphertext, Encodedtext, Plaintexts, PublicKey};

    use ark_ff::FpParameters;
    use ark_mnt4_753::{Fq, FqParameters};
    use num_bigint::{BigInt, BigUint, ToBigInt, UniformBigInt};
    use num_integer::Integer;
    use num_traits::Zero;
    use rand::{thread_rng, Rng};
    use rand_distr::uniform::UniformSampler;

    pub struct Parameters {
        V: i32,
        N: usize,
        tau: BigUint,
        sec: i32,
        d: i32,
        rho: i32,
    }

    impl Parameters {
        pub fn new(V: i32, N: usize, tau: BigUint, sec: i32, d: i32, rho: i32) -> Self {
            Self {
                V,
                N,
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

        pub fn get_N(&self) -> usize {
            self.N
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
        pub fn new(m: Vec<Plaintexts>, x: &Vec<Encodedtext>, r: &Vec<Encodedtext>) -> Self {
            Self {
                m,
                x: x.clone(),
                r: r.clone(),
            }
        }
    }

    pub struct Proof {
        a: Vec<Ciphertext>,  //G^V
        z: Vec<Encodedtext>, //\mathbb{Z}^{N\times V}
        T: Vec<Encodedtext>, //\mathbb{Z}^{V\times d}
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

        for i in (0..parameters.V as usize) {
            assert_eq!(u[i].get_degree(), parameters.N as usize);
            let m_i = &witness.m[i].encode(she_params);
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
            .map(|(&ref y_i, s_i)| y_i.encrypt(&instance.pk, s_i, she_params))
            .collect();

        // step 3
        //let commit_a = commit(a);

        // step 4
        let e = hash(&a, &instance.c, parameters);

        // step 5
        let M_e: Vec<Vec<u128>> = generate_M_e(&e, parameters);

        let z: Vec<Encodedtext> = y
            .iter()
            .zip(M_e.iter())
            .map(|(&ref y_i, &ref row)| y_i.clone() + dot_product2(&row, &witness.x))
            .collect();

        let T: Vec<Encodedtext> = s
            .iter()
            .zip(M_e.iter())
            .map(|(&ref s_i, &ref row)| s_i.clone() + dot_product2(&row, &witness.r))
            .collect();

        Proof { a, z, T }
    }

    fn generate_u(
        parameters: &Parameters,
        witness: &Witness,
        she_params: &SHEParameters,
    ) -> Vec<Encodedtext> {
        let mut rng = rand::thread_rng();
        let upper_bound_y: BigUint =
            128 * parameters.N * parameters.tau.clone() * parameters.sec.pow(2) as usize / 2_u32;

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

        let u = (0..parameters.V as usize)
            .map(|i| {
                let mut vec = Vec::new();
                for j in 0..parameters.N {
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
                Encodedtext::new(vec, parameters.N)
            })
            .collect::<Vec<Encodedtext>>();

        u
    }

    fn generate_s(parameters: &Parameters) -> Vec<Encodedtext> {
        let mut rng = rand::thread_rng();
        let upper_bound_s = 128 * parameters.d * parameters.rho * parameters.sec.pow(2) / 2;
        let s: Vec<Vec<i32>> = (0..parameters.V)
            .map(|_| {
                (0..parameters.d)
                    .map(|_| rng.gen_range(-upper_bound_s..upper_bound_s))
                    .collect::<Vec<i32>>()
            })
            .collect();
        s.iter()
            .map(|s_i| {
                Encodedtext::new(
                    s_i.iter().map(|&s| Fq::from(s)).collect(),
                    parameters.d as usize,
                )
            })
            .collect()
    }

    // TODO: Implement hash function. output is sec bit.
    fn hash(a: &Vec<Ciphertext>, c: &Vec<Ciphertext>, parameters: &Parameters) -> Vec<bool> {
        //let rng = &mut thread_rng();
        let mut rng: rand::rngs::StdRng = rand::SeedableRng::seed_from_u64(10);
        (0..parameters.sec).map(|_| rng.gen_bool(0.5)).collect()
    }

    fn generate_M_e(e: &Vec<bool>, parameters: &Parameters) -> Vec<Vec<u128>> {
        let Me: Vec<Vec<u128>> = (0..parameters.V)
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
        Me
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
            .zip(proof.T.iter())
            .map(|(&ref z_i, &ref t_i)| z_i.encrypt(&instance.pk, &t_i.clone(), she_params))
            .collect();

        // step 7
        let M_e: Vec<Vec<u128>> = generate_M_e(&e, parameters);

        let rhs: Vec<Ciphertext> = M_e
            .iter()
            .zip(proof.a.iter())
            .map(|(&ref row, &ref a_i)| a_i.clone() + dot_product3(&row, &instance.c, parameters))
            .collect();

        assert_eq!(d, rhs);

        let norm_z = proof.z.iter().map(|z_i| z_i.norm()).max().unwrap();

        assert!(
            norm_z
                < (BigUint::from(128_usize)
                    * BigUint::from(parameters.N)
                    * parameters.tau.clone()
                    * BigUint::from(parameters.sec.pow(2) as usize)) as BigUint
        );

        let norm_T = proof.T.iter().map(|t_i| t_i.norm()).max().unwrap();

        assert!(
            norm_T
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

        let mut sum = Encodedtext::new(vec![Fq::zero(); x[0].get_degree()], x[0].get_degree());

        for i in 0..row.len() {
            sum = sum + x[i].clone() * Fq::from(row[i]);
        }

        sum
    }

    fn dot_product3(row: &Vec<u128>, c: &Vec<Ciphertext>, parameters: &Parameters) -> Ciphertext {
        assert_eq!(row.len(), c.len(), "Vector dimensions must match!");

        let rng = &mut thread_rng();

        let mut sum = Ciphertext::new(
            Encodedtext::new(
                vec![Fq::zero(); parameters.N as usize],
                parameters.N as usize,
            ),
            Encodedtext::new(
                vec![Fq::zero(); parameters.N as usize],
                parameters.N as usize,
            ),
            Encodedtext::new(
                vec![Fq::zero(); parameters.N as usize],
                parameters.N as usize,
            ),
        );

        for i in 0..row.len() {
            sum = sum + c[i].clone() * Fq::from(row[i]);
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
                V: 7, // 2*sec-1
                N: 2, // degree
                tau: std::convert::Into::<BigUint>::into(FrParameters::MODULUS) / 2_u32,
                sec: 4,
                d: 6, // 3*N
                rho: 2,
            };

            let she_params = SHEParameters::new(
                parameters.N as usize,
                parameters.N as usize,
                FrParameters::MODULUS.into(),
                FqParameters::MODULUS.into(),
                3.2,
            );

            let m = vec![
                Plaintexts::new(vec![Fr::from(0); parameters.N as usize]);
                parameters.V as usize
            ];
            let x: Vec<Encodedtext> =
                vec![Encodedtext::rand(&she_params, &mut rng); parameters.sec as usize];
            let r: Vec<Encodedtext> = vec![
                Encodedtext::new(
                    vec![Fq::zero(); parameters.d as usize],
                    parameters.d as usize
                );
                parameters.sec as usize
            ];

            let witness = Witness::new(m, &x, &r);

            let sk = SecretKey::generate(&she_params, &mut rng);

            let pk = sk.public_key_gen(&she_params, &mut rng);

            let c: Vec<Ciphertext> = x
                .iter()
                .zip(r.iter())
                .map(|(x_i, r_i)| x_i.encrypt(&pk, r_i, &she_params))
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
use ZKPoPK::Parameters;

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
    let r = get_gaussian(she_params, (parameters.get_N() * 3) as usize, &mut rng);
    let e_f_vec: Vec<Ciphertext> = f
        .iter()
        .map(|f_i| f_i.encode(she_params).encrypt(pk, &r, she_params))
        .collect();

    // step 3
    for i in (0..n) {
        let f_i = &f[i];
        let e_f_i = &e_f_vec[i];

        let instance = ZKPoPK::Instance::new(pk.clone(), vec![e_f_i.clone()]);

        let r2: Vec<Encodedtext> = vec![
            Encodedtext::new(
                vec![Fq::zero(); parameters.get_d() as usize],
                parameters.get_d() as usize
            );
            parameters.get_sec() as usize
        ];

        let witness = ZKPoPK::Witness::new(
            vec![f_i.clone()],
            &vec![f_i.encode(she_params)],
            &vec![r.clone(); parameters.get_sec() as usize],
        );

        let proof = ZKPoPK::prove(parameters, &witness, &instance, she_params);

        ZKPoPK::verify(&proof, parameters, &instance, she_params).unwrap();
    }

    // step4
    let mut sum = Ciphertext::new(
        Encodedtext::new(vec![Fq::zero(); parameters.get_N()], parameters.get_N()),
        Encodedtext::new(vec![Fq::zero(); parameters.get_N()], parameters.get_N()),
        Encodedtext::new(vec![Fq::zero(); parameters.get_N()], parameters.get_N()),
    );

    for i in 0..e_f_vec.len() {
        sum = sum + e_f_vec[i].clone();
    }

    //let e_f = e_f_vec.iter().sum();
    let e_f = sum;
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
    let e_m_new = mf.encode(she_params).encrypt(pk, &r, she_params) - e_f;

    match enc {
        _NewCiphertext => (m, Some(e_m_new)),
        _NoNewCiphertext => (m, None),
    }
}

#[derive(Debug, Clone)]
pub struct AngleShare {
    public_modifier: Plaintexts,
    share: Vec<Plaintexts>,
    MAC: Vec<Plaintexts>,
}

impl Add<Plaintexts> for AngleShare {
    type Output = AngleShare;
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
) -> AngleShare {
    let mut rng = thread_rng();

    let e_malpha = e_m * e_alpha.clone();

    let (gamma_vec, _) = reshare(
        e_malpha,
        CiphertextOpiton::NoNewCiphertext,
        parameters,
        pk,
        sk,
        she_params,
    );

    AngleShare {
        public_modifier: Plaintexts::new(vec![Fr::from(0); parameters.get_N()]),
        share: m_vec,
        MAC: gamma_vec,
    }
}

// TODO: Implement for Plaintext instead of Plaintexts
fn verify_angle_share(angle_share: &AngleShare, alpha: &Plaintexts) -> bool {
    let mac_1: Plaintexts = angle_share.MAC.iter().cloned().sum();
    let original: Plaintexts = angle_share.share.iter().cloned().sum();
    let mac_2: Plaintexts = alpha.clone() * (angle_share.public_modifier.clone() + original);
    if mac_1 == mac_2 {
        return true;
    }
    return false;
}

pub struct BracketShare {
    share: Vec<Plaintexts>,
    MAC: Vec<(Plaintexts, Vec<Plaintexts>)>,
}

fn bracket(
    m_vec: Vec<Plaintexts>,
    e_m: Ciphertext,
    parameters: &Parameters,
    pk: &PublicKey,
    sk: &SecretKey,
    she_params: &SHEParameters,
) -> BracketShare {
    let n = 3;

    let mut rng = thread_rng();

    // step 1
    // let beta_vec: Vec<SecretKey> = (0..n)
    //     .map(|_| SecretKey::generate(she_params, &mut rng))
    //     .collect();
    let beta_vec: Vec<Plaintexts> = (0..n)
        .map(|_| Plaintexts::rand(she_params, &mut rng))
        .collect();

    let r = get_gaussian(she_params, parameters.get_N() * 3, &mut rng);

    let e_beta_vec: Vec<Ciphertext> = beta_vec
        .iter()
        .map(|beta_i| beta_i.encode(she_params).encrypt(pk, &r, she_params))
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

    BracketShare {
        share: m_vec,
        MAC: mac,
    }
}

fn verify_bracket_share(bracket_share: &BracketShare, parameters: &Parameters) -> bool {
    let n = bracket_share.share.len();
    let mut flag = true;
    let original: Plaintexts = bracket_share.share.iter().cloned().sum();
    for i in 0..n {
        let mut mac_sum = Plaintexts::new(vec![Fr::zero(); parameters.get_N()]);

        for j in 0..n {
            mac_sum = mac_sum + bracket_share.MAC[j].1[i].clone();
        }

        if (mac_sum != original.clone() * bracket_share.MAC[i].0.clone()) {
            flag = false;
        }
    }
    flag
}

// initialize
pub fn initialize(parameters: &Parameters, she_params: &SHEParameters) -> BracketShare {
    let n = 3;

    let mut rng = thread_rng();
    let length_s = 1;

    // step 1
    //pk = keygendec

    let sk = SecretKey::generate(she_params, &mut rng);
    let pk = sk.public_key_gen(she_params, &mut rng);

    let r = get_gaussian(she_params, parameters.get_N() * 3, &mut rng);

    // step 2
    let beta: Vec<Plaintext> = (0..n).map(|_| Plaintext::rand(&mut rng)).collect();

    // step 3
    let alpha_vec: Vec<Plaintext> = (0..n).map(|_| Plaintext::rand(&mut rng)).collect();

    // step 4
    let diagonalized_alpha_vec: Vec<Plaintexts> = alpha_vec
        .iter()
        .map(|alpha_i| alpha_i.diagonalize(parameters.get_N()))
        .collect();

    let diagonalized_beta: Vec<Plaintexts> = beta
        .iter()
        .map(|beta_i| beta_i.diagonalize(parameters.get_N()))
        .collect();

    let e_alpha_vec: Vec<Ciphertext> = diagonalized_alpha_vec
        .iter()
        .map(|alpha_i| alpha_i.encode(she_params).encrypt(&pk, &r, she_params))
        .collect();
    let e_beta_vec: Vec<Ciphertext> = diagonalized_beta
        .iter()
        .map(|beta_i| beta_i.encode(she_params).encrypt(&pk, &r, she_params))
        .collect();

    // step 5
    // ZKPoPK
    for i in (0..n) {
        let instance_alpha = ZKPoPK::Instance::new(pk.clone(), vec![e_alpha_vec[i].clone()]);

        let witness_alpha = ZKPoPK::Witness::new(
            vec![diagonalized_alpha_vec[i].clone()],
            &vec![diagonalized_alpha_vec[i].encode(&she_params)],
            &vec![r.clone(); parameters.get_sec() as usize],
        );

        let proof_alpha = ZKPoPK::prove(&parameters, &witness_alpha, &instance_alpha, she_params);

        let instance_beta = ZKPoPK::Instance::new(pk.clone(), vec![e_beta_vec[i].clone()]);

        let witness_beta = ZKPoPK::Witness::new(
            vec![diagonalized_beta[i].clone()],
            &vec![diagonalized_beta[i].encode(she_params)],
            &vec![r.clone(); parameters.get_sec() as usize],
        );

        let proof_beta = ZKPoPK::prove(&parameters, &witness_beta, &instance_beta, she_params);

        ZKPoPK::verify(&proof_alpha, &parameters, &instance_alpha, she_params).unwrap();
        ZKPoPK::verify(&proof_beta, &parameters, &instance_beta, she_params).unwrap();
    }

    // step 6
    // let e_alpha = e_alpha_vec.iter().sum();

    let mut sum = Ciphertext::new(
        Encodedtext::new(vec![Fq::zero(); parameters.get_N()], parameters.get_N()),
        Encodedtext::new(vec![Fq::zero(); parameters.get_N()], parameters.get_N()),
        Encodedtext::new(vec![Fq::zero(); parameters.get_N()], parameters.get_N()),
    );

    for i in 0..e_alpha_vec.len() {
        sum = sum + e_alpha_vec[i].clone();
    }

    let diag_alpha = bracket(
        diagonalized_alpha_vec,
        sum,
        parameters,
        &pk,
        &sk,
        she_params,
    );

    diag_alpha
}

pub fn pair(
    e_alpha: &Ciphertext,
    pk: &PublicKey,
    sk: &SecretKey,
    parameters: &Parameters,
    she_params: &SHEParameters,
) -> (BracketShare, AngleShare) {
    let n = 3;
    let mut rng = thread_rng();

    let r = get_gaussian(she_params, parameters.get_N() * 3, &mut rng);

    // step 1
    let r_vec: Vec<Plaintexts> = (0..n)
        .map(|_| Plaintexts::rand(she_params, &mut rng))
        .collect();

    // step 2
    let e_r_vec: Vec<Ciphertext> = r_vec
        .iter()
        .map(|r_vec_i| r_vec_i.encode(she_params).encrypt(&pk, &r, she_params))
        .collect();

    // step 3
    for i in (0..n) {
        let r_i = &r_vec[i];
        let e_r_i = &e_r_vec[i];

        let instance = ZKPoPK::Instance::new(pk.clone(), vec![e_r_i.clone()]);

        let witness = ZKPoPK::Witness::new(
            vec![r_i.clone()],
            &vec![r_i.encode(she_params)],
            &vec![r.clone(); parameters.get_sec() as usize],
        );

        let proof = ZKPoPK::prove(&parameters, &witness, &instance, she_params);

        ZKPoPK::verify(&proof, &parameters, &instance, she_params).unwrap();
    }

    // step 4
    let mut sum = Ciphertext::new(
        Encodedtext::new(vec![Fq::zero(); parameters.get_N()], parameters.get_N()),
        Encodedtext::new(vec![Fq::zero(); parameters.get_N()], parameters.get_N()),
        Encodedtext::new(vec![Fq::zero(); parameters.get_N()], parameters.get_N()),
    );

    for i in 0..e_r_vec.len() {
        sum = sum + e_r_vec[i].clone();
    }

    let r_bracket = bracket(r_vec.clone(), sum.clone(), parameters, &pk, &sk, she_params);
    let r_angle = generate_angle_share(r_vec, sum, e_alpha, parameters, &pk, &sk, she_params);

    (r_bracket, r_angle)
}

pub fn triple(
    e_alpha: &Ciphertext,
    pk: &PublicKey,
    sk: &SecretKey,
    parameters: &Parameters,
    she_params: &SHEParameters,
) -> (AngleShare, AngleShare, AngleShare) {
    let n = 3;
    let length_s = 10;
    let mut rng = thread_rng();

    let r = get_gaussian(she_params, parameters.get_N() * 3, &mut rng);

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
        .map(|a_vec_i| a_vec_i.encode(she_params).encrypt(&pk, &r, she_params))
        .collect();
    let e_b_vec: Vec<Ciphertext> = b_vec
        .iter()
        .map(|b_vec_i| b_vec_i.encode(she_params).encrypt(&pk, &r, she_params))
        .collect();

    // step 3
    for i in (0..n) {
        let instance_a = ZKPoPK::Instance::new(pk.clone(), vec![e_a_vec[i].clone()]);

        let witness_a = ZKPoPK::Witness::new(
            vec![a_vec[i].clone()],
            &vec![a_vec[i].encode(she_params)],
            &vec![r.clone(); parameters.get_sec() as usize],
        );

        let proof_a = ZKPoPK::prove(&parameters, &witness_a, &instance_a, she_params);

        let instance_b = ZKPoPK::Instance::new(pk.clone(), vec![e_b_vec[i].clone()]);

        let witness_b = ZKPoPK::Witness::new(
            vec![b_vec[i].clone()],
            &vec![b_vec[i].encode(she_params)],
            &vec![r.clone(); parameters.get_sec() as usize],
        );

        let proof_b = ZKPoPK::prove(&parameters, &witness_b, &instance_b, she_params);

        ZKPoPK::verify(&proof_a, &parameters, &instance_a, she_params).unwrap();
        ZKPoPK::verify(&proof_b, &parameters, &instance_b, she_params).unwrap();
    }

    // step 4
    let mut e_a = Ciphertext::new(
        Encodedtext::new(vec![Fq::zero(); parameters.get_N()], parameters.get_N()),
        Encodedtext::new(vec![Fq::zero(); parameters.get_N()], parameters.get_N()),
        Encodedtext::new(vec![Fq::zero(); parameters.get_N()], parameters.get_N()),
    );

    for i in 0..e_a_vec.len() {
        e_a = e_a + e_a_vec[i].clone();
    }

    let mut e_b = Ciphertext::new(
        Encodedtext::new(vec![Fq::zero(); parameters.get_N()], parameters.get_N()),
        Encodedtext::new(vec![Fq::zero(); parameters.get_N()], parameters.get_N()),
        Encodedtext::new(vec![Fq::zero(); parameters.get_N()], parameters.get_N()),
    );

    for i in 0..e_b_vec.len() {
        e_b = e_b + e_b_vec[i].clone();
    }

    // step 5
    let a_angle = generate_angle_share(
        a_vec,
        e_a.clone(),
        e_alpha,
        parameters,
        &pk,
        &sk,
        she_params,
    );
    let b_angle = generate_angle_share(
        b_vec,
        e_b.clone(),
        e_alpha,
        parameters,
        &pk,
        &sk,
        she_params,
    );

    // step 6
    let e_c = e_a * e_b;

    // step 7
    let (c_vec, ct) = reshare(
        e_c,
        CiphertextOpiton::NewCiphertext,
        &parameters,
        &pk,
        &sk,
        she_params,
    );

    // step 8
    let c_angle = generate_angle_share(
        c_vec,
        ct.unwrap(),
        e_alpha,
        parameters,
        &pk,
        &sk,
        she_params,
    );

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

        let parameters = ZKPoPK::Parameters::new(
            1,
            2,
            std::convert::Into::<num_bigint::BigUint>::into(FrParameters::MODULUS) / 2_u32,
            1,
            6,
            2,
        );
        let she_params = SHEParameters::new(
            parameters.get_N(),
            parameters.get_N(),
            FrParameters::MODULUS.into(),
            FqParameters::MODULUS.into(),
            3.2,
        );

        let sk = SecretKey::generate(&she_params, &mut rng);
        let pk = sk.public_key_gen(&she_params, &mut rng);

        let e_m = Ciphertext::rand(&pk, parameters.get_N(), &mut rng, &she_params);

        let (m_vec, ct) = reshare(
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

        let parameters = ZKPoPK::Parameters::new(
            1,
            2,
            std::convert::Into::<num_bigint::BigUint>::into(FrParameters::MODULUS) / 2_u32,
            1,
            6,
            2,
        );
        let she_params = SHEParameters::new(
            parameters.get_N(),
            parameters.get_N(),
            FrParameters::MODULUS.into(),
            FqParameters::MODULUS.into(),
            3.2,
        );

        let sk = SecretKey::generate(&she_params, &mut rng);
        let pk = sk.public_key_gen(&she_params, &mut rng);

        let r = get_gaussian(&she_params, parameters.get_N() * 3, &mut rng);

        let m_vec: Vec<Plaintexts> = (0..n)
            .map(|_| Plaintexts::rand(&she_params, &mut rng))
            .collect();
        let m_sum = m_vec.iter().cloned().sum::<Plaintexts>();

        let e_m = m_sum.encode(&she_params).encrypt(&pk, &r, &she_params);

        let e_alpha = Ciphertext::rand(&pk, parameters.get_N(), &mut rng, &she_params);

        let result = generate_angle_share(m_vec, e_m, &e_alpha, &parameters, &pk, &sk, &she_params);

        assert!(verify_angle_share(
            &result,
            &e_alpha.decrypt(&sk).decode(&she_params)
        ));

        // test with non-zero public modifier
        let const_plain: Plaintexts = Plaintexts::new(vec![Fr::from(5); parameters.get_N()]);
        let result_added_const: AngleShare = result + const_plain;
        assert!(verify_angle_share(
            &result_added_const,
            &e_alpha.decrypt(&sk).decode(&she_params)
        ));
    }

    #[test]
    fn test_bracket() {
        let n = 3;
        let mut rng = rand::thread_rng();

        let parameters = ZKPoPK::Parameters::new(
            1,
            2,
            std::convert::Into::<num_bigint::BigUint>::into(FrParameters::MODULUS) / 2_u32,
            1,
            6,
            2,
        );
        let she_params = SHEParameters::new(
            parameters.get_N(),
            parameters.get_N(),
            FrParameters::MODULUS.into(),
            FqParameters::MODULUS.into(),
            3.2,
        );

        let sk = SecretKey::generate(&she_params, &mut rng);
        let pk = sk.public_key_gen(&she_params, &mut rng);

        let r = get_gaussian(&she_params, parameters.get_N() * 3, &mut rng);

        let m_vec: Vec<Plaintexts> = (0..n)
            .map(|_| Plaintexts::rand(&she_params, &mut rng))
            .collect();

        let mut sum = Plaintexts::new(vec![Fr::from(0); parameters.get_N()]);

        for i in 0..m_vec.len() {
            sum = sum + m_vec[i].clone();
        }
        let e_m = sum.encode(&she_params).encrypt(&pk, &r, &she_params);

        let result = bracket(m_vec, e_m, &parameters, &pk, &sk, &she_params);

        assert!(verify_bracket_share(&result, &parameters));
    }

    #[test]
    fn test_initialize() {
        let parameters = ZKPoPK::Parameters::new(
            1,
            2,
            std::convert::Into::<num_bigint::BigUint>::into(FrParameters::MODULUS) / 2_u32,
            1,
            6,
            2,
        );
        let she_params = SHEParameters::new(
            parameters.get_N(),
            parameters.get_N(),
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
        let parameters = ZKPoPK::Parameters::new(
            1,
            2,
            std::convert::Into::<num_bigint::BigUint>::into(FrParameters::MODULUS) / 2_u32,
            1,
            6,
            2,
        );
        let she_params = SHEParameters::new(
            parameters.get_N(),
            parameters.get_N(),
            FrParameters::MODULUS.into(),
            FqParameters::MODULUS.into(),
            3.2,
        );

        let sk = SecretKey::generate(&she_params, &mut rng);
        let pk = sk.public_key_gen(&she_params, &mut rng);

        let e_alpha = Ciphertext::rand(&pk, parameters.get_N(), &mut rng, &she_params);

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
        let parameters = ZKPoPK::Parameters::new(
            1,
            2,
            std::convert::Into::<num_bigint::BigUint>::into(FrParameters::MODULUS) / 2_u32,
            1,
            6,
            2,
        );
        let she_params = SHEParameters::new(
            parameters.get_N(),
            parameters.get_N(),
            FrParameters::MODULUS.into(),
            FqParameters::MODULUS.into(),
            3.2,
        );

        let sk = SecretKey::generate(&she_params, &mut rng);
        let pk = sk.public_key_gen(&she_params, &mut rng);

        let e_alpha = Ciphertext::rand(&pk, parameters.get_N(), &mut rng, &she_params);

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
