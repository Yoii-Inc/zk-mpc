mod ZKPoPK {

    use super::super::she::{Ciphertext, Encodedtext, Plaintext, PublicKey, SecretKey};
    use ark_bls12_377::Fr;
    use rand::{thread_rng, Rng};

    pub struct Parameters {
        V: i32,
        N: i32,
        tau: i32,
        sec: i32,
        d: i32,
        rho: i32,
        p: i128,
        q: i128, //she
    }

    impl Parameters {
        pub fn new(V: i32, N: i32, tau: i32, sec: i32, d: i32, rho: i32, p: i128, q: i128) -> Self {
            Self {
                V,
                N,
                tau,
                sec,
                d,
                rho,
                p,
                q,
            }
        }

        pub fn get_sec(&self) -> i32 {
            self.sec
        }

        pub fn get_d(&self) -> i32 {
            self.d
        }

        pub fn get_p(&self) -> i128 {
            self.p
        }

        pub fn get_q(&self) -> i128 {
            self.q
        }

        pub fn get_N(&self) -> i32 {
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
        m: Vec<Plaintext>,
        x: Vec<Encodedtext>,
        r: Vec<Encodedtext>,
    }

    impl Witness {
        pub fn new(m: Vec<Plaintext>, x: &Vec<Encodedtext>, r: &Vec<Encodedtext>) -> Self {
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

    pub fn prove(parameters: &Parameters, witness: &Witness, instance: &Instance) -> Proof {
        // step 1
        let u: Vec<Encodedtext> = generate_u(parameters);
        let s: Vec<Encodedtext> = generate_s(parameters);

        let y: Vec<Encodedtext> = witness
            .m
            .iter()
            .zip(u.iter())
            .map(|(&ref m_i, &ref u_i)| m_i.encode() + u_i.clone())
            .collect();

        // step 2
        let a: Vec<Ciphertext> = y
            .iter()
            .zip(s.iter())
            .map(|(&ref y_i, s_i)| y_i.encrypt(&instance.pk, s_i))
            .collect();

        // step 3
        //let commit_a = commit(a);

        // step 4
        let e = hash(&a, &instance.c, parameters);

        // step 5
        let M_e: Vec<Vec<i128>> = generate_M_e(&e, parameters);

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

    fn generate_u(parameters: &Parameters) -> Vec<Encodedtext> {
        //let mut rng = rand::thread_rng();
        //let u: Vec<i32> = (0..V).map(|_| rng.gen_range(0, upper_bound_y-m_i)).collect_vec();
        //u
        (0..parameters.V)
            .map(|_| Encodedtext::new(vec![0; parameters.N as usize], parameters.q))
            .collect()
    }

    fn generate_s(parameters: &Parameters) -> Vec<Encodedtext> {
        //let mut rng = rand::thread_rng();
        //let s: Vec<Vec<i32>> = (0..V).map(|_| (0..N).map(|_| rng.gen_range(0, upper_bound_s)).collect_vec()).collect_vec();
        //s
        (0..parameters.V)
            .map(|_| Encodedtext::new(vec![0; parameters.d as usize], parameters.q))
            .collect()
    }

    // outputがsec bitのハッシュ関数
    fn hash(a: &Vec<Ciphertext>, c: &Vec<Ciphertext>, parameters: &Parameters) -> Vec<bool> {
        //let rng = &mut thread_rng();
        let mut rng: rand::rngs::StdRng = rand::SeedableRng::seed_from_u64(10);
        (0..parameters.sec).map(|_| rng.gen_bool(0.5)).collect()
    }

    fn generate_M_e(e: &Vec<bool>, parameters: &Parameters) -> Vec<Vec<i128>> {
        let Me: Vec<Vec<i128>> = (0..parameters.V)
            .map(|i| {
                (0..parameters.sec)
                    .map(|k| {
                        if i - k + 1 >= 1 && i - k < parameters.sec {
                            // e[(i - k + 1) as usize] as i32
                            e[(i - k) as usize] as i128
                        } else {
                            0
                        }
                    })
                    .collect()
            })
            .collect();
        Me
    }

    pub fn dummy_prove(parameters: &Parameters) -> Proof {
        let mut rng = thread_rng();
        let sk = SecretKey::generate(10, parameters.q, 3.2, &mut rng);
        let pk = sk.public_key_gen(parameters.N, parameters.p, parameters.q, 3.2, &mut rng);
        let a = vec![Ciphertext::rand(&pk, 2, parameters.q, &mut rng); 4];
        let z = vec![Encodedtext::new(vec![0, 0], parameters.q); 2];
        let T = vec![Encodedtext::new(vec![0, 0], parameters.q); 2];

        Proof { a, z, T }
    }

    pub fn verify(proof: &Proof, parameters: &Parameters, instance: &Instance) -> Result<(), ()> {
        // TODO: SHEを整えてから実装する
        // step 6
        let e = hash(&proof.a, &instance.c, parameters);
        let d: Vec<Ciphertext> = proof
            .z
            .iter()
            .zip(proof.T.iter())
            .map(|(&ref z_i, &ref t_i)| z_i.encrypt(&instance.pk, &t_i.clone()))
            .collect();

        // step 7
        let M_e: Vec<Vec<i128>> = generate_M_e(&e, parameters);

        let rhs: Vec<Ciphertext> = M_e
            .iter()
            .zip(proof.a.iter())
            .map(|(&ref row, &ref a_i)| a_i.clone() + dot_product3(&row, &instance.c, parameters))
            .collect();

        assert_eq!(d, rhs);

        let norm_z = proof.z.iter().map(|z_i| z_i.norm()).max().unwrap();

        //assert!(norm_z < (128 * parameters.N * parameters.tau * parameters.sec.pow(2)) as i128);

        let norm_T = proof.T.iter().map(|t_i| t_i.norm()).max().unwrap();

        assert!(norm_T < (128 * parameters.d * parameters.rho * parameters.sec.pow(2)) as i128);

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

    fn dot_product2(row: &Vec<i128>, x: &Vec<Encodedtext>) -> Encodedtext {
        assert_eq!(row.len(), x.len(), "Vector dimensions must match!");

        let mut sum = Encodedtext::new(vec![0; x[0].get_degree()], x[0].get_q());

        for i in 0..row.len() {
            sum = sum + x[i].clone() * row[i];
        }

        sum
    }

    fn dot_product3(row: &Vec<i128>, c: &Vec<Ciphertext>, parameters: &Parameters) -> Ciphertext {
        assert_eq!(row.len(), c.len(), "Vector dimensions must match!");

        let rng = &mut thread_rng();

        let mut sum = Ciphertext::new(
            Encodedtext::new(vec![0; parameters.N as usize], parameters.q),
            Encodedtext::new(vec![0; parameters.N as usize], parameters.q),
            Encodedtext::new(vec![0; parameters.N as usize], parameters.q),
        );

        for i in 0..row.len() {
            sum = sum + c[i].clone() * row[i];
        }

        sum
    }

    #[test]
    fn test_proof() {
        let mut rng = thread_rng();
        // /let length = 10;
        let parameters = Parameters {
            V: 7,  // 2*sec-1
            N: 10, // degree
            tau: 2,
            sec: 4,
            d: 30, // 3*N
            rho: 2,
            p: 41,
            q: 83380292323641237751,
        };

        //let m = vec![Plaintext::new(vec![Fr::from(0); parameters.N as usize]); parameters.V as usize];
        let x: Vec<Encodedtext> = vec![
            Encodedtext::rand(parameters.N, parameters.q, &mut rng)
                .modulo_p(parameters.p);
            parameters.sec as usize
        ];
        let r: Vec<Encodedtext> =
            vec![
                Encodedtext::new(vec![0; parameters.d as usize], parameters.q);
                parameters.sec as usize
            ];

        let witness = Witness::new(
            vec![Plaintext::new(vec![Fr::from(0); parameters.N as usize]); parameters.V as usize],
            &x,
            &r,
        );

        let sk = SecretKey::generate(parameters.N, parameters.q, 3.2, &mut rng);

        let pk = sk.public_key_gen(parameters.N, parameters.p, parameters.q, 3.2, &mut rng);

        let c: Vec<Ciphertext> = x
            .iter()
            .zip(r.iter())
            .map(|(&ref x_i, &ref r_i)| x_i.encrypt(&pk, &r_i))
            .collect();
        let instance = Instance::new(pk.clone(), c);

        let proof = prove(&parameters, &witness, &instance);

        verify(&proof, &parameters, &instance).unwrap();
    }
}

use super::she::{get_gaussian, Ciphertext, Encodedtext, Plaintext, PublicKey, SecretKey};
use ark_bls12_377::Fr;
use ark_std::{test_rng, UniformRand};
use rand::{thread_rng, Rng};
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
) -> (Vec<Plaintext>, Option<Ciphertext>) {
    let n = 3;
    let s = 10;
    let degree = 10;
    let std_dev = 3.2;
    let q = 83380292323641237751;

    // step 1
    let mut rng = thread_rng();

    //let f: Vec<Plaintext> = (0..n).map(|_| Fr::rand(rng)).collect();
    let f: Vec<Plaintext> = (0..n).map(|_| Plaintext::rand(s, &mut rng)).collect();

    // // step 2
    //let e_f_vec: Vec<i32> = f.iter().map(|&f_i| encode(f_i)).collect();
    let r = get_gaussian(std_dev, degree as usize * 3, q, &mut rng);
    let e_f_vec: Vec<Ciphertext> = f.iter().map(|f_i| f_i.encode().encrypt(pk, &r)).collect();

    // step 3
    //let parameters = ZKPoPK::Parameters::new(7, 10, 2, 4, 30, 2, 41, 83380292323641237751);

    for i in (0..n) {
        let f_i = &f[i];
        let e_f_i = &e_f_vec[i];

        let instance = ZKPoPK::Instance::new(pk.clone(), vec![e_f_i.clone()]);

        let r2: Vec<Encodedtext> =
            vec![
                Encodedtext::new(vec![0; parameters.get_d() as usize], parameters.get_q());
                parameters.get_sec() as usize
            ];

        let witness = ZKPoPK::Witness::new(
            vec![f_i.clone()],
            &vec![f_i.encode()],
            &vec![r.clone(); parameters.get_sec() as usize],
        );

        let proof = ZKPoPK::prove(&parameters, &witness, &instance);

        ZKPoPK::verify(&proof, &parameters, &instance).unwrap();
    }

    // step4
    let mut sum = Ciphertext::new(
        Encodedtext::new(vec![0; parameters.get_N() as usize], parameters.get_q()),
        Encodedtext::new(vec![0; parameters.get_N() as usize], parameters.get_q()),
        Encodedtext::new(vec![0; parameters.get_N() as usize], parameters.get_q()),
    );

    for i in 0..e_f_vec.len() {
        sum = sum + e_f_vec[i].clone();
    }

    //let e_f = e_f_vec.iter().sum();
    let e_f = sum;
    let e_mf = e_m + e_f.clone();

    // TODO: SHEのencodeとdecodeができるようになったら消す。
    let encoded_mf = e_mf.clone().decrypt(sk);

    // step 5
    let mf: Plaintext = e_mf.decrypt(&sk).decode();

    // step 6
    let mut m: Vec<Plaintext> = vec![Plaintext::rand(s, &mut rng); n];
    m[0] = mf.clone() - f[0].clone();

    for i in 1..n {
        m[i] = -f[i].clone();
    }

    // step 7
    //let e_m_new = mf.encode().encrypt(pk, &r) - e_f;

    // TODO: SHEのencodeとdecodeができるようになったら消す。
    let e_m_new = encoded_mf.encrypt(pk, &r) - e_f;

    match enc {
        _NewCiphertext => (m, Some(e_m_new)),
        _NoNewCiphertext => (m, None),
    }
}

struct AngleShare {
    public_modifier: Plaintext,
    share: Vec<Plaintext>,
    MAC: Vec<Plaintext>,
}

fn angle(
    m_vec: Vec<Plaintext>,
    e_m: Ciphertext,
    parameters: &Parameters,
    pk: &PublicKey,
    sk: &SecretKey,
) -> AngleShare {
    let mut rng = thread_rng();

    let e_alpha = Ciphertext::rand(pk, parameters.get_N(), parameters.get_q(), &mut rng); //encode(Fr::from(0));

    let e_malpha = e_m * e_alpha;

    let (gamma_vec, _) = reshare(
        e_malpha,
        CiphertextOpiton::NoNewCiphertext,
        parameters,
        pk,
        sk,
    );

    AngleShare {
        public_modifier: Plaintext::new(vec![Fr::from(0); parameters.get_N() as usize]),
        share: m_vec,
        MAC: gamma_vec,
    }
}

struct BracketShare {
    share: Vec<Plaintext>,
    MAC: Vec<(SecretKey, Vec<Plaintext>)>,
}

fn bracket(
    m_vec: Vec<Plaintext>,
    e_m: Ciphertext,
    parameters: &Parameters,
    pk: &PublicKey,
    sk: &SecretKey,
) -> BracketShare {
    let n = 3;

    let mut rng = thread_rng();

    // step 1
    let beta_vec: Vec<SecretKey> = (0..n)
        .map(|_| SecretKey::generate(parameters.get_N(), parameters.get_q(), 3.2, &mut rng))
        .collect();
    let e_beta_vec: Vec<Ciphertext> = (0..n)
        .map(|_| Ciphertext::rand(pk, parameters.get_N(), parameters.get_q(), &mut rng))
        .collect();

    let e_gamma_vec: Vec<Ciphertext> = e_beta_vec
        .iter()
        .map(|e_beta_i| e_beta_i.clone() * e_m.clone())
        .collect();

    // step 2
    let gamma_vecvec: Vec<Vec<Plaintext>> = e_gamma_vec
        .iter()
        .map(|e_gamma_i| {
            let (gamma_vec, _) = reshare(
                e_gamma_i.clone(),
                CiphertextOpiton::NoNewCiphertext,
                parameters,
                pk,
                sk,
            );
            gamma_vec
        })
        .collect();

    // step 3
    // step 4
    let mac: Vec<(SecretKey, Vec<Plaintext>)> = (1..n)
        .map(|i| {
            (
                beta_vec[i].clone(),
                (1..n)
                    .map(|j| gamma_vecvec[j][i].clone())
                    .collect::<Vec<Plaintext>>(),
            )
        })
        .collect();

    BracketShare {
        share: m_vec,
        MAC: mac,
    }
}

// initialize
fn initialize(parameters: &Parameters) {
    let n = 3;

    let mut rng = thread_rng();
    let length_s = 1;

    // step 1
    //pk = keygendec

    let sk = SecretKey::generate(parameters.get_N(), parameters.get_q(), 3.2, &mut rng);
    let pk = sk.public_key_gen(
        parameters.get_N(),
        parameters.get_p(),
        parameters.get_q(),
        3.2,
        &mut rng,
    );

    let r = get_gaussian(
        3.2,
        parameters.get_N() as usize * 3,
        parameters.get_q(),
        &mut rng,
    );

    // step 2
    let beta: Vec<Plaintext> = (0..n)
        .map(|_| Plaintext::rand(length_s, &mut rng))
        .collect();

    // step 3
    let alpha_vec: Vec<Plaintext> = (0..n)
        .map(|_| Plaintext::rand(length_s, &mut rng))
        .collect();

    // step 4
    // TODO 対角化
    let e_alpha_vec: Vec<Ciphertext> = alpha_vec
        .iter()
        .map(|alpha_i| alpha_i.encode().encrypt(&pk, &r))
        .collect();
    let e_beta_vec: Vec<Ciphertext> = beta
        .iter()
        .map(|beta_i| beta_i.encode().encrypt(&pk, &r))
        .collect();

    // step 5
    // ZKPoPK
    for i in (0..n) {
        let instance_alpha = ZKPoPK::Instance::new(pk.clone(), vec![e_alpha_vec[i].clone()]);

        // TODO これは何？
        let r2: Vec<Encodedtext> =
            vec![
                Encodedtext::new(vec![0; parameters.get_d() as usize], parameters.get_q());
                parameters.get_sec() as usize
            ];

        let witness_alpha = ZKPoPK::Witness::new(
            vec![alpha_vec[i].clone()],
            &vec![alpha_vec[i].encode()],
            &vec![r.clone(); parameters.get_sec() as usize],
        );

        let proof_alpha = ZKPoPK::prove(&parameters, &witness_alpha, &instance_alpha);

        let instance_beta = ZKPoPK::Instance::new(pk.clone(), vec![e_beta_vec[i].clone()]);

        let witness_beta = ZKPoPK::Witness::new(
            vec![beta[i].clone()],
            &vec![beta[i].encode()],
            &vec![r.clone(); parameters.get_sec() as usize],
        );

        let proof_beta = ZKPoPK::prove(&parameters, &witness_beta, &instance_beta);

        ZKPoPK::verify(&proof_beta, &parameters, &instance_beta).unwrap();
    }

    // step 6
    // let e_alpha = e_alpha_vec.iter().sum();

    let mut sum = Ciphertext::new(
        Encodedtext::new(vec![0; parameters.get_N() as usize], parameters.get_q()),
        Encodedtext::new(vec![0; parameters.get_N() as usize], parameters.get_q()),
        Encodedtext::new(vec![0; parameters.get_N() as usize], parameters.get_q()),
    );

    for i in 0..e_alpha_vec.len() {
        sum = sum + e_alpha_vec[i].clone();
    }

    //let diag_alpha = bracket(diag_alpha_vec, e_alpha, parameters, &pk, &sk);
    let diag_alpha = bracket(alpha_vec, sum, parameters, &pk, &sk);
}

fn pair(pk: &PublicKey, sk: &SecretKey, parameters: &Parameters) -> (BracketShare, AngleShare) {
    let n = 3;
    let length_s = 10;
    let mut rng = thread_rng();

    let r = get_gaussian(
        3.2,
        parameters.get_N() as usize * 3,
        parameters.get_q(),
        &mut rng,
    );

    // step 1
    let r_vec: Vec<Plaintext> = (0..n)
        .map(|_| Plaintext::rand(length_s, &mut rng))
        .collect();

    // step 2
    let e_r_vec: Vec<Ciphertext> = r_vec
        .iter()
        .map(|r_vec_i| r_vec_i.encode().encrypt(&pk, &r))
        .collect();

    // step 3
    for i in (0..n) {
        let r_i = &r_vec[i];
        let e_r_i = &e_r_vec[i];

        let instance = ZKPoPK::Instance::new(pk.clone(), vec![e_r_i.clone()]);

        let witness = ZKPoPK::Witness::new(
            vec![r_i.clone()],
            &vec![r_i.encode()],
            &vec![r.clone(); parameters.get_sec() as usize],
        );

        let proof = ZKPoPK::prove(&parameters, &witness, &instance);

        ZKPoPK::verify(&proof, &parameters, &instance).unwrap();
    }

    // step 4
    let mut sum = Ciphertext::new(
        Encodedtext::new(vec![0; parameters.get_N() as usize], parameters.get_q()),
        Encodedtext::new(vec![0; parameters.get_N() as usize], parameters.get_q()),
        Encodedtext::new(vec![0; parameters.get_N() as usize], parameters.get_q()),
    );

    for i in 0..e_r_vec.len() {
        sum = sum + e_r_vec[i].clone();
    }

    let r_bracket = bracket(r_vec.clone(), sum.clone(), parameters, &pk, &sk);
    let r_angle = angle(r_vec, sum, parameters, &pk, &sk);

    (r_bracket, r_angle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reshare() {
        let mut rng = rand::thread_rng();

        let parameters = ZKPoPK::Parameters::new(1, 10, 2, 1, 30, 2, 41, 83380292323641237751);

        let sk = SecretKey::generate(parameters.get_N(), parameters.get_q(), 3.2, &mut rng);
        let pk = sk.public_key_gen(
            parameters.get_N(),
            parameters.get_p(),
            parameters.get_q(),
            3.2,
            &mut rng,
        );

        let e_m = Ciphertext::rand(&pk, parameters.get_N(), parameters.get_q(), &mut rng);

        let (m_vec, ct) = reshare(
            e_m.clone(),
            CiphertextOpiton::NewCiphertext,
            &parameters,
            &pk,
            &sk,
        );
        let ct = ct.unwrap();

        //assert_eq!(e_m.decrypt(&sk).decode(), m_vec.iter().sum::<Plaintext>());

        assert_eq!(
            e_m.decrypt(&sk).modulo_p(parameters.get_p()),
            ct.decrypt(&sk).modulo_p(parameters.get_p())
        );
    }

    #[test]
    fn test_angle() {
        let n = 3;

        let mut rng = rand::thread_rng();

        let parameters = ZKPoPK::Parameters::new(1, 10, 2, 1, 30, 2, 41, 83380292323641237751);

        let sk = SecretKey::generate(parameters.get_N(), parameters.get_q(), 3.2, &mut rng);
        let pk = sk.public_key_gen(
            parameters.get_N(),
            parameters.get_p(),
            parameters.get_q(),
            3.2,
            &mut rng,
        );

        let r = get_gaussian(
            3.2,
            parameters.get_N() as usize * 3,
            parameters.get_q(),
            &mut rng,
        );

        let m_vec: Vec<Plaintext> = (0..n).map(|_| Plaintext::rand(10, &mut rng)).collect();

        let mut sum = Plaintext::new(vec![Fr::from(0); 10]);

        for i in 0..m_vec.len() {
            sum = sum + m_vec[i].clone();
        }
        let e_m = sum.encode().encrypt(&pk, &r);
        let result = angle(m_vec, e_m, &parameters, &pk, &sk);
    }

    #[test]
    fn test_bracket() {
        let n = 3;
        let mut rng = rand::thread_rng();

        let parameters = ZKPoPK::Parameters::new(1, 10, 2, 1, 30, 2, 41, 83380292323641237751);

        let sk = SecretKey::generate(parameters.get_N(), parameters.get_q(), 3.2, &mut rng);
        let pk = sk.public_key_gen(
            parameters.get_N(),
            parameters.get_p(),
            parameters.get_q(),
            3.2,
            &mut rng,
        );

        let r = get_gaussian(
            3.2,
            parameters.get_N() as usize * 3,
            parameters.get_q(),
            &mut rng,
        );

        let m_vec: Vec<Plaintext> = (0..n).map(|_| Plaintext::rand(10, &mut rng)).collect();

        let mut sum = Plaintext::new(vec![Fr::from(0); 10]);

        for i in 0..m_vec.len() {
            sum = sum + m_vec[i].clone();
        }
        let e_m = sum.encode().encrypt(&pk, &r);

        let result = bracket(m_vec, e_m, &parameters, &pk, &sk);
    }

    #[test]
    fn test_initialize() {
        let parameters = ZKPoPK::Parameters::new(1, 10, 2, 1, 30, 2, 41, 83380292323641237751);

        initialize(&parameters);
    }

    #[test]
    fn test_pair() {
        let mut rng = rand::thread_rng();
        let parameters = ZKPoPK::Parameters::new(1, 10, 2, 1, 30, 2, 41, 83380292323641237751);

        let sk = SecretKey::generate(parameters.get_N(), parameters.get_q(), 3.2, &mut rng);
        let pk = sk.public_key_gen(
            parameters.get_N(),
            parameters.get_p(),
            parameters.get_q(),
            3.2,
            &mut rng,
        );

        let (r_bracket, r_angle) = pair(&pk, &sk, &parameters);
    }
}
