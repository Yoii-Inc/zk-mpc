mod ZKPoPK {
    type Plaintext = i32; // Finite field
    type Ciphertext = i32;

    pub struct Parameters {
        V: i32,
        N: i32,
        tau: i32,
        sec: i32,
        d: i32,
        rho: i32,
    }

    impl Parameters {
        pub fn new(V: i32, N: i32, tau: i32, sec: i32, d: i32, rho: i32) -> Self {
            Self {
                V: V,
                N: N,
                tau: tau,
                sec: sec,
                d: d,
                rho: rho,
            }
        }
    }

    pub struct Instance {
        c: Vec<Ciphertext>,
    }

    impl Instance {
        pub fn new(c: Vec<Ciphertext>) -> Self {
            Self { c: c }
        }
    }

    struct Witness {
        m: Vec<Plaintext>,
    }

    #[derive(Debug)]
    pub struct Proof {
        a: Vec<Ciphertext>, //G^V
        z: Vec<Vec<i32>>,   //\mathbb{Z}^{N\times V}
        T: Vec<Vec<i32>>,   //\mathbb{Z}^{V\times d}
    }

    struct ZKPoPK {
        parameters: Parameters,
        instance: Instance,
        witness: Witness,
    }

    // TODO: SHEを整えてから実装する
    // fn prove() -> Proof {

    //     let N = 10; //SHEのパラメータ

    //     // step 1
    //     let u: Vec<i32> = generate_u();
    //     let s: Vec<Vec<i32>> = generate_s();
    //     // let y_i = encode(m_i)+u_i;

    //     let y = m.iter().zip(u.iter()).map(|(&m_i, &u_i)| encode(m_i) + u_i).collect_vec();

    //     // step 2
    //     //let a_i = y_i.encrypt(&public_key, s_i);
    //     // let S = (s_1,...,s_V);
    //     //let y = y_i.collect_vec();
    //     let a = y.iter().zip(s.iter()).map(|(&y_i, &s_i)| y_i.encrypt(&public_key, s_i)).collect_vec();

    //     // step 3
    //     let commit_a = commit(a);

    //     // step 4
    //     let e = h(a,c); //outputがsec bitのハッシュ関数

    //     // step 5
    //     let M_e: Vec<Vec<i32>> = generate_M_e(e);
    //     //let z=y+M_e*x;
    //     let z = y + M_e.iter().zip(x.iter()).map(|(&row,&x_i)| dot_product(&row, &x_i)).collect_vec();

    //     let R: Vec<Vec<i32>> = generate_R();
    //     let trans_R = transpose(R);
    //     // let T=S+M_e*R;
    //     let T = s + M_e.iter().zip(trans_R.iter()).map(|(&row,&R_i)| dot_product(&row, &R_i)).collect_vec();

    //     Proof {a,z,T}
    // }

    pub fn dummy_prove() -> Proof {
        let a = vec![0, 0];
        let z = vec![vec![0, 0], vec![0, 0]];
        let T = vec![vec![0, 0], vec![0, 0]];

        Proof { a, z, T }
    }

    pub fn verify(proof: Proof, parameters: Parameters, instance: Instance) -> Result<(), ()> {
        // TODO: SHEを整えてから実装する
        // step 6
        // let e = h(proof.a, instance.c);
        // let d = z.iter().zip(t.iter()).map(|(&z_i, &t_i)| z_i.encrypt(&public_key, t_i)).collect_vec();

        // step 7
        //let M_e: Vec<Vec<i32>> = generate_M_e(e);
        let M_e: Vec<Vec<i32>> = vec![vec![0, 0], vec![0, 0]];

        let rhs: Vec<Ciphertext> = M_e
            .iter()
            .zip(proof.a.iter())
            .map(|(&ref row, &a_i)| a_i + dot_product(&row, &instance.c))
            .collect();
        let dummy_d = &rhs;

        assert!(dummy_d == &rhs);

        let norm_z = proof
            .z
            .iter()
            .flatten()
            .map(|&z_i| z_i.abs())
            .max()
            .unwrap();

        assert!(norm_z < 128 * parameters.N * parameters.tau * parameters.sec.pow(2));

        let norm_T = proof
            .T
            .iter()
            .flatten()
            .map(|&t_i| t_i.abs())
            .max()
            .unwrap();

        assert!(norm_T < 128 * parameters.d * parameters.rho * parameters.sec.pow(2));

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

    #[test]
    fn test_proof() {
        let parameters = Parameters {
            V: 2,
            N: 2,
            tau: 2,
            sec: 2,
            d: 2,
            rho: 2,
        };
        let instance = Instance { c: vec![0, 0] };

        let dummy_proof = dummy_prove();

        verify(dummy_proof, parameters, instance).unwrap();
    }
}

use ark_bls12_377::Fr;
use ark_std::{test_rng, UniformRand};
type Ciphertext = i32;

enum CiphertextOpiton {
    NewCiphertext,
    NoNewCiphertext,
}

fn encode(f: Fr) -> Ciphertext {
    0
}

fn decode(c: Ciphertext) -> Fr {
    Fr::from(0)
}

fn reshare(e_m: Ciphertext, enc: CiphertextOpiton) -> (Vec<Fr>, Option<Ciphertext>) {
    let n = 3;

    // step 1
    let rng = &mut test_rng();

    let f: Vec<Fr> = (0..n).map(|_| Fr::rand(rng)).collect();

    // // step 2
    let e_f_vec: Vec<i32> = f.iter().map(|&f_i| encode(f_i)).collect();

    // step 3
    let parameters = ZKPoPK::Parameters::new(2, 2, 2, 2, 2, 2);

    let instance = ZKPoPK::Instance::new(vec![0, 0]);

    let dummy_proof = ZKPoPK::dummy_prove();

    ZKPoPK::verify(dummy_proof, parameters, instance).unwrap();

    // step4
    let e_f: Ciphertext = e_f_vec.iter().sum();
    let e_mf: Ciphertext = e_m + e_f;

    // step 5
    let mf = decode(e_mf);

    // step 6
    let mut m: Vec<Fr> = vec![Fr::from(0); n];
    m[0] = mf - f[0];

    for i in 1..n {
        m[i] = -f[i];
    }

    // step 7
    let e_m_new = encode(mf) - e_f;
    match enc {
        _NewCiphertext => (m, Some(e_m_new)),
        _NoNewCiphertext => (m, None),
    }
}

struct AngleShare {
    public_modifier: Fr,
    share: Vec<Fr>,
    MAC: Vec<Fr>,
}

fn angle(m_vec: Vec<Fr>, e_m: Ciphertext) -> AngleShare {
    let e_alpha = encode(Fr::from(0));
    let e_malpha: Ciphertext = e_m * e_alpha;
    let (gamma_vec, _) = reshare(e_malpha, CiphertextOpiton::NoNewCiphertext);

    AngleShare {
        public_modifier: Fr::from(0),
        share: m_vec,
        MAC: gamma_vec,
    }
}

type PrivateKey = Fr;
struct BracketShare {
    share: Vec<Fr>,
    MAC: Vec<(PrivateKey, Vec<Fr>)>,
}

fn bracket(m_vec: Vec<Fr>, e_m: Ciphertext) -> BracketShare {
    let n = 3;

    // step 1
    let beta_vec = vec![Fr::from(0); n];
    let e_beta_vec = vec![encode(Fr::from(0)); n];

    let e_gamma_vec: Vec<Ciphertext> = e_beta_vec.iter().map(|&e_beta_i| e_beta_i * e_m).collect();

    // step 2
    let gamma_vecvec: Vec<Vec<Fr>> = e_gamma_vec
        .iter()
        .map(|&e_gamma_i| {
            let (gamma_vec, _) = reshare(e_gamma_i, CiphertextOpiton::NoNewCiphertext);
            gamma_vec
        })
        .collect();

    // step 3
    // step 4
    let mac: Vec<(PrivateKey, Vec<Fr>)> = (1..n)
        .map(|i| (beta_vec[i], (1..n).map(|j| gamma_vecvec[j][i]).collect()))
        .collect();

    BracketShare {
        share: m_vec,
        MAC: mac,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reshare() {
        let result = reshare(0, CiphertextOpiton::NewCiphertext);
    }

    #[test]
    fn test_angle() {
        let m_vec = vec![Fr::from(0); 3];
        let e_m = 0;
        let result = angle(m_vec, e_m);
    }

    #[test]
    fn test_bracket() {
        let m_vec = vec![Fr::from(0); 3];
        let e_m = 0;
        let result = bracket(m_vec, e_m);
    }
}
