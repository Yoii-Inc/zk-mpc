mod ZKPoPK {
    type Plaintext = i32; // Finite field
    type Ciphertext = i32;

    struct Parameters {
        V: i32,
        N: i32,
        tau: i32,
        sec: i32,
        d: i32,
        rho: i32,
    }

    struct Instance {
        c: Vec<Ciphertext>,
    }

    struct Witness {
        m: Vec<Plaintext>,
    }

    #[derive(Debug)]
    struct Proof {
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

    fn dummy_prove() -> Proof {
        let a = vec![0, 0];
        let z = vec![vec![0, 0], vec![0, 0]];
        let T = vec![vec![0, 0], vec![0, 0]];

        Proof { a, z, T }
    }

    fn verify(proof: Proof, parameters: Parameters, instance: Instance) -> Result<(), ()> {
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
