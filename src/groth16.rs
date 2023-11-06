#[cfg(test)]
mod tests {
    use ark_bls12_377::{Bls12_377, Fr};
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    use ark_std::UniformRand;

    use super::super::circuits::circuit::MySimpleCircuit;

    #[test]
    fn test_single() {
        let mut rng = rand::thread_rng();

        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);

        let mut c = a;
        c *= b;

        let circuit = MySimpleCircuit::<Fr> {
            a: Some(a),
            b: Some(b),
        };

        let (circuit_pk, circuit_vk) =
            Groth16::<Bls12_377>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();

        let proof = Groth16::<Bls12_377>::prove(&circuit_pk, circuit.clone(), &mut rng).unwrap();

        assert!(Groth16::<Bls12_377>::verify(&circuit_vk, &[c], &proof).unwrap());
        assert!(!Groth16::<Bls12_377>::verify(&circuit_vk, &[a], &proof).unwrap());
    }

    // #[test]
    // fn test_mpc() {
    //     let mut rng = rand::thread_rng();

    //     // let a = Fr::rand(&mut rng);
    //     // let b = Fr::rand(&mut rng);

    //     let a = AngleShare::rand(&mut rng);
    //     let b = AngleShare::rand(&mut rng);

    //     let mut c = a;
    //     c = c * b;

    //     let circuit = MyCircuit::<Fr> {
    //         a: Some(a),
    //         b: Some(b),
    //     };

    //     // let params = generate_random_parameters(circuit, &mut rng);
    //     let (circuit_pk, circuit_vk) =
    //         Groth16::<Bls12_377>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();

    //     // let pvk = prepare_verifying_key::<E>(&params.vk);

    //     // let mpc_proof = prover::create_random_proof(circuit, &circuit_pk, &mut rng);

    //     // let proof = mpc_proof.reveal();

    //     // TODO: implement reveal
    //     // let pub_a = a.reveal();
    //     // let pub_c = c.reveal();

    //     // assert!(verify_proof(&pvk, &proof, &[pub_c]).unwrap());
    //     // assert!(Groth16::<Bls12_377>::verify(&circuit_vk, &[pub_c], &proof).unwrap());
    //     // assert!(!Groth16::<Bls12_377>::verify(&circuit_vk, &[pub_a], &proof).unwrap());
    // }
}
