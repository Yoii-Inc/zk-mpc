use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mpc_net::MpcNet;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::cell::Cell;

/// A trait for MPC networks that can serialize and deserialize.
pub trait MpcSerNet: MpcNet {
    /// Broadcast a value to each other.
    fn broadcast<T: CanonicalSerialize + CanonicalDeserialize>(out: &T) -> Vec<T> {
        let mut bytes_out = Vec::new();
        out.serialize(&mut bytes_out).unwrap();
        let bytes_in = Self::broadcast_bytes(&bytes_out);
        bytes_in
            .into_iter()
            .map(|b| T::deserialize(&b[..]).unwrap())
            .collect()
    }

    fn send_to_king<T: CanonicalDeserialize + CanonicalSerialize>(out: &T) -> Option<Vec<T>> {
        let mut bytes_out = Vec::new();
        out.serialize(&mut bytes_out).unwrap();
        Self::send_bytes_to_king(&bytes_out).map(|bytes_in| {
            bytes_in
                .into_iter()
                .map(|b| T::deserialize(&b[..]).unwrap())
                .collect()
        })
    }

    fn recieve_from_king<T: CanonicalSerialize + CanonicalDeserialize>(out: Option<Vec<T>>) -> T {
        let bytes_in = Self::recv_bytes_from_king(out.map(|outs| {
            outs.iter()
                .map(|out| {
                    let mut bytes_out = Vec::new();
                    out.serialize(&mut bytes_out).unwrap();
                    bytes_out
                })
                .collect()
        }));
        T::deserialize(&bytes_in[..]).unwrap()
    }

    fn atomic_broadcast<T: CanonicalDeserialize + CanonicalSerialize>(out: &T) -> Vec<T> {
        let mut bytes_out = Vec::new();
        out.serialize(&mut bytes_out).unwrap();
        let ser_len = bytes_out.len();
        bytes_out.resize(ser_len + COMMIT_RAND_BYTES, 0);
        rand::thread_rng().fill_bytes(&mut bytes_out[ser_len..]);
        let commitment = CommitHash::new().chain(&bytes_out).finalize();
        // exchange commitments
        let all_commits = Self::broadcast_bytes(&commitment[..]);
        // exchange (data || randomness)
        let all_data = Self::broadcast_bytes(&bytes_out);
        let self_id = Self::party_id();
        for i in 0..all_commits.len() {
            if i != self_id {
                // check other commitment
                assert_eq!(
                    &all_commits[i][..],
                    &CommitHash::new().chain(&all_data[i]).finalize()[..]
                );
            }
        }
        all_data
            .into_iter()
            .map(|d| T::deserialize(&d[..ser_len]).unwrap())
            .collect()
    }

    fn king_compute<T: CanonicalDeserialize + CanonicalSerialize>(
        x: &T,
        f: impl Fn(Vec<T>) -> Vec<T>,
    ) -> T {
        let king_response = Self::send_to_king(x).map(f);
        Self::recieve_from_king(king_response)
    }
}

impl<N: MpcNet> MpcSerNet for N {}

const ALLOW_CHEATING: Cell<bool> = Cell::new(true);

/// Number of randomness bytes to use in the commitment scheme
const COMMIT_RAND_BYTES: usize = 32;

/// The hash function to use for the commitment
type CommitHash = Sha256;

#[inline]
pub fn can_cheat() -> bool {
    ALLOW_CHEATING.get()
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_sernet() {}
}
