use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use async_trait::async_trait;
use mpc_net::{end_timer, start_timer, MPCNetError, MpcNet, MultiplexedStreamID};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use tokio_util::bytes::Bytes;

/// A trait for MPC networks that can serialize and deserialize.
#[async_trait]
pub trait MpcSerNet: MpcNet {
    /// Broadcast a value to each other.
    async fn broadcast<T: CanonicalSerialize + CanonicalDeserialize + Send + Sync>(
        &self,
        out: &T,
    ) -> Vec<T> {
        let mut bytes_out = Vec::new();
        out.serialize(&mut bytes_out).unwrap();
        let bytes_out = Bytes::from(bytes_out);

        let bytes_in = self
            .broadcast_bytes(&bytes_out, MultiplexedStreamID::Zero)
            .await
            .unwrap();
        bytes_in
            .into_iter()
            .map(|b| T::deserialize(&b[..]).unwrap())
            .collect()
    }

    // fn send_to_king<T: CanonicalDeserialize + CanonicalSerialize>(out: &T) -> Option<Vec<T>> {
    //     let mut bytes_out = Vec::new();
    //     out.serialize(&mut bytes_out).unwrap();
    //     Self::send_bytes_to_king(&bytes_out).map(|bytes_in| {
    //         bytes_in
    //             .into_iter()
    //             .map(|b| T::deserialize(&b[..]).unwrap())
    //             .collect()
    //     })
    // }

    fn receive_from_king<T: CanonicalSerialize + CanonicalDeserialize>(out: Option<Vec<T>>) -> T {
        // let bytes_in = Self::recv_bytes_from_king(out.map(|outs| {
        //     outs.iter()
        //         .map(|out| {
        //             let mut bytes_out = Vec::new();
        //             out.serialize(&mut bytes_out).unwrap();
        //             bytes_out
        //         })
        //         .collect()
        // }));
        // T::deserialize(&bytes_in[..]).unwrap()
        unimplemented!()
    }

    fn atomic_broadcast<T: CanonicalDeserialize + CanonicalSerialize>(out: &T) -> Vec<T> {
        // let mut bytes_out = Vec::new();
        // out.serialize(&mut bytes_out).unwrap();
        // let ser_len = bytes_out.len();
        // bytes_out.resize(ser_len + COMMIT_RAND_BYTES, 0);
        // rand::thread_rng().fill_bytes(&mut bytes_out[ser_len..]);
        // let commitment = CommitHash::new().chain(&bytes_out).finalize();
        // // exchange commitments
        // let all_commits = Self::broadcast_bytes(&commitment[..]);
        // // exchange (data || randomness)
        // let all_data = Self::broadcast_bytes(&bytes_out);
        // let self_id = Self::party_id();
        // for i in 0..all_commits.len() {
        //     if i != self_id {
        //         // check other commitment
        //         assert_eq!(
        //             &all_commits[i][..],
        //             &CommitHash::new().chain(&all_data[i]).finalize()[..]
        //         );
        //     }
        // }
        // all_data
        //     .into_iter()
        //     .map(|d| T::deserialize(&d[..ser_len]).unwrap())
        //     .collect()
        unimplemented!()
    }

    // fn king_compute<T: CanonicalDeserialize + CanonicalSerialize>(
    //     x: &T,
    //     f: impl Fn(Vec<T>) -> Vec<T>,
    // ) -> T {
    //     let king_response = Self::send_to_king(x).map(f);
    //     Self::receive_from_king(king_response)
    // }

    async fn worker_send_or_leader_receive_element<
        T: CanonicalDeserialize + CanonicalSerialize + Sync,
    >(
        &self,
        out: &T,
        sid: MultiplexedStreamID,
    ) -> Result<Option<Vec<T>>, MPCNetError> {
        let mut bytes_out = Vec::new();
        out.serialize(&mut bytes_out).unwrap();
        let bytes_in = self.worker_send_or_leader_receive(&bytes_out, sid).await?;
        if let Some(bytes_in) = bytes_in {
            // This is leader
            debug_assert!(self.is_leader());
            let results: Vec<Result<T, MPCNetError>> = bytes_in
                .into_iter()
                .map(|b| {
                    T::deserialize(&b[..]).map_err(|err| MPCNetError::Generic(err.to_string()))
                })
                .collect();

            let mut ret = Vec::new();
            for result in results {
                ret.push(result?);
            }

            Ok(Some(ret))
        } else {
            Ok(None)
        }
    }

    async fn worker_receive_or_leader_send_element<
        T: CanonicalDeserialize + CanonicalSerialize + Send,
        // A bug of rustc, T does not have to be Send actually. See https://github.com/rust-lang/rust/issues/63768
    >(
        &self,
        out: Option<Vec<T>>,
        sid: MultiplexedStreamID,
    ) -> Result<T, MPCNetError> {
        let bytes = out.map(|outs| {
            outs.iter()
                .map(|out| {
                    let mut bytes_out = Vec::new();
                    out.serialize(&mut bytes_out).unwrap();
                    bytes_out.into()
                })
                .collect()
        });

        let bytes_in = self.worker_receive_or_leader_send(bytes, sid).await?;
        Ok(T::deserialize(&bytes_in[..])?)
    }

    async fn leader_compute_element<
        T: CanonicalDeserialize + CanonicalSerialize + Send + Clone + Sync,
    >(
        &self,
        out: &T,
        sid: MultiplexedStreamID,
        f: impl Fn(Vec<T>) -> Vec<T> + Send,
        for_what: &str,
    ) -> Result<T, MPCNetError> {
        let leader_response = self.worker_send_or_leader_receive_element(out, sid).await?;
        let timer = start_timer!(
            format!("Leader: Compute element ({})", for_what),
            self.is_leader()
        );
        let leader_response = leader_response.map(f);
        end_timer!(timer);
        self.worker_receive_or_leader_send_element(leader_response, sid)
            .await
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
