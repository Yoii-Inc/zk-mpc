use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mpc_net::MpcNet;

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

    fn receive_from_king<T: CanonicalSerialize + CanonicalDeserialize>(out: Option<Vec<T>>) -> T {
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
}

impl<N: MpcNet> MpcSerNet for N {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sernet() {}
}
