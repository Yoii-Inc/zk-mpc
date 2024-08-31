pub mod multi;
pub use multi::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub enum MPCNetError {
    Generic(String),
    Protocol { err: String, party: u32 },
    NotConnected,
    BadInput { err: &'static str },
}

impl<T: ToString> From<T> for MPCNetError {
    fn from(e: T) -> Self {
        MPCNetError::Generic(e.to_string())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, Copy)]
pub enum MultiplexedStreamID {
    Zero = 0,
    One = 1,
    Two = 2,
}

pub trait MpcNet {
    /// Am I the first party?
    #[inline]
    fn is_leader() -> bool {
        Self::party_id() == 0
    }
    /// How many parties are there?
    fn n_parties() -> usize;
    /// What is my party number (0 to n-1)?
    fn party_id() -> usize;
    /// Initialize the network layer from a file.
    /// The file should contain one HOST:PORT setting per line, corresponding to the addresses of
    /// the parties in increasing order.
    ///
    /// Parties are zero-indexed.
    fn init_from_file(path: &str, party_id: usize);
    /// Is the network layer initalized?
    fn is_init() -> bool;
    /// Uninitialize the network layer, closing all connections.
    fn deinit();
    /// Set statistics to zero.
    fn reset_stats();
    /// Get statistics.
    fn stats() -> Stats;
    /// All parties send bytes to each other.
    fn broadcast_bytes(bytes: &[u8]) -> Vec<Vec<u8>>;
    /// All parties send bytes to the king.
    fn worker_send_or_leader_receive(bytes: &[u8]) -> Option<Vec<Vec<u8>>>;
    /// All parties recv bytes from the king.
    /// Provide bytes iff you're the king!
    fn worker_receive_or_leader_send(bytes: Option<Vec<Vec<u8>>>) -> Vec<u8>;

    /// Everyone sends bytes to the king, who recieves those bytes, runs a computation on them, and
    /// redistributes the resulting bytes.
    ///
    /// The king's computation is given by a function, `f`
    /// proceeds.
    #[inline]
    fn leader_compute(bytes: &[u8], f: impl Fn(Vec<Vec<u8>>) -> Vec<Vec<u8>>) -> Vec<u8> {
        let king_response = Self::worker_send_or_leader_receive(bytes).map(f);
        Self::worker_receive_or_leader_send(king_response)
    }

    fn uninit();
}
