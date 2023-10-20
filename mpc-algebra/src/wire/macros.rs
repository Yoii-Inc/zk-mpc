use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::channel::MpcSerNet;
use mpc_net::MpcNet;

use std::fmt::Display;

pub fn check_eq<T: CanonicalSerialize + CanonicalDeserialize + Clone + Eq + Display>(t: T) {
    debug_assert!({
        use log::debug;
        debug!("Consistency check");
        let others = mpc_net::MpcMultiNet::broadcast(&t);
        let mut result = true;
        for (i, other_t) in others.iter().enumerate() {
            if &t != other_t {
                println!(
                    "\nConsistency check failed\nI (party {}) have {}\nvs\n  (party {}) has  {}",
                    mpc_net::MpcMultiNet::party_id(),
                    t,
                    i,
                    other_t
                );
                result = false;
                break;
            }
        }
        result
    })
}
