use async_trait::async_trait;
use mpc_net::MultiplexedStreamID;
use rand::Rng;

use crate::channel::MpcSerNet;

/// A type should implement [Reveal] if it represents the MPC abstraction of some base type.
///
/// It is typically implemented for shared (or possibly shared) data.
///
/// For example, and additive secret share can be viewed as the MPC abstraction of the underlying
/// type.
///
/// Typically a [Reveal] implementation assumes that there are a collection of other machines which
/// are participating in a protocol with this one, and that all are running the same code (but with
/// different data!).
#[async_trait]
pub trait AsyncReveal: Sized {
    type Base;

    /// Reveal shared data, yielding plain data.
    async fn reveal(self, net: &impl MpcSerNet, sid: MultiplexedStreamID) -> Self::Base;
    /// Construct a share of the sum of the `b` over all machines in the protocol.
    fn from_add_shared(b: Self::Base) -> Self;
    /// Lift public data (same in all machines) into shared data.
    fn from_public(b: Self::Base, net: &impl MpcSerNet) -> Self;
    /// If this share type has some underlying value of the base type, grabs it.
    ///
    /// The semantics of this are highly dependent on the sharing system.
    fn unwrap_as_public(self) -> Self::Base {
        unimplemented!("No unwrap as public for {}", std::any::type_name::<Self>())
    }
    /// Have the king share their `b` value, and send shares to all parties.
    fn king_share<R: Rng>(_b: Self::Base, _rng: &mut R) -> Self {
        unimplemented!("No king share for {}", std::any::type_name::<Self>())
    }
    /// Have the king share their `b` values, and send shares to all parties.
    fn king_share_batch<R: Rng>(bs: Vec<Self::Base>, rng: &mut R) -> Vec<Self> {
        bs.into_iter().map(|b| Self::king_share(b, rng)).collect()
    }
    /// Initialize the network protocol associated with this sharing system, if it is not
    /// initialized.
    fn init_protocol() {}
    /// Destroy the network protocol associated with this sharing system, if it is initalized.
    fn deinit_protocol() {}
}
