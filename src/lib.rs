pub mod circuits;
pub mod groth16;
pub mod input;
pub mod marlin;
pub mod preprocessing;
pub mod serialize;
pub mod she;

pub mod werewolf;

pub mod field {
    #[cfg(all(feature = "honest", feature = "malicious"))]
    compile_error!("features \"honest\" and \"malicious\" cannot be enabled at the same time");

    #[cfg(feature = "honest")]
    pub use mpc_algebra::honest_but_curious::*;

    #[cfg(feature = "malicious")]
    pub use mpc_algebra::malicious_majority::*;

    #[cfg(not(any(feature = "honest", feature = "malicious")))]
    compile_error!("enable one of features: \"honest\" or \"malicious\"");
}
