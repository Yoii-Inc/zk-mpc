#[macro_export]
macro_rules! impl_Fp_mpc {
    ($Fp:ident, $FpParameters:ident) => {
        impl<P: $FpParameters> crate::PubUniformRand for $Fp<P> {}
    }
}