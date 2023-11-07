use ark_ff::{CubicExtField, CubicExtParameters, QuadExtField, QuadExtParameters};
use ark_ff::{
    Fp256, Fp256Parameters, Fp320, Fp320Parameters, Fp384, Fp384Parameters, Fp448, Fp448Parameters,
    Fp64, Fp64Parameters, Fp768, Fp768Parameters, Fp832, Fp832Parameters,
};
use mpc_trait::PubUniformRand;

use crate::impl_Fp_mpc;
impl<P: QuadExtParameters> PubUniformRand for QuadExtField<P> {}
impl<P: CubicExtParameters> PubUniformRand for CubicExtField<P> {}

impl_Fp_mpc!(Fp64, Fp64Parameters);
impl_Fp_mpc!(Fp256, Fp256Parameters);
impl_Fp_mpc!(Fp320, Fp320Parameters);
impl_Fp_mpc!(Fp384, Fp384Parameters);
impl_Fp_mpc!(Fp448, Fp448Parameters);
impl_Fp_mpc!(Fp768, Fp768Parameters);
impl_Fp_mpc!(Fp832, Fp832Parameters);
