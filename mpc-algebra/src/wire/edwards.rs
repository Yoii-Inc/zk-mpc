use ark_ec::{
    twisted_edwards_extended::GroupProjective, ModelParameters, MontgomeryModelParameters,
    TEModelParameters,
};
use ark_ff::{field_new, BigInteger256, BigInteger384};

use ark_r1cs_std::{fields::fp::FpVar, groups::curves::twisted_edwards::AffineVar};

use crate::{AdditiveFieldShare, MpcField};

// Scalar for ed
type Fr = MpcField<ark_bls12_377::Fq, AdditiveFieldShare<ark_bls12_377::Fq>>;

impl From<Fr> for BigInteger384 {
    fn from(f: Fr) -> Self {
        todo!()
    }
}
// Base for ed
type Fq = MpcField<ark_bls12_377::Fr, AdditiveFieldShare<ark_bls12_377::Fr>>;

pub type MpcEdwardsProjective = GroupProjective<MpcEdwardsParameters>;

#[derive(Clone, Default, PartialEq, Eq)]
pub struct MpcEdwardsParameters;

impl ModelParameters for MpcEdwardsParameters {
    type BaseField = Fq;
    type ScalarField = Fr;
}

impl TEModelParameters for MpcEdwardsParameters {
    /// COEFF_A = -1
    #[rustfmt::skip]
    const COEFF_A: Fq = field_new!(Fq, "-1");

    /// COEFF_D = 3021
    #[rustfmt::skip]
    const COEFF_D: Fq = field_new!(Fq, "3021");

    /// COFACTOR = 4
    const COFACTOR: &'static [u64] = &[4];

    /// COFACTOR_INV =
    /// 527778859339273151515551558673846658209717731602102048798421311598680340096
    #[rustfmt::skip]
    const COFACTOR_INV: Fr = field_new!(Fr, "527778859339273151515551558673846658209717731602102048798421311598680340096");

    /// Generated randomly
    const AFFINE_GENERATOR_COEFFS: (Self::BaseField, Self::BaseField) = (GENERATOR_X, GENERATOR_Y);

    type MontgomeryModelParameters = MpcEdwardsParameters;

    /// Multiplication by `a` is just negation.
    /// Is `a` 1 or -1?
    #[inline(always)]
    fn mul_by_a(elem: &Self::BaseField) -> Self::BaseField {
        -*elem
    }
}

impl MontgomeryModelParameters for MpcEdwardsParameters {
    /// COEFF_A = 0x8D26E3FADA9010A26949031ECE3971B93952AD84D4753DDEDB748DA37E8F552
    ///         = 3990301581132929505568273333084066329187552697088022219156688740916631500114
    #[rustfmt::skip]
    const COEFF_A: Fq = field_new!(Fq, "3990301581132929505568273333084066329187552697088022219156688740916631500114");
    /// COEFF_B = 0x9D8F71EEC83A44C3A1FBCEC6F5418E5C6154C2682B8AC231C5A3725C8170AAD
    ///         = 4454160168295440918680551605697480202188346638066041608778544715000777738925
    #[rustfmt::skip]
    const COEFF_B: Fq = field_new!(Fq, "4454160168295440918680551605697480202188346638066041608778544715000777738925");

    type TEModelParameters = MpcEdwardsParameters;
}

/// GENERATOR_X =
/// 4497879464030519973909970603271755437257548612157028181994697785683032656389,
#[rustfmt::skip]
const GENERATOR_X: Fq = field_new!(Fq, "4497879464030519973909970603271755437257548612157028181994697785683032656389");

/// GENERATOR_Y =
/// 4357141146396347889246900916607623952598927460421559113092863576544024487809
#[rustfmt::skip]
const GENERATOR_Y: Fq = field_new!(Fq, "4357141146396347889246900916607623952598927460421559113092863576544024487809");

impl Fr {
    /// Interpret a string of decimal numbers as a prime field element.
    /// Does not accept unnecessary leading zeroes or a blank string.
    /// For *internal* use only; please use the `field_new` macro instead
    /// of this method
    #[doc(hidden)]
    pub const fn const_from_str(
        limbs: &[u64],
        is_positive: bool,
        r2: BigInteger384,
        modulus: BigInteger384,
        inv: u64,
    ) -> Self {
        todo!()
    }

    #[inline]
    pub(crate) const fn const_from_repr(
        repr: BigInteger384,
        r2: BigInteger384,
        modulus: BigInteger384,
        inv: u64,
    ) -> Self {
        todo!()
    }
}

impl Fq {
    /// Interpret a string of decimal numbers as a prime field element.
    /// Does not accept unnecessary leading zeroes or a blank string.
    /// For *internal* use only; please use the `field_new` macro instead
    /// of this method
    #[doc(hidden)]
    pub const fn const_from_str(
        limbs: &[u64],
        is_positive: bool,
        r2: BigInteger256,
        modulus: BigInteger256,
        inv: u64,
    ) -> Self {
        let mut repr = BigInteger256([0; 4]);
        let mut i = 0;
        while i < limbs.len() {
            repr.0[i] = limbs[i];
            i += 1;
        }
        let res = Self::const_from_repr(repr, r2, modulus, inv);
        if is_positive {
            res
        } else {
            //res.const_neg(modulus)
            todo!()
        }
    }

    #[inline]
    pub(crate) const fn const_from_repr(
        repr: BigInteger256,
        r2: BigInteger256,
        modulus: BigInteger256,
        inv: u64,
    ) -> Self {
        let mut r = Self::Public(ark_bls12_377::Fr::new(repr));
        // if r.const_is_zero() {
        //     r
        // } else {
        //     r = r.const_mul(&$Fp(r2, PhantomData), modulus, inv);
        //     r
        // }
        r
    }
}

pub type FqVar = FpVar<Fq>;
pub type MpcEdwardsVar = AffineVar<MpcEdwardsParameters, FqVar>;
