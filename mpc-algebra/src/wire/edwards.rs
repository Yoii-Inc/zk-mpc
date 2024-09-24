use ark_ec::{
    twisted_edwards_extended::{GroupAffine, GroupProjective},
    ModelParameters, MontgomeryModelParameters, TEModelParameters,
};
use ark_ed_on_bls12_377::{EdwardsParameters, EdwardsProjective};
use ark_ff::{field_new, BigInteger256, Field};
use ark_r1cs_std::{fields::fp::FpVar, groups::curves::twisted_edwards::AffineVar};

use ark_crypto_primitives::commitment::pedersen::{Parameters, Randomness};
use ark_crypto_primitives::encryption::elgamal::Parameters as ElGamalParameters;
use ark_crypto_primitives::encryption::elgamal::Randomness as ElGamalRandomness;

use mpc_net::LocalTestNet as Net;
use mpc_trait::MpcWire;

use crate::{channel::MPCSerNet, SpdzFieldShare};
use crate::{AdditiveFieldShare, MpcField, Reveal};

type AdditiveFq = MpcField<ark_bls12_377::Fr, AdditiveFieldShare<ark_bls12_377::Fr>>;
type AdditiveFr = MpcField<ark_ed_on_bls12_377::Fr, AdditiveFieldShare<ark_ed_on_bls12_377::Fr>>;

type SpdzFq = MpcField<ark_bls12_377::Fr, SpdzFieldShare<ark_bls12_377::Fr>>;
type SpdzFr = MpcField<ark_ed_on_bls12_377::Fr, SpdzFieldShare<ark_ed_on_bls12_377::Fr>>;

impl From<AdditiveFr> for BigInteger256 {
    fn from(f: AdditiveFr) -> Self {
        f.unwrap_as_public().into()
    }
}

impl From<SpdzFr> for BigInteger256 {
    fn from(f: SpdzFr) -> Self {
        f.unwrap_as_public().into()
    }
}

pub type AdditiveMpcEdwardsProjective = GroupProjective<AdditiveMpcEdwardsParameters>;
pub type AdditiveMpcEdwardsAffine = GroupAffine<AdditiveMpcEdwardsParameters>;

pub type SpdzMpcEdwardsProjective = GroupProjective<SpdzMpcEdwardsParameters>;
pub type SpdzMpcEdwardsAffine = GroupAffine<SpdzMpcEdwardsParameters>;

#[derive(Clone, Default, PartialEq, Eq)]
pub struct AdditiveMpcEdwardsParameters;

#[derive(Clone, Default, PartialEq, Eq)]
pub struct SpdzMpcEdwardsParameters;

impl ModelParameters for AdditiveMpcEdwardsParameters {
    type BaseField = AdditiveFq;
    type ScalarField = AdditiveFr;
}

impl TEModelParameters for AdditiveMpcEdwardsParameters {
    /// COEFF_A = -1
    #[rustfmt::skip]
    const COEFF_A: AdditiveFq = field_new!(AdditiveFq, "-1");

    /// COEFF_D = 3021
    #[rustfmt::skip]
    const COEFF_D: AdditiveFq = field_new!(AdditiveFq, "3021");

    /// COFACTOR = 4
    const COFACTOR: &'static [u64] = &[4];

    /// COFACTOR_INV =
    /// 527778859339273151515551558673846658209717731602102048798421311598680340096
    #[rustfmt::skip]
    const COFACTOR_INV: AdditiveFr = field_new!(AdditiveFr, "527778859339273151515551558673846658209717731602102048798421311598680340096");

    /// Generated randomly
    const AFFINE_GENERATOR_COEFFS: (Self::BaseField, Self::BaseField) =
        (ADDITIVE_GENERATOR_X, ADDITIVE_GENERATOR_Y);

    type MontgomeryModelParameters = AdditiveMpcEdwardsParameters;

    /// Multiplication by `a` is just negation.
    /// Is `a` 1 or -1?
    #[inline(always)]
    fn mul_by_a(elem: &Self::BaseField) -> Self::BaseField {
        -*elem
    }
}

impl MontgomeryModelParameters for AdditiveMpcEdwardsParameters {
    /// COEFF_A = 0x8D26E3FADA9010A26949031ECE3971B93952AD84D4753DDEDB748DA37E8F552
    ///         = 3990301581132929505568273333084066329187552697088022219156688740916631500114
    #[rustfmt::skip]
    const COEFF_A: AdditiveFq = field_new!(AdditiveFq, "3990301581132929505568273333084066329187552697088022219156688740916631500114");
    /// COEFF_B = 0x9D8F71EEC83A44C3A1FBCEC6F5418E5C6154C2682B8AC231C5A3725C8170AAD
    ///         = 4454160168295440918680551605697480202188346638066041608778544715000777738925
    #[rustfmt::skip]
    const COEFF_B: AdditiveFq = field_new!(AdditiveFq, "4454160168295440918680551605697480202188346638066041608778544715000777738925");

    type TEModelParameters = AdditiveMpcEdwardsParameters;
}

/// GENERATOR_X =
/// 4497879464030519973909970603271755437257548612157028181994697785683032656389,
#[rustfmt::skip]
const ADDITIVE_GENERATOR_X: AdditiveFq = field_new!(AdditiveFq, "4497879464030519973909970603271755437257548612157028181994697785683032656389");

/// GENERATOR_Y =
/// 4357141146396347889246900916607623952598927460421559113092863576544024487809
#[rustfmt::skip]
const ADDITIVE_GENERATOR_Y: AdditiveFq = field_new!(AdditiveFq, "4357141146396347889246900916607623952598927460421559113092863576544024487809");

impl AdditiveFr {
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
        let val = ark_ed_on_bls12_377::Fr::const_from_str(limbs, is_positive, r2, modulus, inv);
        Self::Public(val)
    }
}

impl AdditiveFq {
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
        let val = ark_bls12_377::Fr::const_from_str(limbs, is_positive, r2, modulus, inv);
        Self::Public(val)
    }
}

impl ModelParameters for SpdzMpcEdwardsParameters {
    type BaseField = SpdzFq;
    type ScalarField = SpdzFr;
}

impl TEModelParameters for SpdzMpcEdwardsParameters {
    /// COEFF_A = -1
    #[rustfmt::skip]
    const COEFF_A: SpdzFq = field_new!(SpdzFq, "-1");

    /// COEFF_D = 3021
    #[rustfmt::skip]
    const COEFF_D: SpdzFq = field_new!(SpdzFq, "3021");

    /// COFACTOR = 4
    const COFACTOR: &'static [u64] = &[4];

    /// COFACTOR_INV =
    /// 527778859339273151515551558673846658209717731602102048798421311598680340096
    #[rustfmt::skip]
    const COFACTOR_INV: SpdzFr = field_new!(SpdzFr, "527778859339273151515551558673846658209717731602102048798421311598680340096");

    /// Generated randomly
    const AFFINE_GENERATOR_COEFFS: (Self::BaseField, Self::BaseField) =
        (SPDZ_GENERATOR_X, SPDZ_GENERATOR_Y);

    type MontgomeryModelParameters = SpdzMpcEdwardsParameters;

    /// Multiplication by `a` is just negation.
    /// Is `a` 1 or -1?
    #[inline(always)]
    fn mul_by_a(elem: &Self::BaseField) -> Self::BaseField {
        -*elem
    }
}

impl MontgomeryModelParameters for SpdzMpcEdwardsParameters {
    /// COEFF_A = 0x8D26E3FADA9010A26949031ECE3971B93952AD84D4753DDEDB748DA37E8F552
    ///         = 3990301581132929505568273333084066329187552697088022219156688740916631500114
    #[rustfmt::skip]
    const COEFF_A: SpdzFq = field_new!(SpdzFq, "3990301581132929505568273333084066329187552697088022219156688740916631500114");
    /// COEFF_B = 0x9D8F71EEC83A44C3A1FBCEC6F5418E5C6154C2682B8AC231C5A3725C8170AAD
    ///         = 4454160168295440918680551605697480202188346638066041608778544715000777738925
    #[rustfmt::skip]
    const COEFF_B: SpdzFq = field_new!(SpdzFq, "4454160168295440918680551605697480202188346638066041608778544715000777738925");

    type TEModelParameters = SpdzMpcEdwardsParameters;
}

/// GENERATOR_X =
/// 4497879464030519973909970603271755437257548612157028181994697785683032656389,
#[rustfmt::skip]
const SPDZ_GENERATOR_X: SpdzFq = field_new!(SpdzFq, "4497879464030519973909970603271755437257548612157028181994697785683032656389");

/// GENERATOR_Y =
/// 4357141146396347889246900916607623952598927460421559113092863576544024487809
#[rustfmt::skip]
const SPDZ_GENERATOR_Y: SpdzFq = field_new!(SpdzFq, "4357141146396347889246900916607623952598927460421559113092863576544024487809");

impl SpdzFr {
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
        let val = ark_ed_on_bls12_377::Fr::const_from_str(limbs, is_positive, r2, modulus, inv);
        Self::Public(val)
    }
}

impl SpdzFq {
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
        let val = ark_bls12_377::Fr::const_from_str(limbs, is_positive, r2, modulus, inv);
        Self::Public(val)
    }
}

pub type AdditiveFqVar = FpVar<AdditiveFq>;
pub type AdditiveMpcEdwardsVar = AffineVar<AdditiveMpcEdwardsParameters, AdditiveFqVar>;

pub type SpdzFqVar = FpVar<SpdzFq>;
pub type SpdzMpcEdwardsVar = AffineVar<SpdzMpcEdwardsParameters, SpdzFqVar>;

pub trait ToLocal {
    type Local;

    // lift objects to local
    fn to_local(&self) -> Self::Local;
}

pub trait FromLocal {
    type Local;

    // lift objects from local
    fn from_local(local: &Self::Local) -> Self;
}

macro_rules! impl_edwards_related {
    ($param:ident) => {
        impl ToLocal for GroupProjective<$param> {
            type Local = GroupProjective<ark_ed_on_bls12_377::EdwardsParameters>;
            fn to_local(&self) -> GroupProjective<ark_ed_on_bls12_377::EdwardsParameters> {
                let x = self.x.unwrap_as_public();
                let y = self.y.unwrap_as_public();
                let t = self.t.unwrap_as_public();
                let z = self.z.unwrap_as_public();
                GroupProjective::new(x, y, t, z)
            }
        }

        impl ToLocal for Parameters<GroupProjective<$param>> {
            type Local = Parameters<ark_ed_on_bls12_377::EdwardsProjective>;

            fn to_local(&self) -> Self::Local {
                let randomness_generator = self
                    .randomness_generator
                    .iter()
                    .map(|x| x.to_local())
                    .collect::<Vec<_>>();
                let generators = self
                    .generators
                    .iter()
                    .map(|vec_g| vec_g.iter().map(|g| g.to_local()).collect::<Vec<_>>())
                    .collect::<Vec<_>>();

                Self::Local {
                    randomness_generator,
                    generators,
                }
            }
        }

        impl Reveal for GroupProjective<$param> {
            type Base = EdwardsProjective;

            fn reveal(self) -> Self::Base {
                let GroupProjective { x, y, t, z, .. } = self;
                Self::Base::new(x.reveal(), y.reveal(), t.reveal(), z.reveal())
            }

            fn from_add_shared(b: Self::Base) -> Self {
                let x = <$param as ModelParameters>::BaseField::from_add_shared(b.x);
                let y = <$param as ModelParameters>::BaseField::from_add_shared(b.y);
                let t = <$param as ModelParameters>::BaseField::from_add_shared(b.t);
                let z = <$param as ModelParameters>::BaseField::from_add_shared(b.z);
                GroupProjective::new(x, y, t, z)
            }

            fn from_public(b: Self::Base) -> Self {
                let x = <$param as ModelParameters>::BaseField::from_public(b.x);
                let y = <$param as ModelParameters>::BaseField::from_public(b.y);
                let t = <$param as ModelParameters>::BaseField::from_public(b.t);
                let z = <$param as ModelParameters>::BaseField::from_public(b.z);
                GroupProjective::new(x, y, t, z)
            }
        }

        impl Reveal for Randomness<GroupProjective<$param>> {
            type Base = Randomness<EdwardsProjective>;

            fn reveal(self) -> Self::Base {
                let Randomness(r) = self;
                Randomness(r.reveal())
            }

            fn from_add_shared(_b: Self::Base) -> Self {
                unimplemented!()
            }

            fn from_public(_b: Self::Base) -> Self {
                unimplemented!()
            }
        }

        impl FromLocal for GroupProjective<$param> {
            type Local = GroupProjective<EdwardsParameters>;
            fn from_local(local: &Self::Local) -> Self {
                let x = <$param as ModelParameters>::BaseField::from_public(local.x);
                let y = <$param as ModelParameters>::BaseField::from_public(local.y);
                let t = <$param as ModelParameters>::BaseField::from_public(local.t);
                let z = <$param as ModelParameters>::BaseField::from_public(local.z);
                GroupProjective::new(x, y, t, z)
            }
        }

        impl FromLocal for Parameters<GroupProjective<$param>> {
            type Local = Parameters<EdwardsProjective>;

            fn from_local(local: &Self::Local) -> Self {
                let randomness_generator = local
                    .randomness_generator
                    .iter()
                    .map(|x| GroupProjective::<$param>::from_local(x))
                    .collect::<Vec<_>>();
                let generators = local
                    .generators
                    .iter()
                    .map(|vec_g| {
                        vec_g
                            .iter()
                            .map(|g| GroupProjective::<$param>::from_local(g))
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();

                Self {
                    randomness_generator,
                    generators,
                }
            }
        }

        impl FromLocal for GroupAffine<$param> {
            type Local = GroupAffine<EdwardsParameters>;

            fn from_local(local: &Self::Local) -> Self {
                let x = <$param as ModelParameters>::BaseField::from_public(local.x);
                let y = <$param as ModelParameters>::BaseField::from_public(local.y);
                GroupAffine::new(x, y)
            }
        }

        impl ToLocal for GroupAffine<$param> {
            type Local = GroupAffine<EdwardsParameters>;

            fn to_local(&self) -> Self::Local {
                let x = self.x.unwrap_as_public();
                let y = self.y.unwrap_as_public();
                GroupAffine::new(x, y)
            }
        }

        impl Reveal for GroupAffine<$param> {
            type Base = GroupAffine<EdwardsParameters>;

            fn reveal(self) -> Self::Base {
                let is_shared = self.x.is_shared();

                match is_shared {
                    true => Net::broadcast(&self.to_local())
                        .into_iter()
                        .fold(Self::Base::default(), |acc, x| acc + x),
                    false => self.to_local(),
                }
            }

            fn from_add_shared(b: Self::Base) -> Self {
                todo!()
            }

            fn from_public(b: Self::Base) -> Self {
                let x = <$param as ModelParameters>::BaseField::from_public(b.x);
                let y = <$param as ModelParameters>::BaseField::from_public(b.y);
                GroupAffine::new(x, y)
            }
        }

        impl Reveal for ElGamalParameters<GroupProjective<$param>> {
            type Base = ElGamalParameters<EdwardsProjective>;

            fn reveal(self) -> Self::Base {
                Self::Base {
                    generator: self.generator.to_local(),
                }
            }

            fn from_add_shared(b: Self::Base) -> Self {
                todo!()
            }

            fn from_public(b: Self::Base) -> Self {
                Self {
                    generator: GroupAffine::<$param>::from_local(&b.generator),
                }
            }
        }

        impl Reveal for ElGamalRandomness<GroupProjective<$param>> {
            type Base = ElGamalRandomness<EdwardsProjective>;

            fn reveal(self) -> Self::Base {
                todo!()
            }

            fn from_add_shared(b: Self::Base) -> Self {
                Self(<$param as ModelParameters>::ScalarField::from_add_shared(
                    b.0,
                ))
            }

            fn from_public(b: Self::Base) -> Self {
                Self(<$param as ModelParameters>::ScalarField::from_public(b.0))
            }
        }
    };
}

impl_edwards_related!(AdditiveMpcEdwardsParameters);
impl_edwards_related!(SpdzMpcEdwardsParameters);

impl Reveal for GroupAffine<EdwardsParameters> {
    type Base = GroupAffine<EdwardsParameters>;

    fn reveal(self) -> Self::Base {
        Net::broadcast(&self)
            .into_iter()
            .fold(Self::Base::default(), |acc, x| acc + x)
    }

    fn from_add_shared(b: Self::Base) -> Self {
        b
    }

    fn from_public(_b: Self::Base) -> Self {
        unimplemented!()
    }
}
