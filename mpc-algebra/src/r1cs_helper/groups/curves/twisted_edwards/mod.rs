use ark_ec::{
    twisted_edwards_extended::{GroupAffine as TEAffine, GroupProjective as TEProjective},
    AffineCurve, ModelParameters, MontgomeryModelParameters, ProjectiveCurve, TEModelParameters,
};
use ark_ff::{
    BigInteger, BitIteratorBE, Field, One, PrimeField, SquareRootField, UniformRand, Zero,
};

use ark_r1cs_std::{alloc::AllocationMode, impl_bounded_ops};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use derivative::Derivative;
use mpc_trait::MpcWire;

use crate::{
    groups::{GroupOpsBounds, MpcCurveVar},
    mpc_fields::FieldOpsBounds,
    r1cs_helper::mpc_fields::MpcFieldVar,
    AdditiveAffProjShare, FieldShare, MpcBoolean, MpcCondSelectGadget, MpcTwoBitLookupGadget,
    Reveal,
};

use crate::MpcGroupProjectiveVariant;

use crate::MpcEqGadget;
use crate::MpcToBitsGadget;
use ark_r1cs_std::{prelude::*, ToConstraintFieldGadget};

use ark_r1cs_std::fields::fp::FpVar;

use core::{borrow::Borrow, marker::PhantomData};

use crate::wire::MpcGroupAffine as MpcTEAffine;
use crate::wire::MpcGroupProjective as MpcTEProjective;

// use crate::honest_but_curious::*;
use crate::malicious_majority::*;

use mpc_net::{MpcMultiNet as Net, MpcNet};

type MpcBaseField<P: TEModelParameters> = MpcField<P::BaseField>;
type MpcScalarField<P: TEModelParameters> = MpcField<P::ScalarField>;

// /// An implementation of arithmetic for Montgomery curves that relies on
// /// incomplete addition formulae for the affine model, as outlined in the
// /// [EFD](https://www.hyperelliptic.org/EFD/g1p/auto-montgom.html).
// ///
// /// This is intended for use primarily for implementing efficient
// /// multi-scalar-multiplication in the Bowe-Hopwood-Pedersen hash.
// #[derive(Derivative)]
// #[derivative(Debug, Clone)]
// #[must_use]
// pub struct MontgomeryAffineVar<
//     P: TEModelParameters,
//     F: FieldVar<P::BaseField, <P::BaseField as Field>::BasePrimeField>,
// > where
//     for<'a> &'a F: FieldOpsBounds<'a, P::BaseField, F>,
// {
//     /// The x-coordinate.
//     pub x: F,
//     /// The y-coordinate.
//     pub y: F,
//     #[derivative(Debug = "ignore")]
//     _params: PhantomData<P>,
// }

// mod montgomery_affine_impl {
//     use super::*;
//     use ark_ec::twisted_edwards_extended::GroupAffine;
//     use ark_ff::Field;
//     use core::ops::Add;

//     impl<P, F> R1CSVar<<P::BaseField as Field>::BasePrimeField> for MontgomeryAffineVar<P, F>
//     where
//         P: TEModelParameters,
//         F: FieldVar<P::BaseField, <P::BaseField as Field>::BasePrimeField>,
//         for<'a> &'a F: FieldOpsBounds<'a, P::BaseField, F>,
//     {
//         type Value = (P::BaseField, P::BaseField);

//         fn cs(&self) -> ConstraintSystemRef<<P::BaseField as Field>::BasePrimeField> {
//             self.x.cs().or(self.y.cs())
//         }

//         fn value(&self) -> Result<Self::Value, SynthesisError> {
//             let x = self.x.value()?;
//             let y = self.y.value()?;
//             Ok((x, y))
//         }
//     }

//     impl<
//             P: TEModelParameters,
//             F: FieldVar<P::BaseField, <P::BaseField as Field>::BasePrimeField>,
//         > MontgomeryAffineVar<P, F>
//     where
//         for<'a> &'a F: FieldOpsBounds<'a, P::BaseField, F>,
//     {
//         /// Constructs `Self` from an `(x, y)` coordinate pair.
//         pub fn new(x: F, y: F) -> Self {
//             Self {
//                 x,
//                 y,
//                 _params: PhantomData,
//             }
//         }

//         /// Converts a Twisted Edwards curve point to coordinates for the
//         /// corresponding affine Montgomery curve point.
//         #[tracing::instrument(target = "r1cs")]
//         pub fn from_edwards_to_coords(
//             p: &TEAffine<P>,
//         ) -> Result<(P::BaseField, P::BaseField), SynthesisError> {
//             let montgomery_point: GroupAffine<P> = if p.y == P::BaseField::one() {
//                 GroupAffine::zero()
//             } else if p.x == P::BaseField::zero() {
//                 GroupAffine::new(P::BaseField::zero(), P::BaseField::zero())
//             } else {
//                 let u =
//                     (P::BaseField::one() + &p.y) * &(P::BaseField::one() - &p.y).inverse().unwrap();
//                 let v = u * &p.x.inverse().unwrap();
//                 GroupAffine::new(u, v)
//             };

//             Ok((montgomery_point.x, montgomery_point.y))
//         }

//         /// Converts a Twisted Edwards curve point to coordinates for the
//         /// corresponding affine Montgomery curve point.
//         #[tracing::instrument(target = "r1cs")]
//         pub fn new_witness_from_edwards(
//             cs: ConstraintSystemRef<<P::BaseField as Field>::BasePrimeField>,
//             p: &TEAffine<P>,
//         ) -> Result<Self, SynthesisError> {
//             let montgomery_coords = Self::from_edwards_to_coords(p)?;
//             let u = F::new_witness(ark_relations::ns!(cs, "u"), || Ok(montgomery_coords.0))?;
//             let v = F::new_witness(ark_relations::ns!(cs, "v"), || Ok(montgomery_coords.1))?;
//             Ok(Self::new(u, v))
//         }

//         /// Converts `self` into a Twisted Edwards curve point variable.
//         #[tracing::instrument(target = "r1cs")]
//         pub fn into_edwards(&self) -> Result<AffineVar<P, F>, SynthesisError> {
//             let cs = self.cs();

//             let mode = if cs.is_none() {
//                 AllocationMode::Constant
//             } else {
//                 AllocationMode::Witness
//             };

//             // Compute u = x / y
//             let u = F::new_variable(
//                 ark_relations::ns!(cs, "u"),
//                 || {
//                     let y_inv = self
//                         .y
//                         .value()?
//                         .inverse()
//                         .ok_or(SynthesisError::DivisionByZero)?;
//                     Ok(self.x.value()? * &y_inv)
//                 },
//                 mode,
//             )?;

//             u.mul_equals(&self.y, &self.x)?;

//             let v = F::new_variable(
//                 ark_relations::ns!(cs, "v"),
//                 || {
//                     let mut t0 = self.x.value()?;
//                     let mut t1 = t0;
//                     t0 -= &P::BaseField::one();
//                     t1 += &P::BaseField::one();

//                     Ok(t0 * &t1.inverse().ok_or(SynthesisError::DivisionByZero)?)
//                 },
//                 mode,
//             )?;

//             let xplusone = &self.x + P::BaseField::one();
//             let xminusone = &self.x - P::BaseField::one();
//             v.mul_equals(&xplusone, &xminusone)?;

//             Ok(AffineVar::new(u, v))
//         }
//     }

//     impl<'a, P, F> Add<&'a MontgomeryAffineVar<P, F>> for MontgomeryAffineVar<P, F>
//     where
//         P: TEModelParameters,
//         F: FieldVar<P::BaseField, <P::BaseField as Field>::BasePrimeField>,
//         for<'b> &'b F: FieldOpsBounds<'b, P::BaseField, F>,
//     {
//         type Output = MontgomeryAffineVar<P, F>;

//         #[tracing::instrument(target = "r1cs")]
//         fn add(self, other: &'a Self) -> Self::Output {
//             let cs = [&self, other].cs();
//             let mode = if cs.is_none() {
//                 AllocationMode::Constant
//             } else {
//                 AllocationMode::Witness
//             };

//             let coeff_b = P::MontgomeryModelParameters::COEFF_B;
//             let coeff_a = P::MontgomeryModelParameters::COEFF_A;

//             let lambda = F::new_variable(
//                 ark_relations::ns!(cs, "lambda"),
//                 || {
//                     let n = other.y.value()? - &self.y.value()?;
//                     let d = other.x.value()? - &self.x.value()?;
//                     Ok(n * &d.inverse().ok_or(SynthesisError::DivisionByZero)?)
//                 },
//                 mode,
//             )
//             .unwrap();
//             let lambda_n = &other.y - &self.y;
//             let lambda_d = &other.x - &self.x;
//             lambda_d.mul_equals(&lambda, &lambda_n).unwrap();

//             // Compute x'' = B*lambda^2 - A - x - x'
//             let xprime = F::new_variable(
//                 ark_relations::ns!(cs, "xprime"),
//                 || {
//                     Ok(lambda.value()?.square() * &coeff_b
//                         - &coeff_a
//                         - &self.x.value()?
//                         - &other.x.value()?)
//                 },
//                 mode,
//             )
//             .unwrap();

//             let xprime_lc = &self.x + &other.x + &xprime + coeff_a;
//             // (lambda) * (lambda) = (A + x + x' + x'')
//             let lambda_b = &lambda * coeff_b;
//             lambda_b.mul_equals(&lambda, &xprime_lc).unwrap();

//             let yprime = F::new_variable(
//                 ark_relations::ns!(cs, "yprime"),
//                 || {
//                     Ok(-(self.y.value()?
//                         + &(lambda.value()? * &(xprime.value()? - &self.x.value()?))))
//                 },
//                 mode,
//             )
//             .unwrap();

//             let xres = &self.x - &xprime;
//             let yres = &self.y + &yprime;
//             lambda.mul_equals(&xres, &yres).unwrap();
//             MontgomeryAffineVar::new(xprime, yprime)
//         }
//     }
// }

/// An implementation of arithmetic for Twisted Edwards curves that relies on
/// the complete formulae for the affine model, as outlined in the
/// [EFD](https://www.hyperelliptic.org/EFD/g1p/auto-twisted.html).
#[derive(Derivative)]
#[derivative(Debug, Clone)]
#[must_use]
pub struct MpcAffineVar<
    P: TEModelParameters,
    F: MpcFieldVar<
        <MpcBaseField<P> as Field>::BasePrimeField,
        <MpcBaseField<P> as Field>::BasePrimeField,
    >,
> where
    P::BaseField: PrimeField,
    <<P as ModelParameters>::BaseField as ark_ff::Field>::BasePrimeField: ark_ff::SquareRootField,
    for<'a> &'a F: FieldOpsBounds<'a, MpcBaseField<P>, F>,
{
    /// The x-coordinate.
    pub x: F,
    /// The y-coordinate.
    pub y: F,
    #[derivative(Debug = "ignore")]
    _params: PhantomData<P>,
}

impl<
        P: TEModelParameters,
        F: MpcFieldVar<MpcBaseField<P>, <MpcBaseField<P> as Field>::BasePrimeField>,
    > MpcAffineVar<P, F>
where
    P::BaseField: PrimeField,
    <<P as ModelParameters>::BaseField as Field>::BasePrimeField: ark_ff::SquareRootField,
    for<'a> &'a F: FieldOpsBounds<'a, MpcBaseField<P>, F>,
{
    /// Constructs `Self` from an `(x, y)` coordinate triple.
    pub fn new(x: F, y: F) -> Self {
        Self {
            x,
            y,
            _params: PhantomData,
        }
    }

    /// Allocates a new variable without performing an on-curve check, which is
    /// useful if the variable is known to be on the curve (eg., if the point
    /// is a constant or is a public input).
    #[tracing::instrument(target = "r1cs", skip(cs, f))]
    pub fn new_variable_omit_on_curve_check<T: Into<MpcTEAffine<P, AffProjShare<P>>>>(
        cs: impl Into<Namespace<<MpcBaseField<P> as Field>::BasePrimeField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let (x, y) = match f() {
            Ok(ge) => {
                let ge: MpcTEAffine<P, AffProjShare<P>> = ge.into();

                // TODO: Remove reveal operation.
                let revealed_ge = ge.reveal();
                (Ok(revealed_ge.x), Ok(revealed_ge.y))
            }
            _ => (
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
            ),
        };

        let wrapped_x = MpcBaseField::<P>::from_public(x.unwrap());
        let wrapped_y = MpcBaseField::<P>::from_public(y.unwrap());

        let x = F::new_variable(ark_relations::ns!(cs, "x"), || Ok(wrapped_x), mode)?;
        let y = F::new_variable(ark_relations::ns!(cs, "y"), || Ok(wrapped_y), mode)?;

        Ok(Self::new(x, y))
    }
}

// impl<P: TEModelParameters, F: FieldVar<P::BaseField, <P::BaseField as Field>::BasePrimeField>>
//     AffineVar<P, F>
// where
//     P: TEModelParameters,
//     F: FieldVar<P::BaseField, <P::BaseField as Field>::BasePrimeField>
//         + TwoBitLookupGadget<<P::BaseField as Field>::BasePrimeField, TableConstant = P::BaseField>
//         + ThreeBitCondNegLookupGadget<
//             <P::BaseField as Field>::BasePrimeField,
//             TableConstant = P::BaseField,
//         >,
//     for<'a> &'a F: FieldOpsBounds<'a, P::BaseField, F>,
// {
//     /// Compute a scalar multiplication of `bases` with respect to `scalars`,
//     /// where the elements of `scalars` are length-three slices of bits, and
//     /// which such that the first two bits are use to select one of the
//     /// bases, while the third bit is used to conditionally negate the
//     /// selection.
//     #[tracing::instrument(target = "r1cs", skip(bases, scalars))]
//     pub fn precomputed_base_3_bit_signed_digit_scalar_mul<J>(
//         bases: &[impl Borrow<[TEProjective<P>]>],
//         scalars: &[impl Borrow<[J]>],
//     ) -> Result<Self, SynthesisError>
//     where
//         J: Borrow<[Boolean<<P::BaseField as Field>::BasePrimeField>]>,
//     {
//         const CHUNK_SIZE: usize = 3;
//         let mut ed_result: Option<AffineVar<P, F>> = None;
//         let mut result: Option<MontgomeryAffineVar<P, F>> = None;

//         let mut process_segment_result = |result: &MontgomeryAffineVar<P, F>| {
//             let sgmt_result = result.into_edwards()?;
//             ed_result = match ed_result.as_ref() {
//                 None => Some(sgmt_result),
//                 Some(r) => Some(sgmt_result + r),
//             };
//             Ok::<(), SynthesisError>(())
//         };

//         // Compute ∏(h_i^{m_i}) for all i.
//         for (segment_bits_chunks, segment_powers) in scalars.iter().zip(bases) {
//             for (bits, base_power) in segment_bits_chunks
//                 .borrow()
//                 .iter()
//                 .zip(segment_powers.borrow())
//             {
//                 let base_power = base_power;
//                 let mut acc_power = *base_power;
//                 let mut coords = vec![];
//                 for _ in 0..4 {
//                     coords.push(acc_power);
//                     acc_power += base_power;
//                 }

//                 let bits = bits.borrow().to_bits_le()?;
//                 if bits.len() != CHUNK_SIZE {
//                     return Err(SynthesisError::Unsatisfiable);
//                 }

//                 let coords = coords
//                     .iter()
//                     .map(|p| MontgomeryAffineVar::from_edwards_to_coords(&p.into_affine()))
//                     .collect::<Result<Vec<_>, _>>()?;

//                 let x_coeffs = coords.iter().map(|p| p.0).collect::<Vec<_>>();
//                 let y_coeffs = coords.iter().map(|p| p.1).collect::<Vec<_>>();

//                 let precomp = bits[0].and(&bits[1])?;

//                 let x = F::zero()
//                     + x_coeffs[0]
//                     + F::from(bits[0].clone()) * (x_coeffs[1] - &x_coeffs[0])
//                     + F::from(bits[1].clone()) * (x_coeffs[2] - &x_coeffs[0])
//                     + F::from(precomp.clone())
//                         * (x_coeffs[3] - &x_coeffs[2] - &x_coeffs[1] + &x_coeffs[0]);

//                 let y = F::three_bit_cond_neg_lookup(&bits, &precomp, &y_coeffs)?;

//                 let tmp = MontgomeryAffineVar::new(x, y);
//                 result = match result.as_ref() {
//                     None => Some(tmp),
//                     Some(r) => Some(tmp + r),
//                 };
//             }

//             process_segment_result(&result.unwrap())?;
//             result = None;
//         }
//         if result.is_some() {
//             process_segment_result(&result.unwrap())?;
//         }
//         Ok(ed_result.unwrap())
//     }
// }

impl<P, F> R1CSVar<<MpcBaseField<P> as Field>::BasePrimeField> for MpcAffineVar<P, F>
where
    P: TEModelParameters,
    P::BaseField: PrimeField,
    F: MpcFieldVar<MpcBaseField<P>, <MpcBaseField<P> as Field>::BasePrimeField>,
    <<P as ModelParameters>::BaseField as ark_ff::Field>::BasePrimeField: ark_ff::SquareRootField,
    for<'a> &'a F: FieldOpsBounds<'a, MpcBaseField<P>, F>,
{
    type Value = MpcTEProjective<P, AffProjShare<P>>;

    fn cs(&self) -> ConstraintSystemRef<<MpcBaseField<P> as Field>::BasePrimeField> {
        self.x.cs().or(self.y.cs())
    }

    #[inline]
    fn value(&self) -> Result<MpcTEProjective<P, AffProjShare<P>>, SynthesisError> {
        let (x, y) = (self.x.value()?, self.y.value()?);

        let proj_variant = if x.is_shared() {
            let t = MpcBaseField::<P>::king_share(P::BaseField::zero(), &mut ark_std::test_rng());
            let z = MpcBaseField::<P>::king_share(P::BaseField::one(), &mut ark_std::test_rng());
            MpcGroupProjectiveVariant::<P, AffProjShare<P>>::new(x, y, t, z)
        } else {
            let t = MpcBaseField::<P>::zero();
            let z = MpcBaseField::<P>::one();
            MpcGroupProjectiveVariant::<P, AffProjShare<P>>::new(x, y, t, z)
        };

        // step1: generate random rsuv
        let rsuv = MpcTEProjective::<P, AffProjShare<P>>::rand(&mut ark_std::test_rng());

        // step2: convert rstu to variant
        let rsuv_variant = rsuv.convert_xytz();

        // step3: calculate (x,y,t,z) + (r,s,u,v)
        let xytzrsuv = rsuv_variant + proj_variant;

        // step4: reveal
        let revealed_xr = xytzrsuv.reveal();

        // step5: allocate share
        let share = if Net::is_leader() {
            MpcTEProjective::from_public(revealed_xr) - rsuv
        } else {
            -rsuv
        };

        Ok(share)
    }
}

impl<P, F>
    MpcCurveVar<MpcTEProjective<P, AffProjShare<P>>, <MpcBaseField<P> as Field>::BasePrimeField>
    for MpcAffineVar<P, F>
where
    P: TEModelParameters,
    P::BaseField: PrimeField,
    F: MpcFieldVar<MpcBaseField<P>, <MpcBaseField<P> as Field>::BasePrimeField>
        + MpcTwoBitLookupGadget<
            <MpcBaseField<P> as Field>::BasePrimeField,
            TableConstant = MpcBaseField<P>,
        >,
    <<P as ModelParameters>::BaseField as ark_ff::Field>::BasePrimeField: ark_ff::SquareRootField,
    for<'a> &'a F: FieldOpsBounds<'a, MpcBaseField<P>, F>,
{
    fn constant(g: MpcTEProjective<P, AffProjShare<P>>) -> Self {
        let cs = ConstraintSystemRef::None;
        Self::new_variable_omit_on_curve_check(cs, || Ok(g), AllocationMode::Constant).unwrap()
    }

    fn zero() -> Self {
        Self::new(F::zero(), F::one())
    }

    fn is_zero(
        &self,
    ) -> Result<MpcBoolean<<MpcBaseField<P> as Field>::BasePrimeField>, SynthesisError> {
        self.x.is_zero()?.and(&self.x.is_one()?)
    }

    #[tracing::instrument(target = "r1cs", skip(cs, f))]
    fn new_variable_omit_prime_order_check(
        cs: impl Into<Namespace<<MpcBaseField<P> as Field>::BasePrimeField>>,
        f: impl FnOnce() -> Result<MpcTEProjective<P, AffProjShare<P>>, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let g = Self::new_variable_omit_on_curve_check(cs, f, mode)?;

        if mode != AllocationMode::Constant {
            let d = MpcBaseField::<P>::from_public(P::COEFF_D);
            let a = MpcBaseField::<P>::from_public(P::COEFF_A);
            // Check that ax^2 + y^2 = 1 + dx^2y^2
            // We do this by checking that ax^2 - 1 = y^2 * (dx^2 - 1)
            let x2 = g.x.square()?;
            let y2 = g.y.square()?;

            let one = MpcBaseField::<P>::one();
            let d_x2_minus_one = &x2 * d - one;
            let a_x2_minus_one = &x2 * a - one;

            d_x2_minus_one.mul_equals(&y2, &a_x2_minus_one)?;
        }
        Ok(g)
    }

    /// Enforce that `self` is in the prime-order subgroup.
    ///
    /// Does so by multiplying by the prime order, and checking that the result
    /// is unchanged.
    #[tracing::instrument(target = "r1cs")]
    fn enforce_prime_order(&self) -> Result<(), SynthesisError> {
        // let r_minus_1 = (-hbc_ScalarField::one()).into_repr();

        // let mut result = Self::zero();
        // for b in BitIteratorBE::without_leading_zeros(r_minus_1) {
        //     result.double_in_place()?;

        //     if b {
        //         result += self;
        //     }
        // }
        // self.negate()?.enforce_equal(&result)?;

        unimplemented!();
        Ok(())
    }

    #[inline]
    #[tracing::instrument(target = "r1cs")]
    fn double_in_place(&mut self) -> Result<(), SynthesisError> {
        if self.is_constant() {
            let value = self.value()?;
            *self = Self::constant(value.double());
        } else {
            let cs = self.cs();
            let a = MpcBaseField::<P>::from_public(P::COEFF_A);

            // xy
            let xy = &self.x * &self.y;
            let x2 = self.x.square()?;
            let y2 = self.y.square()?;

            let a_x2 = &x2 * a;

            // Compute x3 = (2xy) / (ax^2 + y^2)
            let x3 = F::new_witness(ark_relations::ns!(cs, "x3"), || {
                let t0 = xy.value()?.double();
                let t1 = a * &x2.value()? + &y2.value()?;
                Ok(t0 * &t1.inverse().ok_or(SynthesisError::DivisionByZero)?)
            })?;

            let a_x2_plus_y2 = &a_x2 + &y2;
            let two_xy = xy.double()?;
            x3.mul_equals(&a_x2_plus_y2, &two_xy)?;

            // Compute y3 = (y^2 - ax^2) / (2 - ax^2 - y^2)
            let two = MpcBaseField::<P>::one().double();
            let y3 = F::new_witness(ark_relations::ns!(cs, "y3"), || {
                let a_x2 = a * &x2.value()?;
                let t0 = y2.value()? - &a_x2;
                let t1 = two - &a_x2 - &y2.value()?;
                Ok(t0 * &t1.inverse().ok_or(SynthesisError::DivisionByZero)?)
            })?;
            let y2_minus_a_x2 = &y2 - &a_x2;
            let two_minus_ax2_minus_y2 = (&a_x2 + &y2).negate()? + two;

            y3.mul_equals(&two_minus_ax2_minus_y2, &y2_minus_a_x2)?;
            self.x = x3;
            self.y = y3;
        }
        Ok(())
    }

    #[tracing::instrument(target = "r1cs")]
    fn negate(&self) -> Result<Self, SynthesisError> {
        Ok(Self::new(self.x.negate()?, self.y.clone()))
    }

    #[tracing::instrument(target = "r1cs", skip(scalar_bits_with_base_multiples))]
    fn precomputed_base_scalar_mul_le<'a, I, B>(
        &mut self,
        scalar_bits_with_base_multiples: I,
    ) -> Result<(), SynthesisError>
    where
        I: Iterator<Item = (B, &'a MpcTEProjective<P, AffProjShare<P>>)>,
        B: Borrow<MpcBoolean<<MpcBaseField<P> as Field>::BasePrimeField>>,
    {
        let (bits, multiples): (Vec<_>, Vec<_>) = scalar_bits_with_base_multiples
            .map(|(bit, base)| (bit.borrow().clone(), *base))
            .unzip();
        let proj_zero: MpcTEProjective<P, AffProjShare<P>> = MpcTEProjective::zero();
        for (bits, multiples) in bits.chunks(2).zip(multiples.chunks(2)) {
            if bits.len() == 2 {
                let table = [multiples[0], multiples[1], multiples[0] + multiples[1]]
                    .iter()
                    .map(|&g| g.convert_xytz())
                    .collect::<Vec<_>>();

                let normalized_table = MpcGroupProjectiveVariant::batch_normalization(&table);

                let zero_xy = proj_zero.convert_xytz();
                let x_s = [
                    zero_xy.x,
                    normalized_table[0].x,
                    normalized_table[1].x,
                    normalized_table[2].x,
                ];
                let y_s = [
                    zero_xy.y,
                    normalized_table[0].y,
                    normalized_table[1].y,
                    normalized_table[2].y,
                ];

                let x = F::two_bit_lookup(&bits, &x_s)?;
                let y = F::two_bit_lookup(&bits, &y_s)?;
                *self += Self::new(x, y);
            } else if bits.len() == 1 {
                let bit = &bits[0];
                let tmp = &*self + multiples[0];
                *self = bit.select(&tmp, &*self)?;
            }
        }

        Ok(())
    }
}

impl<P, F> AllocVar<MpcTEProjective<P, AffProjShare<P>>, <MpcBaseField<P> as Field>::BasePrimeField>
    for MpcAffineVar<P, F>
where
    P: TEModelParameters,
    P::BaseField: PrimeField,
    F: MpcFieldVar<MpcBaseField<P>, <MpcBaseField<P> as Field>::BasePrimeField>
        + MpcTwoBitLookupGadget<
            <MpcBaseField<P> as Field>::BasePrimeField,
            TableConstant = MpcBaseField<P>,
        >,
    <<P as ModelParameters>::BaseField as ark_ff::Field>::BasePrimeField: ark_ff::SquareRootField,
    for<'a> &'a F: FieldOpsBounds<'a, MpcBaseField<P>, F>,
{
    #[tracing::instrument(target = "r1cs", skip(cs, f))]
    fn new_variable<Point: Borrow<MpcTEProjective<P, AffProjShare<P>>>>(
        cs: impl Into<Namespace<<MpcBaseField<P> as Field>::BasePrimeField>>,
        f: impl FnOnce() -> Result<Point, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let f = || Ok(*f()?.borrow());
        match mode {
            AllocationMode::Constant => Self::new_variable_omit_prime_order_check(cs, f, mode),
            AllocationMode::Input => Self::new_variable_omit_prime_order_check(cs, f, mode),
            AllocationMode::Witness => {
                // if cofactor.is_even():
                //   divide until you've removed all even factors
                // else:
                //   just directly use double and add.
                let mut power_of_2: u32 = 0;
                let mut cofactor = P::COFACTOR.to_vec();
                while cofactor[0] % 2 == 0 {
                    div2(&mut cofactor);
                    power_of_2 += 1;
                }

                let cofactor_weight = BitIteratorBE::new(cofactor.as_slice())
                    .filter(|b| *b)
                    .count();
                let modulus_minus_1 = (-P::ScalarField::one()).into_repr(); // r - 1
                let modulus_minus_1_weight =
                    BitIteratorBE::new(modulus_minus_1).filter(|b| *b).count();

                // We pick the most efficient method of performing the prime order check:
                // If the cofactor has lower hamming weight than the scalar field's modulus,
                // we first multiply by the inverse of the cofactor, and then, after allocating,
                // multiply by the cofactor. This ensures the resulting point has no cofactors
                //
                // Else, we multiply by the scalar field's modulus and ensure that the result
                // equals the identity.

                let (mut ge, iter) = if cofactor_weight < modulus_minus_1_weight {
                    let ge = Self::new_variable_omit_prime_order_check(
                        ark_relations::ns!(cs, "Witness without subgroup check with cofactor mul"),
                        || f().map(|g| g.borrow().into_affine().mul_by_cofactor_inv().into()),
                        mode,
                    )?;
                    (
                        ge,
                        BitIteratorBE::without_leading_zeros(cofactor.as_slice()),
                    )
                } else {
                    let ge = Self::new_variable_omit_prime_order_check(
                        ark_relations::ns!(cs, "Witness without subgroup check with `r` check"),
                        || {
                            f().map(|g| {
                                let g = g.into_affine();
                                let mut power_of_two = P::ScalarField::one().into_repr();
                                power_of_two.muln(power_of_2);
                                let power_of_two_inv = P::ScalarField::from_repr(power_of_two)
                                    .and_then(|n| n.inverse())
                                    .unwrap();
                                g.mul(power_of_two_inv)
                            })
                        },
                        mode,
                    )?;

                    (
                        ge,
                        BitIteratorBE::without_leading_zeros(modulus_minus_1.as_ref()),
                    )
                };
                // Remove the even part of the cofactor
                for _ in 0..power_of_2 {
                    ge.double_in_place()?;
                }

                let mut result = Self::zero();
                for b in iter {
                    result.double_in_place()?;
                    if b {
                        result += &ge;
                    }
                }
                if cofactor_weight < modulus_minus_1_weight {
                    Ok(result)
                } else {
                    ge.enforce_equal(&ge)?;
                    Ok(ge)
                }
            }
        }
    }
}

impl<P, F> AllocVar<MpcTEAffine<P, AffProjShare<P>>, <MpcBaseField<P> as Field>::BasePrimeField>
    for MpcAffineVar<P, F>
where
    P: TEModelParameters,
    F: MpcFieldVar<MpcBaseField<P>, <MpcBaseField<P> as Field>::BasePrimeField>
        + MpcTwoBitLookupGadget<
            <MpcBaseField<P> as Field>::BasePrimeField,
            TableConstant = MpcBaseField<P>,
        >,
    P::BaseField: PrimeField,
    <<P as ModelParameters>::BaseField as ark_ff::Field>::BasePrimeField: ark_ff::SquareRootField,
    for<'a> &'a F: FieldOpsBounds<'a, MpcBaseField<P>, F>,
{
    #[tracing::instrument(target = "r1cs", skip(cs, f))]
    fn new_variable<Point: Borrow<MpcTEAffine<P, AffProjShare<P>>>>(
        cs: impl Into<Namespace<<MpcBaseField<P> as Field>::BasePrimeField>>,
        f: impl FnOnce() -> Result<Point, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        Self::new_variable(cs, || f().map(|b| b.borrow().into_projective()), mode)
    }
}

impl<P, F> ToConstraintFieldGadget<<MpcBaseField<P> as Field>::BasePrimeField>
    for MpcAffineVar<P, F>
where
    P: TEModelParameters,
    F: MpcFieldVar<MpcBaseField<P>, <MpcBaseField<P> as Field>::BasePrimeField>,
    P::BaseField: PrimeField,
    <<P as ModelParameters>::BaseField as Field>::BasePrimeField: SquareRootField,
    for<'a> &'a F: FieldOpsBounds<'a, MpcBaseField<P>, F>,
    F: ToConstraintFieldGadget<<MpcBaseField<P> as Field>::BasePrimeField>,
{
    fn to_constraint_field(
        &self,
    ) -> Result<Vec<FpVar<<MpcBaseField<P> as Field>::BasePrimeField>>, SynthesisError> {
        let mut res = Vec::new();

        res.extend_from_slice(&self.x.to_constraint_field()?);
        res.extend_from_slice(&self.y.to_constraint_field()?);

        Ok(res)
    }
}

#[inline]
fn div2(limbs: &mut [u64]) {
    let mut t = 0;
    for i in limbs.iter_mut().rev() {
        let t2 = *i << 63;
        *i >>= 1;
        *i |= t;
        t = t2;
    }
}

impl_bounded_ops!(
    MpcAffineVar<P, F>,
    MpcTEProjective<P, AffProjShare<P>>,
    Add,
    add,
    AddAssign,
    add_assign,
    |this: &'a MpcAffineVar<P, F>, other: &'a MpcAffineVar<P, F>| {

        if [this, other].is_constant() {
            assert!(this.is_constant() && other.is_constant());
            MpcAffineVar::constant(this.value().unwrap() + &other.value().unwrap())
        } else {
            let cs = [this, other].cs();
            let a = MpcBaseField::<P>::from_public(P::COEFF_A);
            let d = MpcBaseField::<P>::from_public(P::COEFF_D);

            // Compute U = (x1 + y1) * (x2 + y2)
            let u1 = (&this.x * -a) + &this.y;
            let u2 = &other.x + &other.y;

            let u = u1 *  &u2;

            // Compute v0 = x1 * y2
            let v0 = &other.y * &this.x;

            // Compute v1 = x2 * y1
            let v1 = &other.x * &this.y;

            // Compute C = d*v0*v1
            let v2 = &v0 * &v1 * d;

            // Compute x3 = (v0 + v1) / (1 + v2)
            let x3 = F::new_witness(ark_relations::ns!(cs, "x3"), || {
                let t0 = v0.value()? + &v1.value()?;
                let t1 = MpcBaseField::<P>::one() + &v2.value()?;
                Ok(t0 * &t1.inverse().ok_or(SynthesisError::DivisionByZero)?)
            }).unwrap();

            let v2_plus_one = &v2 + MpcBaseField::<P>::one();
            let v0_plus_v1 = &v0 + &v1;
            x3.mul_equals(&v2_plus_one, &v0_plus_v1).unwrap();

            // Compute y3 = (U + a * v0 - v1) / (1 - v2)
            let y3 = F::new_witness(ark_relations::ns!(cs, "y3"), || {
                let t0 = u.value()? + &(a * &v0.value()?) - &v1.value()?;
                let t1 = MpcBaseField::<P>::one() - &v2.value()?;
                Ok(t0 * &t1.inverse().ok_or(SynthesisError::DivisionByZero)?)
            }).unwrap();

            let one_minus_v2 = (&v2 - MpcBaseField::<P>::one()).negate().unwrap();
            let a_v0 = &v0 * a;
            let u_plus_a_v0_minus_v1 = &u + &a_v0 - &v1;

            y3.mul_equals(&one_minus_v2, &u_plus_a_v0_minus_v1).unwrap();

            MpcAffineVar::new(x3, y3)
        }
    },
    |this: &'a MpcAffineVar<P, F>, other: MpcTEProjective<P, AffProjShare<P>>| this + MpcAffineVar::constant(other),
    (
        F :MpcFieldVar<MpcBaseField<P>, <MpcBaseField<P> as Field>::BasePrimeField>
            + MpcTwoBitLookupGadget<<MpcBaseField<P> as Field>::BasePrimeField,TableConstant = MpcBaseField<P>>,
        P: TEModelParameters,
    ),
    P::BaseField: PrimeField,
    <<P as ModelParameters>::BaseField as Field>::BasePrimeField: SquareRootField,
    for <'b> &'b F: FieldOpsBounds<'b, MpcBaseField<P>, F>,
);

impl_bounded_ops!(
    MpcAffineVar<P, F>,
    MpcTEProjective<P, AffProjShare<P>>,
    Sub,
    sub,
    SubAssign,
    sub_assign,
    |this: &'a MpcAffineVar<P, F>, other: &'a MpcAffineVar<P, F>| this + other.negate().unwrap(),
    |this: &'a MpcAffineVar<P, F>, other: MpcTEProjective<P, AffProjShare<P>>| this - MpcAffineVar::constant(other),
    (
        F :MpcFieldVar<MpcBaseField<P>, <MpcBaseField<P> as Field>::BasePrimeField>
            + MpcTwoBitLookupGadget<<MpcBaseField<P> as Field>::BasePrimeField,TableConstant = MpcBaseField<P>>,
        P: TEModelParameters,
    ),
    P::BaseField: PrimeField,
    <<P as ModelParameters>::BaseField as Field>::BasePrimeField: SquareRootField,
    for <'b> &'b F: FieldOpsBounds<'b, MpcBaseField<P>, F>
);

impl<'a, P, F> GroupOpsBounds<'a, MpcTEProjective<P, AffProjShare<P>>, MpcAffineVar<P, F>>
    for MpcAffineVar<P, F>
where
    P: TEModelParameters,
    F: MpcFieldVar<MpcBaseField<P>, <MpcBaseField<P> as Field>::BasePrimeField>
        + MpcTwoBitLookupGadget<
            <MpcBaseField<P> as Field>::BasePrimeField,
            TableConstant = MpcBaseField<P>,
        >,
    P::BaseField: PrimeField,
    <<P as ModelParameters>::BaseField as Field>::BasePrimeField: SquareRootField,
    for<'b> &'b F: FieldOpsBounds<'b, MpcBaseField<P>, F>,
{
}

impl<'a, P, F> GroupOpsBounds<'a, MpcTEProjective<P, AffProjShare<P>>, MpcAffineVar<P, F>>
    for &'a MpcAffineVar<P, F>
where
    P: TEModelParameters,
    F: MpcFieldVar<MpcBaseField<P>, <MpcBaseField<P> as Field>::BasePrimeField>
        + MpcTwoBitLookupGadget<
            <MpcBaseField<P> as Field>::BasePrimeField,
            TableConstant = MpcBaseField<P>,
        >,
    P::BaseField: PrimeField,
    <<P as ModelParameters>::BaseField as Field>::BasePrimeField: SquareRootField,
    for<'b> &'b F: FieldOpsBounds<'b, MpcBaseField<P>, F>,
{
}

impl<P, F> MpcCondSelectGadget<<MpcBaseField<P> as Field>::BasePrimeField> for MpcAffineVar<P, F>
where
    P: TEModelParameters,
    F: MpcFieldVar<MpcBaseField<P>, <MpcBaseField<P> as Field>::BasePrimeField>,
    P::BaseField: PrimeField,
    <<P as ModelParameters>::BaseField as Field>::BasePrimeField: SquareRootField,
    for<'b> &'b F: FieldOpsBounds<'b, MpcBaseField<P>, F>,
{
    #[inline]
    #[tracing::instrument(target = "r1cs")]
    fn conditionally_select(
        cond: &MpcBoolean<<MpcBaseField<P> as Field>::BasePrimeField>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let x = cond.select(&true_value.x, &false_value.x)?;
        let y = cond.select(&true_value.y, &false_value.y)?;

        Ok(Self::new(x, y))
    }
}

impl<P, F> MpcEqGadget<<MpcBaseField<P> as Field>::BasePrimeField> for MpcAffineVar<P, F>
where
    P: TEModelParameters,
    F: MpcFieldVar<MpcBaseField<P>, <MpcBaseField<P> as Field>::BasePrimeField>,
    P::BaseField: PrimeField,
    <<P as ModelParameters>::BaseField as Field>::BasePrimeField: SquareRootField,
    for<'b> &'b F: FieldOpsBounds<'b, MpcBaseField<P>, F>,
{
    #[tracing::instrument(target = "r1cs")]
    fn is_eq(
        &self,
        other: &Self,
    ) -> Result<MpcBoolean<<MpcBaseField<P> as Field>::BasePrimeField>, SynthesisError> {
        let x_equal = self.x.clone().sub(&other.x).is_zero()?;
        let y_equal = self.y.clone().sub(&other.y).is_zero()?;
        x_equal.and(&y_equal)
    }

    #[inline]
    #[tracing::instrument(target = "r1cs")]
    fn conditional_enforce_equal(
        &self,
        other: &Self,
        condition: &MpcBoolean<<MpcBaseField<P> as Field>::BasePrimeField>,
    ) -> Result<(), SynthesisError> {
        self.x.conditional_enforce_equal(&other.x, condition)?;
        self.y.conditional_enforce_equal(&other.y, condition)?;
        Ok(())
    }

    #[inline]
    #[tracing::instrument(target = "r1cs")]
    fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        condition: &MpcBoolean<<MpcBaseField<P> as Field>::BasePrimeField>,
    ) -> Result<(), SynthesisError> {
        self.is_eq(other)?
            .and(condition)?
            .enforce_equal(&MpcBoolean::Constant(false))
    }
}

impl<P, F> MpcToBitsGadget<<MpcBaseField<P> as Field>::BasePrimeField> for MpcAffineVar<P, F>
where
    P: TEModelParameters,
    F: MpcFieldVar<MpcBaseField<P>, <MpcBaseField<P> as Field>::BasePrimeField>,
    P::BaseField: PrimeField,
    <<P as ModelParameters>::BaseField as Field>::BasePrimeField: SquareRootField,
    for<'b> &'b F: FieldOpsBounds<'b, MpcBaseField<P>, F>,
{
    #[tracing::instrument(target = "r1cs")]
    fn to_bits_le(
        &self,
    ) -> Result<Vec<MpcBoolean<<MpcBaseField<P> as Field>::BasePrimeField>>, SynthesisError> {
        let mut x_bits = self.x.to_bits_le()?;
        let y_bits = self.y.to_bits_le()?;
        x_bits.extend_from_slice(&y_bits);
        Ok(x_bits)
    }

    #[tracing::instrument(target = "r1cs")]
    fn to_non_unique_bits_le(
        &self,
    ) -> Result<Vec<MpcBoolean<<MpcBaseField<P> as Field>::BasePrimeField>>, SynthesisError> {
        let mut x_bits = self.x.to_non_unique_bits_le()?;
        let y_bits = self.y.to_non_unique_bits_le()?;
        x_bits.extend_from_slice(&y_bits);

        Ok(x_bits)
    }
}

impl<P, F> ToBytesGadget<<MpcBaseField<P> as Field>::BasePrimeField> for MpcAffineVar<P, F>
where
    P: TEModelParameters,
    F: MpcFieldVar<MpcBaseField<P>, <MpcBaseField<P> as Field>::BasePrimeField>,
    P::BaseField: PrimeField,
    <<P as ModelParameters>::BaseField as Field>::BasePrimeField: SquareRootField,
    for<'b> &'b F: FieldOpsBounds<'b, MpcBaseField<P>, F>,
{
    #[tracing::instrument(target = "r1cs")]
    fn to_bytes(
        &self,
    ) -> Result<Vec<UInt8<<MpcBaseField<P> as Field>::BasePrimeField>>, SynthesisError> {
        // let mut x_bytes = self.x.to_bytes()?;
        // let y_bytes = self.y.to_bytes()?;
        // x_bytes.extend_from_slice(&y_bytes);
        // Ok(x_bytes)
        unimplemented!()
    }

    #[tracing::instrument(target = "r1cs")]
    fn to_non_unique_bytes(
        &self,
    ) -> Result<Vec<UInt8<<MpcBaseField<P> as Field>::BasePrimeField>>, SynthesisError> {
        // let mut x_bytes = self.x.to_non_unique_bytes()?;
        // let y_bytes = self.y.to_non_unique_bytes()?;
        // x_bytes.extend_from_slice(&y_bytes);

        // Ok(x_bytes)
        unimplemented!()
    }
}
