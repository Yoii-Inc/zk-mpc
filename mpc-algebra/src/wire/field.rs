use ark_std::{end_timer, start_timer};
use core::panic;
use derivative::Derivative;
use mpc_trait::MpcWire;
use num_bigint::BigUint;
use rand::Rng;
use std::fmt::{self, Debug, Display};
use std::io::{self, Read, Write};
use std::iter::{Product, Sum};
use std::marker::PhantomData;
use std::ops::*;
use std::str::FromStr;
use zeroize::Zeroize;

use log::debug;

use ark_ff::{poly_stub, prelude::*, BitIteratorBE, FftField};
use ark_ff::{FromBytes, ToBytes};
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags,
};

use crate::boolean_field::{BooleanWire, MpcBooleanField};
// use crate::channel::MpcSerNet;
use crate::share::field::FieldShare;
use crate::{
    mpc_primitives, BeaverSource, BitAdd, BitDecomposition, BitwiseLessThan, LessThan,
    LogicalOperations, Reveal,
};
use crate::{EqualityZero, UniformBitRand};
use mpc_net::{MpcMultiNet as Net, MpcNet};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum MpcField<F: Field, S: FieldShare<F>> {
    Public(F),
    Shared(S),
}

#[derive(Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct DummyFieldTripleSource<F, S> {
    _scalar: PhantomData<F>,
    _share: PhantomData<S>,
}

impl<T: Field, S: FieldShare<T>> BeaverSource<S, S, S> for DummyFieldTripleSource<T, S> {
    fn triple(&mut self) -> (S, S, S) {
        (
            S::from_add_shared(if Net::am_king() { T::one() } else { T::zero() }),
            S::from_add_shared(if Net::am_king() { T::one() } else { T::zero() }),
            S::from_add_shared(if Net::am_king() { T::one() } else { T::zero() }),
        )
    }
    fn inv_pair(&mut self) -> (S, S) {
        (
            S::from_add_shared(if Net::am_king() { T::one() } else { T::zero() }),
            S::from_add_shared(if Net::am_king() { T::one() } else { T::zero() }),
        )
    }
}

impl<F: Field, S: FieldShare<F>> MpcField<F, S> {
    pub fn inv(self) -> Option<Self> {
        match self {
            Self::Public(x) => x.inverse().map(MpcField::Public),
            Self::Shared(x) => Some(MpcField::Shared(
                x.inv(&mut DummyFieldTripleSource::default()),
            )),
        }
    }

    pub fn all_public_or_shared(v: impl IntoIterator<Item = Self>) -> Result<Vec<F>, Vec<S>> {
        let mut out_a = Vec::new();
        let mut out_b = Vec::new();
        let mut force_shared = Vec::new();
        for s in v {
            match s {
                Self::Public(x) => {
                    out_a.push(x);
                    force_shared.push(S::from_public(x));
                }
                Self::Shared(x) => {
                    out_b.push(x);
                    force_shared.push(x)
                }
            }
        }
        if !out_a.is_empty() & !out_b.is_empty() {
            // panic!("Heterogeous")
            Err(force_shared)
        } else if !out_a.is_empty() {
            Ok(out_a)
        } else {
            Err(out_b)
        }
    }
}

impl<T: Field, S: FieldShare<T>> Reveal for MpcField<T, S> {
    type Base = T;
    #[inline]
    fn reveal(self) -> Self::Base {
        let result = match self {
            Self::Shared(s) => s.reveal(),
            Self::Public(s) => s,
        };
        super::macros::check_eq(result);
        result
    }
    #[inline]
    fn from_public(b: Self::Base) -> Self {
        MpcField::Public(b)
    }
    #[inline]
    fn from_add_shared(b: Self::Base) -> Self {
        MpcField::Shared(S::from_add_shared(b))
    }
    #[inline]
    fn unwrap_as_public(self) -> Self::Base {
        match self {
            Self::Shared(s) => s.unwrap_as_public(),
            Self::Public(s) => s,
        }
    }
    #[inline]
    fn king_share<R: Rng>(f: Self::Base, rng: &mut R) -> Self {
        Self::Shared(S::king_share(f, rng))
    }
    #[inline]
    fn king_share_batch<R: Rng>(f: Vec<Self::Base>, rng: &mut R) -> Vec<Self> {
        S::king_share_batch(f, rng)
            .into_iter()
            .map(Self::Shared)
            .collect()
    }
    fn init_protocol() {
        todo!()
    }
    fn deinit_protocol() {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> Display for MpcField<F, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MpcField::Public(x) => write!(f, "{x} (public)"),
            MpcField::Shared(x) => write!(f, "{x} (shared)"),
        }
    }
}

impl<F: Field, S: FieldShare<F>> ToBytes for MpcField<F, S> {
    fn write<W: ark_serialize::Write>(&self, writer: W) -> io::Result<()> {
        match self {
            Self::Public(v) => v.write(writer),
            Self::Shared(v) => v.write(writer),
        }
    }
}

impl<F: Field, S: FieldShare<F>> FromBytes for MpcField<F, S> {
    fn read<R: Read>(_reader: R) -> io::Result<Self> {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> CanonicalSerialize for MpcField<F, S> {
    fn serialize<W: Write>(&self, writer: W) -> Result<(), ark_serialize::SerializationError> {
        match self {
            Self::Public(v) => v.serialize(writer),
            Self::Shared(_) => unimplemented!("serialize share: {}", self),
        }
    }

    fn serialized_size(&self) -> usize {
        match self {
            Self::Public(v) => v.serialized_size(),
            Self::Shared(_) => unimplemented!("serialized_size share: {}", self),
        }
    }
}

impl<F: Field, S: FieldShare<F>> CanonicalSerializeWithFlags for MpcField<F, S> {
    fn serialize_with_flags<W: Write, Fl: ark_serialize::Flags>(
        &self,
        writer: W,
        flags: Fl,
    ) -> Result<(), ark_serialize::SerializationError> {
        match self {
            Self::Public(v) => v.serialize_with_flags(writer, flags),
            Self::Shared(_) => unimplemented!("serialize_with_flag share: {}", self),
        }
    }

    fn serialized_size_with_flags<Fl: ark_serialize::Flags>(&self) -> usize {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> CanonicalDeserialize for MpcField<F, S> {
    fn deserialize<R: Read>(_reader: R) -> Result<Self, ark_serialize::SerializationError> {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> CanonicalDeserializeWithFlags for MpcField<F, S> {
    fn deserialize_with_flags<R: Read, Fl: ark_serialize::Flags>(
        _reader: R,
    ) -> Result<(Self, Fl), ark_serialize::SerializationError> {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> UniformRand for MpcField<F, S> {
    fn rand<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        Self::Shared(<S as UniformRand>::rand(rng))
    }
}

impl<F: Field, S: FieldShare<F>> PubUniformRand for MpcField<F, S> {
    fn pub_rand<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        Self::Public(<F as PubUniformRand>::pub_rand(rng))
    }
}

impl<F: PrimeField + SquareRootField, S: FieldShare<F>> LessThan for MpcField<F, S> {
    type Output = MpcBooleanField<F, S>;
    // check if shared value a is in the interval [0, modulus/2)
    fn is_smaller_or_equal_than_mod_minus_one_div_two(&self) -> Self::Output {
        // define double self as x
        let x = *self * Self::from_public(F::from(2u8));

        // generate pair of random bits & composed random number
        let rng = &mut ark_std::test_rng();
        let (vec_r, r) = Self::Output::rand_number_bitwise(rng);

        // calculate [c]_p = [x]_p + [r]_p and reveal it. Get least significant bits of c
        let c = (r + x).reveal();
        let mut vec_c = c
            .into_repr()
            .to_bits_le()
            .iter()
            .map(|&b| Self::Output::from(b))
            .collect::<Vec<Self::Output>>();
        vec_c.truncate(F::Params::MODULUS_BITS as usize);
        // Get least significant bits of c
        let lsb_c = *vec_c.first().unwrap();

        // Get shared least significant bits of r
        let lsb_r = *vec_r.first().unwrap();

        // compute
        // [lsb_x]_p = [c <B r]_p x (1-{lsb_c xor [lsb_r]_p}) +  (1-[c <B r]_p) x {lsb_c xor [lsb_r]_p}
        let c_lt_r = vec_c.is_smaller_than_le(&vec_r);
        let lsb_c_xor_lsb_r = lsb_c ^ lsb_r;
        let lsb_x = (c_lt_r & !lsb_c_xor_lsb_r) | (!c_lt_r & lsb_c_xor_lsb_r);

        // return 1 - lsb_x
        !lsb_x
    }

    // TODO: Fix: This function should be returns false  when the two values are equal.
    fn is_smaller_than(&self, other: &Self) -> Self::Output {
        let timer = start_timer!(|| "LessThan");
        // [z]=[other−self<p/2],[x]=[self<p/2],[y]=[other>p/2]
        // ([z]∧[x])∨([z]∧[y])∨(¬[z]∧[x]∧[y])=[z(x+y)+(1−2*z)xy].
        let z = (*other - self)
            .is_smaller_or_equal_than_mod_minus_one_div_two()
            .field();
        let x = self
            .is_smaller_or_equal_than_mod_minus_one_div_two()
            .field();
        let y = Self::one()
            - other
                .is_smaller_or_equal_than_mod_minus_one_div_two()
                .field();
        end_timer!(timer);
        (z * (x + y) + (Self::one() - Self::from_public(F::from(2u8)) * z) * x * y).into()
    }
}

impl<F: Field, S: FieldShare<F>> LogicalOperations for Vec<MpcBooleanField<F, S>> {
    type Output = MpcBooleanField<F, S>;
    // TODO: Implement kary_nand

    fn kary_and(&self) -> Self::Output {
        debug_assert!({
            // each element is 0 or 1
            self.iter()
                .all(|x| x.field().reveal().is_zero() || x.field().reveal().is_one())
        });
        self.iter()
            .fold(Self::Output::pub_true(), |acc, &x| acc & x)
    }

    fn kary_or(&self) -> Self::Output {
        let not_self = self.iter().map(|&x| !x).collect::<Vec<_>>();
        !not_self.kary_and()
    }
}

impl<F: Field, S: FieldShare<F>> AddAssign for MpcField<F, S> {
    fn add_assign(&mut self, rhs: Self) {
        self.add_assign(&rhs);
    }
}

impl<'a, F: Field, S: FieldShare<F>> AddAssign<&'a MpcField<F, S>> for MpcField<F, S> {
    fn add_assign(&mut self, rhs: &Self) {
        match self {
            MpcField::Public(a) => match rhs {
                MpcField::Public(b) => {
                    *a += b;
                }
                MpcField::Shared(b) => {
                    let mut tmp = *b;
                    tmp.shift(a);
                    *self = MpcField::Shared(tmp);
                }
            },
            MpcField::Shared(a) => match rhs {
                MpcField::Public(b) => {
                    a.shift(b);
                }
                MpcField::Shared(b) => {
                    a.add(b);
                }
            },
        }
    }
}

impl<F: Field, S: FieldShare<F>> Add for MpcField<F, S> {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self.add_assign(&rhs);
        self
    }
}

impl<'a, F: Field, S: FieldShare<F>> Add<&'a MpcField<F, S>> for MpcField<F, S> {
    type Output = Self;

    fn add(mut self, rhs: &'a MpcField<F, S>) -> Self::Output {
        self.add_assign(rhs);
        self
    }
}

impl<F: Field, S: FieldShare<F>> Sum for MpcField<F, S> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

impl<'a, F: Field, S: FieldShare<F>> Sum<&'a MpcField<F, S>> for MpcField<F, S> {
    fn sum<I: Iterator<Item = &'a MpcField<F, S>>>(iter: I) -> Self {
        iter.fold(Self::zero(), |x, y| x.add(*y))
    }
}

impl<F: Field, S: FieldShare<F>> Neg for MpcField<F, S> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        match self {
            MpcField::Public(x) => MpcField::Public(-x),
            MpcField::Shared(mut x) => MpcField::Shared({
                x.neg();
                x
            }),
        }
    }
}

impl<F: Field, S: FieldShare<F>> SubAssign for MpcField<F, S> {
    fn sub_assign(&mut self, rhs: Self) {
        self.sub_assign(&rhs);
    }
}

impl<'a, F: Field, S: FieldShare<F>> SubAssign<&'a MpcField<F, S>> for MpcField<F, S> {
    fn sub_assign(&mut self, rhs: &Self) {
        match self {
            MpcField::Public(a) => match rhs {
                MpcField::Public(b) => {
                    *a -= b;
                }
                MpcField::Shared(b) => {
                    let mut tmp = *b;
                    tmp.neg().shift(a);
                    *self = MpcField::Shared(tmp);
                }
            },
            MpcField::Shared(a) => match rhs {
                MpcField::Public(b) => {
                    a.shift(&-*b);
                }
                MpcField::Shared(b) => {
                    a.sub(b);
                }
            },
        }
    }
}

impl<F: Field, S: FieldShare<F>> Sub for MpcField<F, S> {
    type Output = Self;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self.sub_assign(&rhs);
        self
    }
}

impl<'a, F: Field, S: FieldShare<F>> Sub<&'a MpcField<F, S>> for MpcField<F, S> {
    type Output = Self;

    fn sub(mut self, rhs: &'a MpcField<F, S>) -> Self::Output {
        self.sub_assign(rhs);
        self
    }
}

impl<F: Field, S: FieldShare<F>> MulAssign for MpcField<F, S> {
    fn mul_assign(&mut self, rhs: Self) {
        self.mul_assign(&rhs);
    }
}

impl<'a, F: Field, S: FieldShare<F>> MulAssign<&'a MpcField<F, S>> for MpcField<F, S> {
    fn mul_assign(&mut self, rhs: &'a MpcField<F, S>) {
        match self {
            MpcField::Public(a) => match rhs {
                MpcField::Public(b) => {
                    *a *= b;
                }
                MpcField::Shared(b) => {
                    let mut t = *b;
                    t.scale(a);
                    *self = MpcField::Shared(t);
                }
            },
            MpcField::Shared(a) => match rhs {
                MpcField::Public(b) => {
                    a.scale(b);
                }
                MpcField::Shared(b) => {
                    // TODO implement correctly by using beaver triples

                    let mut source = DummyFieldTripleSource::<F, S>::default();

                    let t = a.beaver_mul(*b, &mut source);
                    *self = MpcField::Shared(t);
                }
            },
        }
    }
}

impl<F: Field, S: FieldShare<F>> Mul for MpcField<F, S> {
    type Output = Self;

    fn mul(mut self, rhs: Self) -> Self::Output {
        self.mul_assign(&rhs);
        self
    }
}

impl<'a, F: Field, S: FieldShare<F>> Mul<&'a MpcField<F, S>> for MpcField<F, S> {
    type Output = Self;

    fn mul(mut self, rhs: &'a MpcField<F, S>) -> Self::Output {
        self.mul_assign(rhs);
        self
    }
}

impl<F: Field, S: FieldShare<F>> DivAssign for MpcField<F, S> {
    fn div_assign(&mut self, rhs: Self) {
        self.div_assign(&rhs);
    }
}

impl<'a, F: Field, S: FieldShare<F>> DivAssign<&'a MpcField<F, S>> for MpcField<F, S> {
    fn div_assign(&mut self, rhs: &'a MpcField<F, S>) {
        match self {
            MpcField::Public(a) => match rhs {
                MpcField::Public(b) => {
                    *a /= b;
                }
                MpcField::Shared(_b) => {
                    todo!();
                }
            },
            MpcField::Shared(a) => match rhs {
                MpcField::Public(b) => {
                    a.scale(&b.inverse().unwrap());
                }
                MpcField::Shared(b) => {
                    // TODO implement correctly by using beaver triples
                    let src = &mut DummyFieldTripleSource::default();
                    *a = a.beaver_div(*b, src);
                }
            },
        }
    }
}

impl<F: Field, S: FieldShare<F>> Div for MpcField<F, S> {
    type Output = Self;

    fn div(mut self, rhs: Self) -> Self::Output {
        self.div_assign(&rhs);
        self
    }
}

impl<'a, F: Field, S: FieldShare<F>> Div<&'a MpcField<F, S>> for MpcField<F, S> {
    type Output = Self;

    fn div(mut self, rhs: &'a MpcField<F, S>) -> Self::Output {
        self.div_assign(rhs);
        self
    }
}

impl<F: Field, S: FieldShare<F>> Product for MpcField<F, S> {
    fn product<I: Iterator<Item = Self>>(_iter: I) -> Self {
        todo!()
    }
}

impl<'a, F: Field, S: FieldShare<F>> Product<&'a MpcField<F, S>> for MpcField<F, S> {
    fn product<I: Iterator<Item = &'a MpcField<F, S>>>(_iter: I) -> Self {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> One for MpcField<F, S> {
    fn one() -> Self {
        MpcField::Public(F::one())
    }
    fn is_one(&self) -> bool {
        match self {
            MpcField::Public(x) => x.is_one(),
            MpcField::Shared(_) => {
                // There is no good solution to get is_one without revealing.
                // We just return false.
                debug!("Warning: is_zero on shared data. Returning false");
                false
            }
        }
    }
}

impl<F: Field, S: FieldShare<F>> Zero for MpcField<F, S> {
    fn zero() -> Self {
        MpcField::Public(F::zero())
    }

    fn is_zero(&self) -> bool {
        match self {
            MpcField::Public(x) => x.is_zero(),
            MpcField::Shared(_) => {
                // There is no good solution to get is_zero without revealing.
                // Moreover, this shared case is called only truncate coefficient of polynomial. so we just return false.
                debug!("Warning: is_zero on shared data. Returning false");
                false
            }
        }
    }
}

impl<F: PrimeField + SquareRootField, S: FieldShare<F>> EqualityZero for MpcField<F, S> {
    type Output = MpcBooleanField<F, S>;

    /// Check if the MPC field element is zero in MPC.
    ///
    /// # Arguments
    /// `self` - A MPC field element.
    ///
    /// # Returns
    /// A MPC boolean field element.
    fn is_zero_shared(&self) -> Self::Output {
        let res = match self {
            MpcField::Public(_) => {
                panic!("public is not expected here");
            }
            MpcField::Shared(_) => {
                let timer = start_timer!(|| "EqualityZero");
                let rng = &mut ark_std::test_rng();

                let (vec_r, r) = Self::Output::rand_number_bitwise(rng);

                let c = (r + self).reveal();

                let bits: Vec<Option<bool>> = {
                    let field_char = BitIteratorBE::new(F::characteristic());
                    let bits: Vec<_> = BitIteratorBE::new(c.into_repr())
                        .zip(field_char)
                        .skip_while(|(_, c)| !c)
                        .map(|(b, _)| Some(b))
                        .collect();
                    assert_eq!(bits.len(), F::Params::MODULUS_BITS as usize);
                    bits
                };

                let c_prime = bits
                    .iter()
                    .rev()
                    .zip(vec_r.iter())
                    .map(|(&b, &r)| match b {
                        Some(b) => {
                            if b {
                                r
                            } else {
                                !r
                            }
                        }
                        None => panic!("bits decomposition failed"),
                    })
                    .collect::<Vec<_>>();

                end_timer!(timer);
                c_prime.kary_and()
            }
        };
        res
    }
}

impl<F: PrimeField + SquareRootField, S: FieldShare<F>> BitDecomposition for MpcField<F, S> {
    type BooleanField = MpcBooleanField<F, S>;

    /// Bit decomposition of a field element.
    ///
    /// # Arguments
    /// `self` - A Mpc field element.
    ///
    /// # Returns
    /// A vector of bits of the Mpc field element(Little-Endian).
    fn bit_decomposition(&self) -> Vec<Self::BooleanField> {
        match self.is_shared() {
            true => {
                let timer = start_timer!(|| "Bit Decomposition");
                let rng = &mut ark_std::test_rng();

                let l = F::Params::MODULUS_BITS as usize;

                // 1
                let (vec_r, r) = Self::BooleanField::rand_number_bitwise(rng);

                // 2
                let c = -r + self;
                let revealed_c = c.reveal();
                if revealed_c.is_zero() {
                    return vec_r;
                }

                // 3
                let p_minus_c_bool = (-revealed_c).into_repr().to_bits_le();

                // set length to l
                let p_minus_c_bool = p_minus_c_bool[..l].to_vec();

                assert_eq!(p_minus_c_bool.len(), l);

                let p_minus_c_field = p_minus_c_bool
                    .iter()
                    .map(|b| Self::BooleanField::from(*b))
                    .collect::<Vec<_>>();

                let q = !vec_r.is_smaller_than_le(&p_minus_c_field);

                // 4
                let mut two_l = F::BigInt::from(1u64);
                two_l.muln(l as u32);

                let mut bigint_f = two_l;
                bigint_f.add_nocarry(&revealed_c.into_repr());
                bigint_f.sub_noborrow(&F::Params::MODULUS);

                let vec_f = bigint_f
                    .to_bits_le()
                    .iter()
                    .map(|&b| Self::BooleanField::from(b))
                    .collect::<Vec<_>>();

                let vec_f_prime = revealed_c
                    .into_repr()
                    .to_bits_le()
                    .iter()
                    .map(|&b| Self::BooleanField::from(b))
                    .collect::<Vec<_>>();

                let g_vec = vec_f
                    .iter()
                    .zip(vec_f_prime.iter())
                    .map(|(f, f_prime)| {
                        ((f.field() - f_prime.field()) * q.field() + f_prime.field()).into()
                    })
                    .collect::<Vec<_>>();

                // set length to l
                let g_vec = g_vec[..l].to_vec();

                // 5
                let h = vec_r.bit_add(&g_vec);

                // 6
                assert!(h.len() == l + 1);
                end_timer!(timer);
                h[..l].to_vec() // remove the last element
            }
            false => {
                // This can be faster.
                Self::king_share(self.unwrap_as_public(), &mut ark_std::test_rng())
                    .bit_decomposition()
            }
        }
    }
}

impl<F: Field, S: FieldShare<F>> Zeroize for MpcField<F, S> {
    fn zeroize(&mut self) {
        *self = MpcField::Public(F::zero());
    }
}

impl<F: Field, S: FieldShare<F>> Default for MpcField<F, S> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<F: Field, S: FieldShare<F>> From<bool> for MpcField<F, S> {
    fn from(value: bool) -> Self {
        MpcField::from_public(F::from(value))
    }
}

impl<F: Field, S: FieldShare<F>> From<u8> for MpcField<F, S> {
    fn from(value: u8) -> Self {
        MpcField::from_public(F::from(value))
    }
}

impl<F: Field, S: FieldShare<F>> From<u16> for MpcField<F, S> {
    fn from(value: u16) -> Self {
        MpcField::from_public(F::from(value))
    }
}

impl<F: Field, S: FieldShare<F>> From<u32> for MpcField<F, S> {
    fn from(value: u32) -> Self {
        MpcField::from_public(F::from(value))
    }
}

impl<F: Field, S: FieldShare<F>> From<u64> for MpcField<F, S> {
    fn from(value: u64) -> Self {
        MpcField::from_public(F::from(value))
    }
}

impl<F: Field, S: FieldShare<F>> From<u128> for MpcField<F, S> {
    fn from(value: u128) -> Self {
        MpcField::from_public(F::from(value))
    }
}

impl<F: PrimeField, S: FieldShare<F>> FromStr for MpcField<F, S> {
    type Err = F::Err;

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> From<BigUint> for MpcField<F, S> {
    fn from(_value: BigUint) -> Self {
        todo!()
    }
}

// impl<F: PrimeField, S: FieldShare<F>> Into<BigUint> for MpcField<F, S> {
//     fn into(self) -> BigUint {
//         todo!()
//     }
// }

impl<F: PrimeField, S: FieldShare<F>> From<MpcField<F, S>> for BigUint {
    fn from(_value: MpcField<F, S>) -> BigUint {
        todo!()
    }
}

impl<F: Field, S: FieldShare<F>> MpcWire for MpcField<F, S> {
    fn publicize(&mut self) {
        match self {
            MpcField::Public(_) => {}
            MpcField::Shared(s) => {
                *self = MpcField::Public(s.open());
            }
        }
        debug_assert!({
            let self_val = if let MpcField::Public(s) = self {
                *s
            } else {
                unreachable!()
            };
            super::macros::check_eq(self_val);
            true
        })
    }
    fn is_shared(&self) -> bool {
        match self {
            MpcField::Shared(_) => true,
            MpcField::Public(_) => false,
        }
    }
}

impl<F: PrimeField, S: FieldShare<F>> Field for MpcField<F, S> {
    type BasePrimeField = Self;

    fn characteristic() -> &'static [u64] {
        F::characteristic()
    }

    fn extension_degree() -> u64 {
        todo!()
    }

    fn from_base_prime_field_elems(_elems: &[Self::BasePrimeField]) -> Option<Self> {
        todo!()
    }

    fn double(&self) -> Self {
        Self::Public(F::from(2u8)) * self
    }

    fn double_in_place(&mut self) -> &mut Self {
        *self *= Self::Public(F::from(2u8));
        self
    }

    fn from_random_bytes_with_flags<Fl: ark_serialize::Flags>(_bytes: &[u8]) -> Option<(Self, Fl)> {
        todo!()
    }

    fn square(&self) -> Self {
        self.clone() * self
    }

    fn square_in_place(&mut self) -> &mut Self {
        *self *= *self;
        self
    }

    fn inverse(&self) -> Option<Self> {
        self.inv()
    }

    fn inverse_in_place(&mut self) -> Option<&mut Self> {
        todo!()
    }

    fn frobenius_map(&mut self, _power: usize) {
        todo!()
    }

    fn batch_product_in_place(selfs: &mut [Self], others: &[Self]) {
        let selfs_shared = selfs[0].is_shared();
        let others_shared = others[0].is_shared();
        assert!(
            selfs.iter().all(|s| s.is_shared() == selfs_shared),
            "Selfs heterogenously shared!"
        );
        assert!(
            others.iter().all(|s| s.is_shared() == others_shared),
            "others heterogenously shared!"
        );
        if selfs_shared && others_shared {
            let sshares = selfs
                .iter()
                .map(|s| match s {
                    Self::Shared(s) => *s,
                    Self::Public(_) => unreachable!(),
                })
                .collect();
            let oshares = others
                .iter()
                .map(|s| match s {
                    Self::Shared(s) => *s,
                    Self::Public(_) => unreachable!(),
                })
                .collect();
            let nshares = S::batch_mul(sshares, oshares, &mut DummyFieldTripleSource::default());
            for (self_, new) in selfs.iter_mut().zip(nshares.into_iter()) {
                *self_ = Self::Shared(new);
            }
        } else {
            for (a, b) in ark_std::cfg_iter_mut!(selfs).zip(others.iter()) {
                *a *= b;
            }
        }
    }

    fn batch_division_in_place(selfs: &mut [Self], others: &[Self]) {
        let selfs_shared = selfs[0].is_shared();
        let others_shared = others[0].is_shared();
        assert!(
            selfs.iter().all(|s| s.is_shared() == selfs_shared),
            "Selfs heterogenously shared!"
        );
        assert!(
            others.iter().all(|s| s.is_shared() == others_shared),
            "others heterogenously shared!"
        );
        if selfs_shared && others_shared {
            let sshares = selfs
                .iter()
                .map(|s| match s {
                    Self::Shared(s) => *s,
                    Self::Public(_) => unreachable!(),
                })
                .collect();
            let oshares = others
                .iter()
                .map(|s| match s {
                    Self::Shared(s) => *s,
                    Self::Public(_) => unreachable!(),
                })
                .collect();
            let nshares = S::batch_div(sshares, oshares, &mut DummyFieldTripleSource::default());
            for (self_, new) in selfs.iter_mut().zip(nshares.into_iter()) {
                *self_ = Self::Shared(new);
            }
        } else {
            for (a, b) in ark_std::cfg_iter_mut!(selfs).zip(others.iter()) {
                *a *= b;
            }
        }
    }

    fn has_univariate_div_qr() -> bool {
        true
    }
    fn univariate_div_qr<'a>(
        num: poly_stub::DenseOrSparsePolynomial<Self>,
        den: poly_stub::DenseOrSparsePolynomial<Self>,
    ) -> Option<(
        poly_stub::DensePolynomial<Self>,
        poly_stub::DensePolynomial<Self>,
    )> {
        use poly_stub::DenseOrSparsePolynomial::*;
        let shared_num = match num {
            DPolynomial(d) => Ok(d
                .into_owned()
                .coeffs
                .into_iter()
                .map(|c| match c {
                    MpcField::Shared(s) => s,
                    MpcField::Public(_) => panic!("public numerator"),
                })
                .collect()),
            SPolynomial(d) => Err(d
                .into_owned()
                .coeffs
                .into_iter()
                .map(|(i, c)| match c {
                    MpcField::Shared(s) => (i, s),
                    MpcField::Public(_) => panic!("public numerator"),
                })
                .collect()),
        };
        let pub_denom = match den {
            DPolynomial(d) => Ok(d
                .into_owned()
                .coeffs
                .into_iter()
                .map(|c| match c {
                    MpcField::Public(s) => s,
                    MpcField::Shared(_) => panic!("shared denominator"),
                })
                .collect()),
            SPolynomial(d) => Err(d
                .into_owned()
                .coeffs
                .into_iter()
                .map(|(i, c)| match c {
                    MpcField::Public(s) => (i, s),
                    MpcField::Shared(_) => panic!("shared denominator"),
                })
                .collect()),
        };
        S::univariate_div_qr(shared_num, pub_denom).map(|(q, r)| {
            (
                poly_stub::DensePolynomial {
                    coeffs: q.into_iter().map(|qc| MpcField::Shared(qc)).collect(),
                },
                poly_stub::DensePolynomial {
                    coeffs: r.into_iter().map(|rc| MpcField::Shared(rc)).collect(),
                },
            )
        })
    }
}

impl<F: PrimeField, S: FieldShare<F>> FftField for MpcField<F, S> {
    type FftParams = F::FftParams;

    fn two_adic_root_of_unity() -> Self {
        Self::from_public(F::two_adic_root_of_unity())
    }

    fn large_subgroup_root_of_unity() -> Option<Self> {
        F::large_subgroup_root_of_unity().map(Self::from_public)
    }

    fn multiplicative_generator() -> Self {
        Self::from_public(F::multiplicative_generator())
    }
}

impl<F: PrimeField, S: FieldShare<F>> PrimeField for MpcField<F, S> {
    type Params = F::Params;

    type BigInt = F::BigInt;

    fn from_repr(_repr: <Self as PrimeField>::BigInt) -> Option<Self> {
        todo!()
    }

    fn into_repr(&self) -> <Self as PrimeField>::BigInt {
        // unimplemented!("No BigInt reprs for shared fields! (into_repr)")
        self.unwrap_as_public().into_repr()
    }
}

impl<F: PrimeField + SquareRootField, S: FieldShare<F>> SquareRootField for MpcField<F, S> {
    fn legendre(&self) -> ark_ff::LegendreSymbol {
        todo!()
    }

    fn sqrt(&self) -> Option<Self> {
        // todo!()
        // TODO implement correctly.

        let is_shared = self.is_shared();
        let val = self.unwrap_as_public();

        match val.sqrt() {
            Some(sqrt) => {
                if is_shared {
                    Some(Self::from_add_shared(sqrt))
                } else {
                    Some(Self::from_public(sqrt))
                }
            }
            None => None,
        }

        // if is_shared {
        //     Some(Self::from_add_shared(sqrt.unwrap()))
        // } else {
        //     Some(Self::from_public(sqrt.unwrap()))
        // }
    }

    fn sqrt_in_place(&mut self) -> Option<&mut Self> {
        todo!()
    }
}

impl<F1: PrimeField, S1: FieldShare<F1>, F2: PrimeField, S2: FieldShare<F2>>
    mpc_primitives::ModulusConversion<MpcField<F2, S2>> for MpcField<F1, S1>
{
    fn modulus_conversion(&mut self) -> MpcField<F2, S2> {
        match self {
            MpcField::Public(x) => {
                let bits = x.into_repr().to_bits_le();
                MpcField::Public(F2::from_repr(BigInteger::from_bits_le(&bits)).unwrap())
            }
            MpcField::Shared(x) => MpcField::Shared(x.modulus_conversion()),
        }
    }
}

mod poly_impl {

    use crate::share::*;
    use crate::wire::*;
    use crate::Reveal;
    use ark_ff::PrimeField;
    use ark_poly::domain::{EvaluationDomain, GeneralEvaluationDomain};
    use ark_poly::evaluations::univariate::Evaluations;
    use ark_poly::univariate::DensePolynomial;

    impl<E: PrimeField, S: FieldShare<E>> Reveal for DensePolynomial<MpcField<E, S>> {
        type Base = DensePolynomial<E>;
        struct_reveal_simp_impl!(DensePolynomial; coeffs);
    }

    impl<F: PrimeField, S: FieldShare<F>> Reveal for Evaluations<MpcField<F, S>> {
        type Base = Evaluations<F>;

        fn reveal(self) -> Self::Base {
            Evaluations::from_vec_and_domain(
                self.evals.reveal(),
                GeneralEvaluationDomain::new(self.domain.size()).unwrap(),
            )
        }

        fn from_add_shared(b: Self::Base) -> Self {
            Evaluations::from_vec_and_domain(
                Reveal::from_add_shared(b.evals),
                GeneralEvaluationDomain::new(b.domain.size()).unwrap(),
            )
        }

        fn from_public(b: Self::Base) -> Self {
            Evaluations::from_vec_and_domain(
                Reveal::from_public(b.evals),
                GeneralEvaluationDomain::new(b.domain.size()).unwrap(),
            )
        }
    }
}
