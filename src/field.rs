//! Portable constant-time-intent arithmetic for the first profile's base field.

#![allow(
    dead_code,
    reason = "field primitives land before the native verifier consumes them"
)]

use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use subtle::{Choice, ConstantTimeEq};

/// An element of GF(16), represented in the polynomial basis modulo
/// `x^4 + x + 1`.
#[derive(Clone, Copy, Default)]
pub(crate) struct Gf16(u8);

impl Gf16 {
    pub(crate) const ZERO: Self = Self(0);
    pub(crate) const ONE: Self = Self(1);

    pub(crate) const fn new(value: u8) -> Self {
        Self(value & 0x0f)
    }

    pub(crate) const fn value(self) -> u8 {
        self.0
    }

    pub(crate) fn square(self) -> Self {
        self * self
    }

    pub(crate) fn invert(self) -> Self {
        // a^-1 = a^14 for non-zero a. Zero maps to zero; callers that require
        // an inverse must separately reject zero in constant time.
        let a2 = self.square();
        let a4 = a2.square();
        let a8 = a4.square();
        a8 * a4 * a2
    }
}

impl ConstantTimeEq for Gf16 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

#[allow(
    clippy::suspicious_arithmetic_impl,
    reason = "addition in characteristic two is XOR"
)]
impl Add for Gf16 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        // Addition in a binary extension field is XOR. Express it through the
        // trait implementation explicitly rather than delegating to `Sub`.
        Self(self.0 ^ rhs.0)
    }
}

#[allow(
    clippy::suspicious_op_assign_impl,
    reason = "addition in characteristic two is XOR"
)]
impl AddAssign for Gf16 {
    fn add_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

#[allow(
    clippy::suspicious_arithmetic_impl,
    reason = "subtraction equals addition in characteristic two"
)]
impl Sub for Gf16 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

#[allow(
    clippy::suspicious_op_assign_impl,
    reason = "subtraction equals addition in characteristic two"
)]
impl SubAssign for Gf16 {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl Mul for Gf16 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut a = self.0;
        let mut b = rhs.0;
        let mut product = 0u8;

        for _ in 0..4 {
            let b_mask = 0u8.wrapping_sub(b & 1);
            product ^= a & b_mask;

            let high_mask = 0u8.wrapping_sub((a >> 3) & 1);
            a = ((a << 1) & 0x0f) ^ (0x03 & high_mask);
            b >>= 1;
        }

        Self(product & 0x0f)
    }
}

impl MulAssign for Gf16 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

pub(crate) fn unpack_gf16(bytes: &[u8], output: &mut [Gf16]) -> bool {
    let Some(required) = output.len().checked_add(1).map(|value| value / 2) else {
        return false;
    };
    if bytes.len() != required {
        return false;
    }

    for (index, value) in output.iter_mut().enumerate() {
        let shift = 4 * (index & 1);
        *value = Gf16::new(bytes[index / 2] >> shift);
    }
    true
}

pub(crate) fn pack_gf16(elements: &[Gf16], output: &mut [u8]) -> bool {
    let Some(required) = elements.len().checked_add(1).map(|value| value / 2) else {
        return false;
    };
    if output.len() != required {
        return false;
    }

    output.fill(0);
    for (index, value) in elements.iter().enumerate() {
        output[index / 2] |= value.value() << (4 * (index & 1));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn reference_multiply(mut a: u8, mut b: u8) -> u8 {
        let mut product = 0;
        while b != 0 {
            if b & 1 != 0 {
                product ^= a;
            }
            b >>= 1;
            a <<= 1;
            if a & 0x10 != 0 {
                a ^= 0x13;
            }
        }
        product & 0x0f
    }

    #[test]
    fn multiplication_is_exhaustive() {
        for a in 0..16 {
            for b in 0..16 {
                assert_eq!(
                    (Gf16::new(a) * Gf16::new(b)).value(),
                    reference_multiply(a, b)
                );
            }
        }
    }

    #[test]
    fn nonzero_elements_have_inverses() {
        for value in 1..16 {
            let element = Gf16::new(value);
            assert_eq!((element * element.invert()).value(), Gf16::ONE.value());
        }
        assert_eq!(Gf16::ZERO.invert().value(), 0);
    }

    #[test]
    fn packed_order_is_low_nibble_first() {
        let elements = [Gf16::new(1), Gf16::new(2), Gf16::new(3), Gf16::new(4)];
        let mut packed = [0u8; 2];
        assert!(pack_gf16(&elements, &mut packed));
        assert_eq!(packed, [0x21, 0x43]);

        let mut unpacked = [Gf16::ZERO; 4];
        assert!(unpack_gf16(&packed, &mut unpacked));
        assert!(
            unpacked
                .iter()
                .zip(elements)
                .all(|(left, right)| bool::from(left.ct_eq(&right)))
        );

        let mut wrong = vec![0u8; 3];
        assert!(!pack_gf16(&elements, &mut wrong));
    }
}
