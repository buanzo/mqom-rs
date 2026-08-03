//! Portable constant-time-intent arithmetic for the first profile's fields.

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

    /// Embed GF(16) into the GF(256) subfield used by MQOM's extension field.
    pub(crate) fn embed(self) -> Gf256 {
        // The image of the polynomial basis (1, x, x^2, x^3) in the Rijndael
        // field is (0x01, 0xe0, 0x5d, 0xb0). Select each public basis element
        // with an arithmetic mask so the input does not control memory access.
        let bit_0 = 0u8.wrapping_sub(self.0 & 1);
        let bit_1 = 0u8.wrapping_sub((self.0 >> 1) & 1);
        let bit_2 = 0u8.wrapping_sub((self.0 >> 2) & 1);
        let bit_3 = 0u8.wrapping_sub((self.0 >> 3) & 1);

        Gf256::new((0x01 & bit_0) ^ (0xe0 & bit_1) ^ (0x5d & bit_2) ^ (0xb0 & bit_3))
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

/// An element of GF(256), represented in the polynomial basis modulo
/// `x^8 + x^4 + x^3 + x + 1`.
#[derive(Clone, Copy, Default)]
pub(crate) struct Gf256(u8);

impl Gf256 {
    pub(crate) const ZERO: Self = Self(0);
    pub(crate) const ONE: Self = Self(1);

    pub(crate) const fn new(value: u8) -> Self {
        Self(value)
    }

    pub(crate) const fn value(self) -> u8 {
        self.0
    }

    pub(crate) fn square(self) -> Self {
        self * self
    }

    pub(crate) fn invert(self) -> Self {
        // Starting at a^(2^1 - 1), six square-and-multiply steps reach
        // a^(2^7 - 1); the final square gives a^254.
        let mut product = self;
        for _ in 0..6 {
            product = product.square() * self;
        }
        product.square()
    }
}

impl ConstantTimeEq for Gf256 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

#[allow(
    clippy::suspicious_arithmetic_impl,
    reason = "addition in characteristic two is XOR"
)]
impl Add for Gf256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

#[allow(
    clippy::suspicious_op_assign_impl,
    reason = "addition in characteristic two is XOR"
)]
impl AddAssign for Gf256 {
    fn add_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

#[allow(
    clippy::suspicious_arithmetic_impl,
    reason = "subtraction equals addition in characteristic two"
)]
impl Sub for Gf256 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

#[allow(
    clippy::suspicious_op_assign_impl,
    reason = "subtraction equals addition in characteristic two"
)]
impl SubAssign for Gf256 {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl Mul for Gf256 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut a = self.0;
        let mut b = rhs.0;
        let mut product = 0u8;

        for _ in 0..8 {
            let b_mask = 0u8.wrapping_sub(b & 1);
            product ^= a & b_mask;

            let high_mask = 0u8.wrapping_sub(a >> 7);
            a = (a << 1) ^ (0x1b & high_mask);
            b >>= 1;
        }

        Self(product)
    }
}

impl MulAssign for Gf256 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

/// An element of GF(256^2), represented as `c0 + c1 * X` modulo
/// `X^2 + X + 32`.
#[derive(Clone, Copy, Default)]
pub(crate) struct Gf256x2 {
    c0: Gf256,
    c1: Gf256,
}

impl Gf256x2 {
    pub(crate) const ZERO: Self = Self::new(Gf256::ZERO, Gf256::ZERO);
    pub(crate) const ONE: Self = Self::new(Gf256::ONE, Gf256::ZERO);
    pub(crate) const ENCODED_LEN: usize = 2;

    pub(crate) const fn new(c0: Gf256, c1: Gf256) -> Self {
        Self { c0, c1 }
    }

    pub(crate) const fn from_bytes(bytes: [u8; Self::ENCODED_LEN]) -> Self {
        Self::new(Gf256::new(bytes[0]), Gf256::new(bytes[1]))
    }

    pub(crate) const fn to_bytes(self) -> [u8; Self::ENCODED_LEN] {
        [self.c0.value(), self.c1.value()]
    }

    pub(crate) const fn value(self) -> u16 {
        u16::from_le_bytes(self.to_bytes())
    }

    pub(crate) fn square(self) -> Self {
        self * self
    }

    pub(crate) fn invert(self) -> Self {
        // Starting at a^(2^1 - 1), fourteen square-and-multiply steps reach
        // a^(2^15 - 1); the final square gives a^65534.
        let mut product = self;
        for _ in 0..14 {
            product = product.square() * self;
        }
        product.square()
    }
}

impl ConstantTimeEq for Gf256x2 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.c0.ct_eq(&other.c0) & self.c1.ct_eq(&other.c1)
    }
}

#[allow(
    clippy::suspicious_arithmetic_impl,
    reason = "addition in characteristic two is component-wise XOR"
)]
impl Add for Gf256x2 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self::new(self.c0 + rhs.c0, self.c1 + rhs.c1)
    }
}

#[allow(
    clippy::suspicious_op_assign_impl,
    reason = "addition in characteristic two is component-wise XOR"
)]
impl AddAssign for Gf256x2 {
    fn add_assign(&mut self, rhs: Self) {
        self.c0 += rhs.c0;
        self.c1 += rhs.c1;
    }
}

#[allow(
    clippy::suspicious_arithmetic_impl,
    reason = "subtraction equals addition in characteristic two"
)]
impl Sub for Gf256x2 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::new(self.c0 - rhs.c0, self.c1 - rhs.c1)
    }
}

#[allow(
    clippy::suspicious_op_assign_impl,
    reason = "subtraction equals addition in characteristic two"
)]
impl SubAssign for Gf256x2 {
    fn sub_assign(&mut self, rhs: Self) {
        self.c0 -= rhs.c0;
        self.c1 -= rhs.c1;
    }
}

impl Mul for Gf256x2 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let high_product = self.c1 * rhs.c1;
        let low_product = self.c0 * rhs.c0;
        let c0 = low_product + high_product * Gf256::new(32);
        let c1 = low_product + (self.c0 + self.c1) * (rhs.c0 + rhs.c1);

        Self::new(c0, c1)
    }
}

impl MulAssign for Gf256x2 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Mul<Gf256x2> for Gf16 {
    type Output = Gf256x2;

    fn mul(self, rhs: Gf256x2) -> Self::Output {
        let scalar = self.embed();
        Gf256x2::new(scalar * rhs.c0, scalar * rhs.c1)
    }
}

impl Mul<Gf16> for Gf256x2 {
    type Output = Self;

    fn mul(self, rhs: Gf16) -> Self::Output {
        rhs * self
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

    fn reference_gf16_multiply(mut a: u8, mut b: u8) -> u8 {
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
                    reference_gf16_multiply(a, b)
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

    fn reference_gf256_multiply(a: u8, b: u8) -> u8 {
        let mut unreduced = 0u16;
        for bit in 0..8 {
            if (b >> bit) & 1 != 0 {
                unreduced ^= u16::from(a) << bit;
            }
        }
        for bit in (8..=14).rev() {
            if unreduced & (1 << bit) != 0 {
                unreduced ^= 0x11b << (bit - 8);
            }
        }
        u8::try_from(unreduced).expect("reference reduction must fit in one byte")
    }

    #[test]
    fn gf256_multiplication_is_exhaustive() {
        for a in 0..=u8::MAX {
            for b in 0..=u8::MAX {
                assert_eq!(
                    (Gf256::new(a) * Gf256::new(b)).value(),
                    reference_gf256_multiply(a, b)
                );
            }
        }
    }

    #[test]
    fn gf256_nonzero_elements_have_inverses() {
        for value in 1..=u8::MAX {
            let element = Gf256::new(value);
            assert!(bool::from((element * element.invert()).ct_eq(&Gf256::ONE)));
        }
        assert!(bool::from(Gf256::ZERO.invert().ct_eq(&Gf256::ZERO)));
    }

    #[test]
    fn gf16_embedding_preserves_field_operations() {
        let oracle_images = [
            0x00, 0x01, 0xe0, 0xe1, 0x5d, 0x5c, 0xbd, 0xbc, 0xb0, 0xb1, 0x50, 0x51, 0xed, 0xec,
            0x0d, 0x0c,
        ];

        for a in 0..16 {
            assert_eq!(Gf16::new(a).embed().value(), oracle_images[usize::from(a)]);
            for b in 0..16 {
                let a = Gf16::new(a);
                let b = Gf16::new(b);
                assert!(bool::from((a + b).embed().ct_eq(&(a.embed() + b.embed()))));
                assert!(bool::from((a * b).embed().ct_eq(&(a.embed() * b.embed()))));
            }
        }
    }

    #[test]
    fn gf256x2_encoding_is_canonical_little_endian() {
        let element = Gf256x2::from_bytes([0x34, 0x12]);
        assert_eq!(element.value(), 0x1234);
        assert_eq!(element.to_bytes(), [0x34, 0x12]);
    }

    #[test]
    fn gf256x2_arithmetic_matches_oracle_samples() {
        // Filled from the separately built, commit-pinned MQOM v2.1.1 oracle.
        let samples: [(u16, u16, u16); 8] = [
            (0x0000, 0x0000, 0x0000),
            (0x0001, 0x1234, 0x1234),
            (0x1234, 0xabcd, 0x8ee3),
            (0xffff, 0xffff, 0x1345),
            (0x0100, 0x0100, 0x0120),
            (0x53ca, 0xbeef, 0x0f14),
            (0x8001, 0x7ffe, 0x652c),
            (0x00ff, 0xff00, 0x1300),
        ];

        for (left, right, expected) in samples {
            let left = Gf256x2::from_bytes(left.to_le_bytes());
            let right = Gf256x2::from_bytes(right.to_le_bytes());
            assert_eq!((left * right).value(), expected);
        }
    }

    #[test]
    fn gf256x2_nonzero_elements_have_inverses() {
        for value in 1..=u16::MAX {
            let element = Gf256x2::from_bytes(value.to_le_bytes());
            assert!(bool::from(
                (element * element.invert()).ct_eq(&Gf256x2::ONE)
            ));
        }
        assert!(bool::from(Gf256x2::ZERO.invert().ct_eq(&Gf256x2::ZERO)));
    }

    #[test]
    fn gf16_scales_both_extension_coefficients() {
        let scalar = Gf16::new(7);
        let element = Gf256x2::from_bytes(0x53cau16.to_le_bytes());
        let expected = Gf256x2::from_bytes(0x3e93u16.to_le_bytes());

        assert!(bool::from((scalar * element).ct_eq(&expected)));
        assert!(bool::from((element * scalar).ct_eq(&expected)));
    }
}
