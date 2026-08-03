//! Expansion and arithmetic for the packed MQ system.

#![allow(
    dead_code,
    reason = "equation expansion lands before the native verifier consumes it"
)]

use crate::{
    field::{Gf16, Gf256x2},
    params, prg,
    xof::shake128,
};
use alloc::{vec, vec::Vec};

pub(crate) const EQUATION_COUNT: usize = params::MQ_M / params::MU;
pub(crate) const TRIANGULAR_ELEMENT_COUNT: usize = params::MQ_N * (params::MQ_N + 1) / 2;
pub(crate) const EQUATION_ELEMENT_COUNT: usize = TRIANGULAR_ELEMENT_COUNT + params::MQ_N;
pub(crate) const EQUATION_BYTE_COUNT: usize = EQUATION_ELEMENT_COUNT * Gf256x2::ENCODED_LEN;

const MASTER_SEED_SIZE: usize = 2 * params::SEED_SIZE;
const ZERO_SALT: [u8; params::SALT_SIZE] = [0u8; params::SALT_SIZE];

const _: () = {
    assert!(EQUATION_COUNT == 14);
    assert!(TRIANGULAR_ELEMENT_COUNT == 1_596);
    assert!(EQUATION_ELEMENT_COUNT == 1_652);
    assert!(EQUATION_BYTE_COUNT == 3_304);
    assert!(params::SEED_SIZE == 16);
    assert!(params::SALT_SIZE == 16);
};

/// One lower-triangular packed quadratic equation and its linear vector.
pub(crate) struct PackedEquation {
    quadratic: Vec<Gf256x2>,
    linear: [Gf256x2; params::MQ_N],
}

impl PackedEquation {
    pub(crate) fn quadratic(&self) -> &[Gf256x2] {
        &self.quadratic
    }

    pub(crate) fn linear(&self) -> &[Gf256x2; params::MQ_N] {
        &self.linear
    }

    /// Multiply the lower-triangular matrix by a base-field vector.
    pub(crate) fn multiply_base(&self, vector: &[Gf16; params::MQ_N]) -> [Gf256x2; params::MQ_N] {
        let mut output = [Gf256x2::ZERO; params::MQ_N];
        let mut offset = 0;

        for (row_index, output_element) in output.iter_mut().enumerate() {
            for (coefficient, vector_element) in self.quadratic[offset..=offset + row_index]
                .iter()
                .zip(&vector[..=row_index])
            {
                *output_element += *vector_element * *coefficient;
            }
            offset += row_index + 1;
        }
        debug_assert_eq!(offset, TRIANGULAR_ELEMENT_COUNT);
        output
    }

    /// Multiply the lower-triangular matrix by an extension-field vector.
    pub(crate) fn multiply_extension(
        &self,
        vector: &[Gf256x2; params::MQ_N],
    ) -> [Gf256x2; params::MQ_N] {
        let mut output = [Gf256x2::ZERO; params::MQ_N];
        let mut offset = 0;

        for (row_index, output_element) in output.iter_mut().enumerate() {
            for (coefficient, vector_element) in self.quadratic[offset..=offset + row_index]
                .iter()
                .zip(&vector[..=row_index])
            {
                *output_element += *coefficient * *vector_element;
            }
            offset += row_index + 1;
        }
        debug_assert_eq!(offset, TRIANGULAR_ELEMENT_COUNT);
        output
    }

    /// Evaluate `x^T A x + b^T x` for a base-field vector.
    pub(crate) fn evaluate_base(&self, vector: &[Gf16; params::MQ_N]) -> Gf256x2 {
        let matrix_product = self.multiply_base(vector);
        let mut result = Gf256x2::ZERO;

        for ((vector_element, matrix_element), linear_element) in vector
            .iter()
            .zip(matrix_product.iter())
            .zip(self.linear.iter())
        {
            result += *vector_element * *matrix_element;
            result += *vector_element * *linear_element;
        }
        result
    }
}

/// Expand one of the frozen profile's packed MQ equations.
pub(crate) fn expand_equation(
    master_seed: &[u8; MASTER_SEED_SIZE],
    equation_index: usize,
) -> Option<PackedEquation> {
    if equation_index >= EQUATION_COUNT {
        return None;
    }

    let equation_index = u16::try_from(equation_index).ok()?;
    let equation_index_bytes = equation_index.to_le_bytes();
    let mut equation_seed = [0u8; params::SEED_SIZE];
    shake128(
        &[&[0x01], master_seed, &equation_index_bytes],
        &mut equation_seed,
    );

    let mut stream = vec![0u8; EQUATION_BYTE_COUNT];
    if !prg::fill(&ZERO_SALT, 0, &equation_seed, &mut stream) {
        return None;
    }

    let mut elements = stream
        .chunks_exact(Gf256x2::ENCODED_LEN)
        .map(|bytes| Gf256x2::from_bytes([bytes[0], bytes[1]]));
    let quadratic = elements
        .by_ref()
        .take(TRIANGULAR_ELEMENT_COUNT)
        .collect::<Vec<_>>();
    let mut linear = [Gf256x2::ZERO; params::MQ_N];
    for (destination, source) in linear.iter_mut().zip(elements.by_ref()) {
        *destination = source;
    }

    if quadratic.len() != TRIANGULAR_ELEMENT_COUNT || elements.next().is_some() {
        return None;
    }

    Some(PackedEquation { quadratic, linear })
}

#[cfg(test)]
mod tests {
    use super::*;
    use subtle::ConstantTimeEq;

    fn sequential_master_seed() -> [u8; MASTER_SEED_SIZE] {
        core::array::from_fn(|index| u8::try_from(index).unwrap())
    }

    #[test]
    fn dimensions_are_fixed_and_invalid_indices_are_rejected() {
        let master_seed = sequential_master_seed();
        let equation = expand_equation(&master_seed, 0).unwrap();
        assert_eq!(equation.quadratic().len(), TRIANGULAR_ELEMENT_COUNT);
        assert_eq!(equation.linear().len(), params::MQ_N);
        assert!(expand_equation(&master_seed, EQUATION_COUNT - 1).is_some());
        assert!(expand_equation(&master_seed, EQUATION_COUNT).is_none());
    }

    #[test]
    fn zero_vectors_produce_zero() {
        let equation = expand_equation(&sequential_master_seed(), 0).unwrap();
        let base = [Gf16::ZERO; params::MQ_N];
        let extension = [Gf256x2::ZERO; params::MQ_N];

        assert!(bool::from(
            equation.evaluate_base(&base).ct_eq(&Gf256x2::ZERO)
        ));
        assert!(
            equation
                .multiply_base(&base)
                .iter()
                .all(|element| bool::from(element.ct_eq(&Gf256x2::ZERO)))
        );
        assert!(
            equation
                .multiply_extension(&extension)
                .iter()
                .all(|element| bool::from(element.ct_eq(&Gf256x2::ZERO)))
        );
    }

    #[test]
    fn extension_matrix_multiplication_uses_lower_triangular_rows() {
        let mut quadratic = vec![Gf256x2::ZERO; TRIANGULAR_ELEMENT_COUNT];
        let linear = [Gf256x2::ZERO; params::MQ_N];
        let row = 2;
        let row_offset = row * (row + 1) / 2;
        let coefficient_0 = Gf256x2::from_bytes(0x1234u16.to_le_bytes());
        let coefficient_2 = Gf256x2::from_bytes(0xabcd_u16.to_le_bytes());
        quadratic[row_offset] = coefficient_0;
        quadratic[row_offset + 2] = coefficient_2;
        let equation = PackedEquation { quadratic, linear };

        let mut vector = [Gf256x2::ZERO; params::MQ_N];
        vector[0] = Gf256x2::from_bytes(0x00ffu16.to_le_bytes());
        vector[2] = Gf256x2::from_bytes(0xff00u16.to_le_bytes());
        let expected = coefficient_0 * vector[0] + coefficient_2 * vector[2];
        let product = equation.multiply_extension(&vector);

        assert!(bool::from(product[row].ct_eq(&expected)));
        assert!(
            product[..row]
                .iter()
                .chain(&product[row + 1..])
                .all(|element| bool::from(element.ct_eq(&Gf256x2::ZERO)))
        );
    }

    #[test]
    fn expansion_matches_v2_1_1_oracle_samples() {
        let master_seed = sequential_master_seed();
        let samples = [
            (
                0,
                [
                    0xe016, 0x3db6, 0x0602, 0x53dc, 0x8681, 0x606a, 0x5e69, 0x3f06,
                ],
            ),
            (
                13,
                [
                    0x7d89, 0x2144, 0xc69f, 0x9146, 0x2da4, 0x7464, 0xacba, 0xa87c,
                ],
            ),
        ];

        for (equation_index, expected) in samples {
            let equation = expand_equation(&master_seed, equation_index).unwrap();
            let observed = [
                equation.quadratic()[0].value(),
                equation.quadratic()[1].value(),
                equation.quadratic()[2].value(),
                equation.quadratic()[162].value(),
                equation.quadratic()[1_540].value(),
                equation.quadratic()[1_595].value(),
                equation.linear()[0].value(),
                equation.linear()[55].value(),
            ];
            assert_eq!(observed, expected);
        }
    }

    #[test]
    fn fixed_vector_evaluations_match_v2_1_1_oracle() {
        let master_seed = sequential_master_seed();
        let vector = core::array::from_fn(|index| Gf16::new(u8::try_from(index & 0x0f).unwrap()));
        let expected = [
            0xdd30, 0x290d, 0xf944, 0xf7f6, 0x87ce, 0x5e93, 0x0df7, 0x68f9, 0x3527, 0xb13b, 0x80b7,
            0x5f3b, 0xb65b, 0xcb6d,
        ];

        for (equation_index, expected) in expected.into_iter().enumerate() {
            let equation = expand_equation(&master_seed, equation_index).unwrap();
            assert_eq!(equation.evaluate_base(&vector).value(), expected);
        }
    }
}
