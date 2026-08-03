//! Native verification for the frozen MQOM profile.

use crate::{
    blc,
    field::Gf256x2,
    mq::{self, PackedEquation},
    params,
    xof::{Shake128State, shake128},
};
use alloc::{vec, vec::Vec};
use subtle::ConstantTimeEq;

const SALT_OFFSET: usize = 0;
const FIRST_COMMITMENT_OFFSET: usize = SALT_OFFSET + params::SALT_SIZE;
const SECOND_COMMITMENT_OFFSET: usize = FIRST_COMMITMENT_OFFSET + params::DIGEST_SIZE;
const ALPHA_ONE_OFFSET: usize = SECOND_COMMITMENT_OFFSET + params::DIGEST_SIZE;
const ALPHA_ONE_SIZE: usize = params::TAU * params::ETA * Gf256x2::ENCODED_LEN;
const OPENING_OFFSET: usize = ALPHA_ONE_OFFSET + ALPHA_ONE_SIZE;
const NONCE_SIZE: usize = 4;
const NONCE_OFFSET: usize = params::SIGNATURE_SIZE - NONCE_SIZE;
const CHALLENGE_STREAM_SIZE: usize = 2 * params::TAU + 2;
const PUBLIC_SEED_SIZE: usize = 2 * params::SEED_SIZE;

const _: () = {
    assert!(ALPHA_ONE_SIZE == 192);
    assert!(OPENING_OFFSET == 272);
    assert!(OPENING_OFFSET + params::OPENING_SIZE == NONCE_OFFSET);
};

fn parse_extension_vector<const N: usize>(bytes: &[u8]) -> Option<[Gf256x2; N]> {
    if bytes.len() != N * Gf256x2::ENCODED_LEN {
        return None;
    }
    Some(core::array::from_fn(|index| {
        let offset = index * Gf256x2::ENCODED_LEN;
        Gf256x2::from_bytes([bytes[offset], bytes[offset + 1]])
    }))
}

fn evaluation_point(index: u16) -> Gf256x2 {
    Gf256x2::from_bytes((index ^ (index >> 1)).to_le_bytes())
}

fn parse_challenge(
    hash: &[u8; params::DIGEST_SIZE],
    nonce: [u8; NONCE_SIZE],
) -> Option<[u16; params::TAU]> {
    let mut stream = [0u8; CHALLENGE_STREAM_SIZE];
    shake128(&[&[0x05], hash, &nonce], &mut stream);
    let evaluation_mask = u16::try_from(params::NB_EVALS - 1).ok()?;
    let indices = core::array::from_fn(|execution| {
        let offset = 2 * execution;
        u16::from_le_bytes([stream[offset], stream[offset + 1]]) & evaluation_mask
    });
    let grinding = u16::from_le_bytes([stream[2 * params::TAU], stream[2 * params::TAU + 1]]);
    let grinding_mask = (1u16 << params::GRINDING_BITS) - 1;
    (grinding & grinding_mask == 0).then_some(indices)
}

fn expand_equations(master_seed: &[u8; PUBLIC_SEED_SIZE]) -> Option<Vec<PackedEquation>> {
    let equations = (0..mq::EQUATION_COUNT)
        .map(|index| mq::expand_equation(master_seed, index))
        .collect::<Option<Vec<_>>>()?;
    (equations.len() == mq::EQUATION_COUNT).then_some(equations)
}

fn recompute_alpha_zero(
    first_commitment: &[u8; params::DIGEST_SIZE],
    alpha_one: &[[Gf256x2; params::ETA]; params::TAU],
    hidden_indices: &[u16; params::TAU],
    opened: &blc::OpenedEvaluations,
    master_seed: &[u8; PUBLIC_SEED_SIZE],
    public_output: &[Gf256x2; mq::EQUATION_COUNT],
) -> Option<[[Gf256x2; params::ETA]; params::TAU]> {
    let mut batching_stream = vec![0u8; params::ETA * mq::EQUATION_COUNT * Gf256x2::ENCODED_LEN];
    shake128(&[&[0x08], first_commitment], &mut batching_stream);
    let mut batching = [[Gf256x2::ZERO; mq::EQUATION_COUNT]; params::ETA];
    for (row, encoded_row) in batching
        .iter_mut()
        .zip(batching_stream.chunks_exact(mq::EQUATION_COUNT * Gf256x2::ENCODED_LEN))
    {
        *row = parse_extension_vector(encoded_row)?;
    }

    let equations = expand_equations(master_seed)?;
    let mut alpha_zero = [[Gf256x2::ZERO; params::ETA]; params::TAU];
    for execution in 0..params::TAU {
        let evaluation_point = evaluation_point(hidden_indices[execution]);
        let evaluation_point_squared = evaluation_point.square();
        let mut z_evaluations = [Gf256x2::ZERO; mq::EQUATION_COUNT];

        for ((z_evaluation, equation), public_output) in z_evaluations
            .iter_mut()
            .zip(equations.iter())
            .zip(public_output)
        {
            let mut t_evaluation = equation.multiply_extension(&opened.x[execution]);
            for (element, linear) in t_evaluation.iter_mut().zip(equation.linear()) {
                *element += evaluation_point * *linear;
            }

            for (t_element, x_element) in t_evaluation.iter().zip(&opened.x[execution]) {
                *z_evaluation += *t_element * *x_element;
            }
            *z_evaluation += evaluation_point_squared * *public_output;
        }

        for component in 0..params::ETA {
            let mut value = opened.u[execution][component];
            for (batching_element, z_evaluation) in batching[component].iter().zip(z_evaluations) {
                value += *batching_element * z_evaluation;
            }
            alpha_zero[execution][component] =
                value + evaluation_point * alpha_one[execution][component];
        }
    }
    Some(alpha_zero)
}

fn verify_inner(public_key: &[u8], message: &[u8], signature: &[u8]) -> Option<()> {
    if public_key.len() != params::PUBLIC_KEY_SIZE || signature.len() != params::SIGNATURE_SIZE {
        return None;
    }

    let master_seed: &[u8; PUBLIC_SEED_SIZE] = public_key[..PUBLIC_SEED_SIZE].try_into().ok()?;
    let public_output =
        parse_extension_vector::<{ mq::EQUATION_COUNT }>(&public_key[PUBLIC_SEED_SIZE..])?;
    let salt: &[u8; params::SALT_SIZE] = signature[SALT_OFFSET..SALT_OFFSET + params::SALT_SIZE]
        .try_into()
        .ok()?;
    let first_commitment: &[u8; params::DIGEST_SIZE] = signature
        [FIRST_COMMITMENT_OFFSET..FIRST_COMMITMENT_OFFSET + params::DIGEST_SIZE]
        .try_into()
        .ok()?;
    let second_commitment: &[u8; params::DIGEST_SIZE] = signature
        [SECOND_COMMITMENT_OFFSET..SECOND_COMMITMENT_OFFSET + params::DIGEST_SIZE]
        .try_into()
        .ok()?;
    let serialized_alpha_one = &signature[ALPHA_ONE_OFFSET..OPENING_OFFSET];
    let opening = &signature[OPENING_OFFSET..NONCE_OFFSET];
    let nonce: &[u8; NONCE_SIZE] = signature[NONCE_OFFSET..].try_into().ok()?;

    let mut message_hash = [0u8; params::DIGEST_SIZE];
    shake128(&[&[0x02], message], &mut message_hash);
    let mut fiat_shamir_hash = [0u8; params::DIGEST_SIZE];
    shake128(
        &[
            &[0x04],
            public_key,
            first_commitment,
            second_commitment,
            &message_hash,
        ],
        &mut fiat_shamir_hash,
    );
    let hidden_indices = parse_challenge(&fiat_shamir_hash, *nonce)?;
    let opened = blc::evaluate_opening(salt, first_commitment, opening, &hidden_indices)?;

    let mut alpha_one = [[Gf256x2::ZERO; params::ETA]; params::TAU];
    for (destination, encoded) in alpha_one
        .iter_mut()
        .zip(serialized_alpha_one.chunks_exact(params::ETA * Gf256x2::ENCODED_LEN))
    {
        *destination = parse_extension_vector(encoded)?;
    }
    let alpha_zero = recompute_alpha_zero(
        first_commitment,
        &alpha_one,
        &hidden_indices,
        &opened,
        master_seed,
        &public_output,
    )?;

    let mut commitment_state = Shake128State::new();
    commitment_state.absorb(&[0x03]);
    for execution in alpha_zero {
        for element in execution {
            commitment_state.absorb(&element.to_bytes());
        }
    }
    commitment_state.absorb(serialized_alpha_one);
    let mut observed_second_commitment = [0u8; params::DIGEST_SIZE];
    commitment_state.squeeze(&mut observed_second_commitment);
    bool::from(observed_second_commitment.ct_eq(second_commitment)).then_some(())
}

pub(crate) fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    verify_inner(public_key, message, signature).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grinding_failure_is_rejected() {
        let hash = [0u8; params::DIGEST_SIZE];
        let nonce = [0u8; NONCE_SIZE];
        let mut stream = [0u8; CHALLENGE_STREAM_SIZE];
        shake128(&[&[0x05], &hash, &nonce], &mut stream);
        let grinding = u16::from_le_bytes([stream[2 * params::TAU], stream[2 * params::TAU + 1]]);
        assert_ne!(grinding & 0xff, 0);
        assert!(parse_challenge(&hash, nonce).is_none());
    }

    #[test]
    fn wrong_lengths_are_rejected() {
        assert!(!verify(
            &[0u8; params::PUBLIC_KEY_SIZE - 1],
            b"",
            &[0u8; params::SIGNATURE_SIZE]
        ));
        assert!(!verify(
            &[0u8; params::PUBLIC_KEY_SIZE],
            b"",
            &[0u8; params::SIGNATURE_SIZE - 1]
        ));
    }
}
