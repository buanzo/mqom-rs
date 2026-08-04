//! Randomized signing for the frozen MQOM profile.

use crate::{
    blc,
    field::{Gf16, Gf256x2, unpack_gf16},
    keygen, mq, params,
    xof::{Shake128State, shake128},
};
use alloc::{vec, vec::Vec};
use zeroize::{Zeroize, Zeroizing};

const FIRST_COMMITMENT_OFFSET: usize = params::SALT_SIZE;
const SECOND_COMMITMENT_OFFSET: usize = FIRST_COMMITMENT_OFFSET + params::DIGEST_SIZE;
const ALPHA_ONE_OFFSET: usize = SECOND_COMMITMENT_OFFSET + params::DIGEST_SIZE;
const ALPHA_ONE_SIZE: usize = params::TAU * params::ETA * Gf256x2::ENCODED_LEN;
const OPENING_OFFSET: usize = ALPHA_ONE_OFFSET + ALPHA_ONE_SIZE;
const NONCE_SIZE: usize = 4;
const NONCE_OFFSET: usize = params::SIGNATURE_SIZE - NONCE_SIZE;
const CHALLENGE_STREAM_SIZE: usize = 2 * params::TAU + 2;

const _: () = {
    assert!(ALPHA_ONE_SIZE == 192);
    assert!(OPENING_OFFSET == 272);
    assert!(OPENING_OFFSET + params::OPENING_SIZE == NONCE_OFFSET);
    assert!(NONCE_OFFSET + NONCE_SIZE == params::SIGNATURE_SIZE);
    assert!(
        params::PUBLIC_KEY_SIZE + params::MQ_N * params::BASE_FIELD_BITS / 8
            == params::SECRET_KEY_SIZE
    );
};

type Alpha = [[Gf256x2; params::ETA]; params::TAU];

struct SecretEquationVectors(Vec<[Gf256x2; params::MQ_N]>);

impl Drop for SecretEquationVectors {
    fn drop(&mut self) {
        for vector in &mut self.0 {
            vector.zeroize();
        }
    }
}

fn parse_extension_vector<const N: usize>(bytes: &[u8]) -> Option<[Gf256x2; N]> {
    if bytes.len() != N * Gf256x2::ENCODED_LEN {
        return None;
    }
    Some(core::array::from_fn(|index| {
        let offset = index * Gf256x2::ENCODED_LEN;
        Gf256x2::from_bytes([bytes[offset], bytes[offset + 1]])
    }))
}

fn expand_equations(
    master_seed: &[u8; keygen::KEYGEN_SEED_SIZE],
) -> Option<Vec<mq::PackedEquation>> {
    (0..mq::EQUATION_COUNT)
        .map(|index| mq::expand_equation(master_seed, index))
        .collect()
}

fn compute_alpha(
    first_commitment: &[u8; params::DIGEST_SIZE],
    commitment: &blc::SigningCommitment,
    secret: &[Gf16; params::MQ_N],
    master_seed: &[u8; keygen::KEYGEN_SEED_SIZE],
) -> Option<(Zeroizing<Alpha>, Zeroizing<Alpha>)> {
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
    let mut t_one = SecretEquationVectors(Vec::with_capacity(mq::EQUATION_COUNT));
    for equation in &equations {
        let mut value = equation.multiply_base(secret);
        for (element, linear) in value.iter_mut().zip(equation.linear()) {
            *element += *linear;
        }
        t_one.0.push(value);
    }

    let mut alpha_zero = Zeroizing::new([[Gf256x2::ZERO; params::ETA]; params::TAU]);
    let mut alpha_one = Zeroizing::new([[Gf256x2::ZERO; params::ETA]; params::TAU]);
    for execution in 0..params::TAU {
        let mut z_zero = Zeroizing::new([Gf256x2::ZERO; mq::EQUATION_COUNT]);
        let mut z_one = Zeroizing::new([Gf256x2::ZERO; mq::EQUATION_COUNT]);
        for equation_index in 0..mq::EQUATION_COUNT {
            let t_zero = Zeroizing::new(
                equations[equation_index].multiply_extension(&commitment.x_zero[execution]),
            );
            for ((t_zero_element, x_zero_element), secret_element) in
                t_zero.iter().zip(&commitment.x_zero[execution]).zip(secret)
            {
                z_zero[equation_index] += *t_zero_element * *x_zero_element;
                z_one[equation_index] += *t_zero_element * *secret_element;
            }
            for (t_one_element, x_zero_element) in t_one.0[equation_index]
                .iter()
                .zip(&commitment.x_zero[execution])
            {
                z_one[equation_index] += *t_one_element * *x_zero_element;
            }
        }

        for component in 0..params::ETA {
            let mut zero = commitment.u_zero[execution][component];
            let mut one = commitment.u_one[execution][component];
            for equation_index in 0..mq::EQUATION_COUNT {
                zero += batching[component][equation_index] * z_zero[equation_index];
                one += batching[component][equation_index] * z_one[equation_index];
            }
            alpha_zero[execution][component] = zero;
            alpha_one[execution][component] = one;
        }
    }
    Some((alpha_zero, alpha_one))
}

fn sample_challenge(
    hash: &[u8; params::DIGEST_SIZE],
) -> Option<([u16; params::TAU], [u8; NONCE_SIZE])> {
    let evaluation_mask = u16::try_from(params::NB_EVALS - 1).ok()?;
    let grinding_mask = (1u16 << params::GRINDING_BITS) - 1;
    for nonce_value in 0..=u32::MAX {
        let nonce = nonce_value.to_le_bytes();
        let mut stream = [0u8; CHALLENGE_STREAM_SIZE];
        shake128(&[&[0x05], hash, &nonce], &mut stream);
        let grinding = u16::from_le_bytes([stream[2 * params::TAU], stream[2 * params::TAU + 1]]);
        if grinding & grinding_mask == 0 {
            let indices = core::array::from_fn(|execution| {
                let offset = 2 * execution;
                u16::from_le_bytes([stream[offset], stream[offset + 1]]) & evaluation_mask
            });
            return Some((indices, nonce));
        }
    }
    None
}

pub(crate) fn sign(
    secret_key: &[u8; params::SECRET_KEY_SIZE],
    message: &[u8],
    master_seed: &[u8; params::SEED_SIZE],
    salt: &[u8; params::SALT_SIZE],
) -> Option<[u8; params::SIGNATURE_SIZE]> {
    let public_key: &[u8; params::PUBLIC_KEY_SIZE] =
        secret_key[..params::PUBLIC_KEY_SIZE].try_into().ok()?;
    let equation_seed: &[u8; keygen::KEYGEN_SEED_SIZE] =
        public_key[..keygen::KEYGEN_SEED_SIZE].try_into().ok()?;
    let mut secret = Zeroizing::new([Gf16::ZERO; params::MQ_N]);
    unpack_gf16(&secret_key[params::PUBLIC_KEY_SIZE..], secret.as_mut()).then_some(())?;

    let commitment = blc::commit(master_seed, salt, &secret)?;
    let first_commitment = commitment.commitment;
    let (alpha_zero, alpha_one) =
        compute_alpha(&first_commitment, &commitment, &secret, equation_seed)?;

    let mut signature = [0u8; params::SIGNATURE_SIZE];
    signature[..params::SALT_SIZE].copy_from_slice(salt);
    signature[FIRST_COMMITMENT_OFFSET..SECOND_COMMITMENT_OFFSET].copy_from_slice(&first_commitment);

    let mut alpha_one_offset = ALPHA_ONE_OFFSET;
    for execution in alpha_one.iter() {
        for element in execution {
            let encoded = element.to_bytes();
            signature[alpha_one_offset..alpha_one_offset + encoded.len()].copy_from_slice(&encoded);
            alpha_one_offset += encoded.len();
        }
    }
    if alpha_one_offset != OPENING_OFFSET {
        return None;
    }

    let mut second_commitment_state = Shake128State::new();
    second_commitment_state.absorb(&[0x03]);
    for execution in alpha_zero.iter() {
        for element in execution {
            second_commitment_state.absorb(&element.to_bytes());
        }
    }
    second_commitment_state.absorb(&signature[ALPHA_ONE_OFFSET..OPENING_OFFSET]);
    let mut second_commitment = [0u8; params::DIGEST_SIZE];
    second_commitment_state.squeeze(&mut second_commitment);
    signature[SECOND_COMMITMENT_OFFSET..ALPHA_ONE_OFFSET].copy_from_slice(&second_commitment);

    let mut message_hash = [0u8; params::DIGEST_SIZE];
    shake128(&[&[0x02], message], &mut message_hash);
    let mut fiat_shamir_hash = [0u8; params::DIGEST_SIZE];
    shake128(
        &[
            &[0x04],
            public_key,
            &first_commitment,
            &second_commitment,
            &message_hash,
        ],
        &mut fiat_shamir_hash,
    );
    let (hidden_indices, nonce) = sample_challenge(&fiat_shamir_hash)?;
    let opening = commitment.open(&hidden_indices)?;
    signature[OPENING_OFFSET..NONCE_OFFSET].copy_from_slice(&opening);
    signature[NONCE_OFFSET..].copy_from_slice(&nonce);

    crate::verify::verify(public_key, message, &signature).then_some(signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_sampler_finds_the_first_valid_nonce() {
        let hash = [0u8; params::DIGEST_SIZE];
        let (indices, nonce) = sample_challenge(&hash).unwrap();
        assert!(
            indices
                .iter()
                .all(|index| usize::from(*index) < params::NB_EVALS)
        );

        let nonce_value = u32::from_le_bytes(nonce);
        for earlier in 0..nonce_value {
            let earlier = earlier.to_le_bytes();
            let mut stream = [0u8; CHALLENGE_STREAM_SIZE];
            shake128(&[&[0x05], &hash, &earlier], &mut stream);
            let grinding =
                u16::from_le_bytes([stream[2 * params::TAU], stream[2 * params::TAU + 1]]);
            assert_ne!(grinding & 0xff, 0);
        }
    }
}
