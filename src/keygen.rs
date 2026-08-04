//! Deterministic core for randomized MQOM key generation.

use crate::{
    field::{Gf16, unpack_gf16},
    mq, params,
    xof::shake128,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub(crate) const KEYGEN_SEED_SIZE: usize = 2 * params::SEED_SIZE;
const SECRET_VECTOR_SIZE: usize = params::MQ_N * params::BASE_FIELD_BITS / 8;
const EXPANSION_SIZE: usize = SECRET_VECTOR_SIZE + KEYGEN_SEED_SIZE;

const _: () = {
    assert!(KEYGEN_SEED_SIZE == 32);
    assert!(SECRET_VECTOR_SIZE == 28);
    assert!(EXPANSION_SIZE == 60);
};

pub(crate) fn keypair_from_seed(
    seed: &[u8; KEYGEN_SEED_SIZE],
) -> Option<([u8; params::SECRET_KEY_SIZE], [u8; params::PUBLIC_KEY_SIZE])> {
    let mut expansion = Zeroizing::new([0u8; EXPANSION_SIZE]);
    shake128(&[&[0x00], seed], expansion.as_mut());

    let mut secret_vector = Zeroizing::new([Gf16::ZERO; params::MQ_N]);
    unpack_gf16(&expansion[..SECRET_VECTOR_SIZE], secret_vector.as_mut()).then_some(())?;
    let master_seed: &[u8; KEYGEN_SEED_SIZE] = expansion[SECRET_VECTOR_SIZE..].try_into().ok()?;

    let mut public_key = [0u8; params::PUBLIC_KEY_SIZE];
    public_key[..KEYGEN_SEED_SIZE].copy_from_slice(master_seed);
    for equation_index in 0..mq::EQUATION_COUNT {
        let equation = mq::expand_equation(master_seed, equation_index)?;
        let output = equation.evaluate_base(&secret_vector).to_bytes();
        let offset = KEYGEN_SEED_SIZE + equation_index * output.len();
        public_key[offset..offset + output.len()].copy_from_slice(&output);
    }

    let mut secret_key = [0u8; params::SECRET_KEY_SIZE];
    secret_key[..params::PUBLIC_KEY_SIZE].copy_from_slice(&public_key);
    secret_key[params::PUBLIC_KEY_SIZE..].copy_from_slice(&expansion[..SECRET_VECTOR_SIZE]);
    Some((secret_key, public_key))
}

pub(crate) fn secret_key_is_consistent(secret_key: &[u8; params::SECRET_KEY_SIZE]) -> bool {
    let Some(master_seed) = secret_key[..KEYGEN_SEED_SIZE].try_into().ok() else {
        return false;
    };
    let mut secret_vector = Zeroizing::new([Gf16::ZERO; params::MQ_N]);
    if !unpack_gf16(
        &secret_key[params::PUBLIC_KEY_SIZE..],
        secret_vector.as_mut(),
    ) {
        return false;
    }

    let mut matches = subtle::Choice::from(1);
    for equation_index in 0..mq::EQUATION_COUNT {
        let Some(equation) = mq::expand_equation(master_seed, equation_index) else {
            return false;
        };
        let observed_offset = KEYGEN_SEED_SIZE + equation_index * 2;
        let observed = &secret_key[observed_offset..observed_offset + 2];
        matches &= equation
            .evaluate_base(&secret_vector)
            .to_bytes()
            .ct_eq(observed);
    }
    bool::from(matches)
}

#[cfg(test)]
mod tests {
    use super::*;
    use subtle::ConstantTimeEq;

    #[test]
    fn generated_public_output_matches_secret_vector() {
        let seed = core::array::from_fn(|index| u8::try_from(index).unwrap());
        let (secret_key, public_key) = keypair_from_seed(&seed).unwrap();
        assert_eq!(&secret_key[..params::PUBLIC_KEY_SIZE], &public_key);

        let mut secret_vector = [Gf16::ZERO; params::MQ_N];
        assert!(unpack_gf16(
            &secret_key[params::PUBLIC_KEY_SIZE..],
            &mut secret_vector
        ));
        let master_seed: &[u8; KEYGEN_SEED_SIZE] =
            public_key[..KEYGEN_SEED_SIZE].try_into().unwrap();
        for equation_index in 0..mq::EQUATION_COUNT {
            let expected = mq::expand_equation(master_seed, equation_index)
                .unwrap()
                .evaluate_base(&secret_vector);
            let offset = KEYGEN_SEED_SIZE + equation_index * 2;
            let observed =
                crate::field::Gf256x2::from_bytes([public_key[offset], public_key[offset + 1]]);
            assert!(bool::from(expected.ct_eq(&observed)));
        }
    }
}
