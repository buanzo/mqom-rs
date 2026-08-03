//! Parameters fixed by MQOM v2.1.1 for the first supported profile.

pub(crate) const SECURITY_BITS: usize = 128;
pub(crate) const SEED_SIZE: usize = SECURITY_BITS / 8;
pub(crate) const SALT_SIZE: usize = SECURITY_BITS / 8;
pub(crate) const DIGEST_SIZE: usize = 2 * SECURITY_BITS / 8;
pub(crate) const MQ_N: usize = 56;
pub(crate) const MQ_M: usize = 56;
pub(crate) const BASE_FIELD_BITS: usize = 4;
pub(crate) const EXT_FIELD_BITS: usize = 16;
pub(crate) const MU: usize = EXT_FIELD_BITS / BASE_FIELD_BITS;
pub(crate) const TAU: usize = 12;
pub(crate) const NB_EVALS_LOG: usize = 11;
pub(crate) const NB_EVALS: usize = 1 << NB_EVALS_LOG;
pub(crate) const GRINDING_BITS: usize = 8;
pub(crate) const ETA: usize = SECURITY_BITS / EXT_FIELD_BITS;

pub(crate) const PUBLIC_KEY_SIZE: usize = 2 * SEED_SIZE + (MQ_M / MU) * EXT_FIELD_BITS / 8;
pub(crate) const SECRET_KEY_SIZE: usize = PUBLIC_KEY_SIZE + MQ_N * BASE_FIELD_BITS / 8;
pub(crate) const OPENING_SIZE: usize =
    TAU * (MQ_N * BASE_FIELD_BITS / 8 - SEED_SIZE + NB_EVALS_LOG * SEED_SIZE + DIGEST_SIZE);
pub(crate) const SIGNATURE_SIZE: usize =
    4 + TAU * (ETA * MU) * BASE_FIELD_BITS / 8 + SALT_SIZE + 2 * DIGEST_SIZE + OPENING_SIZE;

const _: () = {
    assert!(PUBLIC_KEY_SIZE == 60);
    assert!(SECRET_KEY_SIZE == 88);
    assert!(SIGNATURE_SIZE == 2916);
};
