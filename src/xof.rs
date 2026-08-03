//! SHAKE128 helper for the category-I transcript.

#![allow(
    dead_code,
    reason = "transcript primitive lands before the native verifier consumes it"
)]

use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update, XofReader},
};

pub(crate) fn shake128(parts: &[&[u8]], output: &mut [u8]) {
    let mut state = Shake128::default();
    for part in parts {
        state.update(part);
    }
    state.finalize_xof().read(output);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_matches_fips_202() {
        let mut output = [0u8; 32];
        shake128(&[], &mut output);
        assert_eq!(
            output,
            [
                0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d, 0x61, 0x60, 0x45, 0x50, 0x76, 0x05,
                0x85, 0x3e, 0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88, 0xeb, 0x1a, 0x6e, 0xac,
                0xfa, 0x66, 0xef, 0x26,
            ]
        );
    }

    #[test]
    fn updates_are_stream_equivalent() {
        let mut joined = [0u8; 64];
        let mut split = [0u8; 64];
        shake128(&[b"mqom-rs"], &mut joined);
        shake128(&[b"mqom", b"-", b"rs"], &mut split);
        assert_eq!(joined, split);
    }
}
