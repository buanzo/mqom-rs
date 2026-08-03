//! AES-based pseudorandom generator used by MQOM v2.1.1.

#![allow(
    dead_code,
    reason = "the PRG lands before all native proof stages consume it"
)]

use aes::{
    Aes128,
    cipher::{Array, BlockCipherEncrypt, KeyInit},
};
use alloc::vec::Vec;
use zeroize::{Zeroize, Zeroizing};

pub(crate) const BLOCK_SIZE: usize = 16;
const PRG_SELECTOR: u8 = 3;

fn linear_orthomorphism(seed: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut image = [0u8; BLOCK_SIZE];
    image[..BLOCK_SIZE / 2].copy_from_slice(&seed[BLOCK_SIZE / 2..]);
    image[BLOCK_SIZE / 2..].copy_from_slice(&seed[..BLOCK_SIZE / 2]);

    for (left, source) in image[..BLOCK_SIZE / 2]
        .iter_mut()
        .zip(&seed[..BLOCK_SIZE / 2])
    {
        *left ^= source;
    }
    image
}

pub(crate) fn tweak_salt(
    salt: &[u8; BLOCK_SIZE],
    selector: u8,
    execution: u8,
    index: u16,
) -> [u8; BLOCK_SIZE] {
    let mut tweaked = *salt;
    let index_bytes = index.to_le_bytes();
    tweaked[0] ^= selector.wrapping_add(execution.wrapping_mul(4));
    tweaked[1] ^= index_bytes[0];
    tweaked[2] ^= index_bytes[1];
    tweaked
}

pub(crate) struct SeedDeriver(Aes128);

impl SeedDeriver {
    pub(crate) fn new(key: &[u8; BLOCK_SIZE]) -> Self {
        Self(Aes128::new(&Array::from(*key)))
    }

    pub(crate) fn derive(&self, seed: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        let linear_image = Zeroizing::new(linear_orthomorphism(seed));
        let mut block = Array::from(*seed);
        self.0.encrypt_block(&mut block);
        for (byte, mask) in block.iter_mut().zip(linear_image.iter()) {
            *byte ^= mask;
        }

        let mut output = [0u8; BLOCK_SIZE];
        output.copy_from_slice(&block);
        block.as_mut_slice().zeroize();
        output
    }
}

pub(crate) struct Generator {
    blocks: Vec<SeedDeriver>,
}

impl Generator {
    pub(crate) fn new(salt: &[u8; BLOCK_SIZE], execution: u8, output_len: usize) -> Option<Self> {
        let block_count = output_len.checked_add(BLOCK_SIZE - 1)? / BLOCK_SIZE;
        if block_count > usize::from(u16::MAX) + 1 {
            return None;
        }

        let mut blocks = Vec::with_capacity(block_count);
        for block_index in 0..block_count {
            let block_index = u16::try_from(block_index).ok()?;
            let key = Zeroizing::new(tweak_salt(salt, PRG_SELECTOR, execution, block_index));
            blocks.push(SeedDeriver::new(&key));
        }
        Some(Self { blocks })
    }

    pub(crate) fn fill(&self, seed: &[u8; BLOCK_SIZE], output: &mut [u8]) -> bool {
        let Some(required_blocks) = output
            .len()
            .checked_add(BLOCK_SIZE - 1)
            .map(|length| length / BLOCK_SIZE)
        else {
            return false;
        };
        if required_blocks > self.blocks.len() {
            return false;
        }

        for (deriver, output_block) in self.blocks.iter().zip(output.chunks_mut(BLOCK_SIZE)) {
            let mut block = deriver.derive(seed);
            output_block.copy_from_slice(&block[..output_block.len()]);
            block.zeroize();
        }
        true
    }
}

/// Fill `output` with the MQOM PRG stream.
///
/// Returns `false` if the request would require a block index outside the
/// 16-bit tweak encoding.
pub(crate) fn fill(
    salt: &[u8; BLOCK_SIZE],
    execution: u8,
    seed: &[u8; BLOCK_SIZE],
    output: &mut [u8],
) -> bool {
    let Some(generator) = Generator::new(salt, execution, output.len()) else {
        return false;
    };
    generator.fill(seed, output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linear_map_matches_definition() {
        let seed = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        assert_eq!(
            linear_orthomorphism(&seed),
            [
                0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                0x06, 0x07,
            ]
        );
    }

    #[test]
    fn tweak_is_little_endian_and_domain_separated() {
        let salt = [0x55; BLOCK_SIZE];
        let tweaked = tweak_salt(&salt, PRG_SELECTOR, 2, 0x1234);
        assert_eq!(tweaked[0], 0x55 ^ 0x0b);
        assert_eq!(tweaked[1], 0x55 ^ 0x34);
        assert_eq!(tweaked[2], 0x55 ^ 0x12);
        assert_eq!(&tweaked[3..], &[0x55; BLOCK_SIZE - 3]);
    }

    #[test]
    fn partial_output_is_a_prefix_of_full_blocks() {
        let salt = [0x33; BLOCK_SIZE];
        let seed = [0xa5; BLOCK_SIZE];
        let mut short = [0u8; BLOCK_SIZE + 3];
        let mut full = [0u8; 2 * BLOCK_SIZE];
        assert!(fill(&salt, 7, &seed, &mut short));
        assert!(fill(&salt, 7, &seed, &mut full));
        assert_eq!(short, full[..short.len()]);
    }

    #[test]
    fn stream_matches_v2_1_1_oracle() {
        let salt = core::array::from_fn(|index| u8::try_from(index).unwrap());
        let seed = core::array::from_fn(|index| 0xf0 + u8::try_from(index).unwrap());
        let mut output = [0u8; 35];
        assert!(fill(&salt, 2, &seed, &mut output));
        assert_eq!(
            output,
            [
                0xb5, 0xf7, 0x35, 0x5f, 0xe7, 0xd1, 0xa8, 0xa0, 0x0e, 0xd2, 0xcc, 0x1d, 0x9a, 0xf0,
                0x41, 0x10, 0x1e, 0x33, 0x2e, 0x1b, 0x53, 0x44, 0x8e, 0x0c, 0x09, 0x8b, 0x23, 0xb6,
                0x63, 0x7e, 0x8b, 0xc8, 0xc2, 0x21, 0xbf,
            ]
        );
    }
}
