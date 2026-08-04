//! Verification-side evaluation of the MQOM binary line commitment.

use crate::{
    field::{Gf16, Gf256x2, pack_gf16, unpack_gf16},
    params,
    prg::{self, Generator, SeedDeriver},
    xof::Shake128State,
};
use alloc::{vec, vec::Vec};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const SEED_SIZE: usize = params::SEED_SIZE;
const COMMITMENT_SIZE: usize = params::DIGEST_SIZE;
const BASE_VECTOR_SIZE: usize = params::MQ_N * params::BASE_FIELD_BITS / 8;
const MASK_VECTOR_SIZE: usize = params::ETA * params::EXT_FIELD_BITS / 8;
const EXPANDED_LEAF_SIZE: usize = BASE_VECTOR_SIZE + MASK_VECTOR_SIZE;
const LEAF_PRG_SIZE: usize = EXPANDED_LEAF_SIZE - SEED_SIZE;
const PARTIAL_DELTA_SIZE: usize = BASE_VECTOR_SIZE - SEED_SIZE;
const PATH_SIZE_PER_EXECUTION: usize = params::NB_EVALS_LOG * SEED_SIZE;
const PATHS_SIZE: usize = params::TAU * PATH_SIZE_PER_EXECUTION;
const HIDDEN_COMMITMENTS_SIZE: usize = params::TAU * COMMITMENT_SIZE;
const PARTIAL_DELTAS_OFFSET: usize = PATHS_SIZE + HIDDEN_COMMITMENTS_SIZE;
const FULL_TREE_SIZE: usize = 2 * params::NB_EVALS;
const LEAF_OFFSET: usize = params::NB_EVALS;
const ROOT_SEEDS_SIZE: usize = params::TAU * SEED_SIZE;
const ZERO_SALT: [u8; params::SALT_SIZE] = [0u8; params::SALT_SIZE];

const _: () = {
    assert!(BASE_VECTOR_SIZE == 28);
    assert!(MASK_VECTOR_SIZE == 16);
    assert!(LEAF_PRG_SIZE == 28);
    assert!(PARTIAL_DELTA_SIZE == 12);
    assert!(PATHS_SIZE == 2_112);
    assert!(HIDDEN_COMMITMENTS_SIZE == 384);
    assert!(PARTIAL_DELTAS_OFFSET + params::TAU * PARTIAL_DELTA_SIZE == params::OPENING_SIZE);
};

pub(crate) struct OpenedEvaluations {
    pub(crate) x: [[Gf256x2; params::MQ_N]; params::TAU],
    pub(crate) u: [[Gf256x2; params::ETA]; params::TAU],
}

pub(crate) struct SigningCommitment {
    pub(crate) commitment: [u8; COMMITMENT_SIZE],
    pub(crate) x_zero: [[Gf256x2; params::MQ_N]; params::TAU],
    pub(crate) u_zero: [[Gf256x2; params::ETA]; params::TAU],
    pub(crate) u_one: [[Gf256x2; params::ETA]; params::TAU],
    salt: [u8; SEED_SIZE],
    delta: [u8; SEED_SIZE],
    root_seeds: [[u8; SEED_SIZE]; params::TAU],
    partial_deltas: [[u8; PARTIAL_DELTA_SIZE]; params::TAU],
}

struct SecretTree(Vec<[u8; SEED_SIZE]>);

impl Drop for SecretTree {
    fn drop(&mut self) {
        for node in &mut self.0 {
            node.zeroize();
        }
    }
}

impl Drop for SigningCommitment {
    fn drop(&mut self) {
        self.x_zero.zeroize();
        self.u_zero.zeroize();
        self.u_one.zeroize();
        self.delta.zeroize();
        self.root_seeds.zeroize();
        self.partial_deltas.zeroize();
    }
}

struct SeedCommitter {
    first: SeedDeriver,
    second: SeedDeriver,
}

impl SeedCommitter {
    fn new(salt: &[u8; SEED_SIZE], execution: u8) -> Self {
        let first_key = prg::tweak_salt(salt, 0, execution, 0);
        let mut second_key = first_key;
        second_key[0] ^= 1;
        Self {
            first: SeedDeriver::new(&first_key),
            second: SeedDeriver::new(&second_key),
        }
    }

    fn commit(&self, seed: &[u8; SEED_SIZE]) -> [u8; COMMITMENT_SIZE] {
        let mut commitment = [0u8; COMMITMENT_SIZE];
        commitment[..SEED_SIZE].copy_from_slice(&self.first.derive(seed));
        commitment[SEED_SIZE..].copy_from_slice(&self.second.derive(seed));
        commitment
    }
}

fn partially_expand_tree(
    salt: &[u8; SEED_SIZE],
    path: &[u8],
    execution: u8,
    hidden_index: usize,
) -> Option<Vec<[u8; SEED_SIZE]>> {
    if path.len() != PATH_SIZE_PER_EXECUTION || hidden_index >= params::NB_EVALS {
        return None;
    }

    let mut nodes = vec![[0u8; SEED_SIZE]; FULL_TREE_SIZE];
    let mut present = vec![false; FULL_TREE_SIZE];
    let mut node_index = params::NB_EVALS + hidden_index;
    for sibling_seed in path.chunks_exact(SEED_SIZE) {
        let sibling_index = node_index ^ 1;
        nodes[sibling_index].copy_from_slice(sibling_seed);
        present[sibling_index] = true;
        node_index /= 2;
    }

    for depth in 1..params::NB_EVALS_LOG {
        let depth_index = u16::try_from(depth - 1).ok()?;
        let key = prg::tweak_salt(salt, 2, execution, depth_index);
        let deriver = SeedDeriver::new(&key);
        for parent_index in (1 << depth)..(1 << (depth + 1)) {
            if !present[parent_index] {
                continue;
            }
            let parent = nodes[parent_index];
            let left_index = 2 * parent_index;
            let left = deriver.derive(&parent);
            let mut right = left;
            for (right_byte, parent_byte) in right.iter_mut().zip(parent) {
                *right_byte ^= parent_byte;
            }
            nodes[left_index] = left;
            nodes[left_index + 1] = right;
            present[left_index] = true;
            present[left_index + 1] = true;
        }
    }

    for (index, is_present) in present[params::NB_EVALS..].iter().copied().enumerate() {
        if is_present == (index == hidden_index) {
            return None;
        }
    }

    nodes.drain(..params::NB_EVALS);
    nodes.truncate(params::NB_EVALS);
    Some(nodes)
}

fn fully_expand_tree(
    salt: &[u8; SEED_SIZE],
    root_seed: &[u8; SEED_SIZE],
    delta: &[u8; SEED_SIZE],
    execution: u8,
) -> SecretTree {
    let mut nodes = vec![[0u8; SEED_SIZE]; FULL_TREE_SIZE];
    nodes[2] = *root_seed;
    for ((right, left), delta) in nodes[3].iter_mut().zip(root_seed).zip(delta) {
        *right = *left ^ *delta;
    }

    for depth in 1..params::NB_EVALS_LOG {
        let depth_index = u16::try_from(depth - 1).expect("tree depth fits u16");
        let key = prg::tweak_salt(salt, 2, execution, depth_index);
        let deriver = SeedDeriver::new(&key);
        for parent_index in (1 << depth)..(1 << (depth + 1)) {
            let parent = nodes[parent_index];
            let left_index = 2 * parent_index;
            let left = deriver.derive(&parent);
            let mut right = left;
            for (right_byte, parent_byte) in right.iter_mut().zip(parent) {
                *right_byte ^= parent_byte;
            }
            nodes[left_index] = left;
            nodes[left_index + 1] = right;
        }
    }
    SecretTree(nodes)
}

fn opening_path(
    salt: &[u8; SEED_SIZE],
    root_seed: &[u8; SEED_SIZE],
    delta: &[u8; SEED_SIZE],
    execution: u8,
    hidden_index: usize,
    path: &mut [u8],
) -> Option<[u8; SEED_SIZE]> {
    if hidden_index >= params::NB_EVALS || path.len() != PATH_SIZE_PER_EXECUTION {
        return None;
    }

    let mut parent = *delta;
    let leaf_index = params::NB_EVALS + hidden_index;
    for depth in 0..params::NB_EVALS_LOG {
        let left = if depth == 0 {
            *root_seed
        } else {
            let depth_index = u16::try_from(depth - 1).ok()?;
            let key = prg::tweak_salt(salt, 2, execution, depth_index);
            SeedDeriver::new(&key).derive(&parent)
        };
        let mut right = left;
        for (right_byte, parent_byte) in right.iter_mut().zip(parent) {
            *right_byte ^= parent_byte;
        }

        let bit = (leaf_index >> (params::NB_EVALS_LOG - 1 - depth)) & 1;
        let (selected, sibling) = if bit == 0 {
            (left, right)
        } else {
            (right, left)
        };
        let path_index = params::NB_EVALS_LOG - 1 - depth;
        path[path_index * SEED_SIZE..(path_index + 1) * SEED_SIZE].copy_from_slice(&sibling);
        parent = selected;
    }
    Some(parent)
}

fn gray_code(index: usize) -> Option<u16> {
    let index = u16::try_from(index).ok()?;
    Some(index ^ (index >> 1))
}

fn gray_code_bit_position(index: usize) -> Option<usize> {
    let current = gray_code(index)?;
    let next = if index + 1 < params::NB_EVALS {
        gray_code(index + 1)?
    } else {
        0
    };
    let position = usize::try_from((current ^ next).trailing_zeros()).ok()?;
    (position < params::NB_EVALS_LOG).then_some(position)
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

fn xor_bytes(destination: &mut [u8], source: &[u8]) -> Option<()> {
    if destination.len() != source.len() {
        return None;
    }
    for (destination, source) in destination.iter_mut().zip(source) {
        *destination ^= source;
    }
    Some(())
}

pub(crate) fn commit(
    master_seed: &[u8; SEED_SIZE],
    salt: &[u8; SEED_SIZE],
    secret: &[Gf16; params::MQ_N],
) -> Option<SigningCommitment> {
    let mut serialized_secret = Zeroizing::new([0u8; BASE_VECTOR_SIZE]);
    pack_gf16(secret, serialized_secret.as_mut()).then_some(())?;
    let mut delta = [0u8; SEED_SIZE];
    delta.copy_from_slice(&serialized_secret[..SEED_SIZE]);

    let mut root_seed_stream = Zeroizing::new([0u8; ROOT_SEEDS_SIZE]);
    prg::fill(&ZERO_SALT, 0, master_seed, root_seed_stream.as_mut()).then_some(())?;
    let mut root_seeds = [[0u8; SEED_SIZE]; params::TAU];
    for (destination, encoded) in root_seeds
        .iter_mut()
        .zip(root_seed_stream.chunks_exact(SEED_SIZE))
    {
        destination.copy_from_slice(encoded);
    }

    let mut x_zero = [[Gf256x2::ZERO; params::MQ_N]; params::TAU];
    let mut u_zero = [[Gf256x2::ZERO; params::ETA]; params::TAU];
    let mut u_one = [[Gf256x2::ZERO; params::ETA]; params::TAU];
    let mut partial_deltas = [[0u8; PARTIAL_DELTA_SIZE]; params::TAU];
    let mut leaf_commitment_hashes = [[0u8; COMMITMENT_SIZE]; params::TAU];

    for execution in 0..params::TAU {
        let execution_u8 = u8::try_from(execution).ok()?;
        let nodes = fully_expand_tree(salt, &root_seeds[execution], &delta, execution_u8);
        let leaves = &nodes.0[LEAF_OFFSET..];
        if leaves.len() != params::NB_EVALS {
            return None;
        }

        let committer = SeedCommitter::new(salt, execution_u8);
        let generator = Generator::new(salt, execution_u8, LEAF_PRG_SIZE)?;
        let mut commitment_hash = Shake128State::new();
        commitment_hash.absorb(&[0x06]);
        let mut accumulator = Zeroizing::new([0u8; EXPANDED_LEAF_SIZE]);
        let mut folding = Zeroizing::new([[0u8; EXPANDED_LEAF_SIZE]; params::NB_EVALS_LOG]);

        for (leaf_index, leaf_seed) in leaves.iter().enumerate() {
            let commitment = Zeroizing::new(committer.commit(leaf_seed));
            commitment_hash.absorb(commitment.as_ref());

            let mut expanded = Zeroizing::new([0u8; EXPANDED_LEAF_SIZE]);
            expanded[..SEED_SIZE].copy_from_slice(leaf_seed);
            generator
                .fill(leaf_seed, &mut expanded[SEED_SIZE..])
                .then_some(())?;
            xor_bytes(accumulator.as_mut(), expanded.as_ref())?;
            let folding_index = gray_code_bit_position(leaf_index)?;
            xor_bytes(&mut folding[folding_index], accumulator.as_ref())?;
        }
        commitment_hash.squeeze(&mut leaf_commitment_hashes[execution]);

        for (folding_index, folded) in folding.iter().enumerate() {
            let basis = Gf256x2::from_bytes((1u16 << folding_index).to_le_bytes());
            let mut base_vector = Zeroizing::new([Gf16::ZERO; params::MQ_N]);
            unpack_gf16(&folded[..BASE_VECTOR_SIZE], base_vector.as_mut()).then_some(())?;
            for (evaluation, base_element) in x_zero[execution]
                .iter_mut()
                .zip(base_vector.iter().copied())
            {
                *evaluation += base_element * basis;
            }

            let mask_vector =
                parse_extension_vector::<{ params::ETA }>(&folded[BASE_VECTOR_SIZE..])?;
            for (evaluation, mask_element) in u_zero[execution].iter_mut().zip(mask_vector) {
                *evaluation += basis * mask_element;
            }
        }
        u_one[execution] =
            parse_extension_vector::<{ params::ETA }>(&accumulator[BASE_VECTOR_SIZE..])?;
        for (destination, (secret_byte, accumulator_byte)) in
            partial_deltas[execution].iter_mut().zip(
                serialized_secret[SEED_SIZE..]
                    .iter()
                    .zip(&accumulator[SEED_SIZE..BASE_VECTOR_SIZE]),
            )
        {
            *destination = *secret_byte ^ *accumulator_byte;
        }
    }

    let mut commitment_hash = Shake128State::new();
    commitment_hash.absorb(&[0x07]);
    for hash in &leaf_commitment_hashes {
        commitment_hash.absorb(hash);
    }
    for partial_delta in &partial_deltas {
        commitment_hash.absorb(partial_delta);
    }
    let mut commitment = [0u8; COMMITMENT_SIZE];
    commitment_hash.squeeze(&mut commitment);

    Some(SigningCommitment {
        commitment,
        x_zero,
        u_zero,
        u_one,
        salt: *salt,
        delta,
        root_seeds,
        partial_deltas,
    })
}

impl SigningCommitment {
    pub(crate) fn open(
        &self,
        hidden_indices: &[u16; params::TAU],
    ) -> Option<[u8; params::OPENING_SIZE]> {
        let mut opening = [0u8; params::OPENING_SIZE];
        for (execution, hidden_index) in hidden_indices.iter().copied().enumerate() {
            let execution_u8 = u8::try_from(execution).ok()?;
            let hidden_index = usize::from(hidden_index);
            let path_offset = execution * PATH_SIZE_PER_EXECUTION;
            let hidden_seed = Zeroizing::new(opening_path(
                &self.salt,
                &self.root_seeds[execution],
                &self.delta,
                execution_u8,
                hidden_index,
                &mut opening[path_offset..path_offset + PATH_SIZE_PER_EXECUTION],
            )?);
            let hidden_commitment =
                SeedCommitter::new(&self.salt, execution_u8).commit(&hidden_seed);
            let commitment_offset = PATHS_SIZE + execution * COMMITMENT_SIZE;
            opening[commitment_offset..commitment_offset + COMMITMENT_SIZE]
                .copy_from_slice(&hidden_commitment);

            let partial_delta_offset = PARTIAL_DELTAS_OFFSET + execution * PARTIAL_DELTA_SIZE;
            opening[partial_delta_offset..partial_delta_offset + PARTIAL_DELTA_SIZE]
                .copy_from_slice(&self.partial_deltas[execution]);
        }
        Some(opening)
    }
}

pub(crate) fn evaluate_opening(
    salt: &[u8; params::SALT_SIZE],
    expected_commitment: &[u8; params::DIGEST_SIZE],
    opening: &[u8],
    hidden_indices: &[u16; params::TAU],
) -> Option<OpenedEvaluations> {
    if opening.len() != params::OPENING_SIZE {
        return None;
    }

    let mut x_evaluations = [[Gf256x2::ZERO; params::MQ_N]; params::TAU];
    let mut u_evaluations = [[Gf256x2::ZERO; params::ETA]; params::TAU];
    let mut leaf_commitment_hashes = [[0u8; params::DIGEST_SIZE]; params::TAU];

    for execution in 0..params::TAU {
        let execution_u8 = u8::try_from(execution).ok()?;
        let hidden_index = usize::from(hidden_indices[execution]);
        if hidden_index >= params::NB_EVALS {
            return None;
        }

        let path_offset = execution * PATH_SIZE_PER_EXECUTION;
        let path = &opening[path_offset..path_offset + PATH_SIZE_PER_EXECUTION];
        let leaves = partially_expand_tree(salt, path, execution_u8, hidden_index)?;
        let hidden_commitment_offset = PATHS_SIZE + execution * COMMITMENT_SIZE;
        let hidden_commitment =
            &opening[hidden_commitment_offset..hidden_commitment_offset + COMMITMENT_SIZE];
        let partial_delta_offset = PARTIAL_DELTAS_OFFSET + execution * PARTIAL_DELTA_SIZE;
        let partial_delta =
            &opening[partial_delta_offset..partial_delta_offset + PARTIAL_DELTA_SIZE];

        let committer = SeedCommitter::new(salt, execution_u8);
        let generator = Generator::new(salt, execution_u8, LEAF_PRG_SIZE)?;
        let mut commitment_hash = Shake128State::new();
        commitment_hash.absorb(&[0x06]);
        let mut accumulator = [0u8; EXPANDED_LEAF_SIZE];
        let mut folding = [[0u8; EXPANDED_LEAF_SIZE]; params::NB_EVALS_LOG];

        for (leaf_index, leaf_seed) in leaves.iter().enumerate() {
            let mut expanded = [0u8; EXPANDED_LEAF_SIZE];
            if leaf_index == hidden_index {
                commitment_hash.absorb(hidden_commitment);
            } else {
                let commitment = committer.commit(leaf_seed);
                commitment_hash.absorb(&commitment);
                expanded[..SEED_SIZE].copy_from_slice(leaf_seed);
                if !generator.fill(leaf_seed, &mut expanded[SEED_SIZE..]) {
                    return None;
                }
            }

            xor_bytes(&mut accumulator, &expanded)?;
            let folding_index = gray_code_bit_position(leaf_index)?;
            xor_bytes(&mut folding[folding_index], &accumulator)?;
        }
        commitment_hash.squeeze(&mut leaf_commitment_hashes[execution]);

        for (folding_index, folded) in folding.iter().enumerate() {
            let basis = Gf256x2::from_bytes((1u16 << folding_index).to_le_bytes());
            let mut base_vector = [Gf16::ZERO; params::MQ_N];
            if !unpack_gf16(&folded[..BASE_VECTOR_SIZE], &mut base_vector) {
                return None;
            }
            for (evaluation, base_element) in x_evaluations[execution].iter_mut().zip(base_vector) {
                *evaluation += base_element * basis;
            }

            let mask_vector =
                parse_extension_vector::<{ params::ETA }>(&folded[BASE_VECTOR_SIZE..])?;
            for (evaluation, mask_element) in u_evaluations[execution].iter_mut().zip(mask_vector) {
                *evaluation += basis * mask_element;
            }
        }

        let evaluation_point = Gf256x2::from_bytes(gray_code(hidden_index)?.to_le_bytes());
        let mut adjusted_base = [0u8; BASE_VECTOR_SIZE];
        adjusted_base.copy_from_slice(&accumulator[..BASE_VECTOR_SIZE]);
        xor_bytes(&mut adjusted_base[SEED_SIZE..], partial_delta)?;
        let mut adjusted_base_vector = [Gf16::ZERO; params::MQ_N];
        if !unpack_gf16(&adjusted_base, &mut adjusted_base_vector) {
            return None;
        }
        for (evaluation, base_element) in x_evaluations[execution]
            .iter_mut()
            .zip(adjusted_base_vector)
        {
            *evaluation += base_element * evaluation_point;
        }

        let accumulated_mask =
            parse_extension_vector::<{ params::ETA }>(&accumulator[BASE_VECTOR_SIZE..])?;
        for (evaluation, mask_element) in u_evaluations[execution].iter_mut().zip(accumulated_mask)
        {
            *evaluation += evaluation_point * mask_element;
        }
    }

    let mut commitment_hash = Shake128State::new();
    commitment_hash.absorb(&[0x07]);
    for hash in &leaf_commitment_hashes {
        commitment_hash.absorb(hash);
    }
    commitment_hash.absorb(&opening[PARTIAL_DELTAS_OFFSET..]);
    let mut observed_commitment = [0u8; params::DIGEST_SIZE];
    commitment_hash.squeeze(&mut observed_commitment);
    if !bool::from(observed_commitment.ct_eq(expected_commitment)) {
        return None;
    }

    Some(OpenedEvaluations {
        x: x_evaluations,
        u: u_evaluations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gray_code_cycle_has_one_bit_transitions() {
        for index in 0..params::NB_EVALS {
            let position = gray_code_bit_position(index).unwrap();
            assert!(position < params::NB_EVALS_LOG);
            let current = gray_code(index).unwrap();
            let next = if index + 1 < params::NB_EVALS {
                gray_code(index + 1).unwrap()
            } else {
                0
            };
            assert_eq!(current ^ next, 1 << position);
        }
    }

    #[test]
    fn malformed_opening_is_rejected_before_expansion() {
        assert!(
            evaluate_opening(
                &[0u8; params::SALT_SIZE],
                &[0u8; params::DIGEST_SIZE],
                &[0u8; params::OPENING_SIZE - 1],
                &[0u16; params::TAU],
            )
            .is_none()
        );
    }
}
