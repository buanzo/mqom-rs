#![no_main]

use libfuzzer_sys::fuzz_target;
use mqom::mqom2_l1_gf16_short_r5::{
    PUBLIC_KEY_SIZE, SIGNATURE_SIZE, Signature, VerifyingKey,
};

const ENCODINGS_SIZE: usize = PUBLIC_KEY_SIZE + SIGNATURE_SIZE;

fuzz_target!(|data: &[u8]| {
    if data.len() < ENCODINGS_SIZE {
        return;
    }

    let Ok(key) = VerifyingKey::from_slice(&data[..PUBLIC_KEY_SIZE]) else {
        return;
    };
    let Ok(signature) = Signature::from_slice(&data[PUBLIC_KEY_SIZE..ENCODINGS_SIZE]) else {
        return;
    };
    let message = &data[ENCODINGS_SIZE..];
    let _ = key.verify(message, &signature);
});
