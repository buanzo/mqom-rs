#![no_main]

use libfuzzer_sys::fuzz_target;
use mqom::mqom2_l1_gf16_short_r5::{
    PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, SIGNATURE_SIZE, Signature, SigningKey, VerifyingKey,
};

fuzz_target!(|data: &[u8]| {
    let _ = VerifyingKey::from_slice(data);
    let _ = Signature::from_slice(data);
    let _ = SigningKey::from_slice(data);

    if data.len() >= PUBLIC_KEY_SIZE {
        let _ = VerifyingKey::from_slice(&data[..PUBLIC_KEY_SIZE]);
    }
    if data.len() >= SECRET_KEY_SIZE {
        let _ = SigningKey::from_slice(&data[..SECRET_KEY_SIZE]);
    }
    if data.len() >= SIGNATURE_SIZE {
        let _ = Signature::from_slice(&data[..SIGNATURE_SIZE]);
    }
});
