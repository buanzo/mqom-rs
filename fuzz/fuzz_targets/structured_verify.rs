#![no_main]

use libfuzzer_sys::fuzz_target;
use mqom::mqom2_l1_gf16_short_r5::{
    PUBLIC_KEY_SIZE, SIGNATURE_SIZE, Signature, SigningKey, VerifyingKey,
};
use rand_core::{TryCryptoRng, TryRng};
use std::{convert::Infallible, sync::OnceLock};

const MESSAGE: &[u8] = b"mqom-rs structured verifier fuzz fixture";

struct Fixture {
    public_key: [u8; PUBLIC_KEY_SIZE],
    signature: [u8; SIGNATURE_SIZE],
}

struct DeterministicRng(u8);

impl TryRng for DeterministicRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

impl TryCryptoRng for DeterministicRng {}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let mut rng = DeterministicRng(0);
        let signing_key = SigningKey::generate(&mut rng).expect("fixture key generation");
        let signature = signing_key
            .try_sign_with_rng(&mut rng, MESSAGE)
            .expect("fixture signing");
        Fixture {
            public_key: signing_key.verifying_key().to_bytes(),
            signature: signature.to_bytes(),
        }
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let fixture = fixture();
    // Byte 0 selects the invariant, bytes 1-2 select an encoded offset, and
    // byte 3 selects the bit to flip. Extra bytes remain available to
    // libFuzzer for crossover and input-shape exploration.
    let offset = usize::from(u16::from_le_bytes([data[1], data[2]]));
    let mask = 1u8 << (data[3] & 7);

    match data[0] & 3 {
        0 => {
            let key = VerifyingKey::from_slice(&fixture.public_key).expect("fixture public key");
            let signature = Signature::from_slice(&fixture.signature).expect("fixture signature");
            assert!(key.verify(MESSAGE, &signature).is_ok());
        }
        1 => {
            let key = VerifyingKey::from_slice(&fixture.public_key).expect("fixture public key");
            let mut encoded = fixture.signature;
            encoded[offset % SIGNATURE_SIZE] ^= mask;
            let signature = Signature::from_slice(&encoded).expect("mutated signature encoding");
            assert!(key.verify(MESSAGE, &signature).is_err());
        }
        2 => {
            let mut encoded = fixture.public_key;
            encoded[offset % PUBLIC_KEY_SIZE] ^= mask;
            let key = VerifyingKey::from_slice(&encoded).expect("mutated public-key encoding");
            let signature = Signature::from_slice(&fixture.signature).expect("fixture signature");
            assert!(key.verify(MESSAGE, &signature).is_err());
        }
        _ => {
            let key = VerifyingKey::from_slice(&fixture.public_key).expect("fixture public key");
            let signature = Signature::from_slice(&fixture.signature).expect("fixture signature");
            let mut message = MESSAGE.to_vec();
            let message_len = message.len();
            message[offset % message_len] ^= mask;
            assert!(key.verify(&message, &signature).is_err());
        }
    }
});
