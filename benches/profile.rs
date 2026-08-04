use getrandom::SysRng;
use mqom::mqom2_l1_gf16_short_r5::{Signature, SigningKey};
use std::{hint::black_box, time::Instant};

fn measure<T>(name: &str, iterations: u32, mut operation: impl FnMut() -> T) -> T {
    let start = Instant::now();
    let mut result = black_box(operation());
    for _ in 1..iterations {
        result = black_box(operation());
    }
    let elapsed = start.elapsed();
    println!(
        "{name}: {iterations} iterations, {:?} total, {:?} average",
        elapsed,
        elapsed / iterations
    );
    result
}

fn main() {
    const MESSAGE: &[u8] = b"mqom-rs benchmark message";
    let keygen_iterations = 20;
    let signing_iterations = 5;
    let verification_iterations = 100;

    let mut keygen_rng = SysRng;
    let key = measure("key generation", keygen_iterations, || {
        SigningKey::generate(&mut keygen_rng).unwrap()
    });
    let verifying_key = key.verifying_key();

    let mut signing_rng = SysRng;
    let signature: Signature = measure("signing", signing_iterations, || {
        key.try_sign_with_rng(&mut signing_rng, MESSAGE).unwrap()
    });
    measure("verification", verification_iterations, || {
        verifying_key.verify(MESSAGE, &signature).unwrap();
    });
}
