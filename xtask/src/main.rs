use std::{
    convert::Infallible,
    env,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

use aes::{
    Aes256,
    cipher::{Array, BlockCipherEncrypt, KeyInit},
};
use mqom::mqom2_l1_gf16_short_r5::SigningKey;
use mqom::mqom2_l1_gf16_short_r5::{Signature, VerifyingKey};
use rand_core::{TryCryptoRng, TryRng};

const ORACLE_COMMIT: &str = "01af24ad01203ad08e84f71f59cfa47cbb574050";
const PROFILE_CFLAGS: &str = "-DMQOM2_PARAM_SECURITY=128 -DMQOM2_PARAM_BASE_FIELD=4 -DMQOM2_PARAM_TRADEOFF=1 -DMQOM2_PARAM_NBROUNDS=5";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args_os().skip(1);
    let Some(command) = arguments.next() else {
        return Err(usage());
    };
    if command != "oracle" {
        return Err(usage());
    }

    let Some(flag) = arguments.next() else {
        return Err(usage());
    };
    if flag != "--source" {
        return Err(usage());
    }
    let Some(source) = arguments.next() else {
        return Err(usage());
    };
    if arguments.next().is_some() {
        return Err(usage());
    }

    prepare_oracle(&PathBuf::from(source))
}

fn usage() -> String {
    "usage: cargo xtask oracle --source /absolute/path/to/mqom-v2".to_owned()
}

fn prepare_oracle(source: &Path) -> Result<(), String> {
    if !source.is_absolute() {
        return Err("--source must be an absolute path".to_owned());
    }
    if !source.join(".git").exists() {
        return Err(format!("{} is not a Git checkout", source.display()));
    }

    let actual_commit =
        command_output(Command::new("git").args(["-C", path_text(source)?, "rev-parse", "HEAD"]))?;
    if actual_commit != ORACLE_COMMIT {
        return Err(format!(
            "oracle must be MQOM v2.1.1 commit {ORACLE_COMMIT}; found {actual_commit}"
        ));
    }

    run_command(Command::new("git").args([
        "-C",
        path_text(source)?,
        "diff",
        "--quiet",
        "--ignore-submodules",
        "HEAD",
        "--",
    ]))
    .map_err(|_| "oracle checkout has tracked modifications".to_owned())?;

    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| "xtask has no workspace parent".to_owned())?;
    let destination = workspace.join("target/oracle").join(ORACLE_COMMIT);
    let oracle_root = workspace.join("target/oracle");
    if destination.exists() {
        let canonical_destination = destination
            .canonicalize()
            .map_err(|error| format!("cannot resolve {}: {error}", destination.display()))?;
        let canonical_root = oracle_root
            .canonicalize()
            .map_err(|error| format!("cannot resolve {}: {error}", oracle_root.display()))?;
        if !canonical_destination.starts_with(&canonical_root) {
            return Err("refusing to replace an oracle path outside target/oracle".to_owned());
        }
        fs::remove_dir_all(&canonical_destination).map_err(|error| {
            format!("cannot clear {}: {error}", canonical_destination.display())
        })?;
    }
    fs::create_dir_all(&oracle_root)
        .map_err(|error| format!("cannot create {}: {error}", oracle_root.display()))?;

    run_command(
        Command::new("git")
            .args(["clone", "--quiet", "--no-local", "--no-checkout"])
            .arg(source)
            .arg(&destination),
    )?;
    run_command(Command::new("git").arg("-C").arg(&destination).args([
        "checkout",
        "--quiet",
        "--detach",
        ORACLE_COMMIT,
    ]))?;

    run_command(
        Command::new("make")
            .arg("-C")
            .arg(&destination)
            .args(["-j2", "kat_gen", "kat_check"])
            .env("EXTRA_CFLAGS", PROFILE_CFLAGS)
            .env("FORCE_PLATFORM_REF", "1"),
    )?;
    run_command(Command::new(destination.join("kat_gen")).current_dir(&destination))?;

    let response = destination.join("PQCsignKAT_88.rsp");
    let contents = fs::read_to_string(&response)
        .map_err(|error| format!("cannot read {}: {error}", response.display()))?;
    let case_count = contents
        .lines()
        .filter(|line| line.starts_with("count = "))
        .count();
    if case_count != 100 {
        return Err(format!(
            "expected 100 KAT cases in {}, found {case_count}",
            response.display()
        ));
    }
    let (verified_count, rust_response) = verify_response(&contents)?;
    let rust_output = destination.join("rust-generated");
    fs::create_dir_all(&rust_output)
        .map_err(|error| format!("cannot create {}: {error}", rust_output.display()))?;
    let rust_response_path = rust_output.join("PQCsignKAT_88.rsp");
    fs::write(&rust_response_path, rust_response)
        .map_err(|error| format!("cannot write {}: {error}", rust_response_path.display()))?;
    run_command(Command::new(destination.join("kat_check")).current_dir(&rust_output))?;

    println!("verified oracle commit: {ORACLE_COMMIT}");
    println!("generated 100 KAT cases: {}", response.display());
    println!(
        "reproduced {verified_count} KAT keypairs and signatures byte-for-byte in native Rust"
    );
    println!(
        "upstream kat_check accepted Rust output: {}",
        rust_response_path.display()
    );
    Ok(())
}

#[derive(Default)]
struct KatCase<'a> {
    count: Option<usize>,
    seed: Option<&'a str>,
    message_len: Option<usize>,
    message: Option<&'a str>,
    public_key: Option<&'a str>,
    secret_key: Option<&'a str>,
    signed_message_len: Option<usize>,
    signed_message: Option<&'a str>,
}

fn verify_response(contents: &str) -> Result<(usize, String), String> {
    let mut current = KatCase::default();
    let mut verified = 0;
    let mut rust_response = "# MQOM2-L1-gf16-short-r5\n\n".to_owned();

    for line in contents.lines().chain([""]) {
        let line = line.trim();
        if line.is_empty() {
            if current.count.is_some() {
                verify_case(&current, verified == 0, &mut rust_response)?;
                verified += 1;
                current = KatCase::default();
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }

        let Some((name, value)) = line.split_once(" = ") else {
            return Err(format!("malformed KAT line: {line}"));
        };
        match name {
            "count" => current.count = Some(parse_decimal(name, value)?),
            "seed" => current.seed = Some(value),
            "mlen" => current.message_len = Some(parse_decimal(name, value)?),
            "msg" => current.message = Some(value),
            "pk" => current.public_key = Some(value),
            "sk" => current.secret_key = Some(value),
            "smlen" => current.signed_message_len = Some(parse_decimal(name, value)?),
            "sm" => current.signed_message = Some(value),
            _ => {}
        }
    }

    if verified != 100 {
        return Err(format!(
            "native verifier expected 100 cases, found {verified}"
        ));
    }
    Ok((verified, rust_response))
}

fn parse_decimal(name: &str, value: &str) -> Result<usize, String> {
    value
        .parse()
        .map_err(|error| format!("invalid {name} value {value}: {error}"))
}

fn verify_case(
    case: &KatCase<'_>,
    test_mutations: bool,
    rust_response: &mut String,
) -> Result<(), String> {
    let count = case
        .count
        .ok_or_else(|| "KAT case has no count".to_owned())?;
    let message_len = case
        .message_len
        .ok_or_else(|| format!("KAT case {count} has no mlen"))?;
    let message = decode_hex(
        case.message
            .ok_or_else(|| format!("KAT case {count} has no msg"))?,
    )?;
    let seed = decode_fixed_hex::<48>(
        case.seed
            .ok_or_else(|| format!("KAT case {count} has no seed"))?,
    )?;
    let public_key_bytes = decode_hex(
        case.public_key
            .ok_or_else(|| format!("KAT case {count} has no pk"))?,
    )?;
    let secret_key_bytes = decode_hex(
        case.secret_key
            .ok_or_else(|| format!("KAT case {count} has no sk"))?,
    )?;
    let signed_message_len = case
        .signed_message_len
        .ok_or_else(|| format!("KAT case {count} has no smlen"))?;
    let signed_message = decode_hex(
        case.signed_message
            .ok_or_else(|| format!("KAT case {count} has no sm"))?,
    )?;

    if message.len() != message_len
        || signed_message.len() != signed_message_len
        || signed_message.get(..message_len) != Some(message.as_slice())
    {
        return Err(format!("KAT case {count} has inconsistent message lengths"));
    }
    let signature_bytes = signed_message
        .get(message_len..)
        .ok_or_else(|| format!("KAT case {count} has no detached signature"))?;
    let public_key = VerifyingKey::from_slice(&public_key_bytes)
        .map_err(|error| format!("KAT case {count} public key: {error}"))?;
    let mut kat_rng = KatDrbg::new(&seed);
    let generated_key = SigningKey::generate(&mut kat_rng)
        .map_err(|_| format!("native key generation failed for KAT case {count}"))?;
    if generated_key.verifying_key().as_ref() != public_key_bytes
        || generated_key.to_bytes().as_ref() != secret_key_bytes
    {
        return Err(format!(
            "native key generation differs from KAT case {count}"
        ));
    }
    let generated_signature = generated_key
        .try_sign_with_rng(&mut kat_rng, &message)
        .map_err(|_| format!("native signing failed for KAT case {count}"))?;
    if generated_signature.as_ref() != signature_bytes {
        let first_difference = generated_signature
            .as_ref()
            .iter()
            .zip(signature_bytes)
            .position(|(generated, expected)| generated != expected);
        return Err(format!(
            "native signature differs from KAT case {count} at byte {first_difference:?}"
        ));
    }
    writeln!(rust_response, "count = {count}").map_err(|error| error.to_string())?;
    append_hex_line(rust_response, "seed", &seed);
    writeln!(rust_response, "mlen = {}", message.len()).map_err(|error| error.to_string())?;
    append_hex_line(rust_response, "msg", &message);
    append_hex_line(rust_response, "pk", generated_key.verifying_key().as_ref());
    let generated_secret_key = generated_key.to_bytes();
    append_hex_line(rust_response, "sk", generated_secret_key.as_ref());
    writeln!(
        rust_response,
        "smlen = {}",
        message.len() + generated_signature.as_ref().len()
    )
    .map_err(|error| error.to_string())?;
    rust_response.push_str("sm = ");
    append_hex(rust_response, &message);
    append_hex(rust_response, generated_signature.as_ref());
    rust_response.push_str("\n\n");
    let signature = Signature::from_slice(signature_bytes)
        .map_err(|error| format!("KAT case {count} signature: {error}"))?;
    public_key
        .verify(&message, &signature)
        .map_err(|_| format!("native verification failed for KAT case {count}"))?;

    if test_mutations {
        reject_targeted_mutations(count, &public_key_bytes, &message, signature_bytes)?;
    }
    Ok(())
}

fn append_hex_line(output: &mut String, name: &str, bytes: &[u8]) {
    output.push_str(name);
    output.push_str(" = ");
    append_hex(output, bytes);
    output.push('\n');
}

fn append_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}

struct KatDrbg {
    key: [u8; 32],
    value: [u8; 16],
}

impl KatDrbg {
    fn new(seed: &[u8; 48]) -> Self {
        let mut state = Self {
            key: [0u8; 32],
            value: [0u8; 16],
        };
        state.update(Some(seed));
        state
    }

    fn increment_value(&mut self) {
        for byte in self.value.iter_mut().rev() {
            let (incremented, overflow) = byte.overflowing_add(1);
            *byte = incremented;
            if !overflow {
                break;
            }
        }
    }

    fn update(&mut self, provided: Option<&[u8; 48]>) {
        let cipher = Aes256::new(&Array::from(self.key));
        let mut temporary = [0u8; 48];
        for block in temporary.chunks_exact_mut(16) {
            self.increment_value();
            let mut encrypted = Array::from(self.value);
            cipher.encrypt_block(&mut encrypted);
            block.copy_from_slice(&encrypted);
        }
        if let Some(provided) = provided {
            for (byte, provided) in temporary.iter_mut().zip(provided) {
                *byte ^= provided;
            }
        }
        self.key.copy_from_slice(&temporary[..32]);
        self.value.copy_from_slice(&temporary[32..]);
    }

    fn generate(&mut self, output: &mut [u8]) {
        let cipher = Aes256::new(&Array::from(self.key));
        for block in output.chunks_mut(16) {
            self.increment_value();
            let mut encrypted = Array::from(self.value);
            cipher.encrypt_block(&mut encrypted);
            block.copy_from_slice(&encrypted[..block.len()]);
        }
        self.update(None);
    }
}

impl TryRng for KatDrbg {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.generate(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.generate(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        self.generate(destination);
        Ok(())
    }
}

impl TryCryptoRng for KatDrbg {}

fn reject_targeted_mutations(
    count: usize,
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), String> {
    for position in [0, 16, 80, 272, signature_bytes.len() - 1] {
        let mut mutated = signature_bytes.to_vec();
        mutated[position] ^= 1;
        let signature = Signature::from_slice(&mutated)
            .map_err(|error| format!("mutation parse for case {count}: {error}"))?;
        let public_key = VerifyingKey::from_slice(public_key_bytes)
            .map_err(|error| format!("mutation key for case {count}: {error}"))?;
        if public_key.verify(message, &signature).is_ok() {
            return Err(format!(
                "KAT case {count} accepted signature mutation at byte {position}"
            ));
        }
    }

    let mut mutated_message = message.to_vec();
    let Some(first_byte) = mutated_message.first_mut() else {
        return Err(format!("KAT case {count} has an empty mutation message"));
    };
    *first_byte ^= 1;
    let public_key = VerifyingKey::from_slice(public_key_bytes)
        .map_err(|error| format!("message mutation key for case {count}: {error}"))?;
    let signature = Signature::from_slice(signature_bytes)
        .map_err(|error| format!("message mutation signature for case {count}: {error}"))?;
    if public_key.verify(&mutated_message, &signature).is_ok() {
        return Err(format!("KAT case {count} accepted a message mutation"));
    }

    let mut mutated_key = public_key_bytes.to_vec();
    let Some(last_byte) = mutated_key.last_mut() else {
        return Err(format!("KAT case {count} has an empty public key"));
    };
    *last_byte ^= 1;
    let public_key = VerifyingKey::from_slice(&mutated_key)
        .map_err(|error| format!("public-key mutation for case {count}: {error}"))?;
    if public_key.verify(message, &signature).is_ok() {
        return Err(format!("KAT case {count} accepted a public-key mutation"));
    }
    Ok(())
}

fn decode_hex(encoded: &str) -> Result<Vec<u8>, String> {
    if encoded.len() % 2 != 0 {
        return Err("hex value has odd length".to_owned());
    }

    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = decode_nibble(pair[0])?;
            let low = decode_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn decode_fixed_hex<const N: usize>(encoded: &str) -> Result<[u8; N], String> {
    decode_hex(encoded)?
        .try_into()
        .map_err(|value: Vec<u8>| format!("expected {N} decoded bytes, found {}", value.len()))
}

fn decode_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex digit: {}", char::from(byte))),
    }
}

fn path_text(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("path is not valid UTF-8: {}", path.display()))
}

fn command_output(command: &mut Command) -> Result<String, String> {
    let description = format!("{command:?}");
    let output = command
        .output()
        .map_err(|error| format!("cannot run {description}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{description} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn run_command(command: &mut Command) -> Result<(), String> {
    let description = format!("{command:?}");
    let status = command
        .status()
        .map_err(|error| format!("cannot run {description}: {error}"))?;
    if !status.success() {
        return Err(format!("{description} exited with {status}"));
    }
    Ok(())
}
